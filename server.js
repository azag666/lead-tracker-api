// Forçando novo deploy em 29/08/2025 - 20:10 (Cadastro simplificado e remoção do Twilio)
const express = require('express');
const cors = require('cors');
const { neon } = require('@neondatabase/serverless');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const path = require('path');
const crypto = require('crypto');
const webpush = require('web-push');

const app = express();
app.use(cors());
app.use(express.json());

// --- OTIMIZAÇÃO CRÍTICA: A conexão com o banco é inicializada UMA VEZ e reutilizada ---
const sql = neon(process.env.DATABASE_URL);

// --- CONFIGURAÇÃO DAS NOTIFICAÇÕES ---
if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
    webpush.setVapidDetails(
        process.env.VAPID_SUBJECT,
        process.env.VAPID_PUBLIC_KEY,
        process.env.VAPID_PRIVATE_KEY
    );
}
let adminSubscription = null;

// --- CONFIGURAÇÃO ---
const PUSHINPAY_SPLIT_ACCOUNT_ID = process.env.PUSHINPAY_SPLIT_ACCOUNT_ID;
const CNPAY_SPLIT_PRODUCER_ID = process.env.CNPAY_SPLIT_PRODUCER_ID;
const OASYFY_SPLIT_PRODUCER_ID = process.env.OASYFY_SPLIT_PRODUCER_ID;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;

// URL base da API da SyncPay
const SYNCPAY_API_BASE_URL = 'https://api.syncpayments.com.br';

// Cache para tokens da SyncPay (evita pedir um token novo a cada PIX)
const syncPayTokenCache = new Map();


// --- MIDDLEWARE DE AUTENTICAÇÃO ---
async function authenticateJwt(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token não fornecido.' });
    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error("Erro na verificação do JWT:", err.message);
            return res.status(403).json({ message: 'Token inválido ou expirado.' });
        }
        req.user = user;
        next();
    });
}

// --- MIDDLEWARE DE LOG DE REQUISIÇÕES ---
async function logApiRequest(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) return next();
    try {
        const sellerResult = await sql`SELECT id FROM sellers WHERE api_key = ${apiKey}`;
        if (sellerResult.length > 0) {
            const sellerId = sellerResult[0].id;
            const endpoint = req.path;
            sql`INSERT INTO api_requests (seller_id, endpoint) VALUES (${sellerId}, ${endpoint})`.catch(err => console.error("Falha ao logar requisição:", err));
        }
    } catch (error) {
        console.error("Erro no middleware de log:", error);
    }
    next();
}

// --- FUNÇÕES DE LÓGICA DE NEGÓCIO ---

async function getSyncPayAuthToken(seller) {
    const cachedToken = syncPayTokenCache.get(seller.id);
    if (cachedToken && cachedToken.expiresAt > Date.now() + 60000) {
        return cachedToken.accessToken;
    }

    if (!seller.syncpay_client_id || !seller.syncpay_client_secret) {
        throw new Error('Credenciais da SyncPay não configuradas para este vendedor.');
    }
    
    console.log(`[SyncPay] Solicitando novo token para o vendedor ID: ${seller.id}`);
    const response = await axios.post(`${SYNCPAY_API_BASE_URL}/api/partner/v1/auth-token`, {
        client_id: seller.syncpay_client_id,
        client_secret: seller.syncpay_client_secret,
    });

    const { access_token, expires_in } = response.data;
    const expiresAt = Date.now() + (expires_in * 1000);

    syncPayTokenCache.set(seller.id, { accessToken: access_token, expiresAt });
    return access_token;
}

async function generatePixForProvider(provider, seller, value_cents, host, apiKey) {
    let pixData;
    let acquirer = 'Não identificado';
    const clientPayload = {
        name: "Cliente Padrão",
        email: "gabriel@gmail.com",
        document: "21376710773",
        phone: "27995310379"
    };
    
    if (provider === 'syncpay') {
        const token = await getSyncPayAuthToken(seller);
        const payload = { amount: value_cents / 100, payer: clientPayload };
        const commission_percentage = 2.99;
        
        if (apiKey !== ADMIN_API_KEY && process.env.SYNCPAY_SPLIT_ACCOUNT_ID) {
            payload.split = [{
                percentage: Math.round(commission_percentage), 
                user_id: process.env.SYNCPAY_SPLIT_ACCOUNT_ID 
            }];
        }
        
        const response = await axios.post(`${SYNCPAY_API_BASE_URL}/api/partner/v1/cash-in`, payload, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        pixData = response.data;
        acquirer = "SyncPay";
        
        return { 
            qr_code_text: pixData.pix_code, 
            qr_code_base64: null, 
            transaction_id: pixData.identifier, 
            acquirer, 
            provider 
        };

    } else if (provider === 'cnpay' || provider === 'oasyfy') {
        const isCnpay = provider === 'cnpay';
        const publicKey = isCnpay ? seller.cnpay_public_key : seller.oasyfy_public_key;
        const secretKey = isCnpay ? seller.cnpay_secret_key : seller.oasyfy_secret_key;
        if (!publicKey || !secretKey) throw new Error(`Credenciais para ${provider.toUpperCase()} não configuradas.`);

        const apiUrl = isCnpay ? 'https://painel.appcnpay.com/api/v1/gateway/pix/receive' : 'https://app.oasyfy.com/api/v1/gateway/pix/receive';
        const splitId = isCnpay ? CNPAY_SPLIT_PRODUCER_ID : OASYFY_SPLIT_PRODUCER_ID;
        
        const payload = {
            identifier: uuidv4(),
            amount: value_cents / 100,
            client: clientPayload,
            callbackUrl: `https://${host}/api/webhook/${provider}`
        };

        const commission = parseFloat(((value_cents / 100) * 0.0299).toFixed(2));
        if (apiKey !== ADMIN_API_KEY && commission > 0 && splitId) {
            payload.splits = [{ producerId: splitId, amount: commission }];
        }

        const response = await axios.post(apiUrl, payload, { headers: { 'x-public-key': publicKey, 'x-secret-key': secretKey } });
        pixData = response.data;
        acquirer = isCnpay ? "CNPay" : "Oasy.fy";
        return { qr_code_text: pixData.pix.code, qr_code_base64: pixData.pix.base64, transaction_id: pixData.transactionId, acquirer, provider };

    } else { // Padrão é PushinPay
        if (!seller.pushinpay_token) throw new Error(`Token da PushinPay não configurado.`);
        const payload = {
            value: value_cents,
            webhook_url: `https://${host}/api/webhook/pushinpay`,
        };
        
        const commission_cents = Math.floor(value_cents * 0.0299);
        if (apiKey !== ADMIN_API_KEY && commission_cents > 0 && PUSHINPAY_SPLIT_ACCOUNT_ID) {
            payload.split_rules = [{ value: commission_cents, account_id: PUSHINPAY_SPLIT_ACCOUNT_ID }];
        }

        const pushinpayResponse = await axios.post('https://api.pushinpay.com.br/api/pix/cashIn', payload, { headers: { Authorization: `Bearer ${seller.pushinpay_token}` } });
        pixData = pushinpayResponse.data;
        acquirer = "Woovi";
        return { qr_code_text: pixData.qr_code, qr_code_base64: pixData.qr_code_base64, transaction_id: pixData.id, acquirer, provider: 'pushinpay' };
    }
}

async function handleSuccessfulPayment(transaction_id, customerData) {
    try {
        const [transaction] = await sql`UPDATE pix_transactions SET status = 'paid', paid_at = NOW() WHERE id = ${transaction_id} AND status != 'paid' RETURNING *`;
        if (!transaction) { 
            console.log(`[handleSuccessfulPayment] Transação ${transaction_id} já processada ou não encontrada.`);
            return; 
        }

        console.log(`[handleSuccessfulPayment] Processando pagamento para transação ${transaction_id}.`);

        if (adminSubscription && webpush) {
            const payload = JSON.stringify({
                title: 'Nova Venda Paga!',
                body: `Venda de R$ ${parseFloat(transaction.pix_value).toFixed(2)} foi confirmada.`,
            });
            webpush.sendNotification(adminSubscription, payload).catch(error => {
                if (error.statusCode === 410) {
                    console.log("Inscrição de notificação expirada. Removendo.");
                    adminSubscription = null;
                } else {
                    console.warn("Falha ao enviar notificação push (não-crítico):", error.message);
                }
            });
        }
        
        const [click] = await sql`SELECT * FROM clicks WHERE id = ${transaction.click_id_internal}`;
        const [seller] = await sql`SELECT * FROM sellers WHERE id = ${click.seller_id}`;

        if (click && seller) {
            const finalCustomerData = customerData || { name: "Cliente Pagante", document: null };
            const productData = { id: "prod_final", name: "Produto Vendido" };

            await sendEventToUtmify('paid', click, transaction, seller, finalCustomerData, productData);
            await sendMetaEvent('Purchase', click, transaction, finalCustomerData);
            await checkAndAwardAchievements(seller.id); 
        } else {
            console.error(`[handleSuccessfulPayment] ERRO: Não foi possível encontrar dados do clique ou vendedor para a transação ${transaction_id}`);
        }
    } catch(error) {
        console.error(`[handleSuccessfulPayment] ERRO CRÍTICO ao processar pagamento da transação ${transaction_id}:`, error);
    }
}


// --- ROTAS DO PAINEL ADMINISTRATIVO ---
function authenticateAdmin(req, res, next) {
    const adminKey = req.headers['x-admin-api-key'];
    if (!adminKey || adminKey !== ADMIN_API_KEY) {
        return res.status(403).json({ message: 'Acesso negado. Chave de administrador inválida.' });
    }
    next();
}

async function sendHistoricalMetaEvent(eventName, clickData, transactionData, targetPixel) {
    let payload_sent = null;
    try {
        const userData = {};
        if (clickData.ip_address) userData.client_ip_address = clickData.ip_address;
        if (clickData.user_agent) userData.client_user_agent = clickData.user_agent;
        if (clickData.fbp) userData.fbp = clickData.fbp;
        if (clickData.fbc) userData.fbc = clickData.fbc;
        if (clickData.firstName) userData.fn = crypto.createHash('sha256').update(clickData.firstName.toLowerCase()).digest('hex');
        if (clickData.lastName) userData.ln = crypto.createHash('sha256').update(clickData.lastName.toLowerCase()).digest('hex');
        
        const city = clickData.city && clickData.city !== 'Desconhecida' ? clickData.city.toLowerCase().replace(/[^a-z]/g, '') : null;
        const state = clickData.state && clickData.state !== 'Desconhecido' ? clickData.state.toLowerCase().replace(/[^a-z]/g, '') : null;
        if (city) userData.ct = crypto.createHash('sha256').update(city).digest('hex');
        if (state) userData.st = crypto.createHash('sha256').update(state).digest('hex');

        Object.keys(userData).forEach(key => userData[key] === undefined && delete userData[key]);
        
        const { pixelId, accessToken } = targetPixel;
        const event_time = Math.floor(new Date(transactionData.paid_at).getTime() / 1000);
        const event_id = `${eventName}.${transactionData.id}.${pixelId}`;

        const payload = {
            data: [{
                event_name: eventName,
                event_time: event_time,
                event_id,
                action_source: 'other',
                user_data: userData,
                custom_data: {
                    currency: 'BRL',
                    value: parseFloat(transactionData.pix_value)
                },
            }]
        };
        payload_sent = payload;

        if (Object.keys(userData).length === 0) {
            throw new Error('Dados de usuário insuficientes para envio (IP/UserAgent faltando).');
        }

        await axios.post(`https://graph.facebook.com/v19.0/${pixelId}/events`, payload, { params: { access_token: accessToken } });
        
        return { success: true, payload: payload_sent };

    } catch (error) {
        const metaError = error.response?.data?.error || { message: error.message };
        console.error(`Erro ao reenviar evento (Transação ID: ${transactionData.id}):`, metaError.message);
        return { success: false, error: metaError, payload: payload_sent };
    }
}


app.post('/api/admin/resend-events', authenticateAdmin, async (req, res) => {
    const { 
        target_pixel_id, target_meta_api_token, seller_id, 
        start_date, end_date, page = 1, limit = 50
    } = req.body;

    if (!target_pixel_id || !target_meta_api_token || !start_date || !end_date) {
        return res.status(400).json({ message: 'Todos os campos obrigatórios devem ser preenchidos.' });
    }

    try {
        const query = seller_id
            ? sql`SELECT pt.*, c.click_id, c.ip_address, c.user_agent, c.fbp, c.fbc, c.city, c.state FROM pix_transactions pt JOIN clicks c ON pt.click_id_internal = c.id WHERE pt.status = 'paid' AND c.seller_id = ${seller_id} AND pt.paid_at BETWEEN ${start_date} AND ${end_date} ORDER BY pt.paid_at ASC`
            : sql`SELECT pt.*, c.click_id, c.ip_address, c.user_agent, c.fbp, c.fbc, c.city, c.state FROM pix_transactions pt JOIN clicks c ON pt.click_id_internal = c.id WHERE pt.status = 'paid' AND pt.paid_at BETWEEN ${start_date} AND ${end_date} ORDER BY pt.paid_at ASC`;
        
        const allPaidTransactions = await query;
        
        if (allPaidTransactions.length === 0) {
            return res.status(200).json({ 
                total_events: 0, 
                total_pages: 0, 
                message: 'Nenhuma transação paga encontrada para os filtros fornecidos.' 
            });
        }

        const clickIds = allPaidTransactions.map(t => t.click_id).filter(Boolean);
        let userDataMap = new Map();
        if (clickIds.length > 0) {
            const telegramUsers = await sql`
                SELECT click_id, first_name, last_name 
                FROM telegram_chats 
                WHERE click_id = ANY(${clickIds})
            `;
            telegramUsers.forEach(user => {
                const cleanClickId = user.click_id.startsWith('/start ') ? user.click_id : `/start ${user.click_id}`;
                userDataMap.set(cleanClickId, { firstName: user.first_name, lastName: user.last_name });
            });
        }

        const totalEvents = allPaidTransactions.length;
        const totalPages = Math.ceil(totalEvents / limit);
        const offset = (page - 1) * limit;
        const batch = allPaidTransactions.slice(offset, offset + limit);
        
        const detailedResults = [];
        const targetPixel = { pixelId: target_pixel_id, accessToken: target_meta_api_token };

        console.log(`[ADMIN] Processando página ${page}/${totalPages}. Lote com ${batch.length} eventos.`);

        for (const transaction of batch) {
            const extraUserData = userDataMap.get(transaction.click_id);
            const enrichedTransactionData = { ...transaction, ...extraUserData };
            const result = await sendHistoricalMetaEvent('Purchase', enrichedTransactionData, transaction, targetPixel);
            
            detailedResults.push({
                transaction_id: transaction.id,
                status: result.success ? 'success' : 'failure',
                payload_sent: result.payload,
                meta_response: result.error || 'Enviado com sucesso.'
            });
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        
        res.status(200).json({
            total_events: totalEvents,
            total_pages: totalPages,
            current_page: page,
            limit: limit,
            results: detailedResults
        });

    } catch (error) {
        console.error("Erro geral na rota de reenviar eventos:", error);
        res.status(500).json({ message: 'Erro interno do servidor ao processar o reenvio.' });
    }
});

app.get('/api/admin/vapidPublicKey', authenticateAdmin, (req, res) => {
    if (!process.env.VAPID_PUBLIC_KEY) {
        return res.status(500).send('VAPID Public Key não configurada no servidor.');
    }
    res.type('text/plain').send(process.env.VAPID_PUBLIC_KEY);
});

app.post('/api/admin/save-subscription', authenticateAdmin, (req, res) => {
    adminSubscription = req.body;
    console.log("Inscrição de admin para notificações recebida e guardada.");
    res.status(201).json({});
});

app.get('/api/admin/dashboard', authenticateAdmin, async (req, res) => {
    try {
        const totalSellers = await sql`SELECT COUNT(*) FROM sellers;`;
        const paidTransactions = await sql`SELECT COUNT(*) as count, SUM(pix_value) as total_revenue FROM pix_transactions WHERE status = 'paid';`;
        const total_sellers = parseInt(totalSellers[0].count);
        const total_paid_transactions = parseInt(paidTransactions[0].count);
        const total_revenue = parseFloat(paidTransactions[0].total_revenue || 0);
        const saas_profit = total_revenue * 0.0299;
        res.json({
            total_sellers, total_paid_transactions,
            total_revenue: total_revenue.toFixed(2),
            saas_profit: saas_profit.toFixed(2)
        });
    } catch (error) {
        console.error("Erro no dashboard admin:", error);
        res.status(500).json({ message: 'Erro ao buscar dados do dashboard.' });
    }
});
app.get('/api/admin/ranking', authenticateAdmin, async (req, res) => {
    try {
        const ranking = await sql`
            SELECT s.id, s.name, s.email, COUNT(pt.id) AS total_sales, COALESCE(SUM(pt.pix_value), 0) AS total_revenue
            FROM sellers s LEFT JOIN clicks c ON s.id = c.seller_id
            LEFT JOIN pix_transactions pt ON c.id = pt.click_id_internal AND pt.status = 'paid'
            GROUP BY s.id, s.name, s.email ORDER BY total_revenue DESC LIMIT 20;`;
        res.json(ranking);
    } catch (error) {
        console.error("Erro no ranking de sellers:", error);
        res.status(500).json({ message: 'Erro ao buscar ranking.' });
    }
});
app.get('/api/admin/sellers', authenticateAdmin, async (req, res) => {
    try {
        const sellers = await sql`SELECT id, name, email, created_at, is_active FROM sellers ORDER BY created_at DESC;`;
        res.json(sellers);
    } catch (error) {
        res.status(500).json({ message: 'Erro ao listar vendedores.' });
    }
});
app.post('/api/admin/sellers/:id/toggle-active', authenticateAdmin, async (req, res) => {
    const { id } = req.params;
    const { isActive } = req.body;
    try {
        await sql`UPDATE sellers SET is_active = ${isActive} WHERE id = ${id};`;
        res.status(200).json({ message: `Usuário ${isActive ? 'ativado' : 'bloqueado'} com sucesso.` });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao alterar status do usuário.' });
    }
});
app.put('/api/admin/sellers/:id/password', authenticateAdmin, async (req, res) => {
    const { id } = req.params;
    const { newPassword } = req.body;
    if (!newPassword || newPassword.length < 8) return res.status(400).json({ message: 'A nova senha deve ter pelo menos 8 caracteres.' });
    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await sql`UPDATE sellers SET password_hash = ${hashedPassword} WHERE id = ${id};`;
        res.status(200).json({ message: 'Senha alterada com sucesso.' });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao alterar senha.' });
    }
});
app.put('/api/admin/sellers/:id/credentials', authenticateAdmin, async (req, res) => {
    const { id } = req.params;
    const { pushinpay_token, cnpay_public_key, cnpay_secret_key } = req.body;
    try {
        await sql`
            UPDATE sellers 
            SET pushinpay_token = ${pushinpay_token}, cnpay_public_key = ${cnpay_public_key}, cnpay_secret_key = ${cnpay_secret_key}
            WHERE id = ${id};`;
        res.status(200).json({ message: 'Credenciais alteradas com sucesso.' });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao alterar credenciais.' });
    }
});
app.get('/api/admin/transactions', authenticateAdmin, async (req, res) => {
    try {
        const page = parseInt(req.query.page || 1);
        const limit = parseInt(req.query.limit || 20);
        const offset = (page - 1) * limit;
        const transactions = await sql`
            SELECT pt.id, pt.status, pt.pix_value, pt.provider, pt.created_at, s.name as seller_name, s.email as seller_email
            FROM pix_transactions pt JOIN clicks c ON pt.click_id_internal = c.id
            JOIN sellers s ON c.seller_id = s.id ORDER BY pt.created_at DESC
            LIMIT ${limit} OFFSET ${offset};`;
         const totalTransactionsResult = await sql`SELECT COUNT(*) FROM pix_transactions;`;
         const total = parseInt(totalTransactionsResult[0].count);
        res.json({ transactions, total, page, pages: Math.ceil(total / limit), limit });
    } catch (error) {
        console.error("Erro ao buscar transações admin:", error);
        res.status(500).json({ message: 'Erro ao buscar transações.' });
    }
});
app.get('/api/admin/usage-analysis', authenticateAdmin, async (req, res) => {
    try {
        const usageData = await sql`
            SELECT
                s.id, s.name, s.email,
                COUNT(ar.id) FILTER (WHERE ar.created_at > NOW() - INTERVAL '1 hour') AS requests_last_hour,
                COUNT(ar.id) FILTER (WHERE ar.created_at > NOW() - INTERVAL '24 hours') AS requests_last_24_hours
            FROM sellers s
            LEFT JOIN api_requests ar ON s.id = ar.seller_id
            GROUP BY s.id, s.name, s.email
            ORDER BY requests_last_24_hours DESC, requests_last_hour DESC;
        `;
        res.json(usageData);
    } catch (error) {
        console.error("Erro na análise de uso:", error);
        res.status(500).json({ message: 'Erro ao buscar dados de uso.' });
    }
});


// --- ROTAS GERAIS DE USUÁRIO ---
app.post('/api/sellers/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password || password.length < 8) {
        return res.status(400).json({ message: 'Dados inválidos. Nome, email e senha (mínimo 8 caracteres) são obrigatórios.' });
    }
    
    try {
        const normalizedEmail = email.trim().toLowerCase();
        const existingSeller = await sql`SELECT id FROM sellers WHERE LOWER(email) = ${normalizedEmail}`;
        if (existingSeller.length > 0) {
            return res.status(409).json({ message: 'Este email já está em uso.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const apiKey = uuidv4();
        
        await sql`INSERT INTO sellers (name, email, password_hash, api_key, is_active) VALUES (${name}, ${normalizedEmail}, ${hashedPassword}, ${apiKey}, TRUE)`;
        
        res.status(201).json({ message: 'Vendedor cadastrado com sucesso!' });
    } catch (error) {
        console.error("Erro no registro:", error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

app.post('/api/sellers/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email e senha são obrigatórios.' });
    try {
        const normalizedEmail = email.trim().toLowerCase();
        const [seller] = await sql`SELECT * FROM sellers WHERE email = ${normalizedEmail}`;
        if (!seller) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }
        
        if (!seller.is_active) {
            return res.status(403).json({ message: 'Este usuário está bloqueado.' });
        }
        
        const isPasswordCorrect = await bcrypt.compare(password, seller.password_hash);
        if (!isPasswordCorrect) return res.status(401).json({ message: 'Senha incorreta.' });
        
        const tokenPayload = { id: seller.id, email: seller.email };
        const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: '1d' });
        
        const { password_hash, ...sellerData } = seller;
        res.status(200).json({ message: 'Login bem-sucedido!', token, seller: sellerData });

    } catch (error) {
        console.error("ERRO DETALHADO NO LOGIN:", error); 
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

app.get('/api/dashboard/data', authenticateJwt, async (req, res) => {
    try {
        const bots = await sql`SELECT * FROM telegram_bots WHERE seller_id = ${req.user.id} ORDER BY created_at DESC`;
        res.json({ bots });
    } catch (error) {
        console.error("Erro ao buscar dados do dashboard:", error);
        res.status(500).json({ message: 'Erro ao buscar dados.' });
    }
});

// --- ROTAS DE GERENCIAMENTO DE BOTS ---
app.post('/api/bots', authenticateJwt, async (req, res) => {
    const { bot_name } = req.body;
    if (!bot_name) return res.status(400).json({ message: 'O nome do bot é obrigatório.' });
    try {
        const [newBot] = await sql`
            INSERT INTO telegram_bots (seller_id, bot_name, bot_token) 
            VALUES (${req.user.id}, ${bot_name}, '') RETURNING *;`;
        res.status(201).json(newBot);
    } catch (error) {
        res.status(500).json({ message: 'Erro ao salvar o bot.' });
    }
});

app.delete('/api/bots/:id', authenticateJwt, async (req, res) => {
    try {
        await sql`DELETE FROM telegram_bots WHERE id = ${req.params.id} AND seller_id = ${req.user.id}`;
        res.status(204).send();
    } catch (error) {
        res.status(500).json({ message: 'Erro ao excluir o bot.' });
    }
});

app.put('/api/bots/:id', authenticateJwt, async (req, res) => {
    const { id } = req.params;
    let { bot_token } = req.body;
    if (!bot_token) return res.status(400).json({ message: 'O token do bot é obrigatório.' });
    bot_token = bot_token.trim();
    try {
        await sql`UPDATE telegram_bots SET bot_token = ${bot_token} WHERE id = ${id} AND seller_id = ${req.user.id}`;
        res.status(200).json({ message: 'Token do bot atualizado com sucesso.' });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao atualizar o token do bot.' });
    }
});

app.post('/api/bots/:id/set-webhook', authenticateJwt, async (req, res) => {
    const { id } = req.params;
    try {
        const [bot] = await sql`SELECT bot_token FROM telegram_bots WHERE id = ${id} AND seller_id = ${req.user.id}`;
        if (!bot || !bot.bot_token?.trim()) {
            return res.status(400).json({ message: 'O token do bot não está configurado. Salve um token válido primeiro.' });
        }
        const webhookUrl = `https://novaapi-one.vercel.app/api/webhook/telegram/${id}`;
        const telegramApiUrl = `https://api.telegram.org/bot${bot.bot_token.trim()}/setWebhook?url=${webhookUrl}`;
        const response = await axios.get(telegramApiUrl);
        if (response.data.ok) {
            res.status(200).json({ message: 'Webhook configurado com sucesso!' });
        } else {
            throw new Error(response.data.description);
        }
    } catch (error) {
        const errorMessage = error.isAxiosError ? error.response.data?.description : error.message;
        res.status(500).json({ message: `Falha ao configurar webhook: ${errorMessage}` });
    }
});


// --- ROTAS DE FLUXOS ---
const createInitialFlowStructure = () => ({
    nodes: [{ id: 'start', type: 'message', position: { x: 100, y: 100 }, data: { label: 'Início', text: 'Gatilho: Novo Contato' } }],
    edges: []
});

app.get('/api/flows', authenticateJwt, async (req, res) => {
    try {
        const flows = await sql`
            SELECT f.* FROM flows f
            WHERE f.seller_id = ${req.user.id} ORDER BY f.created_at DESC`;
        res.status(200).json(flows.map(flow => ({...flow, nodes: flow.nodes || JSON.stringify(createInitialFlowStructure())})));
    } catch (error) {
        res.status(500).json({ message: 'Erro ao buscar os fluxos.' });
    }
});

app.post('/api/flows', authenticateJwt, async (req, res) => {
    const { name, botId } = req.body;
    if (!name || !botId) return res.status(400).json({ message: 'Nome do fluxo e ID do bot são obrigatórios.' });
    try {
        const [newFlow] = await sql`
            INSERT INTO flows (seller_id, bot_id, name, nodes) 
            VALUES (${req.user.id}, ${botId}, ${name}, ${JSON.stringify(createInitialFlowStructure())}) 
            RETURNING *;`;
        res.status(201).json(newFlow);
    } catch (error) {
        res.status(500).json({ message: 'Erro ao criar o fluxo.' });
    }
});

app.put('/api/flows/:id', authenticateJwt, async (req, res) => {
    const { id } = req.params;
    const { name, nodes } = req.body; 
    if (!name || !nodes) return res.status(400).json({ message: 'Nome e estrutura de nós são obrigatórios.' });
    try {
        const [updatedFlow] = await sql`
            UPDATE flows SET name = ${name}, nodes = ${nodes}, updated_at = CURRENT_TIMESTAMP
            WHERE id = ${id} AND seller_id = ${req.user.id} RETURNING *;`;
        if (updatedFlow) res.status(200).json(updatedFlow);
        else res.status(404).json({ message: 'Fluxo não encontrado ou não autorizado.' });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao salvar o fluxo.' });
    }
});

app.delete('/api/flows/:id', authenticateJwt, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await sql`DELETE FROM flows WHERE id = ${id} AND seller_id = ${req.user.id}`;
        if (result.count > 0) res.status(204).send();
        else res.status(404).json({ message: 'Fluxo não encontrado ou não autorizado.' });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao deletar o fluxo.' });
    }
});

// --- ROTAS PARA CHAT AO VIVO ---
app.get('/api/chats/:botId', authenticateJwt, async (req, res) => {
    const { botId } = req.params;
    try {
        const [bot] = await sql`SELECT id FROM telegram_bots WHERE id = ${botId} AND seller_id = ${req.user.id}`;
        if (!bot) return res.status(404).json({ message: 'Bot não autorizado.' });
        const users = await sql`
            SELECT DISTINCT ON (chat_id) 
                   chat_id, first_name, last_name, username, click_id,
                   (SELECT MAX(created_at) FROM telegram_chats tc2 WHERE tc2.chat_id = tc1.chat_id) as last_message_at
            FROM telegram_chats tc1
            WHERE bot_id = ${botId}
            ORDER BY chat_id, last_message_at DESC;
        `;
        res.status(200).json(users);
    } catch (error) {
        res.status(500).json({ message: 'Erro ao buscar usuários do chat.' });
    }
});

app.get('/api/chats/:botId/:chatId', authenticateJwt, async (req, res) => {
    const { botId, chatId } = req.params;
    try {
        const messages = await sql`
            SELECT * FROM telegram_chats 
            WHERE bot_id = ${botId} AND chat_id = ${chatId} AND seller_id = ${req.user.id}
            ORDER BY created_at ASC;`;
        res.status(200).json(messages);
    } catch (error) {
        res.status(500).json({ message: 'Erro ao buscar mensagens do chat.' });
    }
});

app.post('/api/chats/:botId/send-message', authenticateJwt, async (req, res) => {
    const { botId } = req.params;
    const { chatId, text } = req.body;
    try {
        const [bot] = await sql`
            SELECT bot_token, (SELECT name FROM sellers WHERE id = ${req.user.id}) as seller_name 
            FROM telegram_bots WHERE id = ${botId} AND seller_id = ${req.user.id}`;
        if (!bot || !bot.bot_token) return res.status(404).json({ message: 'Bot não encontrado ou sem token.' });

        const response = await axios.post(`https://api.telegram.org/bot${bot.bot_token}/sendMessage`, { chat_id: chatId, text: text });
        if (response.data.ok) {
            const sentMessage = response.data.result;
            await sql`
                INSERT INTO telegram_chats (seller_id, bot_id, chat_id, message_id, user_id, first_name, last_name, message_text, sender_type)
                VALUES (${req.user.id}, ${botId}, ${chatId}, ${sentMessage.message_id}, ${req.user.id}, ${bot.seller_name}, '(Operador)', ${text}, 'operator')
                ON CONFLICT (chat_id, message_id) DO NOTHING;
            `;
            res.status(200).json({ message: 'Mensagem enviada com sucesso!' });
        } else {
            throw new Error('Telegram API retornou um erro.');
        }
    } catch (error) {
        res.status(500).json({ message: 'Não foi possível enviar a mensagem.' });
    }
});

app.delete('/api/chats/:botId/:chatId', authenticateJwt, async (req, res) => {
    const { botId, chatId } = req.params;
    try {
        await sql`DELETE FROM telegram_chats WHERE bot_id = ${botId} AND chat_id = ${chatId} AND seller_id = ${req.user.id}`;
        res.status(204).send();
    } catch (error) {
        res.status(500).json({ message: 'Erro ao excluir a conversa.' });
    }
});

// --- ROTA DE WEBHOOK (COM MOTOR DE FLUXO) ---
app.post('/api/webhook/telegram/:botId', async (req, res) => {
    const { botId } = req.params;
    const { message } = req.body;

    res.sendStatus(200);

    if (!message || !message.text || !message.chat) return;

    try {
        const { chat, from, text, message_id } = message;
        const [bot] = await sql`SELECT seller_id, bot_token FROM telegram_bots WHERE id = ${botId}`;
        if (!bot) return;

        const clickId = text.startsWith('/start ') ? text.replace('/start ', '') : null;
        await sql`
            INSERT INTO telegram_chats (seller_id, bot_id, chat_id, message_id, user_id, first_name, last_name, username, click_id, message_text, sender_type)
            VALUES (${bot.seller_id}, ${botId}, ${chat.id}, ${message_id}, ${from.id}, ${from.first_name}, ${from.last_name || null}, ${from.username || null}, ${clickId}, ${text}, 'user')
            ON CONFLICT (chat_id, message_id) DO NOTHING;
        `;
        
        if (clickId) {
            const [flow] = await sql`SELECT * FROM flows WHERE bot_id = ${botId} ORDER BY updated_at DESC LIMIT 1`;
            if (!flow || !flow.nodes) return;

            const flowData = JSON.parse(flow.nodes);
            const startNode = flowData.nodes?.find(n => n.data.label === 'Início');
            if (!startNode) return;
            
            const firstEdge = flowData.edges?.find(e => e.source === startNode.id);
            if (!firstEdge) return;
            
            const nextNode = flowData.nodes?.find(n => n.id === firstEdge.target);
            if (nextNode?.type === 'message' && nextNode.data.text) {
                await axios.post(`https://api.telegram.org/bot${bot.bot_token}/sendMessage`, {
                    chat_id: chat.id,
                    text: nextNode.data.text,
                });
            }
        }
    } catch (error) {
        console.error("Erro ao processar webhook ou gatilho:", error);
    }
});

// --- ROTAS DE DISPAROS (Preservadas do código original) ---
app.post('/api/bots/mass-send', authenticateJwt, async (req, res) => {
    const sellerId = req.user.id;
    const { botIds, initialText } = req.body;

    if (!botIds || botIds.length === 0 || !initialText) {
        return res.status(400).json({ message: 'Bots e mensagem são obrigatórios.' });
    }

    try {
        const bots = await sql`SELECT id, bot_token FROM telegram_bots WHERE id = ANY(${botIds}) AND seller_id = ${sellerId}`;
        if (bots.length === 0) return res.status(404).json({ message: 'Nenhum bot válido selecionado.' });
        
        const users = await sql`SELECT DISTINCT ON (chat_id) chat_id, bot_id FROM telegram_chats WHERE bot_id = ANY(${botIds}) AND seller_id = ${sellerId}`;
        if (users.length === 0) return res.status(404).json({ message: 'Nenhum usuário encontrado para os bots selecionados.' });

        res.status(202).json({ message: `Disparo agendado para ${users.length} usuários.` });
        
        (async () => {
            let successCount = 0, failureCount = 0;
            const botTokenMap = new Map(bots.map(b => [b.id, b.bot_token]));

            for (const user of users) {
                const botToken = botTokenMap.get(user.bot_id);
                if (!botToken) continue;

                try {
                    await axios.post(`https://api.telegram.org/bot${botToken}/sendMessage`, {
                        chat_id: user.chat_id,
                        text: initialText,
                    }, { timeout: 10000 });
                    successCount++;
                } catch (error) {
                    failureCount++;
                    console.error(`Falha ao enviar para ${user.chat_id}: ${error.message}`);
                }
                await new Promise(resolve => setTimeout(resolve, 300));
            }
            console.log(`Disparo concluído. Sucessos: ${successCount}, Falhas: ${failureCount}`);
        })();

    } catch (error) {
        console.error("Erro no disparo em massa:", error);
        if (!res.headersSent) res.status(500).json({ message: 'Erro ao iniciar o disparo.' });
    }
});

module.exports = app;
