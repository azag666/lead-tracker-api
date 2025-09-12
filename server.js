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

const SYNCPAY_API_BASE_URL = 'https://api.syncpayments.com.br';
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

// --- FUNÇÃO PARA OBTER TOKEN DA SYNC PAY ---
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


// --- FUNÇÃO HELPER DE GERAÇÃO DE PIX ---
async function generatePixForProvider(provider, seller, value_cents, host, apiKey) {
    let pixData;
    let acquirer = 'Não identificado';
    const clientPayload = { 
        name: "Cliente Teste", 
        email: "cliente@email.com", 
        document: "11111111111",
        phone: "11999999999"
    };
    
    if (provider === 'syncpay') {
        const token = await getSyncPayAuthToken(seller);
        const payload = {
            amount: value_cents,
            payer: clientPayload
        };
        
        const response = await axios.post(`${SYNCPAY_API_BASE_URL}/api/partner/v1/cash-in`, payload, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        pixData = response.data;
        acquirer = "SyncPay";
        
        // --- CORREÇÃO APLICADA AQUI ---
        // A resposta da SyncPay não tem um objeto `pix`. Os campos são diretos no corpo da resposta.
        return { 
            qr_code_text: pixData.pixCopyPaste, 
            qr_code_base64: pixData.pixQrCode, 
            transaction_id: pixData.transactionId, 
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

// --- FUNÇÃO PARA LIDAR COM PAGAMENTO BEM-SUCEDIDO ---
async function handleSuccessfulPayment(transaction_id, customerData) {
    try {
        const [transaction] = await sql`UPDATE pix_transactions SET status = 'paid', paid_at = NOW() WHERE id = ${transaction_id} AND status != 'paid' RETURNING *`;
        if (!transaction) { return; }

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
        }
    } catch(error) {
        console.error("Erro ao lidar com pagamento bem-sucedido:", error);
    }
}

// --- ROTAS DE ADMIN ---
function authenticateAdmin(req, res, next) {
    const adminKey = req.headers['x-admin-api-key'];
    if (!adminKey || adminKey !== ADMIN_API_KEY) {
        return res.status(403).json({ message: 'Acesso negado. Chave de administrador inválida.' });
    }
    next();
}
// (Outras rotas de admin aqui...)

// --- ROTAS DE CADASTRO, LOGIN E CONFIGURAÇÕES ---
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
        const sellerResult = await sql`SELECT * FROM sellers WHERE email = ${normalizedEmail}`;
        if (sellerResult.length === 0) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }
        
        const seller = sellerResult[0];
        
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
        console.error("Erro no login:", error); 
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

app.get('/api/dashboard/data', authenticateJwt, async (req, res) => {
    try {
        const sellerId = req.user.id;
        const [settingsResult] = await sql`SELECT api_key, pushinpay_token, cnpay_public_key, cnpay_secret_key, oasyfy_public_key, oasyfy_secret_key, syncpay_client_id, syncpay_client_secret, pix_provider_primary, pix_provider_secondary, pix_provider_tertiary, utmify_api_token FROM sellers WHERE id = ${sellerId}`;
        res.json({ settings: settingsResult || {} });
    } catch (error) {
        console.error("Erro ao buscar dados do dashboard:", error);
        res.status(500).json({ message: 'Erro ao buscar dados.' });
    }
});

app.post('/api/settings/pix', authenticateJwt, async (req, res) => {
    const { 
        pushinpay_token, cnpay_public_key, cnpay_secret_key, oasyfy_public_key, oasyfy_secret_key,
        syncpay_client_id, syncpay_client_secret,
        pix_provider_primary, pix_provider_secondary, pix_provider_tertiary
    } = req.body;
    try {
        await sql`UPDATE sellers SET 
            pushinpay_token = ${pushinpay_token || null}, 
            cnpay_public_key = ${cnpay_public_key || null}, 
            cnpay_secret_key = ${cnpay_secret_key || null}, 
            oasyfy_public_key = ${oasyfy_public_key || null}, 
            oasyfy_secret_key = ${oasyfy_secret_key || null},
            syncpay_client_id = ${syncpay_client_id || null},
            syncpay_client_secret = ${syncpay_client_secret || null},
            pix_provider_primary = ${pix_provider_primary || 'pushinpay'},
            pix_provider_secondary = ${pix_provider_secondary || null},
            pix_provider_tertiary = ${pix_provider_tertiary || null}
            WHERE id = ${req.user.id}`;
        res.status(200).json({ message: 'Configurações de PIX salvas com sucesso.' });
    } catch (error) {
        console.error("Erro ao salvar configurações de PIX:", error);
        res.status(500).json({ message: 'Erro ao salvar as configurações.' });
    }
});

// --- ROTAS DA API PÚBLICA ---

app.post('/api/registerClick', logApiRequest, async (req, res) => {
    const { sellerApiKey, ...utmParams } = req.body;

    if (!sellerApiKey) {
        return res.status(400).json({ message: 'API Key do vendedor é obrigatória.' });
    }
    const ip_address = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;

    try {
        const [sellerResult] = await sql`SELECT id FROM sellers WHERE api_key = ${sellerApiKey}`;
        if (!sellerResult) {
            return res.status(404).json({ message: 'API Key inválida.' });
        }
        
        const [newClick] = await sql`INSERT INTO clicks (
            seller_id, ip_address, user_agent, referer, fbclid, fbp, fbc,
            utm_source, utm_campaign, utm_medium, utm_content, utm_term
        ) VALUES (
            ${sellerResult.id}, ${ip_address}, ${req.headers['user-agent']}, ${utmParams.referer}, ${utmParams.fbclid}, ${utmParams.fbp}, ${utmParams.fbc},
            ${utmParams.utm_source}, ${utmParams.utm_campaign}, ${utmParams.utm_medium}, ${utmParams.utm_content}, ${utmParams.utm_term}
        ) RETURNING id;`;
        
        const clean_click_id = `lead${newClick.id.toString().padStart(6, '0')}`;
        await sql`UPDATE clicks SET click_id = ${'/start ' + clean_click_id} WHERE id = ${newClick.id}`;

        res.status(200).json({ status: 'success', click_id: clean_click_id });
    } catch (error) {
        console.error("Erro ao registrar clique:", error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

app.post('/api/pix/generate', logApiRequest, async (req, res) => {
    const apiKey = req.headers['x-api-key'];
    const { click_id, value_cents } = req.body;
    
    if (!apiKey || !click_id || !value_cents) {
        return res.status(400).json({ message: 'API Key, click_id e value_cents são obrigatórios.' });
    }

    try {
        const [seller] = await sql`SELECT * FROM sellers WHERE api_key = ${apiKey}`;
        if (!seller) return res.status(401).json({ message: 'API Key inválida.' });

        const db_click_id = click_id.startsWith('/start ') ? click_id : `/start ${click_id}`;
        const [click] = await sql`SELECT * FROM clicks WHERE click_id = ${db_click_id} AND seller_id = ${seller.id}`;
        if (!click) return res.status(404).json({ message: 'Click ID não encontrado.' });
        
        const providerOrder = [ seller.pix_provider_primary, seller.pix_provider_secondary, seller.pix_provider_tertiary ].filter(Boolean);
        if(providerOrder.length === 0) providerOrder.push('pushinpay');
        
        let lastError = null;

        for (const provider of providerOrder) {
            try {
                const pixResult = await generatePixForProvider(provider, seller, value_cents, req.headers.host, apiKey);
                await sql`INSERT INTO pix_transactions (click_id_internal, pix_value, qr_code_text, qr_code_base64, provider, provider_transaction_id, pix_id) VALUES (${click.id}, ${value_cents / 100}, ${pixResult.qr_code_text}, ${pixResult.qr_code_base64}, ${pixResult.provider}, ${pixResult.transaction_id}, ${pixResult.transaction_id})`;
                return res.status(200).json(pixResult);
            } catch (error) {
                console.error(`[PIX GENERATE FALLBACK] Falha ao gerar PIX com ${provider}:`, error.message);
                lastError = error;
            }
        }

        console.error(`[PIX GENERATE FINAL ERROR] Seller ID: ${seller?.id} - Todas as tentativas falharam. Último erro:`, lastError?.message || lastError);
        return res.status(500).json({ message: 'Não foi possível gerar o PIX. Todos os provedores falharam.' });

    } catch (error) {
        console.error(`[PIX GENERATE ERROR] Erro geral na rota:`, error.message);
        res.status(500).json({ message: 'Erro interno ao processar a geração de PIX.' });
    }
});

app.get('/api/pix/status/:transaction_id', async (req, res) => {
    const apiKey = req.headers['x-api-key'];
    const { transaction_id } = req.params;

    if (!apiKey) return res.status(401).json({ message: 'API Key não fornecida.' });
    if (!transaction_id) return res.status(400).json({ message: 'ID da transação é obrigatório.' });

    try {
        const [seller] = await sql`SELECT * FROM sellers WHERE api_key = ${apiKey}`;
        if (!seller) {
            return res.status(401).json({ message: 'API Key inválida.' });
        }
        
        const [transaction] = await sql`
            SELECT pt.* FROM pix_transactions pt JOIN clicks c ON pt.click_id_internal = c.id
            WHERE (pt.provider_transaction_id = ${transaction_id} OR pt.pix_id = ${transaction_id}) AND c.seller_id = ${seller.id}`;

        if (!transaction) {
            return res.status(404).json({ status: 'not_found', message: 'Transação não encontrada.' });
        }
        if (transaction.status === 'paid') {
            return res.status(200).json({ status: 'paid' });
        }

        let providerStatus, customerData = {};
        try {
            if (transaction.provider === 'syncpay') {
                const syncPayToken = await getSyncPayAuthToken(seller);
                const response = await axios.get(`${SYNCPAY_API_BASE_URL}/api/partner/v1/transaction/${transaction.provider_transaction_id}`, {
                    headers: { 'Authorization': `Bearer ${syncPayToken}` }
                });
                providerStatus = response.data.status;
                customerData = response.data.payer;
            } else if (transaction.provider === 'pushinpay') {
                const response = await axios.get(`https://api.pushinpay.com.br/api/transactions/${transaction.provider_transaction_id}`, { headers: { Authorization: `Bearer ${seller.pushinpay_token}` } });
                providerStatus = response.data.status;
                customerData = { name: response.data.payer_name, document: response.data.payer_document };
            } else if (transaction.provider === 'cnpay' || transaction.provider === 'oasyfy') {
                const isCnpay = transaction.provider === 'cnpay';
                const publicKey = isCnpay ? seller.cnpay_public_key : seller.oasyfy_public_key;
                const secretKey = isCnpay ? seller.cnpay_secret_key : seller.oasyfy_secret_key;

                if (!publicKey || !secretKey) {
                    return res.status(200).json({ status: 'pending' });
                }

                const apiUrl = isCnpay 
                    ? `https://painel.appcnpay.com/api/v1/gateway/transactions?id=${transaction.provider_transaction_id}`
                    : `https://app.oasyfy.com/api/v1/gateway/transactions?id=${transaction.provider_transaction_id}`;

                const response = await axios.get(apiUrl, { 
                    headers: { 'x-public-key': publicKey, 'x-secret-key': secretKey } 
                });
                
                providerStatus = response.data.status;
                customerData = { name: response.data.customer?.name, document: response.data.customer?.taxID?.taxID };
            }
        } catch (providerError) {
             console.error(`Falha ao consultar o provedor para a transação ${transaction.id}:`, providerError.message);
             return res.status(200).json({ status: 'pending' });
        }

        if (providerStatus === 'paid' || providerStatus === 'COMPLETED') {
            await handleSuccessfulPayment(transaction.id, customerData);
            return res.status(200).json({ status: 'paid' });
        }

        res.status(200).json({ status: 'pending' });

    } catch (error) {
        console.error("Erro ao consultar status da transação:", error);
        res.status(500).json({ message: 'Erro interno ao consultar o status.' });
    }
});

app.post('/api/pix/test-provider', authenticateJwt, async (req, res) => {
    const sellerId = req.user.id;
    const { provider } = req.body;

    if (!provider) {
        return res.status(400).json({ message: 'O nome do provedor é obrigatório.' });
    }

    try {
        const [seller] = await sql`SELECT * FROM sellers WHERE id = ${sellerId}`;
        if (!seller) return res.status(404).json({ message: 'Vendedor não encontrado.' });
        
        const value_cents = 50;
        const startTime = Date.now();
        const pixResult = await generatePixForProvider(provider, seller, value_cents, req.headers.host, seller.api_key);
        const endTime = Date.now();
        const responseTime = ((endTime - startTime) / 1000).toFixed(2);

        res.status(200).json({
            provider: provider.toUpperCase(),
            acquirer: pixResult.acquirer,
            responseTime: responseTime,
            qr_code_text: pixResult.qr_code_text
        });

    } catch (error) {
        console.error(`[ERRO DE TESTE PIX] ID do vendedor: ${sellerId}, Provedor: ${provider} - Erro:`, error.message);
        res.status(500).json({ 
            message: `Falha ao gerar PIX de teste com ${provider.toUpperCase()}. Verifique as credenciais.`, 
            details: error.response?.data?.message || error.message 
        });
    }
});

// --- WEBHOOKS ---
app.post('/api/webhook/pushinpay', async (req, res) => {
    const { id, status, payer_name, payer_document } = req.body;
    if (status === 'paid') {
        try {
            const [tx] = await sql`SELECT * FROM pix_transactions WHERE provider_transaction_id = ${id} AND provider = 'pushinpay'`;
            if (tx && tx.status !== 'paid') {
                await handleSuccessfulPayment(tx.id, { name: payer_name, document: payer_document });
            }
        } catch (error) { console.error("Erro no webhook da PushinPay:", error); }
    }
    res.sendStatus(200);
});

app.post('/api/webhook/cnpay', async (req, res) => {
    const { transactionId, status, customer } = req.body;
    if (status === 'COMPLETED') {
        try {
            const [tx] = await sql`SELECT * FROM pix_transactions WHERE provider_transaction_id = ${transactionId} AND provider = 'cnpay'`;
            if (tx && tx.status !== 'paid') {
                await handleSuccessfulPayment(tx.id, { name: customer?.name, document: customer?.taxID?.taxID });
            }
        } catch (error) { console.error("Erro no webhook da CNPay:", error); }
    }
    res.sendStatus(200);
});

app.post('/api/webhook/oasyfy', async (req, res) => {
    const { transactionId, status, customer } = req.body;
    if (status === 'COMPLETED') {
        try {
            const [tx] = await sql`SELECT * FROM pix_transactions WHERE provider_transaction_id = ${transactionId} AND provider = 'oasyfy'`;
            if (tx && tx.status !== 'paid') {
                await handleSuccessfulPayment(tx.id, { name: customer?.name, document: customer?.taxID?.taxID });
            }
        } catch (error) { console.error("Erro no webhook da Oasy.fy:", error); }
    }
    res.sendStatus(200);
});

app.post('/api/webhook/syncpay', async (req, res) => {
    const { transactionId, status, payer } = req.body;
    console.log('[WEBHOOK SYNC PAY] Payload recebido:', req.body);
    if (status === 'paid' || status === 'COMPLETED') {
        try {
            const [tx] = await sql`SELECT * FROM pix_transactions WHERE provider_transaction_id = ${transactionId} AND provider = 'syncpay'`;
            if (tx && tx.status !== 'paid') {
                await handleSuccessfulPayment(tx.id, payer);
            }
        } catch (error) { console.error("Erro no webhook da SyncPay:", error); }
    }
    res.sendStatus(200);
});


// --- HELPERS DE INTEGRAÇÃO (UTMIFY, META) ---
async function sendEventToUtmify(status, clickData, pixData, sellerData, customerData, productData) {
    if (!sellerData.utmify_api_token) { return; }
    const createdAt = (pixData.created_at || new Date()).toISOString().replace('T', ' ').substring(0, 19);
    const approvedDate = status === 'paid' ? (pixData.paid_at || new Date()).toISOString().replace('T', ' ').substring(0, 19) : null;
    const payload = {
        orderId: pixData.provider_transaction_id, platform: "HotTrack", paymentMethod: 'pix',
        status: status, createdAt: createdAt, approvedDate: approvedDate, refundedAt: null,
        customer: {
            name: customerData?.name || "Não informado", email: customerData?.email || "naoinformado@email.com",
            phone: customerData?.phone || null, document: customerData?.document || null,
        },
        products: [{
            id: productData?.id || "default_product", name: productData?.name || "Produto Digital",
            planId: null, planName: null, quantity: 1, priceInCents: Math.round(pixData.pix_value * 100)
        }],
        trackingParameters: {
            src: null, sck: null, utm_source: clickData.utm_source, utm_campaign: clickData.utm_campaign,
            utm_medium: clickData.utm_medium, utm_content: clickData.utm_content, utm_term: clickData.utm_term
        },
        commission: {
            totalPriceInCents: Math.round(pixData.pix_value * 100),
            gatewayFeeInCents: Math.round(pixData.pix_value * 100 * 0.0299),
            userCommissionInCents: Math.round(pixData.pix_value * 100 * (1 - 0.0299))
        },
        isTest: false
    };
    try {
        await axios.post('https://api.utmify.com.br/api-credentials/orders', payload, {
            headers: { 'x-api-token': sellerData.utmify_api_token }
        });
        console.log(`Evento '${status}' do pedido ${payload.orderId} enviado para Utmify.`);
    } catch (error) {
        console.error(`Erro ao enviar evento '${status}' para a Utmify:`, error.response?.data || error.message);
    }
}
async function sendMetaEvent(eventName, clickData, transactionData, customerData = null) {
    try {
        let presselPixels = [];
        if (clickData.pressel_id) {
            presselPixels = await sql`SELECT pixel_config_id FROM pressel_pixels WHERE pressel_id = ${clickData.pressel_id}`;
        } else if (clickData.checkout_id) {
            presselPixels = await sql`SELECT pixel_config_id FROM checkout_pixels WHERE checkout_id = ${clickData.checkout_id}`;
        }

        if (presselPixels.length === 0) {
            return;
        }

        const userData = {
            client_ip_address: clickData.ip_address,
            client_user_agent: clickData.user_agent,
            fbp: clickData.fbp || undefined,
            fbc: clickData.fbc || undefined,
            external_id: clickData.click_id ? clickData.click_id.replace('/start ', '') : undefined
        };

        if (customerData?.name) {
            const nameParts = customerData.name.trim().split(' ');
            const firstName = nameParts[0].toLowerCase();
            const lastName = nameParts.length > 1 ? nameParts[nameParts.length - 1].toLowerCase() : undefined;
            userData.fn = crypto.createHash('sha256').update(firstName).digest('hex');
            if (lastName) {
                userData.ln = crypto.createHash('sha256').update(lastName).digest('hex');
            }
        }
        if (customerData?.document) {
            const cleanedDocument = customerData.document.replace(/\D/g, '');
             userData.cpf = [crypto.createHash('sha256').update(cleanedDocument).digest('hex')];
        }

        const city = clickData.city && clickData.city !== 'Desconhecida' ? clickData.city.toLowerCase().replace(/[^a-z]/g, '') : null;
        const state = clickData.state && clickData.state !== 'Desconhecido' ? clickData.state.toLowerCase().replace(/[^a-z]/g, '') : null;
        if (city) userData.ct = crypto.createHash('sha256').update(city).digest('hex');
        if (state) userData.st = crypto.createHash('sha256').update(state).digest('hex');

        Object.keys(userData).forEach(key => userData[key] === undefined && delete userData[key]);
        
        for (const { pixel_config_id } of presselPixels) {
            const [pixelConfig] = await sql`SELECT pixel_id, meta_api_token FROM pixel_configurations WHERE id = ${pixel_config_id}`;
            if (pixelConfig) {
                const { pixel_id, meta_api_token } = pixelConfig;
                const event_id = `${eventName}.${transactionData.id || clickData.id}.${pixel_id}`;
                
                const payload = {
                    data: [{
                        event_name: eventName,
                        event_time: Math.floor(Date.now() / 1000),
                        event_id,
                        user_data: userData,
                        custom_data: {
                            currency: 'BRL',
                            value: transactionData.pix_value
                        },
                    }]
                };
                
                if (eventName !== 'Purchase') {
                    delete payload.data[0].custom_data.value;
                }

                await axios.post(`https://graph.facebook.com/v19.0/${pixel_id}/events`, payload, { params: { access_token: meta_api_token } });
                console.log(`Evento '${eventName}' enviado para o Pixel ID ${pixel_id}.`);

                if (eventName === 'Purchase') {
                     await sql`UPDATE pix_transactions SET meta_event_id = ${event_id} WHERE id = ${transactionData.id}`;
                }
            }
        }
    } catch (error) {
        console.error(`Erro ao enviar evento '${eventName}' para a Meta:`, error.response?.data?.error?.message || error.message);
    }
}

module.exports = app;
