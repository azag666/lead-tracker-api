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
// A dependência do Twilio não é mais necessária
// const twilio = require('twilio'); 

const app = express();
app.use(cors());
app.use(express.json());

// --- FUNÇÃO PARA OBTER CONEXÃO COM O BANCO ---
function getDbConnection() {
    return neon(process.env.DATABASE_URL);
}

// --- CONFIGURAÇÃO ---
const PUSHINPAY_SPLIT_ACCOUNT_ID = process.env.PUSHINPAY_SPLIT_ACCOUNT_ID;
const CNPAY_SPLIT_PRODUCER_ID = process.env.CNPAY_SPLIT_PRODUCER_ID;
const OASYFY_SPLIT_PRODUCER_ID = process.env.OASYFY_SPLIT_PRODUCER_ID;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;

// --- CONFIGURAÇÃO TWILIO REMOVIDA ---

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
        const sql = getDbConnection();
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

    if (provider === 'cnpay' || provider === 'oasyfy') {
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
        if (apiKey !== ADMIN_API_KEY && commission > 0) {
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
        if (apiKey !== ADMIN_API_KEY && commission_cents > 0) {
            payload.split_rules = [{ value: commission_cents, account_id: PUSHINPAY_SPLIT_ACCOUNT_ID }];
        }

        const pushinpayResponse = await axios.post('https://api.pushinpay.com.br/api/pix/cashIn', payload, { headers: { Authorization: `Bearer ${seller.pushinpay_token}` } });
        pixData = pushinpayResponse.data;
        acquirer = "Woovi";
        return { qr_code_text: pixData.qr_code, qr_code_base64: pixData.qr_code_base64, transaction_id: pixData.id, acquirer, provider: 'pushinpay' };
    }
}

// --- FUNÇÃO PARA VERIFICAR E CONCEDER CONQUISTAS ---
async function checkAndAwardAchievements(seller_id) {
    const sql = getDbConnection();
    try {
        const [totalRevenueResult] = await sql`
            SELECT COALESCE(SUM(pt.pix_value), 0) AS total_revenue
            FROM pix_transactions pt
            JOIN clicks c ON pt.click_id_internal = c.id
            WHERE c.seller_id = ${seller_id} AND pt.status = 'paid';
        `;
        const totalRevenueCents = Math.round(totalRevenueResult.total_revenue * 100);

        const achievements = await sql`
            SELECT a.id, a.sales_goal
            FROM achievements a
            LEFT JOIN user_achievements ua ON a.id = ua.achievement_id AND ua.seller_id = ${seller_id}
            WHERE ua.id IS NULL OR ua.is_completed = FALSE;
        `;
        
        for (const achievement of achievements) {
            if (totalRevenueCents >= achievement.sales_goal) {
                await sql`INSERT INTO user_achievements (seller_id, achievement_id, is_completed, completion_date) VALUES (${seller_id}, ${achievement.id}, TRUE, NOW());`;
                console.log(`Conquista concedida ao vendedor ${seller_id}.`);
            }
        }
    } catch (error) {
        console.error("Erro ao verificar e conceder conquistas:", error);
    }
}


// --- ROTAS DE AUTENTICAÇÃO ---
app.post('/api/sellers/register', async (req, res) => {
    const sql = getDbConnection();
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
    const sql = getDbConnection();
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email e senha são obrigatórios.' });
    try {
        const normalizedEmail = email.trim().toLowerCase();
        const sellerResult = await sql`SELECT * FROM sellers WHERE email = ${normalizedEmail}`;
        if (sellerResult.length === 0) {
             console.warn(`[LOGIN FAILURE] Usuário não encontrado no banco de dados para o email: "${normalizedEmail}"`);
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
        console.error("ERRO DETALHADO NO LOGIN:", error); 
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

// --- ROTA DE DADOS DO PAINEL ---
app.get('/api/dashboard/data', authenticateJwt, async (req, res) => {
    const sql = getDbConnection();
    try {
        const sellerId = req.user.id;
        const settingsPromise = sql`SELECT api_key, pushinpay_token, cnpay_public_key, cnpay_secret_key, oasyfy_public_key, oasyfy_secret_key, pix_provider_primary, pix_provider_secondary, pix_provider_tertiary, utmify_api_token FROM sellers WHERE id = ${sellerId}`;
        const pixelsPromise = sql`SELECT * FROM pixel_configurations WHERE seller_id = ${sellerId} ORDER BY created_at DESC`;
        const presselsPromise = sql`
            SELECT p.*, COALESCE(px.pixel_ids, ARRAY[]::integer[]) as pixel_ids, b.bot_name
            FROM pressels p
            LEFT JOIN ( SELECT pressel_id, array_agg(pixel_config_id) as pixel_ids FROM pressel_pixels GROUP BY pressel_id ) px ON p.id = px.pressel_id
            JOIN telegram_bots b ON p.bot_id = b.id
            WHERE p.seller_id = ${sellerId} ORDER BY p.created_at DESC`;
        const botsPromise = sql`SELECT * FROM telegram_bots WHERE seller_id = ${sellerId} ORDER BY created_at DESC`;
        const checkoutsPromise = sql`
            SELECT c.*, COALESCE(px.pixel_ids, ARRAY[]::integer[]) as pixel_ids
            FROM checkouts c
            LEFT JOIN ( SELECT checkout_id, array_agg(pixel_config_id) as pixel_ids FROM checkout_pixels GROUP BY checkout_id ) px ON c.id = px.checkout_id
            WHERE c.seller_id = ${sellerId} ORDER BY c.created_at DESC`;

        const [settingsResult, pixels, pressels, bots, checkouts] = await Promise.all([settingsPromise, pixelsPromise, presselsPromise, botsPromise, checkoutsPromise]);
        
        const settings = settingsResult[0] || {};
        res.json({ settings, pixels, pressels, bots, checkouts });
    } catch (error) {
        console.error("Erro ao buscar dados do dashboard:", error);
        res.status(500).json({ message: 'Erro ao buscar dados.' });
    }
});

// --- NOVA ROTA PARA CONQUISTAS E RANKING ---
app.get('/api/dashboard/achievements-and-ranking', authenticateJwt, async (req, res) => {
    const sql = getDbConnection();
    try {
        const sellerId = req.user.id;
        
        const userAchievements = await sql`
            SELECT a.title, a.description, ua.is_completed, a.sales_goal
            FROM achievements a
            JOIN user_achievements ua ON a.id = ua.achievement_id
            WHERE ua.seller_id = ${sellerId}
            ORDER BY a.sales_goal ASC;
        `;

        const topSellersRanking = await sql`
            SELECT s.name, COALESCE(SUM(pt.pix_value), 0) AS total_revenue
            FROM sellers s
            LEFT JOIN clicks c ON s.id = c.seller_id
            LEFT JOIN pix_transactions pt ON c.id = pt.click_id_internal AND pt.status = 'paid'
            GROUP BY s.id, s.name
            ORDER BY total_revenue DESC
            LIMIT 5;
        `;
        
        const [userRevenue] = await sql`
            SELECT COALESCE(SUM(pt.pix_value), 0) AS total_revenue
            FROM sellers s
            LEFT JOIN clicks c ON s.id = c.seller_id
            LEFT JOIN pix_transactions pt ON c.id = pt.click_id_internal AND pt.status = 'paid'
            WHERE s.id = ${sellerId}
            GROUP BY s.id;
        `;

        const userRankResult = await sql`
            SELECT COUNT(T1.id) + 1 AS rank
            FROM (
                SELECT s.id
                FROM sellers s
                LEFT JOIN clicks c ON s.id = c.seller_id
                LEFT JOIN pix_transactions pt ON c.id = pt.click_id_internal AND pt.status = 'paid'
                GROUP BY s.id
                HAVING COALESCE(SUM(pt.pix_value), 0) > ${userRevenue.total_revenue}
            ) AS T1;
        `;
        
        const userRank = userRankResult[0].rank;

        res.json({
            userAchievements,
            topSellersRanking,
            currentUserRank: userRank
        });
    } catch (error) {
        console.error("Erro ao buscar conquistas e ranking:", error);
        res.status(500).json({ message: 'Erro ao buscar dados de ranking.' });
    }
});


// --- ROTAS DE GERENCIAMENTO (CRUD) ---
app.post('/api/pixels', authenticateJwt, async (req, res) => {
    const sql = getDbConnection();
    const { account_name, pixel_id, meta_api_token } = req.body;
    if (!account_name || !pixel_id || !meta_api_token) return res.status(400).json({ message: 'Todos os campos são obrigatórios.' });
    try {
        const newPixel = await sql`INSERT INTO pixel_configurations (seller_id, account_name, pixel_id, meta_api_token) VALUES (${req.user.id}, ${account_name}, ${pixel_id}, ${meta_api_token}) RETURNING *;`;
        res.status(201).json(newPixel[0]);
    } catch (error) {
        if (error.code === '23505') { return res.status(409).json({ message: 'Este ID de Pixel já foi cadastrado.' }); }
        console.error("Erro ao salvar pixel:", error);
        res.status(500).json({ message: 'Erro ao salvar o pixel.' });
    }
});

app.delete('/api/pixels/:id', authenticateJwt, async (req, res) => {
    const sql = getDbConnection();
    try {
        await sql`DELETE FROM pixel_configurations WHERE id = ${req.params.id} AND seller_id = ${req.user.id}`;
        res.status(204).send();
    } catch (error) {
        console.error("Erro ao excluir pixel:", error);
        res.status(500).json({ message: 'Erro ao excluir o pixel.' });
    }
});

app.post('/api/bots', authenticateJwt, async (req, res) => {
    const sql = getDbConnection();
    const { bot_name, bot_token } = req.body;
    if (!bot_name || !bot_token) return res.status(400).json({ message: 'Nome e token são obrigatórios.' });
    try {
        const newBot = await sql`INSERT INTO telegram_bots (seller_id, bot_name, bot_token) VALUES (${req.user.id}, ${bot_name}, ${bot_token}) RETURNING *;`;

        const webhookUrl = `https://${req.headers.host}/api/webhook/telegram/${newBot[0].id}`;
        await axios.post(`https://api.telegram.org/bot${bot_token}/setWebhook`, { url: webhookUrl });
        console.log(`Webhook registrado com sucesso para o bot ${bot_name} em: ${webhookUrl}`);

        res.status(201).json(newBot[0]);
    } catch (error) {
        if (error.code === '23505') { 
            if (error.constraint_name === 'telegram_bots_bot_token_key') {
                return res.status(409).json({ message: 'Este token de bot já está em uso.' });
            }
             if (error.constraint_name === 'telegram_bots_bot_name_key') {
                return res.status(409).json({ message: 'Um bot com este nome de usuário já existe.' });
            }
        }
        console.error("Erro ao salvar bot:", error);
        res.status(500).json({ message: 'Erro ao salvar o bot.' });
    }
});

app.delete('/api/bots/:id', authenticateJwt, async (req, res) => {
    const sql = getDbConnection();
    try {
        await sql`DELETE FROM telegram_bots WHERE id = ${req.params.id} AND seller_id = ${req.user.id}`;
        res.status(204).send();
    } catch (error) {
        console.error("Erro ao excluir bot:", error);
        res.status(500).json({ message: 'Erro ao excluir o bot.' });
    }
});

app.post('/api/bots/test-connection', authenticateJwt, async (req, res) => {
    const sql = getDbConnection();
    const { bot_id } = req.body;
    if (!bot_id) return res.status(400).json({ message: 'ID do bot é obrigatório.' });

    try {
        const [bot] = await sql`SELECT bot_token, bot_name FROM telegram_bots WHERE id = ${bot_id} AND seller_id = ${req.user.id}`;
        if (!bot) {
            return res.status(404).json({ message: 'Bot não encontrado ou não pertence a este usuário.' });
        }

        const response = await axios.get(`https://api.telegram.org/bot${bot.bot_token}/getMe`);
        
        if (response.data.ok) {
            res.status(200).json({ 
                message: `Conexão com o bot @${response.data.result.username} bem-sucedida!`,
                bot_info: response.data.result
            });
        } else {
            throw new Error('A API do Telegram retornou um erro.');
        }

    } catch (error) {
        console.error(`[BOT TEST ERROR] Bot ID: ${bot_id} - Erro:`, error.response?.data || error.message);
        let errorMessage = 'Falha ao conectar com o bot. Verifique o token e tente novamente.';
        if (error.response?.status === 401) {
            errorMessage = 'Token inválido. Verifique se o token do bot foi copiado corretamente do BotFather.';
        } else if (error.response?.status === 404) {
            errorMessage = 'Bot não encontrado. O token pode estar incorreto ou o bot foi deletado.';
        }
        res.status(500).json({ message: errorMessage });
    }
});

app.get('/api/bots/users', authenticateJwt, async (req, res) => {
    const sql = getDbConnection();
    const { botIds } = req.query; // Recebe uma string de IDs: "1,2,3"

    if (!botIds) {
        return res.status(400).json({ message: 'IDs dos bots são obrigatórios.' });
    }
    const botIdArray = botIds.split(',').map(id => parseInt(id.trim(), 10));

    try {
        // Pega todos os usuários únicos dos bots selecionados
        const users = await sql`
            SELECT DISTINCT ON (chat_id) chat_id, first_name, last_name, username 
            FROM telegram_chats 
            WHERE bot_id = ANY(${botIdArray}) AND seller_id = ${req.user.id};
        `;
        res.status(200).json({ total_users: users.length });
    } catch (error) {
        console.error("Erro ao buscar contagem de usuários do bot:", error);
        res.status(500).json({ message: 'Erro interno ao buscar usuários.' });
    }
});


app.post('/api/pressels', authenticateJwt, async (req, res) => {
    const sql = getDbConnection();
    const { name, bot_id, white_page_url, pixel_ids } = req.body;
    if (!name || !bot_id || !white_page_url || !Array.isArray(pixel_ids) || pixel_ids.length === 0) return res.status(400).json({ message: 'Todos os campos são obrigatórios.' });
    
    try {
        const numeric_bot_id = parseInt(bot_id, 10);
        const numeric_pixel_ids = pixel_ids.map(id => parseInt(id, 10));

        const botResult = await sql`SELECT bot_name FROM telegram_bots WHERE id = ${numeric_bot_id} AND seller_id = ${req.user.id}`;
        if (botResult.length === 0) {
            return res.status(404).json({ message: 'Bot não encontrado.' });
        }
        const bot_name = botResult[0].bot_name;

        await sql`BEGIN`;
        try {
            const [newPressel] = await sql`INSERT INTO pressels (seller_id, name, bot_id, bot_name, white_page_url) VALUES (${req.user.id}, ${name}, ${numeric_bot_id}, ${bot_name}, ${white_page_url}) RETURNING *;`;
            
            for (const pixelId of numeric_pixel_ids) {
                await sql`INSERT INTO pressel_pixels (pressel_id, pixel_config_id) VALUES (${newPressel.id}, ${pixelId})`;
            }
            await sql`COMMIT`;
            
            res.status(201).json({ ...newPressel, pixel_ids: numeric_pixel_ids, bot_name });
        } catch (transactionError) {
            await sql`ROLLBACK`;
            throw transactionError;
        }
    } catch (error) {
        console.error("Erro ao salvar pressel:", error);
        res.status(500).json({ message: 'Erro ao salvar a pressel.' });
    }
});

app.delete('/api/pressels/:id', authenticateJwt, async (req, res) => {
    const sql = getDbConnection();
    try {
        await sql`DELETE FROM pressels WHERE id = ${req.params.id} AND seller_id = ${req.user.id}`;
        res.status(204).send();
    } catch (error) {
        console.error("Erro ao excluir pressel:", error);
        res.status(500).json({ message: 'Erro ao excluir a pressel.' });
    }
});

app.post('/api/checkouts', authenticateJwt, async (req, res) => {
    const sql = getDbConnection();
    const { name, product_name, redirect_url, value_type, fixed_value_cents, pixel_ids } = req.body;

    if (!name || !product_name || !redirect_url || !Array.isArray(pixel_ids) || pixel_ids.length === 0) {
        return res.status(400).json({ message: 'Nome, Nome do Produto, URL de Redirecionamento e ao menos um Pixel são obrigatórios.' });
    }
    if (value_type === 'fixed' && (!fixed_value_cents || fixed_value_cents <= 0)) {
        return res.status(400).json({ message: 'Para valor fixo, o valor em centavos deve ser maior que zero.' });
    }

    try {
        await sql`BEGIN`;

        const [newCheckout] = await sql`
            INSERT INTO checkouts (seller_id, name, product_name, redirect_url, value_type, fixed_value_cents)
            VALUES (${req.user.id}, ${name}, ${product_name}, ${redirect_url}, ${value_type}, ${value_type === 'fixed' ? fixed_value_cents : null})
            RETURNING *;
        `;

        for (const pixelId of pixel_ids) {
            await sql`INSERT INTO checkout_pixels (checkout_id, pixel_config_id) VALUES (${newCheckout.id}, ${pixelId})`;
        }
        
        await sql`COMMIT`;

        res.status(201).json({ ...newCheckout, pixel_ids: pixel_ids.map(id => parseInt(id)) });
    } catch (error) {
        await sql`ROLLBACK`;
        console.error("Erro ao salvar checkout:", error);
        res.status(500).json({ message: 'Erro interno ao salvar o checkout.' });
    }
});

app.delete('/api/checkouts/:id', authenticateJwt, async (req, res) => {
    const sql = getDbConnection();
    try {
        await sql`DELETE FROM checkouts WHERE id = ${req.params.id} AND seller_id = ${req.user.id}`;
        res.status(204).send();
    } catch (error) {
        console.error("Erro ao excluir checkout:", error);
        res.status(500).json({ message: 'Erro ao excluir o checkout.' });
    }
});

// --- ROTAS DE CONFIGURAÇÃO ---
app.post('/api/settings/pix', authenticateJwt, async (req, res) => {
    const sql = getDbConnection();
    const { 
        pushinpay_token, cnpay_public_key, cnpay_secret_key, oasyfy_public_key, oasyfy_secret_key,
        pix_provider_primary, pix_provider_secondary, pix_provider_tertiary
    } = req.body;
    try {
        await sql`UPDATE sellers SET 
            pushinpay_token = ${pushinpay_token || null}, 
            cnpay_public_key = ${cnpay_public_key || null}, 
            cnpay_secret_key = ${cnpay_secret_key || null}, 
            oasyfy_public_key = ${oasyfy_public_key || null}, 
            oasyfy_secret_key = ${oasyfy_secret_key || null},
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

app.post('/api/settings/utmify', authenticateJwt, async (req, res) => {
    const sql = getDbConnection();
    const { utmify_api_token } = req.body;
    try {
        await sql`UPDATE sellers SET 
            utmify_api_token = ${utmify_api_token || null}
            WHERE id = ${req.user.id}`;
        res.status(200).json({ message: 'Token da Utmify salvo com sucesso.' });
    } catch (error) {
        console.error("Erro ao salvar token da Utmify:", error);
        res.status(500).json({ message: 'Erro ao salvar as configurações.' });
    }
});

// --- ROTA DE RASTREAMENTO E CONSULTAS ---
app.post('/api/registerClick', logApiRequest, async (req, res) => {
    const sql = getDbConnection();
    const apiKey = req.headers['x-api-key'];
    const { sellerApiKey, presselId, checkoutId, referer, fbclid, fbp, fbc, user_agent, utm_source, utm_campaign, utm_medium, utm_content, utm_term } = req.body;
    
    if (!sellerApiKey || (!presselId && !checkoutId)) return res.status(400).json({ message: 'Dados insuficientes.' });
    
    const ip_address = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
    let city = 'Desconhecida', state = 'Desconhecido';
    try {
        if (ip_address && ip_address !== '::1' && !ip_address.startsWith('192.168.')) {
            const geo = await axios.get(`http://ip-api.com/json/${ip_address}?fields=city,regionName`);
            city = geo.data.city || city;
            state = geo.data.regionName || state;
        }
    } catch (e) { console.error("Erro ao buscar geolocalização:", e.message); }
    
    try {
        const result = await sql`INSERT INTO clicks (
            seller_id, pressel_id, checkout_id, ip_address, user_agent, referer, city, state, fbclid, fbp, fbc,
            utm_source, utm_campaign, utm_medium, utm_content, utm_term
        ) 
        SELECT
            s.id, ${presselId || null}, ${checkoutId || null}, ${ip_address}, ${user_agent}, ${referer}, ${city}, ${state}, ${fbclid}, ${fbp}, ${fbc},
            ${utm_source || null}, ${utm_campaign || null}, ${utm_medium || null}, ${utm_content || null}, ${utm_term || null}
        FROM sellers s WHERE s.api_key = ${sellerApiKey} RETURNING *;`;
        
        if (result.length === 0) return res.status(404).json({ message: 'API Key inválida.' });
        
        const newClick = result[0];
        const click_record_id = newClick.id;
        const clean_click_id = `lead${click_record_id.toString().padStart(6, '0')}`;
        const db_click_id = `/start ${clean_click_id}`;
        await sql`UPDATE clicks SET click_id = ${db_click_id} WHERE id = ${click_record_id}`;

        if (checkoutId) {
            const [checkoutDetails] = await sql`SELECT fixed_value_cents FROM checkouts WHERE id = ${checkoutId}`;
            const eventValue = checkoutDetails ? (checkoutDetails.fixed_value_cents / 100) : 0;
            
            await sendMetaEvent('InitiateCheckout', { ...newClick, click_id: clean_click_id }, { pix_value: eventValue, id: click_record_id });
        }
        
        res.status(200).json({ status: 'success', click_id: clean_click_id });
    } catch (error) {
        console.error("Erro ao registrar clique:", error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});


app.post('/api/click/info', logApiRequest, async (req, res) => {
    const sql = getDbConnection();
    const apiKey = req.headers['x-api-key'];
    const { click_id } = req.body;
    if (!apiKey || !click_id) return res.status(400).json({ message: 'API Key e click_id são obrigatórios.' });
    
    try {
        const sellerResult = await sql`SELECT id, email FROM sellers WHERE api_key = ${apiKey}`;
        if (sellerResult.length === 0) {
            console.warn(`[CLICK INFO] Tentativa de consulta com API Key inválida: ${apiKey}`);
            return res.status(401).json({ message: 'API Key inválida.' });
        }
        
        const seller_id = sellerResult[0].id;
        const seller_email = sellerResult[0].email;
        
        // ##### INÍCIO DA MODIFICAÇÃO #####
        // Lida com ambos os formatos: "lead000103" e "/start lead000103"
        const db_click_id = click_id.startsWith('/start ') ? click_id : `/start ${click_id}`;
        // ##### FIM DA MODIFICAÇÃO #####
        
        const clickResult = await sql`SELECT city, state FROM clicks WHERE click_id = ${db_click_id} AND seller_id = ${seller_id}`;
        
        if (clickResult.length === 0) {
            console.warn(`[CLICK INFO NOT FOUND] Vendedor (ID: ${seller_id}, Email: ${seller_email}) tentou consultar o click_id "${click_id}", mas não foi encontrado.`);
            return res.status(404).json({ message: 'Click ID não encontrado para este vendedor.' });
        }
        
        const clickInfo = clickResult[0];
        res.status(200).json({ status: 'success', city: clickInfo.city, state: clickInfo.state });

    } catch (error) {
        console.error("Erro ao consultar informações do clique:", error);
        res.status(500).json({ message: 'Erro interno ao consultar informações do clique.' });
    }
});

// --- ROTAS DE DASHBOARD E TRANSAÇÕES ---
app.get('/api/dashboard/metrics', authenticateJwt, async (req, res) => {
    const sql = getDbConnection();
    try {
        const sellerId = req.user.id;
        const { startDate, endDate } = req.query;
        const hasDateFilter = startDate && endDate;

        const totalClicksResult = hasDateFilter
            ? await sql`SELECT COUNT(*) FROM clicks c WHERE c.seller_id = ${sellerId} AND c.created_at BETWEEN ${startDate} AND ${endDate}`
            : await sql`SELECT COUNT(*) FROM clicks c WHERE c.seller_id = ${sellerId}`;

        const totalPixGeneratedResult = hasDateFilter
            ? await sql`SELECT COUNT(pt.id) AS total_pix_generated, COALESCE(SUM(pt.pix_value), 0) AS total_revenue FROM pix_transactions pt JOIN clicks c ON pt.click_id_internal = c.id WHERE c.seller_id = ${sellerId} AND c.created_at BETWEEN ${startDate} AND ${endDate}`
            : await sql`SELECT COUNT(pt.id) AS total_pix_generated, COALESCE(SUM(pt.pix_value), 0) AS total_revenue FROM pix_transactions pt JOIN clicks c ON pt.click_id_internal = c.id WHERE c.seller_id = ${sellerId}`;

        const totalPixPaidResult = hasDateFilter
            ? await sql`SELECT COUNT(pt.id) AS total_pix_paid, COALESCE(SUM(pt.pix_value), 0) AS paid_revenue FROM pix_transactions pt JOIN clicks c ON pt.click_id_internal = c.id WHERE c.seller_id = ${sellerId} AND pt.status = 'paid' AND c.created_at BETWEEN ${startDate} AND ${endDate}`
            : await sql`SELECT COUNT(pt.id) AS total_pix_paid, COALESCE(SUM(pt.pix_value), 0) AS paid_revenue FROM pix_transactions pt JOIN clicks c ON pt.click_id_internal = c.id WHERE c.seller_id = ${sellerId} AND pt.status = 'paid'`;

        const botsPerformance = hasDateFilter
            ? await sql`SELECT tb.bot_name, COUNT(c.id) AS total_clicks, COUNT(pt.id) FILTER (WHERE pt.status = 'paid') AS total_pix_paid, COALESCE(SUM(pt.pix_value) FILTER (WHERE pt.status = 'paid'), 0) AS paid_revenue FROM telegram_bots tb LEFT JOIN pressels p ON p.bot_id = tb.id LEFT JOIN clicks c ON c.pressel_id = p.id AND c.seller_id = ${sellerId} AND c.created_at BETWEEN ${startDate} AND ${endDate} LEFT JOIN pix_transactions pt ON pt.click_id_internal = c.id WHERE tb.seller_id = ${sellerId} GROUP BY tb.bot_name ORDER BY paid_revenue DESC, total_clicks DESC`
            : await sql`SELECT tb.bot_name, COUNT(c.id) AS total_clicks, COUNT(pt.id) FILTER (WHERE pt.status = 'paid') AS total_pix_paid, COALESCE(SUM(pt.pix_value) FILTER (WHERE pt.status = 'paid'), 0) AS paid_revenue FROM telegram_bots tb LEFT JOIN pressels p ON p.bot_id = tb.id LEFT JOIN clicks c ON c.pressel_id = p.id AND c.seller_id = ${sellerId} LEFT JOIN pix_transactions pt ON pt.click_id_internal = c.id WHERE tb.seller_id = ${sellerId} GROUP BY tb.bot_name ORDER BY paid_revenue DESC, total_clicks DESC`;

        const clicksByState = hasDateFilter
            ? await sql`SELECT c.state, COUNT(c.id) AS total_clicks FROM clicks c WHERE c.seller_id = ${sellerId} AND c.state IS NOT NULL AND c.created_at BETWEEN ${startDate} AND ${endDate} GROUP BY c.state ORDER BY total_clicks DESC LIMIT 10`
            : await sql`SELECT c.state, COUNT(c.id) AS total_clicks FROM clicks c WHERE c.seller_id = ${sellerId} AND c.state IS NOT NULL GROUP BY c.state ORDER BY total_clicks DESC LIMIT 10`;

        const dailyRevenue = await sql`SELECT DATE(pt.paid_at) as date, COALESCE(SUM(pt.pix_value), 0) as revenue FROM pix_transactions pt JOIN clicks c ON pt.click_id_internal = c.id WHERE c.seller_id = ${sellerId} AND pt.status = 'paid' GROUP BY DATE(pt.paid_at) ORDER BY date ASC`;

        const totalClicks = totalClicksResult[0].count;
        const totalPixGenerated = totalPixGeneratedResult[0].total_pix_generated;
        const totalRevenue = totalPixGeneratedResult[0].total_revenue;
        const totalPixPaid = totalPixPaidResult[0].total_pix_paid;
        const paidRevenue = totalPixPaidResult[0].paid_revenue;
        const conversionRate = totalClicks > 0 ? ((totalPixPaid / totalClicks) * 100).toFixed(2) : 0;
        
        res.status(200).json({
            total_clicks: parseInt(totalClicks),
            total_pix_generated: parseInt(totalPixGenerated),
            total_pix_paid: parseInt(totalPixPaid),
            conversion_rate: parseFloat(conversionRate),
            total_revenue: parseFloat(totalRevenue),
            paid_revenue: parseFloat(paidRevenue),
            bots_performance: botsPerformance.map(b => ({ ...b, total_clicks: parseInt(b.total_clicks), total_pix_paid: parseInt(b.total_pix_paid), paid_revenue: parseFloat(b.paid_revenue) })),
            clicks_by_state: clicksByState.map(s => ({ ...s, total_clicks: parseInt(s.total_clicks) })),
            daily_revenue: dailyRevenue.map(d => ({ date: d.date.toISOString().split('T')[0], revenue: parseFloat(d.revenue) }))
        });
    } catch (error) {
        console.error("Erro ao buscar métricas do dashboard:", error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

app.get('/api/transactions', authenticateJwt, async (req, res) => {
    const sql = getDbConnection();
    try {
        const sellerId = req.user.id;
        const transactions = await sql`
            SELECT 
                pt.status, 
                pt.pix_value, 
                COALESCE(tb.bot_name, ch.name, 'Checkout') as source_name, 
                pt.provider, 
                pt.created_at
            FROM pix_transactions pt
            JOIN clicks c ON pt.click_id_internal = c.id
            LEFT JOIN pressels p ON c.pressel_id = p.id
            LEFT JOIN telegram_bots tb ON p.bot_id = tb.id
            LEFT JOIN checkouts ch ON c.checkout_id = ch.id
            WHERE c.seller_id = ${sellerId}
            ORDER BY pt.created_at DESC;`;
        res.status(200).json(transactions);
    } catch (error) {
        console.error("Erro ao buscar transações:", error);
        res.status(500).json({ message: 'Erro ao buscar dados das transações.' });
    }
});

// --- ROTA DE GERAÇÃO DE PIX ---
app.post('/api/pix/generate', logApiRequest, async (req, res) => {
    const sql = getDbConnection();
    const apiKey = req.headers['x-api-key'];
    const { click_id, value_cents, customer, product } = req.body;
    
    if (!apiKey || !click_id || !value_cents) return res.status(400).json({ message: 'API Key, click_id e value_cents são obrigatórios.' });

    try {
        const [seller] = await sql`SELECT * FROM sellers WHERE api_key = ${apiKey}`;
        if (!seller) return res.status(401).json({ message: 'API Key inválida.' });

        // ##### INÍCIO DA MODIFICAÇÃO #####
        // Lida com ambos os formatos: "lead000103" e "/start lead000103"
        const db_click_id = click_id.startsWith('/start ') ? click_id : `/start ${click_id}`;
        // ##### FIM DA MODIFICAÇÃO #####
        
        const [click] = await sql`SELECT * FROM clicks WHERE click_id = ${db_click_id} AND seller_id = ${seller.id}`;
        if (!click) return res.status(404).json({ message: 'Click ID não encontrado.' });
        
        const providerOrder = [
            seller.pix_provider_primary,
            seller.pix_provider_secondary,
            seller.pix_provider_tertiary
        ].filter(Boolean);

        let lastError = null;

        for (const provider of providerOrder) {
            try {
                const pixResult = await generatePixForProvider(provider, seller, value_cents, req.headers.host, apiKey);
                
                const [transaction] = await sql`INSERT INTO pix_transactions (click_id_internal, pix_value, qr_code_text, qr_code_base64, provider, provider_transaction_id, pix_id) VALUES (${click.id}, ${value_cents / 100}, ${pixResult.qr_code_text}, ${pixResult.qr_code_base64}, ${pixResult.provider}, ${pixResult.transaction_id}, ${pixResult.transaction_id}) RETURNING id`;
                
                if (click.pressel_id) {
                    await sendMetaEvent('InitiateCheckout', click, { id: transaction.id, pix_value: value_cents / 100 }, null);
                }

                const customerDataForUtmify = customer || { name: "Cliente Interessado", email: "cliente@email.com" };
                const productDataForUtmify = product || { id: "prod_1", name: "Produto Ofertado" };
                await sendEventToUtmify('waiting_payment', click, { provider_transaction_id: pixResult.transaction_id, pix_value: value_cents / 100, created_at: new Date() }, seller, customerDataForUtmify, productDataForUtmify);
                
                return res.status(200).json(pixResult);
            } catch (error) {
                console.error(`[PIX GENERATE FALLBACK] Falha ao gerar PIX com ${provider}:`, error.message);
                lastError = error;
            }
        }

        console.error(`[PIX GENERATE FINAL ERROR] Seller ID: ${seller?.id}, Email: ${seller?.email} - Todas as tentativas falharam. Último erro:`, lastError?.message || lastError);
        return res.status(500).json({ message: 'Não foi possível gerar o PIX. Todos os provedores falharam.' });

    } catch (error) {
        console.error(`[PIX GENERATE ERROR] Erro geral na rota:`, error.message);
        res.status(500).json({ message: 'Erro interno ao processar a geração de PIX.' });
    }
});

// ROTA PARA CONSULTAR STATUS DA TRANSAÇÃO PIX
app.get('/api/pix/status/:transaction_id', async (req, res) => {
    const sql = getDbConnection();
    const apiKey = req.headers['x-api-key'];
    const { transaction_id } = req.params;

    if (!apiKey) return res.status(401).json({ message: 'API Key não fornecida.' });
    if (!transaction_id) return res.status(400).json({ message: 'ID da transação é obrigatório.' });

    try {
        const sellerResult = await sql`SELECT id FROM sellers WHERE api_key = ${apiKey}`;
        if (sellerResult.length === 0) {
            return res.status(401).json({ message: 'API Key inválida.' });
        }
        const seller_id = sellerResult[0].id;

        const transactionResult = await sql`
            SELECT pt.status
            FROM pix_transactions pt
            JOIN clicks c ON pt.click_id_internal = c.id
            WHERE (pt.provider_transaction_id = ${transaction_id} OR pt.pix_id = ${transaction_id})
              AND c.seller_id = ${seller_id}`;

        if (transactionResult.length === 0) {
            return res.status(404).json({ status: 'not_found', message: 'Transação não encontrada.' });
        }

        res.status(200).json({ status: transactionResult[0].status });

    } catch (error) {
        console.error("Erro ao consultar status da transação:", error);
        res.status(500).json({ message: 'Erro interno ao consultar o status.' });
    }
});


// --- ROTA DE TESTE DE PROVEDOR DE PIX ---
app.post('/api/pix/test-provider', authenticateJwt, async (req, res) => {
    const sql = getDbConnection();
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
        console.error(`[PIX TEST ERROR] Seller ID: ${sellerId}, Provider: ${provider} - Erro:`, error.response?.data || error.message);
        res.status(500).json({ 
            message: `Falha ao gerar PIX de teste com ${provider.toUpperCase()}. Verifique as credenciais.`, 
            details: error.response?.data?.message || error.message 
        });
    }
});


// --- ROTA PARA TESTAR A ROTA DE PRIORIDADE ---
app.post('/api/pix/test-priority-route', authenticateJwt, async (req, res) => {
    const sql = getDbConnection();
    const sellerId = req.user.id;
    let testLog = [];

    try {
        const [seller] = await sql`SELECT * FROM sellers WHERE id = ${sellerId}`;
        if (!seller) return res.status(404).json({ message: 'Vendedor não encontrado.' });
        
        const providerOrder = [
            { name: seller.pix_provider_primary, position: 'Primário' },
            { name: seller.pix_provider_secondary, position: 'Secundário' },
            { name: seller.pix_provider_tertiary, position: 'Terciário' }
        ].filter(p => p.name); 

        if (providerOrder.length === 0) {
            return res.status(400).json({ message: 'Nenhuma ordem de prioridade de provedores foi configurada.' });
        }

        const value_cents = 50;

        for (const providerInfo of providerOrder) {
            const provider = providerInfo.name;
            const position = providerInfo.position;
            
            try {
                const startTime = Date.now();
                const pixResult = await generatePixForProvider(provider, seller, value_cents, req.headers.host, seller.api_key);
                const endTime = Date.now();
                const responseTime = ((endTime - startTime) / 1000).toFixed(2);

                testLog.push(`SUCESSO com Provedor ${position} (${provider.toUpperCase()}).`);
                return res.status(200).json({
                    success: true,
                    position: position,
                    provider: provider.toUpperCase(),
                    acquirer: pixResult.acquirer,
                    responseTime: responseTime,
                    qr_code_text: pixResult.qr_code_text,
                    log: testLog
                });

            } catch (error) {
                const errorMessage = error.response?.data?.details || error.message;
                console.error(`Falha no provedor ${position} (${provider}):`, errorMessage);
                testLog.push(`FALHA com Provedor ${position} (${provider.toUpperCase()}): ${errorMessage}`);
            }
        }

        console.error("Todos os provedores na rota de prioridade falharam.");
        return res.status(500).json({
            success: false,
            message: 'Todos os provedores configurados na sua rota de prioridade falharam.',
            log: testLog
        });

    } catch (error) {
        console.error(`[PIX PRIORITY TEST ERROR] Erro geral:`, error.message);
        res.status(500).json({ 
            success: false,
            message: 'Ocorreu um erro inesperado ao testar a rota de prioridade.',
            log: testLog
        });
    }
});

// --- ROTA DE WEBHOOK DO TELEGRAM ---
app.post('/api/webhook/telegram/:botId', async (req, res) => {
    const sql = getDbConnection();
    const { botId } = req.params;

    if (req.body.callback_query) {
        const { callback_query } = req.body;
        const chatId = callback_query.message.chat.id;
        const [action, ...params] = callback_query.data.split('|');

        try {
            const [bot] = await sql`SELECT seller_id, bot_token FROM telegram_bots WHERE id = ${botId}`;
            if (!bot) { return res.status(404).send('Bot not found'); }
            const botToken = bot.bot_token;
            const apiUrl = `https://api.telegram.org/bot${botToken}`;

            switch(action) {
                case 'generate_pix':
                    const [value] = params;
                    const value_cents = parseInt(value, 10);
                    const [click] = await sql`INSERT INTO clicks (seller_id) VALUES (${bot.seller_id}) RETURNING id`;
                    if (!click) { throw new Error('Não foi possível criar um registro de clique.'); }
                    const click_id_internal = click.id;
                    const clean_click_id = `lead${click_id_internal.toString().padStart(6, '0')}`;
                    await sql`UPDATE clicks SET click_id = ${'/start ' + clean_click_id} WHERE id = ${click_id_internal}`;
                    const [seller] = await sql`SELECT * FROM sellers WHERE id = ${bot.seller_id}`;
                    const providerOrder = [seller.pix_provider_primary, seller.pix_provider_secondary, seller.pix_provider_tertiary].filter(Boolean);
                    if (providerOrder.length === 0) providerOrder.push('pushinpay');
                    let pixResult;
                    for (const provider of providerOrder) {
                        try {
                            pixResult = await generatePixForProvider(provider, seller, value_cents, req.headers.host, seller.api_key);
                            if (pixResult) break;
                        } catch (e) { console.error(`Falha ao gerar PIX com ${provider} no fluxo do bot: ${e.message}`); }
                    }
                    if (!pixResult) throw new Error('Todos os provedores de PIX falharam.');
                    await sql`INSERT INTO pix_transactions (click_id_internal, pix_value, qr_code_text, qr_code_base64, provider, provider_transaction_id, pix_id) VALUES (${click_id_internal}, ${value_cents / 100}, ${pixResult.qr_code_text}, ${pixResult.qr_code_base64}, ${pixResult.provider}, ${pixResult.transaction_id}, ${pixResult.transaction_id})`;
                    const pixMessagePayload = { chat_id: chatId, text: `<code>${pixResult.qr_code_text}</code>`, parse_mode: 'HTML', reply_markup: { inline_keyboard: [[{ text: "📋 Copiar Código PIX", callback_data: `copy_pix`}]] } };
                    await axios.post(`${apiUrl}/sendMessage`, pixMessagePayload);
                    const confirmationPayload = { chat_id: chatId, text: "Após efetuar o pagamento, clique no botão abaixo para verificar.", parse_mode: 'HTML', reply_markup: { inline_keyboard: [[{ text: "Conferir Pagamento", callback_data: `check_payment|${pixResult.transaction_id}` }]] } };
                    await axios.post(`${apiUrl}/sendMessage`, confirmationPayload);
                    break;
                case 'check_payment':
                    const [txId] = params;
                    const [transaction] = await sql`SELECT status FROM pix_transactions WHERE provider_transaction_id = ${txId} OR pix_id = ${txId}`;
                    let feedbackMessage = "❌ Pagamento ainda não identificado. Por favor, tente novamente em alguns instantes.";
                    if (transaction && (transaction.status === 'paid' || transaction.status === 'COMPLETED')) { feedbackMessage = "✅ Pagamento confirmado com sucesso! Obrigado."; }
                    await axios.post(`${apiUrl}/sendMessage`, { chat_id: chatId, text: feedbackMessage });
                    break;
                case 'copy_pix':
                     await axios.post(`${apiUrl}/answerCallbackQuery`, { callback_query_id: callback_query.id, text: "Copiado! Agora é só colar no app do seu banco.", show_alert: true });
                    break;
            }
        } catch (error) { console.error('Erro no processamento do callback do webhook:', error.message, error.stack); }
        return res.sendStatus(200);
    }

    const { message } = req.body;
    
    if (!message || !message.text || !message.chat || message.chat.id < 0) {
        return res.sendStatus(200);
    }

    if (message.text.startsWith('/start ')) {
        const chatId = message.chat.id;
        const userId = message.from.id;
        const firstName = message.from.first_name;
        const lastName = message.from.last_name || null;
        const username = message.from.username || null;
        const clickId = message.text.split(' ')[1] || null;

        try {
            const [bot] = await sql`SELECT seller_id FROM telegram_bots WHERE id = ${botId}`;
            if (!bot) { 
                console.warn(`Webhook para botId não encontrado no banco de dados: ${botId}`);
                return res.status(404).send('Bot not found'); 
            }
            await sql`
                INSERT INTO telegram_chats (seller_id, bot_id, chat_id, user_id, first_name, last_name, username, click_id)
                VALUES (${bot.seller_id}, ${botId}, ${chatId}, ${userId}, ${firstName}, ${lastName}, ${username}, ${clickId})
                ON CONFLICT (chat_id) DO UPDATE SET
                    user_id = EXCLUDED.user_id, first_name = EXCLUDED.first_name, last_name = EXCLUDED.last_name,
                    username = EXCLUDED.username, click_id = COALESCE(telegram_chats.click_id, EXCLUDED.click_id);
            `;
        } catch (error) {
            console.error('Erro ao processar comando /start do Telegram:', error);
            return res.sendStatus(500);
        }
    }
    
    res.sendStatus(200);
});


// --- ROTAS DA CENTRAL DE DISPAROS ---
app.get('/api/dispatches', authenticateJwt, async (req, res) => {
    const sql = getDbConnection();
    try {
        const dispatches = await sql`SELECT * FROM mass_sends WHERE seller_id = ${req.user.id} ORDER BY sent_at DESC;`;
        res.status(200).json(dispatches);
    } catch (error) {
        console.error("Erro ao buscar histórico de disparos:", error);
        res.status(500).json({ message: 'Erro ao buscar histórico.' });
    }
});

app.get('/api/dispatches/:id', authenticateJwt, async (req, res) => {
    const sql = getDbConnection();
    const { id } = req.params;
    try {
        const details = await sql`
            SELECT d.*, u.first_name, u.username
            FROM mass_send_details d
            LEFT JOIN telegram_chats u ON d.chat_id = u.chat_id
            WHERE d.mass_send_id = ${id}
            ORDER BY d.sent_at;
        `;
        res.status(200).json(details);
    } catch (error) {
        console.error("Erro ao buscar detalhes do disparo:", error);
        res.status(500).json({ message: 'Erro ao buscar detalhes.' });
    }
});

// ROTA DE DISPARO EM MASSA (MULTI-BOT)
app.post('/api/bots/mass-send', authenticateJwt, async (req, res) => {
    const sql = getDbConnection();
    const sellerId = req.user.id;
    const { botIds, flowType, initialText, ctaButtonText, pixValue, externalLink, imageUrl } = req.body;

    if (!botIds || botIds.length === 0 || !initialText || !ctaButtonText) {
        return res.status(400).json({ message: 'Todos os campos são obrigatórios.' });
    }

    try {
        const bots = await sql`SELECT id, bot_token FROM telegram_bots WHERE id = ANY(${botIds}) AND seller_id = ${sellerId}`;
        if (bots.length === 0) return res.status(404).json({ message: 'Nenhum bot válido selecionado.' });
        
        const users = await sql`SELECT DISTINCT ON (chat_id) chat_id, bot_id FROM telegram_chats WHERE bot_id = ANY(${botIds}) AND seller_id = ${sellerId}`;
        if (users.length === 0) return res.status(404).json({ message: 'Nenhum usuário encontrado para os bots selecionados.' });

        const [log] = await sql`INSERT INTO mass_sends (seller_id, message_content, button_text, button_url, image_url) VALUES (${sellerId}, ${initialText}, ${ctaButtonText}, ${externalLink || null}, ${imageUrl || null}) RETURNING id;`;
        const logId = log.id;
        
        res.status(202).json({ message: `Disparo agendado para ${users.length} usuários.`, logId });
        
        (async () => {
            let successCount = 0;
            let failureCount = 0;
            const botTokenMap = new Map(bots.map(b => [b.id, b.bot_token]));

            for (const user of users) {
                const botToken = botTokenMap.get(user.bot_id);
                if (!botToken) continue;

                const endpoint = imageUrl ? 'sendPhoto' : 'sendMessage';
                const apiUrl = `https://api.telegram.org/bot${botToken}/${endpoint}`;
                let payload;

                if (flowType === 'pix_flow') {
                    const valueInCents = Math.round(parseFloat(pixValue) * 100);
                    const callback_data = `generate_pix|${valueInCents}`;
                    payload = { chat_id: user.chat_id, caption: initialText, text: initialText, photo: imageUrl, parse_mode: 'HTML', reply_markup: { inline_keyboard: [[{ text: ctaButtonText, callback_data }]] } };
                } else {
                    payload = { chat_id: user.chat_id, caption: initialText, text: initialText, photo: imageUrl, parse_mode: 'HTML', reply_markup: { inline_keyboard: [[{ text: ctaButtonText, url: externalLink }]] } };
                }
                
                if (!imageUrl) { delete payload.photo; delete payload.caption; } else { delete payload.text; }

                try {
                    await axios.post(apiUrl, payload, { timeout: 10000 });
                    successCount++;
                    await sql`INSERT INTO mass_send_details (mass_send_id, chat_id, status) VALUES (${logId}, ${user.chat_id}, 'success')`;
                } catch (error) {
                    failureCount++;
                    const errorMessage = error.response?.data?.description || error.message;
                    console.error(`Falha ao enviar para ${user.chat_id}: ${errorMessage}`);
                    await sql`INSERT INTO mass_send_details (mass_send_id, chat_id, status, details) VALUES (${logId}, ${user.chat_id}, 'failure', ${errorMessage})`;
                }
                await new Promise(resolve => setTimeout(resolve, 300));
            }

            await sql`UPDATE mass_sends SET success_count = ${successCount}, failure_count = ${failureCount} WHERE id = ${logId};`;
            console.log(`Disparo ${logId} concluído. Sucessos: ${successCount}, Falhas: ${failureCount}`);
        })();

    } catch (error) {
        console.error("Erro no disparo em massa:", error);
        if (!res.headersSent) res.status(500).json({ message: 'Erro ao iniciar o disparo.' });
    }
});


// --- FUNÇÃO PARA CENTRALIZAR EVENTOS DE CONVERSÃO (CORRIGIDA) ---
async function handleSuccessfulPayment(transactionId, customerData) {
    const sql = getDbConnection();
    try {
        // A query agora usa o ID único da transação para evitar o bug
        const [transaction] = await sql`UPDATE pix_transactions SET status = 'paid', paid_at = NOW() WHERE id = ${transactionId} AND status != 'paid' RETURNING *`;
        
        // Se a transação não foi encontrada ou já estava paga, a função para aqui.
        if (!transaction) {
            console.log(`Transação ${transactionId} não precisou de atualização (já paga ou não encontrada).`);
            return;
        }

        const [click] = await sql`SELECT * FROM clicks WHERE id = ${transaction.click_id_internal}`;
        const [seller] = await sql`SELECT * FROM sellers WHERE id = ${click.seller_id}`;

        if (click && seller) {
            const finalCustomerData = customerData || { name: "Cliente Pagante", document: null };
            const productData = { id: "prod_final", name: "Produto Vendido" };

            await sendEventToUtmify('paid', click, transaction, seller, finalCustomerData, productData);
            await sendMetaEvent('Purchase', click, transaction, finalCustomerData);
            await checkAndAwardAchievements(seller.id); 
        }
    } catch(error) {
        console.error(`Erro ao lidar com pagamento bem-sucedido para transactionId ${transactionId}:`, error);
    }
}

// --- WEBHOOKS (CORRIGIDOS) ---
app.post('/api/webhook/pushinpay', async (req, res) => {
    const { id, status, payer_name, payer_document } = req.body;
    if (status === 'paid') {
        try {
            const sql = getDbConnection();
            const [tx] = await sql`SELECT id, status FROM pix_transactions WHERE provider_transaction_id = ${id} AND provider = 'pushinpay'`;
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
            const sql = getDbConnection();
            const [tx] = await sql`SELECT id, status FROM pix_transactions WHERE provider_transaction_id = ${transactionId} AND provider = 'cnpay'`;
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
            const sql = getDbConnection();
            const [tx] = await sql`SELECT id, status FROM pix_transactions WHERE provider_transaction_id = ${transactionId} AND provider = 'oasyfy'`;
            if (tx && tx.status !== 'paid') {
                await handleSuccessfulPayment(tx.id, { name: customer?.name, document: customer?.taxID?.taxID });
            }
        } catch (error) { console.error("Erro no webhook da Oasy.fy:", error); }
    }
    res.sendStatus(200);
});


// --- FUNÇÃO DE ENVIO PARA UTIFY ---
async function sendEventToUtmify(status, clickData, pixData, sellerData, customerData, productData) {
    if (!sellerData.utmify_api_token) {
        return;
    }
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

// --- FUNÇÃO GENÉRICA DE ENVIO PARA META ---
async function sendMetaEvent(eventName, clickData, transactionData, customerData = null) {
    const sql = getDbConnection();
    try {
        let presselPixels = [];
        if (clickData.pressel_id) {
            presselPixels = await sql`SELECT pixel_config_id FROM pressel_pixels WHERE pressel_id = ${clickData.pressel_id}`;
        } else if (clickData.checkout_id) {
            presselPixels = await sql`SELECT pixel_config_id FROM checkout_pixels WHERE checkout_id = ${clickData.checkout_id}`;
        }

        if (presselPixels.length === 0) {
            console.log(`Nenhum pixel configurado para o evento ${eventName} do clique ${clickData.id}.`);
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


// --- ROTINA DE VERIFICAÇÃO DE TRANSAÇÕES PENDENTES (CORRIGIDA) ---
async function checkPendingTransactions() {
    const sql = getDbConnection();
    try {
        const pendingTransactions = await sql`
            SELECT id, provider, provider_transaction_id, click_id_internal, status
            FROM pix_transactions WHERE status = 'pending' AND created_at > NOW() - INTERVAL '24 hours'`;

        if (pendingTransactions.length === 0) return;
        
        for (const tx of pendingTransactions) {
            try {
                const [seller] = await sql`
                    SELECT pushinpay_token, cnpay_public_key, cnpay_secret_key, oasyfy_public_key, oasyfy_secret_key
                    FROM sellers s JOIN clicks c ON c.seller_id = s.id
                    WHERE c.id = ${tx.click_id_internal}`;
                if (!seller) continue;

                let providerStatus, customerData = {};
                if (tx.provider === 'pushinpay') {
                    const response = await axios.get(`https://api.pushinpay.com.br/api/transactions/${tx.provider_transaction_id}`, { headers: { Authorization: `Bearer ${seller.pushinpay_token}` } });
                    providerStatus = response.data.status;
                    customerData = { name: response.data.payer_name, document: response.data.payer_document };
                } else if (tx.provider === 'cnpay') {
                    const response = await axios.get(`https://painel.appcnpay.com/api/v1/gateway/pix/receive/${tx.provider_transaction_id}`, { headers: { 'x-public-key': seller.cnpay_public_key, 'x-secret-key': seller.cnpay_secret_key } });
                    providerStatus = response.data.status;
                    customerData = { name: response.data.customer?.name, document: response.data.customer?.taxID?.taxID };
                } else if (tx.provider === 'oasyfy') {
                    const response = await axios.get(`https://app.oasyfy.com/api/v1/gateway/pix/receive/${tx.provider_transaction_id}`, { headers: { 'x-public-key': seller.oasyfy_public_key, 'x-secret-key': seller.oasyfy_secret_key } });
                    providerStatus = response.data.status;
                    customerData = { name: response.data.customer?.name, document: response.data.customer?.taxID?.taxID };
                }
                
                if ((providerStatus === 'paid' || providerStatus === 'COMPLETED') && tx.status !== 'paid') {
                     await handleSuccessfulPayment(tx.id, customerData);
                }
            } catch (error) {
                console.error(`Erro ao verificar transação ${tx.id}:`, error.response?.data || error.message);
            }
        }
    } catch (error) {
        console.error("Erro na rotina de verificação geral:", error.message);
    }
}
setInterval(checkPendingTransactions, 120000);

// --- ROTAS DO PAINEL ADMINISTRATIVO ---
function authenticateAdmin(req, res, next) {
    const adminKey = req.headers['x-admin-api-key'];
    if (!adminKey || adminKey !== ADMIN_API_KEY) {
        return res.status(403).json({ message: 'Acesso negado. Chave de administrador inválida.' });
    }
    next();
}

app.get('/api/admin/dashboard', authenticateAdmin, async (req, res) => {
    const sql = getDbConnection();
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
    const sql = getDbConnection();
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
    const sql = getDbConnection();
    try {
        const sellers = await sql`SELECT id, name, email, created_at, is_active FROM sellers ORDER BY created_at DESC;`;
        res.json(sellers);
    } catch (error) {
        res.status(500).json({ message: 'Erro ao listar vendedores.' });
    }
});
app.post('/api/admin/sellers/:id/toggle-active', authenticateAdmin, async (req, res) => {
    const sql = getDbConnection();
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
    const sql = getDbConnection();
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
    const sql = getDbConnection();
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
    const sql = getDbConnection();
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
    const sql = getDbConnection();
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

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

module.exports = app;
