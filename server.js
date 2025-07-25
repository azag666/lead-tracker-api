require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios =require('axios');
const db = require('./database');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares
app.use(cors());
app.use(express.json());

// Constantes da API de Geolocalização
const IP_API_BASE_URL = 'http://ip-api.com/json/';

// Função para obter dados de geolocalização (cidade e estado) a partir de um IP
async function getGeoFromIp(ip) {
  if (!ip) return { city: '', state: '' };
  try {
    const response = await axios.get(`${IP_API_BASE_URL}${ip}?fields=status,message,city,regionName`);
    if (response.data && response.data.status === 'success') {
      return {
        city: response.data.city || '',
        state: response.data.regionName || ''
      };
    }
    console.warn('Não foi possível obter geolocalização do IP:', ip, response.data.message);
    return { city: '', state: '' };
  } catch (error) {
    console.error('Exceção ao obter geolocalização do IP:', ip, error.message);
    return { city: '', state: '' };
  }
}

// ROTA 1: Gerar e servir a pressel HTML para um cliente específico
app.get('/api/getClientPresselHtml/:clientId', async (req, res) => {
  const { clientId } = req.params;

  try {
    // Verifica se o cliente existe no banco de dados
    const clientResult = await db.query('SELECT * FROM saas_clients WHERE client_id = $1', [clientId]);
    if (clientResult.rows.length === 0) {
      return res.status(404).send('Cliente não encontrado.');
    }
    const clientData = clientResult.rows[0];

    // Lê o template da pressel (index.html)
    const presselTemplate = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf-8');
    
    // Injeta dinamicamente os dados do cliente no HTML
    const finalHtml = presselTemplate
      .replace(/INSERIR_CLIENT_ID_AQUI_PELA_API/g, clientId)
      .replace(/Mariaduds_bot/g, clientData.telegram_bot_username) // Substitui o bot do Telegram
      .replace(/2157896137958065/g, clientData.meta_pixel_id) // Substitui o ID do Pixel
      .replace(/762701059469722/g, clientData.meta_pixel_id); // Substitui o segundo ID de Pixel (se houver)


    res.setHeader('Content-Type', 'text/html');
    res.send(finalHtml);
  } catch (error) {
    console.error('Erro ao gerar pressel para o cliente:', error);
    res.status(500).send('Erro interno do servidor.');
  }
});


// ROTA 2: Registrar um novo clique (chamada pela pressel)
app.post('/api/registerClick', async (req, res) => {
  const { referer, fbclid, fbp, client_id } = req.body;
  const ip_address = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const user_agent = req.headers['user-agent'];
  const timestamp = new Date();

  if (!client_id) {
    return res.status(400).json({ status: 'error', message: 'client_id é obrigatório.' });
  }

  try {
    const { city, state } = await getGeoFromIp(ip_address);

    const query = `
      INSERT INTO clicks (timestamp, ip_address, user_agent, referer, city, state, fbclid, fbp, client_id)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING id;
    `;
    const values = [timestamp, ip_address, user_agent, referer, city, state, fbclid, fbp, client_id];

    const result = await db.query(query, values);
    const generatedId = result.rows[0].id;
    const formattedClickId = `lead${generatedId.toString().padStart(6, '0')}`;

    await db.query('UPDATE clicks SET click_id = $1 WHERE id = $2', [formattedClickId, generatedId]);

    console.log(`Clique registrado para client_id [${client_id}] com click_id [${formattedClickId}]`);
    res.json({ status: 'success', message: 'Click registrado', click_id: formattedClickId });

  } catch (error) {
    console.error('Erro ao registrar clique:', error);
    res.status(500).json({ status: 'error', message: 'Erro interno do servidor', details: error.message });
  }
});

// ROTA 3: Obter dados do clique para o ManyChat
app.get('/api/getClickData', async (req, res) => {
  const { click_id } = req.query;

  if (!click_id) {
    return res.status(400).json({ status: 'error', message: 'click_id é obrigatório' });
  }

  try {
    const result = await db.query('SELECT city, state, is_converted, conversion_value FROM clicks WHERE click_id = $1', [click_id]);

    if (result.rows.length > 0) {
      const data = result.rows[0];
      res.json({
        status: 'success',
        city: data.city || 'N/A',
        state: data.state || 'N/A',
        is_paid: data.is_converted,
        value: data.conversion_value || 0
      });
    } else {
      res.status(404).json({ status: 'error', message: 'Click ID não encontrado' });
    }
  } catch (error) {
    console.error('Erro ao consultar dados do clique:', error);
    res.status(500).json({ status: 'error', message: 'Erro interno do servidor' });
  }
});

// ROTA 4: Webhook para receber confirmação de PIX e marcar como convertido
// (Esta é uma rota de exemplo, você precisará adaptar para o seu gateway de pagamento)
app.post('/api/webhook/paymentConfirmed', async (req, res) => {
    // A implementação exata dependerá do formato do webhook do seu gateway (ex: PushinPay)
    // Geralmente, o webhook envia um ID de transação ou um "metadata" que você associou ao clique.
    // Vamos supor que você receba o `click_id` e o `valor` no corpo da requisição.
    const { click_id, amount, transaction_id } = req.body;

    if (!click_id || !amount) {
        return res.status(400).json({ status: 'error', message: 'click_id e amount são obrigatórios.' });
    }

    try {
        const updateQuery = `
            UPDATE clicks
            SET is_converted = TRUE,
              conversion_timestamp = NOW(),
              conversion_value = $1,
              pix_id = $2
            WHERE click_id = $3 AND is_converted = FALSE
            RETURNING client_id, fbp, fbc, ip_address, user_agent;
        `;
        const result = await db.query(updateQuery, [amount, transaction_id, click_id]);

        if (result.rows.length > 0) {
            console.log(`Conversão registrada para o click_id: ${click_id}`);
            
            // LÓGICA PARA ENVIAR EVENTO PARA A META CONVERSIONS API
            // const conversionData = result.rows[0];
            // await sendConversionToMeta(conversionData); // Você precisaria criar esta função
            
            res.status(200).json({ status: 'success', message: 'Conversão registrada.' });
        } else {
            console.log(`Webhook recebido para click_id já convertido ou não encontrado: ${click_id}`);
            res.status(202).json({ status: 'ignored', message: 'Clique não encontrado ou já convertido.' });
        }
    } catch (error) {
        console.error('Erro no webhook de pagamento:', error);
        res.status(500).json({ status: 'error', message: 'Erro interno do servidor.' });
    }
});


// Inicializa o servidor
async function startServer() {
  await db.testDbConnection();
  // Garante que AMBAS as tabelas sejam criadas
  await db.createSaasClientsTable();
  await db.createClicksTable();
  
  app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
    console.log(`URL da pressel (exemplo): /api/getClientPresselHtml/SEU_CLIENT_ID`);
  });
}

startServer();
