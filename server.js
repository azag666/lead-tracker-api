const express = require('express');
const cors = require('cors');
const { neon } = require('@neondatabase/serverless');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(express.json());

// Função para enviar conversão para a API da Meta
async function sendConversionToMeta(clickData) {
  console.log('--- Início da Função: sendConversionToMeta ---');
  console.log('Dados de clique recebidos em sendConversionToMeta:', clickData);

  // PIXEL ID E TOKEN DA API DA META FIXOS NO CÓDIGO
  const metaPixelId = '762701059469722';
  const metaConversionApiToken = 'EAAWTsVwbMfYBPGhgkt1u4SbnAqx3ckNdGNT8UIGYXn8RyNZBAmuASX87os096O6lhhP8FtUj7ZBHxNa9b51eOOB5ZAdl3eGRExfl1NcOa2Gguvk5etYfZBOn7gD6b4fntcuI8xcZAbppJWotN9jX7MUGjNnwZDZD';

  if (!metaConversionApiToken || !metaPixelId) {
    console.warn('sendConversionToMeta: Token ou Pixel ID da Meta fixos ausentes. Pulando envio.');
    // Isso não deve acontecer se os valores estão hardcoded, mas é uma segurança.
    return;
  }

  const eventId = uuidv4();
  const eventTime = Math.floor(Date.now() / 1000);
  const metaApiUrl = `https://graph.facebook.com/v19.0/${metaPixelId}/events`;
  
  const payload = {
    data: [{
      event_name: 'Purchase', 
      event_time: eventTime, 
      event_id: eventId, 
      action_source: 'website',
      user_data: { 
        client_ip_address: clickData.ip_address, 
        client_user_agent: clickData.user_agent, 
        fbp: clickData.fbp || null, 
        fbc: clickData.fbc || null 
      },
      custom_data: { 
        currency: 'BRL', 
        value: clickData.pix_value // Garante que pix_value é um número aqui
      },
    }],
  };

  console.log('Payload para Meta API:', JSON.stringify(payload, null, 2));

  try {
    const metaResponse = await axios.post(metaApiUrl, payload, { 
      headers: { 
        'Authorization': `Bearer ${metaConversionApiToken}`, 
        'Content-Type': 'application/json' 
      } 
    });
    console.log('Resposta da Meta API (Sucesso):', metaResponse.data);

    const sql = neon(process.env.DATABASE_URL);
    // Atualiza o event_id na tabela clicks
    // clickData.id é o ID interno do clique no seu DB, não o click_id externo
    await sql('UPDATE clicks SET event_id = $1 WHERE id = $2', [eventId, clickData.id]);
    console.log('event_id atualizado no BD após sucesso da Meta API.');

  } catch (error) { 
    console.error('ERRO ao enviar evento para a API da Meta:', error);
    if (error.response) {
      // O erro veio da resposta HTTP da Meta
      console.error('Detalhes da Resposta de Erro da Meta API (status, data):', error.response.status, error.response.data);
    } else if (error.request) {
      // A requisição foi feita, mas não houve resposta
      console.error('Nenhuma resposta recebida da Meta API:', error.request);
    } else {
      // Algo aconteceu na configuração da requisição que disparou um erro
      console.error('Erro na configuração da requisição para Meta API:', error.message);
    }
    // Re-lança o erro para que a rota confirmPayment possa capturá-lo
    throw error; 
  }
  console.log('--- Fim da Função: sendConversionToMeta ---');
}

// Função para obter geolocalização por IP
async function getGeoFromIp(ip) {
  if (!ip) return { city: '', state: '' };
  try {
    const response = await axios.get(`http://ip-api.com/json/${ip}?fields=status,city,regionName`);
    if (response.data && response.data.status === 'success') { return { city: response.data.city || '', state: response.data.regionName || '' }; }
    return { city: '', state: '' };
  } catch (error) { return { city: '', state: '' }; }
}

// Rota para registrar o clique inicial
app.post('/api/registerClick', async (req, res) => {
  try {
    const { referer, fbclid, fbp, client_id } = req.body;
    const ip_address = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const user_agent = req.headers['user-agent'];
    const { city, state } = await getGeoFromIp(ip_address);
    const sql = neon(process.env.DATABASE_URL);
    const insertQuery = `INSERT INTO clicks (timestamp, ip_address, user_agent, referer, city, state, fbclid, fbp, client_id) VALUES (NOW(), $1, $2, $3, $4, $5, $6, $7, $8) RETURNING id;`;
    const insertResult = await sql(insertQuery, [ip_address, user_agent, referer, city, state, fbclid, fbp, client_id]);
    const generatedId = insertResult[0].id;
    const cleanClickId = `lead${generatedId.toString().padStart(6, '0')}`;
    const prefixedClickId = `/start ${cleanClickId}`;
    await sql('UPDATE clicks SET click_id = $1 WHERE id = $2', [prefixedClickId, generatedId]);
    res.status(200).json({ status: 'success', message: 'Click registrado', click_id: cleanClickId });
  } catch (error) { res.status(500).json({ status: 'error', message: 'Erro interno do servidor.' }); }
});

// Rota para atualizar informações de conversão
app.post('/api/updateConversion', async (req, res) => {
  const { click_id, pix_id, pix_value } = req.body;
  console.log('--- Início da Requisição: /api/updateConversion ---'); // Novo log de início
  console.log('Dados recebidos em /api/updateConversion:', { click_id, pix_id, pix_value });

  if (!click_id || !pix_id || pix_value === undefined) {
    console.error('Erro 400: Campos obrigatórios faltando em /api/updateConversion:', { click_id, pix_id, pix_value });
    return res.status(400).json({ status: 'error', message: 'Campos obrigatórios faltando.' });
  }
  try {
    const sql = neon(process.env.DATABASE_URL);
    const result = await sql(`UPDATE clicks SET pix_id = $1, pix_value = $2 WHERE click_id = $3 RETURNING *;`, [pix_id, pix_value, click_id]);
    if (result.length > 0) {
      console.log('Atualização de conversão BEM-SUCEDIDA para click_id:', click_id);
      res.status(200).json({ status: 'success', message: 'Dados do PIX registrados.' });
    } else {
      console.error('Erro 404: Click ID NÃO ENCONTRADO ou problema na atualização para click_id:', click_id);
      res.status(404).json({ status: 'error', message: 'Click ID não encontrado.' });
    }
  } catch (error) {
    console.error('ERRO INTERNO 500 na rota /api/updateConversion:', error);
    if (error.stack) console.error('Stack Trace:', error.stack);
    res.status(500).json({ status: 'error', message: 'Erro interno do servidor.' });
  }
  console.log('--- Fim da Requisição: /api/updateConversion ---'); // Novo log de fim
});

// Rota para confirmar pagamento e enviar conversão
app.post('/api/confirmPayment', async (req, res) => {
  const { click_id } = req.body;
  console.log('--- Início da Requisição: /api/confirmPayment ---');
  console.log('Recebido /api/confirmPayment para click_id:', click_id);

  if (!click_id) {
    console.error('Erro 400: O campo click_id é obrigatório para /api/confirmPayment. Dados recebidos:', req.body);
    return res.status(400).json({ status: 'error', message: 'O campo click_id é obrigatório.' });
  }

  try {
    const sql = neon(process.env.DATABASE_URL);
    // Busque todos os dados do clique necessários para sendConversionToMeta
    // ATENÇÃO: A query foi simplificada para não depender de 'saas_clients'.
    // Ela agora busca todos os dados da linha 'clicks' para o click_id fornecido.
    const clickDataResult = await sql(`
      SELECT 
        id, ip_address, user_agent, fbp, fbc, pix_value, client_id, is_converted, click_id
      FROM clicks c
      WHERE c.click_id = $1;
    `, [click_id]);

    console.log('Dados do clique buscados para confirmação:', clickDataResult);

    if (clickDataResult.length === 0) {
      console.error('Erro 404: Click ID não encontrado para /api/confirmPayment. Click ID:', click_id);
      return res.status(404).json({ status: 'error', message: 'Click ID não encontrado.' });
    }

    const clickData = clickDataResult[0];

    // Verifica se já foi convertido para evitar reprocessamento
    if (clickData.is_converted) {
      console.warn('Click ID já foi convertido. Pulando atualização e envio para Meta. Click ID:', click_id);
      return res.status(200).json({ status: 'success', message: 'Pagamento já confirmado anteriormente.' });
    }

    // Atualize o status de conversão APENAS se a busca acima foi bem-sucedida e não foi convertido
    await sql(`
      UPDATE clicks 
      SET is_converted = TRUE, conversion_timestamp = NOW() 
      WHERE click_id = $1;
    `, [click_id]);
    console.log('Pagamento confirmado no BD para click_id:', click_id);
      
    // Chama a função para enviar para a Meta API com os dados do clique
    await sendConversionToMeta(clickData); 
    
    console.log('Evento de conversão Meta enviado (ou tentado) para click_id:', click_id);
    res.status(200).json({ status: 'success', message: 'Pagamento confirmado e evento de conversão enviado.' });
  } catch (error) {
    // Este catch agora pegará erros tanto do SQL quanto da sendConversionToMeta
    console.error('ERRO INTERNO 500 na rota /api/confirmPayment:', error);
    if (error.stack) {
      console.error('Stack Trace do Erro 500:', error.stack);
    }
    res.status(500).json({ status: 'error', message: 'Erro interno do servidor.' });
  }
  console.log('--- Fim da Requisição: /api/confirmPayment ---');
});

// ROTA GET existente para pegar a cidade por click_id (via query parameter)
app.get('/api/getCityByClickId', async (req, res) => {
  const { click_id } = req.query; // Pega do query parameter

  if (!click_id) {
    return res.status(400).json({ status: 'error', message: 'O parâmetro click_id é obrigatório.' });
  }

  try {
    const sql = neon(process.env.DATABASE_URL);
    const result = await sql('SELECT city FROM clicks WHERE click_id = $1', [click_id]);

    if (result.length > 0) {
      res.status(200).json({ city: result[0].city || 'N/A' });
    } else {
      res.status(404).json({ status: 'error', message: 'Click ID não encontrado.' });
    }
  } catch (error) {
    console.error('ERRO na rota /api/getCityByClickId (GET):', error);
    res.status(500).json({ status: 'error', message: 'Erro interno do servidor.' });
  }
});

// NOVA ROTA POST para pegar a cidade por click_id (via request body)
app.post('/api/getCityByClickIdPost', async (req, res) => {
  const { click_id } = req.body; // Pega do corpo da requisição

  if (!click_id) {
    return res.status(400).json({ status: 'error', message: 'O campo click_id é obrigatório no corpo da requisição.' });
  }

  try {
    const sql = neon(process.env.DATABASE_URL);
    const result = await sql('SELECT city FROM clicks WHERE click_id = $1', [click_id]);

    if (result.length > 0) {
      res.status(200).json({ city: result[0].city || 'N/A' });
    } else {
      res.status(404).json({ status: 'error', message: 'Click ID não encontrado.' });
    }
  } catch (error) {
    console.error('ERRO na rota /api/getCityByClickIdPost (POST):', error);
    res.status(500).json({ status: 'error', message: 'Erro interno do servidor.' });
  }
});

module.exports = app;
