const express = require('express');
const cors = require('cors');
const { neon } = require('@neondatabase/serverless');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid'); // Para gerar um event_id único para a Meta

const app = express();
app.use(cors());
app.use(express.json());

// Função auxiliar para enviar o evento de conversão para a API da Meta
async function sendConversionToMeta(clickData) {
  // Se não houver token ou pixel_id para este cliente, não faz nada
  if (!clickData.meta_conversion_api_token || !clickData.meta_pixel_id) {
    console.log(`Cliente com client_id ${clickData.client_id} não possui credenciais da Meta. Evento não enviado.`);
    return;
  }

  const eventId = uuidv4(); // Gera um ID único para o evento para evitar duplicidade
  const eventTime = Math.floor(Date.now() / 1000);
  const metaApiUrl = `https://graph.facebook.com/v19.0/${clickData.meta_pixel_id}/events`;

  const payload = {
    data: [
      {
        event_name: 'Purchase',
        event_time: eventTime,
        event_id: eventId,
        action_source: 'website',
        user_data: {
          client_ip_address: clickData.ip_address,
          client_user_agent: clickData.user_agent,
          fbp: clickData.fbp || null,
          fbc: clickData.fbc || null,
        },
        custom_data: {
          currency: 'BRL',
          value: clickData.pix_value,
        },
      },
    ],
    // access_token: clickData.meta_conversion_api_token, // O token agora vai no Header
  };

  try {
    console.log('Enviando evento de conversão para a Meta:', JSON.stringify(payload, null, 2));
    await axios.post(metaApiUrl, payload, {
      headers: {
        'Authorization': `Bearer ${clickData.meta_conversion_api_token}`,
        'Content-Type': 'application/json'
      }
    });
    console.log(`Evento de conversão enviado com sucesso para o Pixel ID ${clickData.meta_pixel_id} com event_id ${eventId}`);
    
    // Salva o event_id no banco para referência
    const sql = neon(process.env.DATABASE_URL);
    await sql('UPDATE clicks SET event_id = $1 WHERE id = $2', [eventId, clickData.id]);

  } catch (error) {
    console.error('Erro ao enviar evento para a API da Meta:', error.response ? error.response.data : error.message);
  }
}


// Função para buscar Cidade e Estado pelo IP
async function getGeoFromIp(ip) {
  if (!ip) return { city: '', state: '' };
  try {
    const response = await axios.get(`http://ip-api.com/json/${ip}?fields=status,city,regionName`);
    if (response.data && response.data.status === 'success') {
      return { city: response.data.city || '', state: response.data.regionName || '' };
    }
    return { city: '', state: '' };
  } catch (error) {
    console.error('Erro ao buscar geolocalização:', error.message);
    return { city: '', state: '' };
  }
}

// ROTA PARA A PRESSEL REGISTRAR O CLIQUE
app.post('/api/registerClick', async (req, res) => {
  // (Esta rota continua a mesma da versão anterior, sem alterações)
  try {
    const { referer, fbclid, fbp, client_id } = req.body;
    const ip_address = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const user_agent = req.headers['user-agent'];
    const { city, state } = await getGeoFromIp(ip_address);
    const sql = neon(process.env.DATABASE_URL);
    const insertQuery = `
      INSERT INTO clicks (timestamp, ip_address, user_agent, referer, city, state, fbclid, fbp, client_id)
      VALUES (NOW(), $1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING id;
    `;
    const insertResult = await sql(insertQuery, [ip_address, user_agent, referer, city, state, fbclid, fbp, client_id]);
    const generatedId = insertResult[0].id;
    const formattedClickId = `lead${generatedId.toString().padStart(6, '0')}`;
    await sql('UPDATE clicks SET click_id = $1 WHERE id = $2', [formattedClickId, generatedId]);
    console.log(`Clique salvo! Client_id: [${client_id}], Click_id: [${formattedClickId}], Cidade: [${city}]`);
    res.status(200).json({ status: 'success', message: 'Click registrado', click_id: formattedClickId });
  } catch (error) {
    console.error('ERRO FATAL NA ROTA /api/registerClick:', error);
    res.status(500).json({ status: 'error', message: 'Erro interno do servidor.' });
  }
});

// ROTA PARA O MANYCHAT ATUALIZAR O PIX GERADO
app.post('/api/updateConversion', async (req, res) => {
  // (Esta rota continua a mesma da versão anterior, sem alterações)
  const { click_id, pix_id, pix_value } = req.body;
  if (!click_id || !pix_id || pix_value === undefined) {
    return res.status(400).json({ status: 'error', message: 'Os campos click_id, pix_id e pix_value são obrigatórios.' });
  }
  try {
    const sql = neon(process.env.DATABASE_URL);
    const updateQuery = `UPDATE clicks SET pix_id = $1, pix_value = $2 WHERE click_id = $3 RETURNING *;`;
    const result = await sql(updateQuery, [pix_id, pix_value, click_id]);
    if (result.length > 0) {
      console.log(`Dados do PIX atualizados para o Click ID: ${click_id}`);
      res.status(200).json({ status: 'success', message: 'Dados do PIX registrados.' });
    } else {
      res.status(404).json({ status: 'error', message: 'Click ID não encontrado.' });
    }
  } catch (error) {
    console.error('ERRO FATAL NA ROTA /api/updateConversion:', error);
    res.status(500).json({ status: 'error', message: 'Erro interno do servidor.' });
  }
});


// ########## NOVA ROTA: CONSULTAR CIDADE PELO CLICK_ID ##########
app.get('/api/getCityByClickId', async (req, res) => {
  const { click_id } = req.query;
  if (!click_id) {
    return res.status(400).json({ status: 'error', message: 'O parâmetro click_id é obrigatório.' });
  }
  try {
    const sql = neon(process.env.DATABASE_URL);
    const result = await sql('SELECT city, state FROM clicks WHERE click_id = $1', [click_id]);
    if (result.length > 0) {
      res.status(200).json({ city: result[0].city || 'N/A', state: result[0].state || 'N/A' });
    } else {
      res.status(404).json({ status: 'error', message: 'Click ID não encontrado.' });
    }
  } catch (error) {
    console.error('ERRO na rota /api/getCityByClickId:', error);
    res.status(500).json({ status: 'error', message: 'Erro interno do servidor.' });
  }
});


// ########## NOVA ROTA: CONFIRMAR PAGAMENTO E ENVIAR PARA A META ##########
app.post('/api/confirmPayment', async (req, res) => {
  const { click_id } = req.body;
  if (!click_id) {
    return res.status(400).json({ status: 'error', message: 'O campo click_id é obrigatório.' });
  }

  try {
    const sql = neon(process.env.DATABASE_URL);
    
    // Passo 1: Atualiza o status do pagamento no banco e retorna todos os dados necessários
    // Usamos um JOIN para buscar os dados do cliente (pixel, token) na mesma consulta
    const query = `
      UPDATE clicks c
      SET 
        is_converted = TRUE,
        conversion_timestamp = NOW()
      FROM saas_clients sc
      WHERE c.click_id = $1 AND c.is_converted = FALSE AND c.client_id = sc.client_id
      RETURNING c.*, sc.meta_pixel_id, sc.meta_conversion_api_token;
    `;
    const result = await sql(query, [click_id]);

    if (result.length > 0) {
      const clickData = result[0];
      console.log(`Pagamento confirmado para Click ID: ${click_id}. Disparando evento para a Meta.`);
      
      // Passo 2: Envia os dados para a API de conversões da Meta
      await sendConversionToMeta(clickData);
      
      res.status(200).json({ status: 'success', message: 'Pagamento confirmado e evento de conversão enviado.' });
    } else {
      console.log(`Click ID não encontrado, já convertido ou sem cliente correspondente: ${click_id}`);
      res.status(404).json({ status: 'error', message: 'Click ID não encontrado ou já convertido.' });
    }
  } catch (error) {
    console.error('ERRO FATAL NA ROTA /api/confirmPayment:', error);
    res.status(500).json({ status: 'error', message: 'Erro interno do servidor.' });
  }
});

module.exports = app;
