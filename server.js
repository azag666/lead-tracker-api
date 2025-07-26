const express = require('express');
const cors = require('cors');
const { neon } = require('@neondatabase/serverless');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(express.json());

// (As outras funções como sendConversionToMeta e getGeoFromIp permanecem as mesmas)
async function sendConversionToMeta(clickData) {
  if (!clickData.meta_conversion_api_token || !clickData.meta_pixel_id) { return; }
  const eventId = uuidv4();
  const eventTime = Math.floor(Date.now() / 1000);
  const metaApiUrl = `https://graph.facebook.com/v19.0/${clickData.meta_pixel_id}/events`;
  const payload = {
    data: [{
      event_name: 'Purchase', event_time: eventTime, event_id: eventId, action_source: 'website',
      user_data: { client_ip_address: clickData.ip_address, client_user_agent: clickData.user_agent, fbp: clickData.fbp || null, fbc: clickData.fbc || null },
      custom_data: { currency: 'BRL', value: clickData.pix_value },
    }],
  };
  try {
    await axios.post(metaApiUrl, payload, { headers: { 'Authorization': `Bearer ${clickData.meta_conversion_api_token}`, 'Content-Type': 'application/json' } });
    const sql = neon(process.env.DATABASE_URL);
    await sql('UPDATE clicks SET event_id = $1 WHERE id = $2', [eventId, clickData.id]);
  } catch (error) { console.error('Erro ao enviar evento para a API da Meta:', error.response ? error.response.data : error.message); }
}
async function getGeoFromIp(ip) {
  if (!ip) return { city: '', state: '' };
  try {
    const response = await axios.get(`http://ip-api.com/json/${ip}?fields=status,city,regionName`);
    if (response.data && response.data.status === 'success') { return { city: response.data.city || '', state: response.data.regionName || '' }; }
    return { city: '', state: '' };
  } catch (error) { return { city: '', state: '' }; }
}

// (As outras rotas permanecem as mesmas)
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
app.post('/api/updateConversion', async (req, res) => {
  const { click_id, pix_id, pix_value } = req.body;
  if (!click_id || !pix_id || pix_value === undefined) { return res.status(400).json({ status: 'error', message: 'Campos obrigatórios faltando.' }); }
  try {
    const sql = neon(process.env.DATABASE_URL);
    const result = await sql(`UPDATE clicks SET pix_id = $1, pix_value = $2 WHERE click_id = $3 RETURNING *;`, [pix_id, pix_value, click_id]);
    if (result.length > 0) { res.status(200).json({ status: 'success', message: 'Dados do PIX registrados.' }); } else { res.status(404).json({ status: 'error', message: 'Click ID não encontrado.' }); }
  } catch (error) { res.status(500).json({ status: 'error', message: 'Erro interno do servidor.' }); }
});
app.post('/api/confirmPayment', async (req, res) => {
  const { click_id } = req.body;
  if (!click_id) { return res.status(400).json({ status: 'error', message: 'O campo click_id é obrigatório.' }); }
  try {
    const sql = neon(process.env.DATABASE_URL);
    const result = await sql(`UPDATE clicks c SET is_converted = TRUE, conversion_timestamp = NOW() FROM saas_clients sc WHERE c.click_id = $1 AND c.is_converted = FALSE AND c.client_id = sc.client_id RETURNING c.*, sc.meta_pixel_id, sc.meta_conversion_api_token;`, [click_id]);
    if (result.length > 0) {
      await sendConversionToMeta(result[0]);
      res.status(200).json({ status: 'success', message: 'Pagamento confirmado e evento de conversão enviado.' });
    } else { res.status(404).json({ status: 'error', message: 'Click ID não encontrado ou já convertido.' }); }
  } catch (error) { res.status(500).json({ status: 'error', message: 'Erro interno do servidor.' }); }
});

// ########## ROTA /api/getCityByClickId MODIFICADA PARA RETORNAR APENAS O TEXTO DA CIDADE ##########
app.get('/api/getCityByClickId', async (req, res) => {
  const { click_id } = req.query;
  if (!click_id) {
    return res.status(400).send('O parâmetro click_id é obrigatório.');
  }
  try {
    const sql = neon(process.env.DATABASE_URL);
    const result = await sql('SELECT city FROM clicks WHERE click_id = $1', [click_id]);

    if (result.length > 0) {
      // Retorna a cidade como TEXTO PURO, não mais como JSON
      res.status(200).send(result[0].city || 'N/A');
    } else {
      res.status(404).send('Click ID não encontrado.');
    }
  } catch (error) {
    console.error('ERRO na rota /api/getCityByClickId:', error);
    res.status(500).send('Erro interno do servidor.');
  }
});
// #########################################################################################

module.exports = app;
