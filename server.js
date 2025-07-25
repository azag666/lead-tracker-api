require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors()); // Essencial para permitir que sua pressel externa acesse a API
app.use(express.json());

// Rota para o Health Check do Railway
app.get('/', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'Lead Tracker API is running.' });
});

const IP_API_BASE_URL = 'http://ip-api.com/json/';

async function getGeoFromIp(ip) {
  if (!ip) return { city: '', state: '' };
  try {
    const response = await axios.get(`${IP_API_BASE_URL}${ip}?fields=status,message,city,regionName`);
    if (response.data && response.data.status === 'success') {
      return { city: response.data.city || '', state: response.data.regionName || '' };
    }
    return { city: '', state: '' };
  } catch (error) {
    return { city: '', state: '' };
  }
}

// ROTA PRINCIPAL: Registrar o clique vindo da pressel externa
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
    console.log(`Clique recebido da pressel externa. Client_id: [${client_id}], Click_id: [${formattedClickId}]`);
    // Retorna o click_id para a pressel
    res.json({ status: 'success', message: 'Click registrado', click_id: formattedClickId });
  } catch (error) {
    console.error('Erro ao registrar clique:', error);
    res.status(500).json({ status: 'error', message: 'Erro interno do servidor' });
  }
});


// ROTA DE CONSULTA: Para o ManyChat obter dados
app.get('/api/getClickData', async (req, res) => {
  const { click_id } = req.query;
  if (!click_id) {
    return res.status(400).json({ status: 'error', message: 'click_id é obrigatório' });
  }
  try {
    const result = await db.query('SELECT city, state FROM clicks WHERE click_id = $1', [click_id]);
    if (result.rows.length > 0) {
      res.json({ status: 'success', city: result.rows[0].city || 'N/A' });
    } else {
      res.status(404).json({ status: 'error', message: 'Click ID não encontrado' });
    }
  } catch (error) {
    console.error('Erro ao consultar cidade:', error);
    res.status(500).json({ status: 'error', message: 'Erro interno do servidor' });
  }
});


async function startServer() {
  await db.testDbConnection();
  await db.createSaasClientsTable();
  await db.createClicksTable();
  app.listen(PORT, () => {
    console.log(`API de leads rodando na porta ${PORT}`);
  });
}

startServer();
