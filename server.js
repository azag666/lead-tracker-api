const express = require('express');
const cors = require('cors');
const { neon } = require('@neondatabase/serverless');
const axios = require('axios'); // Adicionado de volta

const app = express();
app.use(cors());
app.use(express.json());

// Função para buscar Cidade e Estado pelo IP
async function getGeoFromIp(ip) {
  if (!ip) return { city: '', state: '' };
  try {
    // Usamos uma API gratuita para buscar os dados
    const response = await axios.get(`http://ip-api.com/json/${ip}?fields=status,city,regionName`);
    if (response.data && response.data.status === 'success') {
      return { 
        city: response.data.city || '', 
        state: response.data.regionName || '' 
      };
    }
    return { city: '', state: '' };
  } catch (error) {
    console.error('Erro ao buscar geolocalização:', error.message);
    return { city: '', state: '' };
  }
}

app.post('/api/registerClick', async (req, res) => {
  try {
    const { referer, fbclid, fbp, client_id } = req.body;
    const ip_address = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const user_agent = req.headers['user-agent'];

    // Chama a função de geolocalização
    const { city, state } = await getGeoFromIp(ip_address);

    const sql = neon(process.env.DATABASE_URL);

    const insertQuery = `
      INSERT INTO clicks (timestamp, ip_address, user_agent, referer, city, state, fbclid, fbp, client_id)
      VALUES (NOW(), $1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING id;
    `;
    // Adiciona city e state aos valores a serem salvos
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

module.exports = app;
