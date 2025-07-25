const express = require('express');
const cors = require('cors');
const { neon } = require('@neondatabase/serverless');
const axios = require('axios');

const app = express();
app.use(cors());
app.use(express.json());

// Função para buscar Cidade e Estado pelo IP
async function getGeoFromIp(ip) {
  if (!ip) return { city: '', state: '' };
  try {
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

// ROTA PARA A PRESSEL REGISTRAR O CLIQUE
app.post('/api/registerClick', async (req, res) => {
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

// ########## NOVA ROTA PARA O MANYCHAT ATUALIZAR O PIX ##########
app.post('/api/updateConversion', async (req, res) => {
  // Pega os dados que o ManyChat vai enviar no corpo (body) da requisição
  const { click_id, pix_id, pix_value } = req.body;

  // Validação para garantir que os dados necessários foram enviados
  if (!click_id || !pix_id || pix_value === undefined) {
    return res.status(400).json({ status: 'error', message: 'Os campos click_id, pix_id e pix_value são obrigatórios.' });
  }

  try {
    const sql = neon(process.env.DATABASE_URL);
    const updateQuery = `
      UPDATE clicks
      SET 
        is_converted = TRUE,
        pix_id = $1,
        pix_value = $2
      WHERE click_id = $3
      RETURNING *; -- Opcional: retorna a linha atualizada para confirmar
    `;
    
    const result = await sql(updateQuery, [pix_id, pix_value, click_id]);

    // Verifica se alguma linha foi de fato atualizada
    if (result.length > 0) {
      console.log(`Conversão atualizada com sucesso para o Click ID: ${click_id}`);
      res.status(200).json({ status: 'success', message: 'Conversão registrada com sucesso.' });
    } else {
      console.log(`Click ID não encontrado para atualização: ${click_id}`);
      res.status(404).json({ status: 'error', message: 'Click ID não encontrado.' });
    }

  } catch (error) {
    console.error('ERRO FATAL NA ROTA /api/updateConversion:', error);
    res.status(500).json({ status: 'error', message: 'Erro interno do servidor.' });
  }
});
// ###############################################################

module.exports = app;
