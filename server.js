require('dotenv').config();
const express = require('express');
const cors = require('cors');
const db = require('./database'); // Importa nosso novo database.js

const app = express();

app.use(cors());
app.use(express.json());

// A ÚNICA ROTA DA NOSSA API
app.post('/api/registerClick', async (req, res) => {
  const { referer, fbclid, fbp, client_id } = req.body;
  const ip_address = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const user_agent = req.headers['user-agent'];
  
  // Como não temos mais a função de geolocalização, vamos salvar a cidade como vazia
  const city = ''; 
  const state = '';

  try {
    const queryText = `
      INSERT INTO clicks (timestamp, ip_address, user_agent, referer, city, state, fbclid, fbp, client_id)
      VALUES (NOW(), $1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING id;
    `;
    const values = [ip_address, user_agent, referer, city, state, fbclid, fbp, client_id];
    
    const result = await db.query(queryText, values);
    
    const generatedId = result.rows[0].id;
    const formattedClickId = `lead${generatedId.toString().padStart(6, '0')}`;
    
    await db.query('UPDATE clicks SET click_id = $1 WHERE id = $2', [formattedClickId, generatedId]);

    console.log(`Clique salvo com sucesso! Client_id: [${client_id}], Click_id: [${formattedClickId}]`);
    
    res.status(200).json({ status: 'success', message: 'Click registrado', click_id: formattedClickId });

  } catch (error) {
    console.error('ERRO AO SALVAR NO BANCO DE DADOS:', error);
    res.status(500).json({ status: 'error', message: 'Erro interno do servidor ao salvar o clique.' });
  }
});

// Exporta o app para a Vercel
module.exports = app;
