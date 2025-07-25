const express = require('express');
const cors = require('cors');
const { neon } = require('@neondatabase/serverless');

const app = express();
app.use(cors());
app.use(express.json());

// Rota para o Health Check da Vercel
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// A ÚNICA ROTA DA NOSSA API
app.post('/api/registerClick', async (req, res) => {
  try {
    const { referer, fbclid, fbp, client_id } = req.body;
    const ip_address = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const user_agent = req.headers['user-agent'];

    // Instancia a conexão com o banco de dados AQUI, dentro da rota.
    const sql = neon(process.env.DATABASE_URL);

    // Salva o clique inicial e obtém o ID
    const insertQuery = `
      INSERT INTO clicks (timestamp, ip_address, user_agent, referer, fbclid, fbp, client_id)
      VALUES (NOW(), $1, $2, $3, $4, $5, $6)
      RETURNING id;
    `;
    const insertResult = await sql(insertQuery, [ip_address, user_agent, referer, fbclid, fbp, client_id]);
    const generatedId = insertResult[0].id;

    // Cria o click_id formatado e atualiza a linha
    const formattedClickId = `lead${generatedId.toString().padStart(6, '0')}`;
    await sql('UPDATE clicks SET click_id = $1 WHERE id = $2', [formattedClickId, generatedId]);

    console.log(`Clique salvo! Client_id: [${client_id}], Click_id: [${formattedClickId}]`);
    
    // Retorna sucesso com o click_id para a pressel
    res.status(200).json({ status: 'success', message: 'Click registrado', click_id: formattedClickId });

  } catch (error) {
    console.error('ERRO FATAL NA ROTA /api/registerClick:', error);
    res.status(500).json({ status: 'error', message: 'Erro interno do servidor.' });
  }
});

// Exporta o app para a Vercel
module.exports = app;
