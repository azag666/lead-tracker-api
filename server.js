const express = require('express');
const cors = require('cors');
const { neon } = require('@neondatabase/serverless');

const app = express();
app.use(cors());
app.use(express.json());

app.post('/api/registerClick', async (req, res) => {
  try {
    const { referer, fbclid, fbp, client_id } = req.body;
    const ip_address = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const user_agent = req.headers['user-agent'];

    // --- MUDANÇA PRINCIPAL: CONSTRUINDO A URL DE CONEXÃO MANUALMENTE ---
    // Isso usa as variáveis de ambiente individuais para evitar qualquer problema com a string DATABASE_URL.
    const connectionString = `postgres://${process.env.PGUSER}:${process.env.PGPASSWORD}@${process.env.PGHOST}/${process.env.PGDATABASE}?sslmode=require`;
    const sql = neon(connectionString);
    // -------------------------------------------------------------------

    const insertQuery = `
      INSERT INTO clicks (timestamp, ip_address, user_agent, referer, fbclid, fbp, client_id)
      VALUES (NOW(), $1, $2, $3, $4, $5, $6)
      RETURNING id;
    `;
    const insertResult = await sql(insertQuery, [ip_address, user_agent, referer, fbclid, fbp, client_id]);
    const generatedId = insertResult[0].id;

    const formattedClickId = `lead${generatedId.toString().padStart(6, '0')}`;
    await sql('UPDATE clicks SET click_id = $1 WHERE id = $2', [formattedClickId, generatedId]);

    console.log(`Clique salvo! Client_id: [${client_id}], Click_id: [${formattedClickId}]`);
    
    res.status(200).json({ status: 'success', message: 'Click registrado', click_id: formattedClickId });

  } catch (error) {
    console.error('ERRO FATAL NA ROTA /api/registerClick:', error);
    res.status(500).json({ status: 'error', message: 'Erro interno do servidor.' });
  }
});

module.exports = app;
