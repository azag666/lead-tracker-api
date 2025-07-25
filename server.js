require('dotenv').config(); // Carrega variáveis de ambiente do arquivo .env
const express = require('express');
const cors = require('cors'); // Para lidar com Cross-Origin Resource Sharing
const { v4: uuidv4 } = require('uuid'); // Para gerar CLICK_ID único (não usado para o click_id final, mas útil para outros fins se necessário)
const axios = require('axios'); // Para fazer requisições HTTP (ex: para ip-api.com)
const db = require('./database'); // Importa a conexão com o banco de dados

const app = express();
const PORT = process.env.PORT || 3000; // Porta do servidor, Railway.app fornecerá a PORT

// Middleware para permitir requisições de qualquer origem (CORS)
// Isso é CRÍTICO para sua pressel poder se comunicar com a API
app.use(cors());
app.use(express.json()); // Middleware para parsear o corpo das requisições como JSON

// Constantes para a API de geolocalização
const IP_API_BASE_URL = 'http://ip-api.com/json/';
const IP_API_KEY = process.env.IP_API_KEY || ''; // Sua chave da API de IP (opcional)

// Função auxiliar para obter a cidade a partir de um IP
async function getCityFromIp(ip) {
  if (!ip) return '';
  try {
    const response = await axios.get(`${IP_API_BASE_URL}${ip}?fields=city${IP_API_KEY ? '&key=' + IP_API_KEY : ''}`);
    if (response.data && response.data.status === 'success' && response.data.city) {
      return response.data.city;
    }
    console.warn('Erro ao obter cidade do IP:', ip, response.data);
    return '';
  } catch (error) {
    console.error('Exceção ao obter cidade do IP:', ip, error.message);
    return '';
  }
}

// Rota para registrar um novo clique (chamada pela pressel)
app.post('/api/registerClick', async (req, res) => {
  console.log('Requisição POST /api/registerClick recebida.');
  const { referer } = req.body; // Dados enviados pela pressel
  const ip_address = req.headers['x-forwarded-for'] || req.socket.remoteAddress; // Captura o IP
  const user_agent = req.headers['user-agent'];
  const timestamp = new Date();

  try {
    const city = await getCityFromIp(ip_address); // Consulta a cidade

    // Insere os dados e retorna o ID auto-gerado pelo banco de dados
    const query = `
      INSERT INTO clicks (timestamp, ip_address, user_agent, referer, city)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id; -- Retorna o ID auto-gerado
    `;
    const values = [timestamp, ip_address, user_agent, referer, city];

    const result = await db.query(query, values);
    const generatedId = result.rows[0].id; // O ID auto-gerado pelo banco

    // Formata o ID para ter no máximo 6 dígitos com zeros à esquerda
    // Ex: 1 -> "000001", 123 -> "000123"
    const formattedClickId = generatedId.toString().padStart(6, '0');

    // Agora, atualiza a linha recém-criada com o click_id formatado
    const updateQuery = `
      UPDATE clicks
      SET click_id = $1
      WHERE id = $2;
    `;
    await db.query(updateQuery, [formattedClickId, generatedId]);

    console.log('Clique registrado no banco de dados com ID:', generatedId, 'e CLICK_ID formatado:', formattedClickId);

    // Retorna o CLICK_ID formatado para a pressel
    res.json({ status: 'success', message: 'Click registered', click_id: formattedClickId });

  } catch (error) {
    console.error('Erro ao registrar clique:', error);
    res.status(500).json({ status: 'error', message: 'Internal server error', details: error.message });
  }
});

// Rota para consultar a cidade de um CLICK_ID (chamada pelo ManyChat)
app.get('/api/getCity', async (req, res) => {
  console.log('Requisição GET /api/getCity recebida.');
  const { click_id } = req.query; // CLICK_ID virá como parâmetro de query

  if (!click_id) {
    return res.status(400).json({ status: 'error', message: 'click_id is required' });
  }

  try {
    // Busca pelo CLICK_ID formatado
    const query = 'SELECT city FROM clicks WHERE click_id = $1;';
    const result = await db.query(query, [click_id]);

    if (result.rows.length > 0) {
      res.json({ status: 'success', city: result.rows[0].city || 'Não encontrada' });
    } else {
      res.status(404).json({ status: 'error', message: 'Click ID not found' });
    }
  } catch (error) {
    console.error('Erro ao consultar cidade:', error);
    res.status(500).json({ status: 'error', message: 'Internal server error', details: error.message });
  }
});

// Inicializa a conexão com o banco de dados e cria a tabela, depois inicia o servidor
async function startServer() {
  await db.testDbConnection(); // Testa a conexão
  await db.createClicksTable(); // Cria a tabela se não existir
  app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
    console.log(`API_URL para registerClick: http://localhost:${PORT}/api/registerClick`);
    console.log(`API_URL para getCity: http://localhost:${PORT}/api/getCity?click_id=SEU_CLICK_ID`);
  });
}

startServer();
