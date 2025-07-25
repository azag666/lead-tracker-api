const { Pool } = require('pg');

// Configuração da conexão com o banco de dados PostgreSQL
// A URL de conexão é fornecida pelo Railway.app na variável de ambiente DATABASE_URL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Necessário para conexões SSL com o Railway.app
  }
});

// Função para testar a conexão com o banco de dados
async function testDbConnection() {
  try {
    await pool.query('SELECT NOW()');
    console.log('Conexão com o banco de dados PostgreSQL estabelecida com sucesso!');
  } catch (err) {
    console.error('Erro ao conectar ao banco de dados PostgreSQL:', err);
    process.exit(1); // Encerra o processo se a conexão falhar
  }
}

// Função para criar a tabela 'clicks' se ela não existir
async function createClicksTable() {
  const query = `
    CREATE TABLE IF NOT EXISTS clicks (
      id SERIAL PRIMARY KEY,
      click_id VARCHAR(255), -- Seu ID de clique, agora pode ter o prefixo "/start "
      timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
      ip_address VARCHAR(45),
      user_agent TEXT,
      referer TEXT,
      city VARCHAR(255),
      state VARCHAR(255), -- Coluna para o estado
      fbclid VARCHAR(255), -- Coluna para fbclid
      fbp VARCHAR(255),    -- Coluna para fbp
      fbc VARCHAR(255),    -- Coluna para fbc
      is_converted BOOLEAN DEFAULT FALSE, -- Indica se o lead converteu (pagou)
      conversion_timestamp TIMESTAMP WITH TIME ZONE, -- Data/hora da conversão
      conversion_value DECIMAL(10, 2), -- Valor da conversão
      pix_id VARCHAR(255), -- ID do PIX
      pix_value DECIMAL(10, 2), -- Valor do PIX
      event_id VARCHAR(255) UNIQUE, -- ID único do evento para deduplicação na Meta API
      client_id VARCHAR(255) -- ID do cliente SaaS associado ao clique
    );
  `;
  try {
    await pool.query(query);
    console.log('Tabela "clicks" verificada/criada com sucesso!');
  } catch (err) {
    console.error('Erro ao criar/verificar tabela "clicks":', err);
    process.exit(1); // Encerra o processo se a criação da tabela falhar
  }
}

// NOVA FUNÇÃO: Para criar a tabela 'saas_clients' se ela não existir
async function createSaasClientsTable() {
  const query = `
    CREATE TABLE IF NOT EXISTS saas_clients (
      client_id VARCHAR(255) PRIMARY KEY,
      client_name VARCHAR(255) NOT NULL,
      telegram_bot_username VARCHAR(255) NOT NULL,
      pushinpay_token TEXT NOT NULL,
      meta_conversion_api_token TEXT,
      meta_pixel_id VARCHAR(255)
    );
  `;
  try {
    await pool.query(query);
    console.log('Tabela "saas_clients" verificada/criada com sucesso!');
  } catch (err) {
    console.error('Erro ao criar/verificar tabela "saas_clients":', err);
    process.exit(1); // Encerra o processo se a criação da tabela falhar
  }
}

// Função para executar queries no banco de dados
async function query(text, params) {
  const res = await pool.query(text, params);
  return res;
}

module.exports = {
  testDbConnection,
  createClicksTable,
  createSaasClientsTable, // EXPORTADO AGORA
  query
};
