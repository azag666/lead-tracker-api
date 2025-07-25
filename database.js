const { Pool } = require('pg');

// Configuração simplificada para Vercel/Neon
// A própria connectionString já contém a diretiva de SSL (`?sslmode=require`)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function testDbConnection() {
  try {
    await pool.query('SELECT NOW()');
    console.log('Conexão com o banco de dados Vercel/Neon estabelecida com sucesso!');
  } catch (err) {
    console.error('Erro ao conectar ao banco de dados Vercel/Neon:', err);
    process.exit(1);
  }
}

// O restante do arquivo continua igual...

async function createClicksTable() {
  const query = `
    CREATE TABLE IF NOT EXISTS clicks (
      id SERIAL PRIMARY KEY,
      click_id VARCHAR(255),
      timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
      ip_address VARCHAR(45),
      user_agent TEXT,
      referer TEXT,
      city VARCHAR(255),
      state VARCHAR(255),
      fbclid VARCHAR(255),
      fbp VARCHAR(255),
      fbc VARCHAR(255),
      is_converted BOOLEAN DEFAULT FALSE,
      conversion_timestamp TIMESTAMP WITH TIME ZONE,
      conversion_value DECIMAL(10, 2),
      pix_id VARCHAR(255),
      pix_value DECIMAL(10, 2),
      event_id VARCHAR(255) UNIQUE,
      client_id VARCHAR(255)
    );
  `;
  try {
    await pool.query(query);
    console.log('Tabela "clicks" verificada/criada com sucesso!');
  } catch (err) {
    console.error('Erro ao criar/verificar tabela "clicks":', err);
    process.exit(1);
  }
}

async function createSaasClientsTable() {
  const query = `
    CREATE TABLE IF NOT EXISTS saas_clients (
      client_id VARCHAR(255) PRIMARY KEY,
      client_name VARCHAR(255) NOT NULL,
      telegram_bot_username VARCHAR(255) NOT NULL,
      pushinpay_token TEXT,
      meta_conversion_api_token TEXT,
      meta_pixel_id VARCHAR(255)
    );
  `;
  try {
    await pool.query(query);
    console.log('Tabela "saas_clients" verificada/criada com sucesso!');
  } catch (err) {
    console.error('Erro ao criar/verificar tabela "saas_clients":', err);
    process.exit(1);
  }
}

async function query(text, params) {
  const res = await pool.query(text, params);
  return res;
}

module.exports = {
  testDbConnection,
  createClicksTable,
  createSaasClientsTable,
  query
};
