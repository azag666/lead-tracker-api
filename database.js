const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// A única função que exportamos é a de executar uma query.
// A conexão só será usada quando esta função for chamada.
module.exports = {
  query: (text, params) => pool.query(text, params),
};
