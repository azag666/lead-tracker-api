// Importa a função 'neon' do driver serverless.
const { neon } = require('@neondatabase/serverless');

// A URL de conexão será pega diretamente das variáveis de ambiente da Vercel.
const sql = neon(process.env.DATABASE_URL);

// A única função que exportamos é a de executar uma query.
// Ela usa a função 'sql' importada do driver da Neon.
module.exports = {
  query: (text, params) => sql(text, params),
};
