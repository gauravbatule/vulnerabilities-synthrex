const axios = require('axios');

const API_PATHS = [
  // REST API common paths
  '/api', '/api/', '/api/v1', '/api/v2', '/api/v3',
  '/v1', '/v2', '/v3',
  '/rest', '/rest/api',
  // GraphQL
  '/graphql', '/graphiql', '/graphql/console',
  '/altair', '/playground',
  // Documentation
  '/swagger', '/swagger/', '/swagger-ui', '/swagger-ui/',
  '/swagger.json', '/swagger.yaml',
  '/api-docs', '/api-docs/',
  '/openapi.json', '/openapi.yaml', '/openapi/',
  '/redoc', '/docs', '/docs/',
  // Authentication / OAuth
  '/.well-known/openid-configuration',
  '/.well-known/oauth-authorization-server',
  '/.well-known/jwks.json',
  '/oauth/token', '/oauth/authorize', '/auth/login',
  '/token', '/authenticate',
  // Health / Monitoring
  '/health', '/healthz', '/healthcheck',
  '/status', '/ping', '/ready', '/readyz',
  '/metrics', '/prometheus',
  '/actuator', '/actuator/health', '/actuator/info', '/actuator/env', '/actuator/beans',
  // WordPress
  '/wp-json/', '/wp-json/wp/v2/users',
  // Common API endpoints
  '/users', '/api/users', '/api/user',
];

const SCANNER_TIMEOUT = 40000;

async function scan(targetUrl) {
  const results = { tests: [], endpoints: [] };
  const deadline = Date.now() + SCANNER_TIMEOUT;
  try {
    const u = new URL(targetUrl);
    const base = `${u.protocol}//${u.host}`;
    const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

    const batchSize = 8;
    for (let i = 0; i < API_PATHS.length; i += batchSize) {
      if (Date.now() > deadline) break;
      const batch = API_PATHS.slice(i, i + batchSize);
      const checks = await Promise.all(batch.map(async (path) => {
        try {
          const r = await axios.get(`${base}${path}`, {
            timeout: 4000, maxRedirects: 0, validateStatus: () => true,
            headers: { 'User-Agent': ua, 'Accept': 'application/json' }
          });
          const ct = r.headers['content-type'] || '';
          const isJson = ct.includes('json') || ct.includes('xml');
          const size = typeof r.data === 'string' ? r.data.length : JSON.stringify(r.data || '').length;
          return { path, status: r.status, isJson, size };
        } catch {
          return { path, status: 0 };
        }
      }));

      for (const c of checks) {
        if (c.status === 200 && c.size > 20) {
          const isHighRisk = /actuator\/env|actuator\/beans|wp-json\/wp\/v2\/users|jwks|openid-config|swagger\.json/.test(c.path);
          const isMedRisk = /graphql|swagger|api-docs|actuator|users/.test(c.path);
          const severity = isHighRisk ? 'high' : isMedRisk ? 'medium' : 'low';
          results.endpoints.push({ path: c.path, status: c.status, json: c.isJson });
          results.tests.push({ id: `api-${c.path.replace(/[^a-z0-9]/gi, '')}`, name: `API endpoint: ${c.path} (${c.status}${c.isJson ? ', JSON' : ''})`, status: 'fail', severity });
        } else if (c.status === 401 || c.status === 403) {
          results.tests.push({ id: `api-auth-${c.path.replace(/[^a-z0-9]/gi, '')}`, name: `Auth-protected: ${c.path} (${c.status})`, status: 'info', severity: 'info' });
        } else {
          results.tests.push({ id: `api-${c.path.replace(/[^a-z0-9]/gi, '')}`, name: `Not found: ${c.path}`, status: 'pass', severity: 'info' });
        }
      }
    }
  } catch (err) {
    results.error = err.message;
  }
  return { scanner: 'API Endpoint Discovery', icon: '🔌', results, testCount: results.tests.length };
}

module.exports = { scan };
