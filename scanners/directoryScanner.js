const axios = require('axios');

const PATHS = [
  // Admin panels
  '/admin', '/admin/', '/administrator', '/login', '/wp-admin', '/wp-login.php',
  '/cpanel', '/phpmyadmin', '/adminer', '/panel', '/dashboard', '/manage',
  '/console', '/webmail', '/controlpanel',
  // Version control / config leaks
  '/.git/HEAD', '/.git/config', '/.svn/entries', '/.hg/',
  '/.env', '/.env.local', '/.env.production', '/.env.backup',
  '/config.php', '/config.yml', '/config.json', '/wp-config.php',
  '/web.config', '/application.yml', '/settings.py',
  // Backups & dumps
  '/backup', '/backup.zip', '/backup.sql', '/database.sql', '/dump.sql',
  '/db.sql', '/site.zip', '/archive.zip', '/backup.tar.gz',
  // Debug / dev
  '/debug', '/info.php', '/phpinfo.php', '/test.php', '/debug.log',
  '/error.log', '/access.log', '/server-status', '/server-info',
  '/_profiler', '/elmah.axd',
  // API docs
  '/swagger', '/swagger-ui', '/swagger.json', '/swagger.yaml',
  '/api-docs', '/graphql', '/graphiql',
  '/openapi.json', '/openapi.yaml', '/.well-known/openid-configuration',
  // Common frameworks
  '/actuator', '/actuator/health', '/actuator/env',
  '/health', '/healthcheck', '/status', '/metrics',
  // Install / setup
  '/install', '/setup', '/installer', '/upgrade',
  // Files
  '/crossdomain.xml', '/clientaccesspolicy.xml', '/.htaccess', '/.htpasswd',
  '/composer.json', '/package.json', '/Gruntfile.js', '/Makefile',
  '/Dockerfile', '/docker-compose.yml', '/.dockerenv',
];

const SCANNER_TIMEOUT = 45000;

async function scan(targetUrl) {
  const results = { found: [], tests: [] };
  const deadline = Date.now() + SCANNER_TIMEOUT;
  try {
    const u = new URL(targetUrl);
    const base = `${u.protocol}//${u.host}`;
    const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

    const batchSize = 10;
    for (let i = 0; i < PATHS.length; i += batchSize) {
      if (Date.now() > deadline) break;
      const batch = PATHS.slice(i, i + batchSize);
      const checks = await Promise.all(batch.map(async (path) => {
        try {
          const r = await axios.get(`${base}${path}`, {
            timeout: 4000, maxRedirects: 0, validateStatus: () => true,
            headers: { 'User-Agent': ua }
          });
          return { path, status: r.status, size: typeof r.data === 'string' ? r.data.length : 0 };
        } catch {
          return { path, status: 0 };
        }
      }));

      for (const c of checks) {
        if (c.status === 200 && c.size > 50) {
          const isHighRisk = /\.(env|sql|log|php|yml|json|config)/.test(c.path) || /git|svn|backup|dump|secret|htpasswd/.test(c.path);
          const isMedRisk = /admin|login|panel|dashboard|console|swagger|graphql|actuator|phpinfo|profiler/.test(c.path);
          const severity = isHighRisk ? 'high' : isMedRisk ? 'medium' : 'low';
          results.found.push({ path: c.path, status: c.status, severity });
          results.tests.push({ id: `dir-${c.path.replace(/[^a-z0-9]/gi, '')}`, name: `Found: ${c.path} (${c.status})`, status: 'fail', severity });
        } else if (c.status === 403) {
          results.tests.push({ id: `dir-403-${c.path.replace(/[^a-z0-9]/gi, '')}`, name: `Forbidden: ${c.path} (403)`, status: 'warn', severity: 'info' });
        } else {
          results.tests.push({ id: `dir-${c.path.replace(/[^a-z0-9]/gi, '')}`, name: `Not found: ${c.path}`, status: 'pass', severity: 'info' });
        }
      }
    }
  } catch (err) {
    results.error = err.message;
  }
  return { scanner: 'Directory Discovery', icon: '📁', results, testCount: results.tests.length };
}

module.exports = { scan };
