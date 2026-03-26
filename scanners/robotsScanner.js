const axios = require('axios');

async function scan(targetUrl) {
  const results = { tests: [], findings: [] };
  try {
    const u = new URL(targetUrl);
    const base = `${u.protocol}//${u.host}`;
    const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

    const safeGet = (url) =>
      axios.get(url, { timeout: 5000, maxRedirects: 2, validateStatus: () => true, headers: { 'User-Agent': ua } }).catch(() => null);

    // 1. robots.txt analysis
    const robotsResp = await safeGet(`${base}/robots.txt`);
    if (robotsResp && robotsResp.status === 200 && typeof robotsResp.data === 'string' && robotsResp.data.length > 10) {
      results.tests.push({ id: 'robots-present', name: 'robots.txt found', status: 'pass', severity: 'info' });
      const body = robotsResp.data.toLowerCase();
      const lines = body.split('\n');

      // Check for sensitive paths
      const sensitivePatterns = [
        'admin', 'login', 'dashboard', 'cpanel', 'phpmyadmin', 'backup', 'config',
        'wp-admin', 'wp-login', '.env', '.git', 'database', 'dump', 'secret',
        'private', 'internal', 'staging', 'test', 'debug', 'api', 'console',
        'panel', 'manage', 'control', 'server-status', 'server-info',
      ];

      const disallowed = lines.filter(l => l.trim().startsWith('disallow:'));
      for (const line of disallowed) {
        const path = line.split(':').slice(1).join(':').trim();
        if (!path || path === '/') continue;
        const isSensitive = sensitivePatterns.some(p => path.toLowerCase().includes(p));
        if (isSensitive) {
          results.tests.push({ id: `robots-sensitive-${path.substring(0, 20)}`, name: `Sensitive path in robots.txt: ${path}`, status: 'warn', severity: 'medium' });
          results.findings.push({ type: 'sensitive_disallow', path });
        }
      }

      // Check for wildcard user-agent
      if (body.includes('user-agent: *')) {
        results.tests.push({ id: 'robots-wildcard-ua', name: 'robots.txt uses wildcard User-Agent', status: 'pass', severity: 'info' });
      }

      // Check if crawl-delay is set
      if (body.includes('crawl-delay')) {
        results.tests.push({ id: 'robots-crawl-delay', name: 'Crawl-Delay configured', status: 'pass', severity: 'info' });
      }

      // Count disallow rules
      results.tests.push({ id: 'robots-disallow-count', name: `${disallowed.length} Disallow rules found`, status: 'pass', severity: 'info' });
    } else {
      results.tests.push({ id: 'robots-missing', name: 'robots.txt not found', status: 'warn', severity: 'low' });
    }

    // 2. sitemap.xml analysis
    const sitemapPaths = ['/sitemap.xml', '/sitemap_index.xml', '/sitemap.xml.gz'];
    let sitemapFound = false;
    for (const sp of sitemapPaths) {
      const r = await safeGet(`${base}${sp}`);
      if (r && r.status === 200 && typeof r.data === 'string' && (r.data.includes('<urlset') || r.data.includes('<sitemapindex'))) {
        sitemapFound = true;
        results.tests.push({ id: `sitemap-found-${sp}`, name: `Sitemap found at ${sp}`, status: 'pass', severity: 'info' });
        break;
      }
    }
    if (!sitemapFound) {
      results.tests.push({ id: 'sitemap-missing', name: 'No sitemap.xml found', status: 'warn', severity: 'low' });
    }

  } catch (err) {
    results.error = err.message;
  }
  return { scanner: 'Robots & Sitemap', icon: '🤖', results, testCount: results.tests.length };
}

module.exports = { scan };
