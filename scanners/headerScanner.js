const axios = require('axios');

const SECURITY_HEADERS = [
  { name: 'Content-Security-Policy', severity: 'high', status: 'fail', description: 'Prevents XSS, clickjacking, and code injection attacks', recommendation: 'Add a strict CSP header' },
  { name: 'Strict-Transport-Security', severity: 'high', status: 'fail', description: 'Forces HTTPS connections', recommendation: 'Add HSTS with max-age=31536000; includeSubDomains; preload' },
  { name: 'X-Frame-Options', severity: 'medium', status: 'fail', description: 'Prevents clickjacking', recommendation: 'Add X-Frame-Options: DENY or SAMEORIGIN' },
  { name: 'X-Content-Type-Options', severity: 'medium', status: 'fail', description: 'Prevents MIME-type sniffing', recommendation: 'Add X-Content-Type-Options: nosniff' },
  { name: 'Referrer-Policy', severity: 'low', status: 'warn', description: 'Controls referrer information sharing', recommendation: 'Add Referrer-Policy: strict-origin-when-cross-origin' },
  { name: 'Permissions-Policy', severity: 'low', status: 'warn', description: 'Controls browser feature access', recommendation: 'Add Permissions-Policy with restricted directives' },
  { name: 'X-XSS-Protection', severity: 'info', status: 'info', description: 'Legacy XSS filter — deprecated in modern browsers', recommendation: 'Not required if CSP is configured; can add: 0' },
  { name: 'Cross-Origin-Opener-Policy', severity: 'low', status: 'warn', description: 'Isolates browsing context', recommendation: 'Add COOP: same-origin' },
  { name: 'Cross-Origin-Resource-Policy', severity: 'low', status: 'warn', description: 'Controls cross-origin resource loading', recommendation: 'Add CORP: same-origin' },
  { name: 'Cross-Origin-Embedder-Policy', severity: 'info', status: 'info', description: 'Prevents loading cross-origin resources without permission', recommendation: 'Add COEP: require-corp (only needed for SharedArrayBuffer)' },
  { name: 'X-Permitted-Cross-Domain-Policies', severity: 'info', status: 'info', description: 'Controls Flash/PDF cross-domain access — largely obsolete', recommendation: 'Optional: X-Permitted-Cross-Domain-Policies: none' },
  { name: 'X-Download-Options', severity: 'info', status: 'info', description: 'Prevents IE from opening downloads directly — IE-only', recommendation: 'Optional: X-Download-Options: noopen' },
  { name: 'X-DNS-Prefetch-Control', severity: 'info', status: 'info', description: 'Controls DNS prefetching — minor privacy consideration', recommendation: 'Optional: X-DNS-Prefetch-Control: off' },
  { name: 'Expect-CT', severity: 'info', status: 'info', description: 'Certificate Transparency — deprecated since June 2021', recommendation: 'No longer needed; browsers enforce CT by default' },
  { name: 'Feature-Policy', severity: 'info', status: 'info', description: 'Replaced by Permissions-Policy — deprecated', recommendation: 'Use Permissions-Policy instead' },
  { name: 'Cache-Control', severity: 'low', status: 'warn', description: 'Controls caching of sensitive data', recommendation: 'Add Cache-Control: no-store for sensitive pages' },
  { name: 'Pragma', severity: 'info', status: 'info', description: 'Legacy cache control for HTTP/1.0 — rarely needed', recommendation: 'Optional: Pragma: no-cache' },
  { name: 'X-Robots-Tag', severity: 'info', status: 'info', description: 'Controls search engine indexing — not a security header', recommendation: 'Use only if you need to restrict indexing' },
  { name: 'Access-Control-Allow-Origin', severity: 'info', status: 'info', description: 'CORS origin configuration — presence depends on API design', recommendation: 'Ensure CORS is not set to wildcard * with credentials' },
  { name: 'Access-Control-Allow-Credentials', severity: 'info', status: 'info', description: 'CORS credentials configuration', recommendation: 'Review if credentials are needed' },
];

const INFO_LEAK_HEADERS = [
  'server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version',
  'x-generator', 'x-drupal-cache', 'x-drupal-dynamic-cache',
  'x-varnish', 'x-cache', 'x-backend-server', 'x-served-by',
  'x-litespeed-cache', 'x-turbo-charged-by', 'via',
  'x-runtime', 'x-request-id', 'x-amz-request-id',
  'x-debug', 'x-debug-info', 'x-debug-token'
];

async function scan(targetUrl) {
  const results = { present: [], missing: [], info: [], tests: [] };
  try {
    const response = await axios.get(targetUrl, {
      timeout: 15000, maxRedirects: 5, validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
    });
    const headers = response.headers;

    for (const header of SECURITY_HEADERS) {
      const value = headers[header.name.toLowerCase()];
      if (value) {
        results.present.push({ name: header.name, value, severity: 'info', status: 'present', description: header.description });
        results.tests.push({ id: `header-present-${header.name}`, name: `${header.name} Present`, status: 'pass', severity: 'info' });
      } else {
        results.missing.push({ name: header.name, severity: header.severity, status: 'missing', description: header.description, recommendation: header.recommendation });
        results.tests.push({ id: `header-missing-${header.name}`, name: `${header.name} Missing`, status: header.status, severity: header.severity });
      }
    }

    const csp = headers['content-security-policy'];
    if (csp) {
      const cspChecks = [
        'default-src','script-src','style-src','img-src','font-src','connect-src',
        'frame-src','object-src','base-uri','form-action','frame-ancestors','upgrade-insecure-requests',
        'media-src','worker-src','manifest-src','prefetch-src','navigate-to'
      ];
      for (const dir of cspChecks) {
        results.tests.push({ id: `csp-${dir}`, name: `CSP ${dir} directive`, status: csp.includes(dir) ? 'pass' : 'warn', severity: csp.includes(dir) ? 'info' : 'medium' });
      }
      if (csp.includes("'unsafe-inline'")) results.tests.push({ id: 'csp-unsafe-inline', name: 'CSP allows unsafe-inline', status: 'fail', severity: 'high' });
      if (csp.includes("'unsafe-eval'")) results.tests.push({ id: 'csp-unsafe-eval', name: 'CSP allows unsafe-eval', status: 'fail', severity: 'high' });
      if (csp.includes('*')) results.tests.push({ id: 'csp-wildcard', name: 'CSP uses wildcard source', status: 'fail', severity: 'high' });
      if (!csp.includes('report-uri') && !csp.includes('report-to')) results.tests.push({ id: 'csp-reporting', name: 'CSP reporting not configured', status: 'warn', severity: 'low' });
    }

    const hsts = headers['strict-transport-security'];
    if (hsts) {
      results.tests.push({ id: 'hsts-subdomains', name: 'HSTS includeSubDomains', status: hsts.includes('includeSubDomains') ? 'pass' : 'warn', severity: 'medium' });
      results.tests.push({ id: 'hsts-preload', name: 'HSTS preload', status: hsts.includes('preload') ? 'pass' : 'warn', severity: 'low' });
      const maxAgeMatch = hsts.match(/max-age=(\d+)/);
      if (maxAgeMatch) {
        results.tests.push({ id: 'hsts-maxage', name: `HSTS max-age sufficient (≥1yr)`, status: parseInt(maxAgeMatch[1]) >= 31536000 ? 'pass' : 'warn', severity: 'medium' });
      }
    }

    for (const dh of INFO_LEAK_HEADERS) {
      if (headers[dh]) {
        results.info.push({ name: dh, value: headers[dh], severity: 'low', status: 'info-leak', description: `Exposes "${dh}: ${headers[dh]}"` });
        results.tests.push({ id: `leak-${dh}`, name: `Info leak: ${dh}`, status: 'fail', severity: 'low' });
      }
    }
  } catch (err) {
    results.error = `Failed to fetch headers: ${err.message}`;
  }
  return { scanner: 'Security Headers', icon: '🛡️', results, testCount: results.tests.length };
}

module.exports = { scan };
