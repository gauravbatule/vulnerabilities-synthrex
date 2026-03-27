const axios = require('axios');

// Rate Limiting Scanner
// Tests if critical endpoints have brute-force protection
// FP prevention: Only flags if ALL rapid requests succeed (200) — any 429/WAF block = pass
// FN prevention: Tests multiple endpoints and checks multiple rate-limit indicators

const RATE_LIMIT_HEADERS = [
  'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset',
  'x-rate-limit-limit', 'x-rate-limit-remaining', 'x-rate-limit-reset',
  'ratelimit-limit', 'ratelimit-remaining', 'ratelimit-reset',
  'retry-after', 'x-retry-after',
];

const ENDPOINTS_TO_TEST = [
  { path: '/login', name: 'Login page', critical: true },
  { path: '/wp-login.php', name: 'WordPress login', critical: true },
  { path: '/admin/login', name: 'Admin login', critical: true },
  { path: '/api/login', name: 'API login', critical: true },
  { path: '/signin', name: 'Sign-in page', critical: true },
  { path: '/', name: 'Homepage', critical: false },
];

const RAPID_REQUESTS = 15;
const SCANNER_TIMEOUT = 50000;

async function scan(targetUrl) {
  const results = { findings: [], tests: [] };
  const deadline = Date.now() + SCANNER_TIMEOUT;
  const baseUrl = targetUrl.replace(/\/$/, '');

  try {
    // Test 1: Check for rate limit headers on normal request
    const normalReq = await axios.get(targetUrl, {
      timeout: 8000, maxRedirects: 5, validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
    }).catch(() => null);

    if (normalReq) {
      const foundHeaders = [];
      for (const h of RATE_LIMIT_HEADERS) {
        if (normalReq.headers[h]) foundHeaders.push(h);
      }
      if (foundHeaders.length > 0) {
        results.tests.push({
          id: 'rate-headers-present',
          name: `Rate limit headers found: ${foundHeaders.join(', ')}`,
          status: 'pass', severity: 'info'
        });
      } else {
        results.tests.push({
          id: 'rate-headers-missing',
          name: 'No rate limit headers on main page',
          status: 'warn', severity: 'medium'
        });
      }
    }

    // Test 2: Rapid-fire requests to detect rate limiting
    for (const endpoint of ENDPOINTS_TO_TEST) {
      if (Date.now() > deadline) break;

      const url = `${baseUrl}${endpoint.path}`;

      // First check if endpoint exists
      try {
        const probe = await axios.get(url, {
          timeout: 5000, maxRedirects: 3, validateStatus: () => true,
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
        });

        // Skip if endpoint doesn't exist (404/405)
        if (probe.status === 404 || probe.status === 405 || probe.status === 403) {
          continue;
        }

        // Send rapid requests
        let blocked = false;
        let blockedAt = 0;
        let rateLimitHeaderSeen = false;

        const requests = [];
        for (let i = 0; i < RAPID_REQUESTS; i++) {
          requests.push(
            axios.get(url, {
              timeout: 5000, maxRedirects: 0, validateStatus: () => true,
              headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'X-Forwarded-For': `192.168.1.${i + 1}`,
              }
            }).catch(() => ({ status: 0, headers: {} }))
          );
        }

        const responses = await Promise.all(requests);

        for (let i = 0; i < responses.length; i++) {
          const r = responses[i];
          if (r.status === 429 || r.status === 503) {
            blocked = true;
            if (!blockedAt) blockedAt = i + 1;
          }
          // Check for rate limit headers in responses
          for (const h of RATE_LIMIT_HEADERS) {
            if (r.headers && r.headers[h]) rateLimitHeaderSeen = true;
          }
        }

        if (blocked) {
          results.tests.push({
            id: `rate-${endpoint.path.replace(/\//g, '-')}`,
            name: `Rate limiting active: ${endpoint.name} (blocked at request #${blockedAt})`,
            status: 'pass', severity: 'info'
          });
        } else if (rateLimitHeaderSeen) {
          results.tests.push({
            id: `rate-${endpoint.path.replace(/\//g, '-')}`,
            name: `Rate limit headers present: ${endpoint.name} (not enforced)`,
            status: 'warn', severity: 'low'
          });
        } else if (endpoint.critical) {
          results.tests.push({
            id: `rate-${endpoint.path.replace(/\//g, '-')}`,
            name: `No rate limiting: ${endpoint.name} (${RAPID_REQUESTS} requests allowed)`,
            status: 'fail', severity: 'medium'
          });
        } else {
          results.tests.push({
            id: `rate-${endpoint.path.replace(/\//g, '-')}`,
            name: `No rate limiting: ${endpoint.name}`,
            status: 'warn', severity: 'low'
          });
        }
      } catch { /* endpoint unreachable — skip */ }
    }

    // Test 3: Check for Retry-After on rapid POST (login brute-force simulation)
    try {
      const loginUrl = `${baseUrl}/login`;
      const postRequests = [];
      for (let i = 0; i < 10; i++) {
        postRequests.push(
          axios.post(loginUrl, 'username=test&password=test', {
            timeout: 5000, maxRedirects: 0, validateStatus: () => true,
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
          }).catch(() => ({ status: 0, headers: {} }))
        );
      }
      const postResponses = await Promise.all(postRequests);
      const anyBlocked = postResponses.some(r => r.status === 429 || r.status === 503);
      const hasRetryAfter = postResponses.some(r => r.headers && r.headers['retry-after']);

      if (anyBlocked || hasRetryAfter) {
        results.tests.push({ id: 'rate-post-login', name: 'POST login rate limiting active', status: 'pass', severity: 'info' });
      } else if (postResponses.some(r => r.status >= 200 && r.status < 500 && r.status !== 404)) {
        results.tests.push({ id: 'rate-post-login', name: 'POST login not rate limited', status: 'warn', severity: 'medium' });
      }
    } catch { /* skip */ }

  } catch (err) {
    results.error = `Rate limit scan failed: ${err.message}`;
  }
  return { scanner: 'Rate Limiting', icon: '⏱️', results, testCount: results.tests.length };
}

module.exports = { scan };
