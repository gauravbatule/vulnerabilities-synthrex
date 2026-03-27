const axios = require('axios');

// Rate Limiting Scanner
// Tests if critical endpoints have brute-force protection
// FP prevention: Only tests endpoints that actually exist AND contain login/auth forms
// FN prevention: Tests multiple endpoints and both GET and POST methods

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
  { path: '/auth/login', name: 'Auth login', critical: true },
];

// Patterns that indicate a page is actually a login/auth page
const LOGIN_INDICATORS = [
  /type=["']password["']/i,
  /name=["']password["']/i,
  /autocomplete=["']current-password["']/i,
  /<input[^>]*login/i,
  /<form[^>]*login/i,
  /<form[^>]*signin/i,
  /<form[^>]*auth/i,
  /sign.?in/i,
  /log.?in/i,
];

const RAPID_REQUESTS = 15;
const SCANNER_TIMEOUT = 50000;

async function scan(targetUrl) {
  const results = { findings: [], tests: [] };
  const deadline = Date.now() + SCANNER_TIMEOUT;
  const baseUrl = targetUrl.replace(/\/$/, '');
  const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

  try {
    // Test 1: Check for rate limit headers on normal request
    const normalReq = await axios.get(targetUrl, {
      timeout: 8000, maxRedirects: 5, validateStatus: () => true,
      headers: { 'User-Agent': ua }
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
          status: 'warn', severity: 'low'  // lowered from medium — many valid sites don't expose these on homepage
        });
      }
    }

    // Test 2: Find and test actual login endpoints
    let testedEndpoints = 0;
    for (const endpoint of ENDPOINTS_TO_TEST) {
      if (Date.now() > deadline) break;

      const url = `${baseUrl}${endpoint.path}`;

      try {
        const probe = await axios.get(url, {
          timeout: 5000, maxRedirects: 3, validateStatus: () => true,
          headers: { 'User-Agent': ua }
        });

        // Skip if endpoint doesn't exist
        if (probe.status === 404 || probe.status === 405) continue;

        // FP prevention: Verify this is actually a login/auth page, not a random path
        // that happens to return 200. Skip 403 (might be a valid protected endpoint)
        const body = typeof probe.data === 'string' ? probe.data : '';
        const isLoginPage = probe.status === 403 || LOGIN_INDICATORS.some(pattern => pattern.test(body));

        if (!isLoginPage && endpoint.critical) {
          // Page exists but doesn't look like a login page — skip to avoid FP
          continue;
        }

        testedEndpoints++;

        // Send rapid requests from same "IP" (no X-Forwarded-For spoofing — that defeats the test)
        const requests = [];
        for (let i = 0; i < RAPID_REQUESTS; i++) {
          requests.push(
            axios.get(url, {
              timeout: 5000, maxRedirects: 0, validateStatus: () => true,
              headers: { 'User-Agent': ua }
            }).catch(() => ({ status: 0, headers: {} }))
          );
        }

        const responses = await Promise.all(requests);

        let blocked = false;
        let blockedAt = 0;
        let rateLimitHeaderSeen = false;

        for (let i = 0; i < responses.length; i++) {
          const r = responses[i];
          if (r.status === 429 || r.status === 503) {
            blocked = true;
            if (!blockedAt) blockedAt = i + 1;
          }
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
            name: `Rate limit headers present: ${endpoint.name} (not enforced in ${RAPID_REQUESTS} reqs)`,
            status: 'warn', severity: 'low'
          });
        } else {
          results.tests.push({
            id: `rate-${endpoint.path.replace(/\//g, '-')}`,
            name: `No rate limiting: ${endpoint.name} (${RAPID_REQUESTS} requests allowed)`,
            status: 'fail', severity: 'medium'
          });
        }
      } catch { /* endpoint unreachable — skip */ }
    }

    if (testedEndpoints === 0) {
      results.tests.push({
        id: 'rate-no-login',
        name: 'No login/auth endpoints found to test',
        status: 'pass', severity: 'info'
      });
    }

    // Test 3: POST brute-force test — only if a login endpoint was confirmed
    if (testedEndpoints > 0) {
      try {
        // Find first reachable login endpoint
        const loginPaths = ['/login', '/wp-login.php', '/signin', '/auth/login', '/api/login'];
        for (const loginPath of loginPaths) {
          if (Date.now() > deadline) break;
          const loginUrl = `${baseUrl}${loginPath}`;
          const probe = await axios.get(loginUrl, {
            timeout: 5000, maxRedirects: 3, validateStatus: () => true,
            headers: { 'User-Agent': ua }
          }).catch(() => null);

          if (!probe || probe.status === 404) continue;

          const body = typeof probe.data === 'string' ? probe.data : '';
          if (!LOGIN_INDICATORS.some(p => p.test(body)) && probe.status !== 403) continue;

          // Found login endpoint — POST rapid requests
          const postRequests = [];
          for (let i = 0; i < 10; i++) {
            postRequests.push(
              axios.post(loginUrl, 'username=test&password=wrongpassword', {
                timeout: 5000, maxRedirects: 0, validateStatus: () => true,
                headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': ua }
              }).catch(() => ({ status: 0, headers: {} }))
            );
          }
          const postResponses = await Promise.all(postRequests);
          const anyBlocked = postResponses.some(r => r.status === 429 || r.status === 503);
          const hasRetryAfter = postResponses.some(r => r.headers && r.headers['retry-after']);

          if (anyBlocked || hasRetryAfter) {
            results.tests.push({ id: 'rate-post-login', name: `POST brute-force protection active at ${loginPath}`, status: 'pass', severity: 'info' });
          } else {
            const validResponses = postResponses.filter(r => r.status >= 200 && r.status < 500);
            if (validResponses.length >= 8) {
              results.tests.push({ id: 'rate-post-login', name: `POST brute-force not rate limited at ${loginPath}`, status: 'fail', severity: 'medium' });
            }
          }
          break; // Only test first found login endpoint
        }
      } catch { /* skip */ }
    }

  } catch (err) {
    results.error = `Rate limit scan failed: ${err.message}`;
  }
  return { scanner: 'Rate Limiting', icon: '⏱️', results, testCount: results.tests.length };
}

module.exports = { scan };
