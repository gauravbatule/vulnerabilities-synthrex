const axios = require('axios');

// JWT Security Scanner
// Extracts JWTs from responses and analyzes them for weaknesses
// FP prevention: Only analyzes strings matching JWT regex that decode to valid JSON
// FN prevention: Searches headers, cookies, HTML body, inline scripts, meta tags

// Regex to find JWT tokens (3 base64url segments separated by dots)
const JWT_REGEX = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{0,}/g;

function base64UrlDecode(str) {
  try {
    const padded = str.replace(/-/g, '+').replace(/_/g, '/');
    const decoded = Buffer.from(padded, 'base64').toString('utf-8');
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

function analyzeJwt(token) {
  const parts = token.split('.');
  if (parts.length < 2) return null;

  const header = base64UrlDecode(parts[0]);
  const payload = base64UrlDecode(parts[1]);

  if (!header || !payload) return null;
  if (!header.alg && !header.typ) return null; // Not a valid JWT header

  return { header, payload, raw: token };
}

async function scan(targetUrl) {
  const results = { findings: [], tests: [] };

  try {
    // Fetch the page
    const response = await axios.get(targetUrl, {
      timeout: 10000, maxRedirects: 5, validateStatus: () => true,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      }
    });

    const headers = response.headers;
    const body = typeof response.data === 'string' ? response.data : '';
    const allTokens = new Set();
    const sources = [];

    // Source 1: Response headers
    for (const [key, val] of Object.entries(headers)) {
      const strVal = String(val);
      const matches = strVal.match(JWT_REGEX);
      if (matches) {
        matches.forEach(m => { allTokens.add(m); sources.push({ token: m, source: `header:${key}` }); });
      }
    }

    // Source 2: Cookies
    const cookies = headers['set-cookie'];
    if (cookies) {
      const cookieStr = Array.isArray(cookies) ? cookies.join('; ') : String(cookies);
      const matches = cookieStr.match(JWT_REGEX);
      if (matches) {
        matches.forEach(m => { allTokens.add(m); sources.push({ token: m, source: 'cookie' }); });
      }
    }

    // Source 3: HTML body & scripts
    const bodyMatches = body.match(JWT_REGEX);
    if (bodyMatches) {
      bodyMatches.forEach(m => { allTokens.add(m); sources.push({ token: m, source: 'html_body' }); });
    }

    // Source 4: Check URL for tokens (common misconfiguration)
    try {
      const urlObj = new URL(targetUrl);
      const urlStr = urlObj.search + urlObj.hash;
      const urlMatches = urlStr.match(JWT_REGEX);
      if (urlMatches) {
        urlMatches.forEach(m => { allTokens.add(m); sources.push({ token: m, source: 'url' }); });
      }
    } catch { /* skip */ }

    if (allTokens.size === 0) {
      results.tests.push({ id: 'jwt-none-found', name: 'No JWT tokens detected in response', status: 'pass', severity: 'info' });
    } else {
      results.tests.push({
        id: 'jwt-found',
        name: `${allTokens.size} JWT token(s) detected in response`,
        status: 'warn', severity: 'medium'
      });

      // Analyze each unique token
      let tokenIdx = 0;
      for (const token of allTokens) {
        if (tokenIdx >= 5) break; // Limit analysis to 5 tokens
        const jwt = analyzeJwt(token);
        if (!jwt) continue;

        const { header, payload } = jwt;
        const src = sources.find(s => s.token === token)?.source || 'unknown';
        const prefix = `jwt-${tokenIdx}`;

        // Test: Algorithm check
        const alg = (header.alg || '').toUpperCase();
        if (alg === 'NONE' || alg === '') {
          results.tests.push({ id: `${prefix}-alg-none`, name: `JWT uses "none" algorithm (source: ${src})`, status: 'fail', severity: 'critical' });
        } else if (alg === 'HS256') {
          results.tests.push({ id: `${prefix}-alg-hs256`, name: `JWT uses HS256 (may be brute-forceable, source: ${src})`, status: 'warn', severity: 'medium' });
        } else if (alg === 'RS256' || alg === 'ES256' || alg === 'RS384' || alg === 'RS512') {
          results.tests.push({ id: `${prefix}-alg-strong`, name: `JWT uses ${alg} (source: ${src})`, status: 'pass', severity: 'info' });
        } else {
          results.tests.push({ id: `${prefix}-alg`, name: `JWT algorithm: ${alg} (source: ${src})`, status: 'info', severity: 'info' });
        }

        // Test: Expiration
        if (!payload.exp) {
          results.tests.push({ id: `${prefix}-no-exp`, name: `JWT missing expiration claim (source: ${src})`, status: 'fail', severity: 'high' });
        } else {
          const expDate = new Date(payload.exp * 1000);
          const now = new Date();
          const diffDays = (expDate - now) / (1000 * 60 * 60 * 24);
          if (diffDays > 30) {
            results.tests.push({ id: `${prefix}-long-exp`, name: `JWT expires in ${Math.round(diffDays)} days (too long, source: ${src})`, status: 'warn', severity: 'medium' });
          } else if (expDate < now) {
            results.tests.push({ id: `${prefix}-expired`, name: `JWT already expired (source: ${src})`, status: 'warn', severity: 'low' });
          } else {
            results.tests.push({ id: `${prefix}-exp-ok`, name: `JWT expiry valid (${Math.round(diffDays)}d, source: ${src})`, status: 'pass', severity: 'info' });
          }
        }

        // Test: Sensitive data in payload
        const sensitiveKeys = ['password', 'secret', 'ssn', 'credit_card', 'cc_number', 'cvv', 'private_key', 'api_key', 'apikey'];
        const foundSensitive = Object.keys(payload).filter(k => sensitiveKeys.includes(k.toLowerCase()));
        if (foundSensitive.length > 0) {
          results.tests.push({
            id: `${prefix}-sensitive-data`,
            name: `JWT contains sensitive fields: ${foundSensitive.join(', ')} (source: ${src})`,
            status: 'fail', severity: 'critical'
          });
        }

        // Test: PII in payload
        const piiKeys = ['email', 'phone', 'address', 'name', 'first_name', 'last_name', 'dob', 'date_of_birth'];
        const foundPii = Object.keys(payload).filter(k => piiKeys.includes(k.toLowerCase()));
        if (foundPii.length > 0) {
          results.tests.push({
            id: `${prefix}-pii`,
            name: `JWT contains PII: ${foundPii.join(', ')} (source: ${src})`,
            status: 'warn', severity: 'medium'
          });
        }

        // Test: Token in URL
        if (src === 'url') {
          results.tests.push({ id: `${prefix}-in-url`, name: 'JWT token found in URL (visible in logs/referrer)', status: 'fail', severity: 'high' });
        }

        // Test: Token in HTML body (exposed to XSS)
        if (src === 'html_body') {
          results.tests.push({ id: `${prefix}-in-html`, name: 'JWT token exposed in HTML source (XSS risk)', status: 'warn', severity: 'medium' });
        }

        tokenIdx++;
      }
    }

    // Test: Check for JWT-related headers
    const authHeader = headers['www-authenticate'] || '';
    if (authHeader.toLowerCase().includes('bearer')) {
      results.tests.push({ id: 'jwt-bearer-auth', name: 'Server uses Bearer token authentication', status: 'info', severity: 'info' });
    }

  } catch (err) {
    results.error = `JWT scan failed: ${err.message}`;
  }
  return { scanner: 'JWT Security', icon: '🎟️', results, testCount: results.tests.length };
}

module.exports = { scan };
