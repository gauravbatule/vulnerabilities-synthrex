const axios = require('axios');

async function scan(targetUrl) {
  const results = { cookies: [], tests: [] };
  try {
    const response = await axios.get(targetUrl, {
      timeout: 15000, maxRedirects: 5, validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
    });

    const setCookies = response.headers['set-cookie'];
    if (!setCookies || setCookies.length === 0) {
      results.tests.push({ id: 'cookie-none', name: 'No cookies set', status: 'pass', severity: 'info' });
      return { scanner: 'Cookie Security', icon: '🍪', results, testCount: 1 };
    }

    const cookieArray = Array.isArray(setCookies) ? setCookies : [setCookies];
    for (const cookie of cookieArray) {
      const parts = cookie.split(';').map(p => p.trim());
      const nameValue = parts[0] || '';
      const name = nameValue.split('=')[0] || 'unknown';
      const flags = parts.slice(1).map(f => f.toLowerCase());
      const flagStr = flags.join('; ');

      const hasHttpOnly = flags.some(f => f === 'httponly');
      const hasSecure = flags.some(f => f === 'secure');
      const hasSameSite = flags.some(f => f.startsWith('samesite'));
      const sameSiteValue = flags.find(f => f.startsWith('samesite'))?.split('=')[1]?.trim();
      const hasPath = flags.some(f => f.startsWith('path'));
      const hasDomain = flags.some(f => f.startsWith('domain'));
      const hasExpires = flags.some(f => f.startsWith('expires'));
      const hasMaxAge = flags.some(f => f.startsWith('max-age'));
      const isSession = !hasExpires && !hasMaxAge;

      const cookieInfo = { name, httpOnly: hasHttpOnly, secure: hasSecure, sameSite: sameSiteValue || 'not set', path: hasPath, domain: hasDomain, persistent: !isSession };
      results.cookies.push(cookieInfo);

      // Security flag checks
      results.tests.push({ id: `cookie-httponly-${name}`, name: `${name}: HttpOnly flag`, status: hasHttpOnly ? 'pass' : 'fail', severity: 'high' });
      results.tests.push({ id: `cookie-secure-${name}`, name: `${name}: Secure flag`, status: hasSecure ? 'pass' : 'fail', severity: 'high' });
      results.tests.push({ id: `cookie-samesite-${name}`, name: `${name}: SameSite attribute`, status: hasSameSite ? 'pass' : 'fail', severity: 'medium' });

      if (hasSameSite) {
        results.tests.push({ id: `cookie-samesite-val-${name}`, name: `${name}: SameSite=${sameSiteValue}`, status: sameSiteValue === 'none' ? 'fail' : sameSiteValue === 'lax' ? 'warn' : 'pass', severity: sameSiteValue === 'none' ? 'high' : 'medium' });
      }

      results.tests.push({ id: `cookie-path-${name}`, name: `${name}: Path attribute`, status: hasPath ? 'pass' : 'warn', severity: 'low' });

      // Sensitive cookie name checks
      const sensitiveNames = ['session', 'sessid', 'token', 'auth', 'jwt', 'csrf', 'xsrf', 'login', 'user', 'admin', 'phpsessid', 'jsessionid', 'asp.net_sessionid', 'connect.sid'];
      const isSensitive = sensitiveNames.some(s => name.toLowerCase().includes(s));
      if (isSensitive) {
        results.tests.push({ id: `cookie-sensitive-${name}`, name: `${name}: Sensitive cookie detected`, status: 'warn', severity: 'medium' });
        if (!hasHttpOnly) results.tests.push({ id: `cookie-sens-httponly-${name}`, name: `${name}: Sensitive cookie without HttpOnly`, status: 'fail', severity: 'critical' });
        if (!hasSecure) results.tests.push({ id: `cookie-sens-secure-${name}`, name: `${name}: Sensitive cookie without Secure`, status: 'fail', severity: 'critical' });
      }

      // Cookie prefix checks
      if (name.startsWith('__Host-')) {
        results.tests.push({ id: `cookie-host-prefix-${name}`, name: `${name}: __Host- prefix used`, status: 'pass', severity: 'info' });
      }
      if (name.startsWith('__Secure-')) {
        results.tests.push({ id: `cookie-secure-prefix-${name}`, name: `${name}: __Secure- prefix used`, status: 'pass', severity: 'info' });
      }
    }
  } catch (err) {
    results.error = `Cookie scan failed: ${err.message}`;
  }
  return { scanner: 'Cookie Security', icon: '🍪', results, testCount: results.tests.length };
}

module.exports = { scan };
