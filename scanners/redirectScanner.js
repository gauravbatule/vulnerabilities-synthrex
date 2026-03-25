const axios = require('axios');

async function scan(targetUrl) {
  const results = { findings: [], tests: [] };
  try {
    // Test HTTP to HTTPS redirect
    const httpUrl = targetUrl.replace('https://', 'http://');
    try {
      const response = await axios.get(httpUrl, {
        timeout: 10000, maxRedirects: 0, validateStatus: () => true,
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
      });
      const location = response.headers['location'] || '';
      if ([301, 302, 307, 308].includes(response.status)) {
        results.tests.push({ id: 'redir-https', name: 'HTTP→HTTPS redirect exists', status: 'pass', severity: 'info' });
        results.tests.push({ id: 'redir-https-permanent', name: 'Redirect is permanent (301/308)', status: [301,308].includes(response.status) ? 'pass' : 'warn', severity: 'medium' });
        results.tests.push({ id: 'redir-https-target', name: 'Redirect targets HTTPS', status: location.startsWith('https://') ? 'pass' : 'fail', severity: 'high' });
      } else {
        results.tests.push({ id: 'redir-no-https', name: 'No HTTP→HTTPS redirect', status: 'fail', severity: 'high' });
      }
    } catch (e) {
      results.tests.push({ id: 'redir-http-error', name: 'HTTP connection test', status: 'info', severity: 'info' });
    }

    // Open redirect testing
    const redirectPayloads = [
      { param: 'redirect', target: 'https://evil.com', name: 'redirect param' },
      { param: 'url', target: 'https://evil.com', name: 'url param' },
      { param: 'next', target: 'https://evil.com', name: 'next param' },
      { param: 'return', target: 'https://evil.com', name: 'return param' },
      { param: 'returnUrl', target: 'https://evil.com', name: 'returnUrl param' },
      { param: 'return_to', target: 'https://evil.com', name: 'return_to param' },
      { param: 'goto', target: 'https://evil.com', name: 'goto param' },
      { param: 'continue', target: 'https://evil.com', name: 'continue param' },
      { param: 'dest', target: 'https://evil.com', name: 'dest param' },
      { param: 'destination', target: 'https://evil.com', name: 'destination param' },
      { param: 'redir', target: 'https://evil.com', name: 'redir param' },
      { param: 'forward', target: 'https://evil.com', name: 'forward param' },
      { param: 'out', target: 'https://evil.com', name: 'out param' },
      { param: 'view', target: 'https://evil.com', name: 'view param' },
      { param: 'target', target: 'https://evil.com', name: 'target param' },
      { param: 'to', target: 'https://evil.com', name: 'to param' },
      { param: 'link', target: 'https://evil.com', name: 'link param' },
      { param: 'callback', target: 'https://evil.com', name: 'callback param' },
      { param: 'redirect_uri', target: 'https://evil.com', name: 'redirect_uri (OAuth)' },
      { param: 'redirect_url', target: 'https://evil.com', name: 'redirect_url param' },
      // Evasion payloads
      { param: 'url', target: '//evil.com', name: 'Protocol-relative redirect' },
      { param: 'url', target: 'https:evil.com', name: 'Missing slash redirect' },
      { param: 'url', target: 'https://evil.com%00.target.com', name: 'Null byte redirect' },
      { param: 'url', target: 'https://evil.com?.target.com', name: 'Query string redirect' },
      { param: 'url', target: 'https://evil.com#.target.com', name: 'Fragment redirect' },
      { param: 'url', target: 'https://evil.com@target.com', name: 'Auth redirect' },
      { param: 'url', target: 'javascript:alert(1)', name: 'JS protocol redirect' },
      { param: 'url', target: 'data:text/html,<script>alert(1)</script>', name: 'Data URI redirect' },
      { param: 'url', target: '%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d', name: 'URL-encoded redirect' },
      { param: 'url', target: 'https://evil。com', name: 'Unicode dot redirect' },
    ];

    for (const rp of redirectPayloads) {
      try {
        const testUrl = new URL(targetUrl);
        testUrl.searchParams.set(rp.param, rp.target);
        const response = await axios.get(testUrl.toString(), {
          timeout: 5000, maxRedirects: 0, validateStatus: () => true,
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
        });
        const location = (response.headers['location'] || '').toLowerCase();
        if ([301,302,303,307,308].includes(response.status) && (location.includes('evil.com') || location.includes('evil%2e') || location.includes('javascript:'))) {
          results.findings.push({ param: rp.param, payload: rp.target, redirectedTo: response.headers['location'], severity: 'high' });
          results.tests.push({ id: `redir-open-${rp.param}-${rp.name.replace(/\s/g,'-')}`, name: `Open redirect: ${rp.name}`, status: 'fail', severity: 'high' });
        } else {
          results.tests.push({ id: `redir-blocked-${rp.param}-${rp.name.replace(/\s/g,'-')}`, name: `Redirect blocked: ${rp.name}`, status: 'pass', severity: 'info' });
        }
      } catch { /* skip */ }
    }

  } catch (err) {
    results.error = `Redirect scan failed: ${err.message}`;
  }
  return { scanner: 'Redirect Security', icon: '↩️', results, testCount: results.tests.length };
}

module.exports = { scan };
