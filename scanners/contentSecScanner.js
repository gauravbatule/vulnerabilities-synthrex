const axios = require('axios');

async function scan(targetUrl) {
  const results = { tests: [], leaks: [] };
  try {
    const r = await axios.get(targetUrl, {
      timeout: 10000, maxRedirects: 3, validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
    });
    const body = typeof r.data === 'string' ? r.data : '';

    // 1. HTML comments (may contain debug info)
    const comments = body.match(/<!--[\s\S]*?-->/g) || [];
    const suspiciousComments = comments.filter(c =>
      /todo|fixme|hack|bug|password|secret|key|token|debug|temp|remove|api[_-]?key|username/i.test(c)
    );
    if (suspiciousComments.length > 0) {
      results.tests.push({ id: 'content-comments', name: `${suspiciousComments.length} suspicious HTML comments (may leak info)`, status: 'warn', severity: 'medium' });
      results.leaks.push({ type: 'comments', count: suspiciousComments.length });
    } else {
      results.tests.push({ id: 'content-comments', name: `${comments.length} HTML comments (none suspicious)`, status: 'pass', severity: 'info' });
    }

    // 2. Debug / error output detection
    const debugPatterns = [
      { p: /\bstack\s*trace\b/i, name: 'Stack trace detected' },
      { p: /\btraceback\b.*most recent/i, name: 'Python traceback detected' },
      { p: /\bfatal\s+error\b/i, name: 'Fatal error message detected' },
      { p: /\bparse\s+error\b/i, name: 'Parse error message detected' },
      { p: /\bwarning\b.*\bon\s+line\s+\d+/i, name: 'PHP warning detected' },
      { p: /\bNotice\b.*\bon\s+line\s+\d+/i, name: 'PHP notice detected' },
      { p: /\bDeprecated\b.*\bon\s+line\s+\d+/i, name: 'PHP deprecated notice detected' },
      { p: /\bException\b.*\bat\s+[A-Za-z]+\./i, name: 'Java/C# exception detected' },
      { p: /\bTypeError\b|\bReferenceError\b|\bSyntaxError\b/i, name: 'JavaScript error exposed' },
      { p: /\bDjango\s+Version\b/i, name: 'Django debug page detected' },
      { p: /\bRails\.env\b|action_dispatch/i, name: 'Rails debug info detected' },
    ];

    for (const dp of debugPatterns) {
      if (dp.p.test(body)) {
        results.tests.push({ id: `content-debug-${results.tests.length}`, name: dp.name, status: 'fail', severity: 'high' });
        results.leaks.push({ type: 'debug', detail: dp.name });
      }
    }

    // 3. Version numbers in HTML
    const versionPatterns = [
      { p: /\bapache\/[\d.]+/i, name: 'Apache version exposed in HTML' },
      { p: /\bnginx\/[\d.]+/i, name: 'Nginx version exposed in HTML' },
      { p: /\bphp\/[\d.]+/i, name: 'PHP version exposed in HTML' },
      { p: /\biis\/[\d.]+/i, name: 'IIS version exposed in HTML' },
      { p: /\bwordpress\s+[\d.]+/i, name: 'WordPress version exposed' },
      { p: /<meta\s+name=["']generator["']\s+content=["']([^"']+)/i, name: 'Generator meta tag exposes technology' },
    ];

    for (const vp of versionPatterns) {
      const match = body.match(vp.p);
      if (match) {
        results.tests.push({ id: `content-version-${results.tests.length}`, name: `${vp.name}: ${match[0].substring(0, 40)}`, status: 'warn', severity: 'low' });
        results.leaks.push({ type: 'version', detail: match[0].substring(0, 40) });
      }
    }

    // 4. Sensitive data patterns
    const sensitivePatterns = [
      { p: /\bapi[_-]?key\s*[:=]\s*['"][^'"]{8,}/i, name: 'Possible API key in source' },
      { p: /\bpassword\s*[:=]\s*['"][^'"]{3,}/i, name: 'Possible password in source' },
      { p: /\bsecret[_-]?key\s*[:=]\s*['"][^'"]{8,}/i, name: 'Possible secret key in source' },
      { p: /\baccess[_-]?token\s*[:=]\s*['"][^'"]{8,}/i, name: 'Possible access token in source' },
      { p: /\baws[_-]?access[_-]?key/i, name: 'AWS access key reference' },
      { p: /\bprivate[_-]?key/i, name: 'Private key reference in source' },
      { p: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/i, name: 'Private key embedded in source!' },
      { p: /\bsk_live_[a-zA-Z0-9]{20,}/i, name: 'Stripe live key detected' },
    ];

    for (const sp of sensitivePatterns) {
      if (sp.p.test(body)) {
        results.tests.push({ id: `content-sensitive-${results.tests.length}`, name: sp.name, status: 'fail', severity: 'critical' });
        results.leaks.push({ type: 'sensitive', detail: sp.name });
      }
    }

    // 5. Email addresses exposed
    const emails = body.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [];
    const uniqueEmails = [...new Set(emails)];
    if (uniqueEmails.length > 0) {
      results.tests.push({ id: 'content-emails', name: `${uniqueEmails.length} email addresses exposed`, status: 'warn', severity: 'low' });
    } else {
      results.tests.push({ id: 'content-emails', name: 'No email addresses exposed', status: 'pass', severity: 'info' });
    }

    // 6. Internal IP addresses
    const internalIPs = body.match(/\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g) || [];
    if (internalIPs.length > 0) {
      results.tests.push({ id: 'content-internal-ip', name: `${internalIPs.length} internal IP addresses exposed`, status: 'fail', severity: 'medium' });
    }

    if (results.leaks.length === 0 && suspiciousComments.length === 0) {
      results.tests.push({ id: 'content-clean', name: 'No sensitive content leaks detected', status: 'pass', severity: 'info' });
    }

  } catch (err) {
    results.error = err.message;
  }
  return { scanner: 'Content Security', icon: '🔎', results, testCount: results.tests.length };
}

module.exports = { scan };
