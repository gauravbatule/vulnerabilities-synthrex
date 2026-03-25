const axios = require('axios');
const cheerio = require('cheerio');

async function scan(targetUrl) {
  const results = { findings: [], tests: [] };
  try {
    const response = await axios.get(targetUrl, {
      timeout: 15000, maxRedirects: 5, validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
    });
    const headers = response.headers;
    const html = typeof response.data === 'string' ? response.data : '';
    const $ = cheerio.load(html);

    // X-Frame-Options check
    const xfo = headers['x-frame-options'];
    results.tests.push({ id: 'click-xfo', name: 'X-Frame-Options present', status: xfo ? 'pass' : 'fail', severity: 'high' });
    if (xfo) {
      results.tests.push({ id: 'click-xfo-deny', name: 'X-Frame-Options: DENY', status: xfo.toUpperCase() === 'DENY' ? 'pass' : 'warn', severity: 'medium' });
      results.tests.push({ id: 'click-xfo-same', name: 'X-Frame-Options: SAMEORIGIN', status: xfo.toUpperCase() === 'SAMEORIGIN' ? 'pass' : 'info', severity: 'info' });
      results.tests.push({ id: 'click-xfo-allow', name: 'X-Frame-Options: ALLOW-FROM', status: xfo.toUpperCase().includes('ALLOW-FROM') ? 'warn' : 'pass', severity: 'medium' });
    }

    // CSP frame-ancestors
    const csp = headers['content-security-policy'];
    const hasFrameAncestors = csp && csp.includes('frame-ancestors');
    results.tests.push({ id: 'click-csp-ancestors', name: 'CSP frame-ancestors directive', status: hasFrameAncestors ? 'pass' : 'fail', severity: 'high' });
    if (hasFrameAncestors) {
      results.tests.push({ id: 'click-csp-ancestors-none', name: "frame-ancestors 'none'", status: csp.includes("frame-ancestors 'none'") ? 'pass' : 'info', severity: 'info' });
      results.tests.push({ id: 'click-csp-ancestors-self', name: "frame-ancestors 'self'", status: csp.includes("frame-ancestors 'self'") ? 'pass' : 'info', severity: 'info' });
      results.tests.push({ id: 'click-csp-ancestors-wild', name: 'frame-ancestors wildcard', status: csp.includes('frame-ancestors *') ? 'fail' : 'pass', severity: 'high' });
    }

    // Check for JS frame-busting code
    const frameBusters = [
      'top.location', 'parent.location', 'window.top', 'self===top',
      'self!==top', 'top!==self', 'frameElement', 'window.frameElement'
    ];
    for (const fb of frameBusters) {
      const has = html.includes(fb);
      results.tests.push({ id: `click-fb-${fb.replace(/[^a-z]/gi,'')}`, name: `Frame-busting: ${fb}`, status: has ? 'pass' : 'info', severity: 'info' });
    }

    // Check if page contains sensitive forms
    const forms = $('form');
    if (forms.length > 0 && !xfo && !hasFrameAncestors) {
      results.tests.push({ id: 'click-form-risk', name: 'Forms present without frame protection', status: 'fail', severity: 'high' });
    }

    // Check for buttons/links that could be targets
    const sensitiveElements = $('button[type="submit"], input[type="submit"], a[href*="delete"], a[href*="remove"], a[href*="admin"]');
    if (sensitiveElements.length > 0 && !xfo && !hasFrameAncestors) {
      results.tests.push({ id: 'click-sensitive-elements', name: 'Sensitive UI elements without frame protection', status: 'fail', severity: 'high' });
    }

  } catch (err) {
    results.error = `Clickjacking scan failed: ${err.message}`;
  }
  return { scanner: 'Clickjacking Protection', icon: '🖱️', results, testCount: results.tests.length };
}

module.exports = { scan };
