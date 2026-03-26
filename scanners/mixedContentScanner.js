const axios = require('axios');
const cheerio = require('cheerio');

async function scan(targetUrl) {
  const results = { tests: [], issues: [] };
  try {
    const u = new URL(targetUrl);
    if (u.protocol !== 'https:') {
      results.tests.push({ id: 'mixed-no-https', name: 'Site uses HTTP — mixed content check not applicable', status: 'info', severity: 'info' });
      return { scanner: 'Mixed Content', icon: '🔀', results, testCount: results.tests.length };
    }

    const r = await axios.get(targetUrl, {
      timeout: 10000, maxRedirects: 3, validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
    });
    const body = typeof r.data === 'string' ? r.data : '';
    const $ = cheerio.load(body);

    let httpResources = 0;
    const mixed = [];

    // Check scripts
    $('script[src]').each((_, el) => {
      const src = $(el).attr('src') || '';
      if (src.startsWith('http://')) {
        httpResources++;
        mixed.push({ type: 'script', url: src.substring(0, 80) });
      }
    });

    // Check stylesheets
    $('link[rel="stylesheet"][href]').each((_, el) => {
      const href = $(el).attr('href') || '';
      if (href.startsWith('http://')) {
        httpResources++;
        mixed.push({ type: 'stylesheet', url: href.substring(0, 80) });
      }
    });

    // Check images
    $('img[src]').each((_, el) => {
      const src = $(el).attr('src') || '';
      if (src.startsWith('http://')) {
        httpResources++;
        mixed.push({ type: 'image', url: src.substring(0, 80) });
      }
    });

    // Check iframes
    $('iframe[src]').each((_, el) => {
      const src = $(el).attr('src') || '';
      if (src.startsWith('http://')) {
        httpResources++;
        mixed.push({ type: 'iframe', url: src.substring(0, 80) });
      }
    });

    // Check form actions
    $('form[action]').each((_, el) => {
      const action = $(el).attr('action') || '';
      if (action.startsWith('http://')) {
        httpResources++;
        mixed.push({ type: 'form', url: action.substring(0, 80) });
      }
    });

    // Check media (audio/video)
    $('audio[src], video[src], source[src]').each((_, el) => {
      const src = $(el).attr('src') || '';
      if (src.startsWith('http://')) {
        httpResources++;
        mixed.push({ type: 'media', url: src.substring(0, 80) });
      }
    });

    // Check inline CSS for http:// urls
    const httpUrlsInCSS = (body.match(/url\s*\(\s*['"]?http:\/\//gi) || []).length;
    if (httpUrlsInCSS > 0) {
      httpResources += httpUrlsInCSS;
      mixed.push({ type: 'css-url', count: httpUrlsInCSS });
    }

    results.issues = mixed;

    if (httpResources === 0) {
      results.tests.push({ id: 'mixed-clean', name: 'No mixed content detected', status: 'pass', severity: 'info' });
    } else {
      for (const m of mixed.slice(0, 10)) {
        const severity = (m.type === 'script' || m.type === 'iframe' || m.type === 'form') ? 'high' : 'medium';
        results.tests.push({ id: `mixed-${m.type}-${results.tests.length}`, name: `Mixed ${m.type}: ${m.url || m.count + ' items'}`, status: 'fail', severity });
      }
      if (mixed.length > 10) {
        results.tests.push({ id: 'mixed-more', name: `${mixed.length - 10} more mixed content issues`, status: 'fail', severity: 'medium' });
      }
    }

    // Check upgrade-insecure-requests in CSP
    const csp = r.headers['content-security-policy'] || '';
    results.tests.push({ id: 'mixed-upgrade', name: 'CSP upgrade-insecure-requests', status: csp.includes('upgrade-insecure-requests') ? 'pass' : 'warn', severity: csp.includes('upgrade-insecure-requests') ? 'info' : 'medium' });

    // Check block-all-mixed-content
    results.tests.push({ id: 'mixed-block', name: 'CSP block-all-mixed-content', status: csp.includes('block-all-mixed-content') ? 'pass' : 'info', severity: 'info' });

  } catch (err) {
    results.error = err.message;
  }
  return { scanner: 'Mixed Content', icon: '🔀', results, testCount: results.tests.length };
}

module.exports = { scan };
