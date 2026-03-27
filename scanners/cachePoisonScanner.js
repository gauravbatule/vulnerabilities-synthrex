const axios = require('axios');

// Cache Poisoning Scanner
// Tests if unkeyed headers are reflected in cached responses
// FP prevention: Makes two requests — one with injection, one clean — only flags if clean shows injected content
// FN prevention: Tests multiple unkeyed headers and cache deception paths

const UNKEYED_HEADERS = [
  { header: 'X-Forwarded-Host', value: 'synthrex-cache-test.evil.com', name: 'X-Forwarded-Host' },
  { header: 'X-Host', value: 'synthrex-cache-test.evil.com', name: 'X-Host' },
  { header: 'X-Forwarded-Server', value: 'synthrex-cache-test.evil.com', name: 'X-Forwarded-Server' },
  { header: 'X-Original-URL', value: '/synthrex-cache-probe', name: 'X-Original-URL' },
  { header: 'X-Rewrite-URL', value: '/synthrex-cache-probe', name: 'X-Rewrite-URL' },
  { header: 'X-Forwarded-Proto', value: 'nothttps', name: 'X-Forwarded-Proto' },
  { header: 'X-Forwarded-Scheme', value: 'nothttps', name: 'X-Forwarded-Scheme' },
];

const CACHE_HEADERS = ['x-cache', 'x-cache-status', 'cf-cache-status', 'age', 'x-varnish', 'x-drupal-cache', 'x-proxy-cache', 'x-fastly-request-id', 'via'];

async function scan(targetUrl) {
  const results = { findings: [], tests: [] };

  try {
    const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

    // Test 1: Detect caching infrastructure
    const baseResp = await axios.get(targetUrl, {
      timeout: 8000, maxRedirects: 5, validateStatus: () => true,
      headers: { 'User-Agent': ua }
    }).catch(() => null);

    if (!baseResp) {
      results.tests.push({ id: 'cache-unreachable', name: 'Target unreachable for cache analysis', status: 'info', severity: 'info' });
      return { scanner: 'Cache Poisoning', icon: '💣', results, testCount: results.tests.length };
    }

    const foundCacheHeaders = [];
    for (const ch of CACHE_HEADERS) {
      if (baseResp.headers[ch]) foundCacheHeaders.push(`${ch}: ${baseResp.headers[ch]}`);
    }

    if (foundCacheHeaders.length > 0) {
      results.tests.push({
        id: 'cache-detected',
        name: `Cache detected: ${foundCacheHeaders.slice(0, 3).join(', ')}`,
        status: 'info', severity: 'info'
      });
    } else {
      results.tests.push({ id: 'cache-not-detected', name: 'No caching headers detected', status: 'pass', severity: 'info' });
    }

    // Test 2: Unkeyed header reflection
    for (const test of UNKEYED_HEADERS) {
      try {
        // Send request WITH injected header + cache buster so we get a fresh response
        const cacheBuster = `synthrex_cb_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
        const testUrl = new URL(targetUrl);
        testUrl.searchParams.set('cb', cacheBuster);

        const injectedResp = await axios.get(testUrl.toString(), {
          timeout: 6000, maxRedirects: 3, validateStatus: () => true,
          headers: { 'User-Agent': ua, [test.header]: test.value }
        });

        const injectedBody = typeof injectedResp.data === 'string' ? injectedResp.data : '';

        // Check if injected value appears in response body
        if (injectedBody.includes(test.value)) {
          // Now send clean request (same URL without the header) to see if cached
          // Wait slightly to allow cache to populate
          await new Promise(r => setTimeout(r, 200));

          const cleanResp = await axios.get(testUrl.toString(), {
            timeout: 6000, maxRedirects: 3, validateStatus: () => true,
            headers: { 'User-Agent': ua }
          });

          const cleanBody = typeof cleanResp.data === 'string' ? cleanResp.data : '';

          if (cleanBody.includes(test.value)) {
            // Confirmed: injected value persisted in clean request = cache poisoned
            results.tests.push({
              id: `cache-poison-${test.name.replace(/\s/g, '-')}`,
              name: `Cache Poisoning via ${test.name} (reflected in cached response)`,
              status: 'fail', severity: 'critical'
            });
            results.findings.push({ header: test.name, value: test.value, evidence: 'reflected_in_cache' });
          } else {
            // Reflected but not cached — lower severity
            results.tests.push({
              id: `cache-reflect-${test.name.replace(/\s/g, '-')}`,
              name: `${test.name} reflected but not cached`,
              status: 'warn', severity: 'medium'
            });
          }
        } else {
          results.tests.push({
            id: `cache-safe-${test.name.replace(/\s/g, '-')}`,
            name: `${test.name} not reflected`,
            status: 'pass', severity: 'info'
          });
        }
      } catch { /* skip */ }
    }

    // Test 3: Web Cache Deception via path confusion
    const deceptionPaths = [
      '/account%2f..%2fstatic/test.css',
      '/profile/..%2fstatic.css',
      '/api/..;/static/style.css',
    ];
    for (const dp of deceptionPaths) {
      try {
        const testUrl = `${targetUrl.replace(/\/$/, '')}${dp}`;
        const r = await axios.get(testUrl, {
          timeout: 5000, maxRedirects: 0, validateStatus: () => true,
          headers: { 'User-Agent': ua }
        });

        // Check if response includes dynamic/user content but was served with caching headers
        const hasCache = r.headers['cache-control'] && (
          r.headers['cache-control'].includes('public') ||
          r.headers['cache-control'].includes('max-age')
        );
        const hasSensitive = typeof r.data === 'string' && (
          /<form[^>]*action/i.test(r.data) || /csrf|token|session/i.test(r.data)
        );

        if (hasCache && hasSensitive && r.status === 200) {
          results.tests.push({
            id: `cache-deception-${deceptionPaths.indexOf(dp)}`,
            name: `Web Cache Deception: dynamic content cached at ${dp}`,
            status: 'fail', severity: 'high'
          });
        } else {
          results.tests.push({
            id: `cache-deception-${deceptionPaths.indexOf(dp)}`,
            name: `Cache deception safe: ${dp.substring(0, 40)}`,
            status: 'pass', severity: 'info'
          });
        }
      } catch { /* skip */ }
    }

    // Test 4: Host header injection into cached content
    try {
      const cacheBuster2 = `synthrex_host_${Date.now()}`;
      const testUrl = new URL(targetUrl);
      testUrl.searchParams.set('hcb', cacheBuster2);

      const hostResp = await axios.get(testUrl.toString(), {
        timeout: 6000, validateStatus: () => true,
        headers: { 'User-Agent': ua, 'Host': 'synthrex-host-test.evil.com' }
      });

      // Some servers may reject the mismatched host
      if (hostResp.status >= 200 && hostResp.status < 400) {
        const body = typeof hostResp.data === 'string' ? hostResp.data : '';
        if (body.includes('synthrex-host-test.evil.com')) {
          results.tests.push({ id: 'cache-host-injection', name: 'Host header reflected (cache poisoning risk)', status: 'fail', severity: 'high' });
        } else {
          results.tests.push({ id: 'cache-host-safe', name: 'Host header not reflected', status: 'pass', severity: 'info' });
        }
      }
    } catch {
      results.tests.push({ id: 'cache-host-safe', name: 'Host header injection rejected', status: 'pass', severity: 'info' });
    }

  } catch (err) {
    results.error = `Cache poisoning scan failed: ${err.message}`;
  }
  return { scanner: 'Cache Poisoning', icon: '💣', results, testCount: results.tests.length };
}

module.exports = { scan };
