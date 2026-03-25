const axios = require('axios');

async function scan(targetUrl) {
  const results = { metrics: {}, tests: [] };
  try {
    // TTFB measurement
    const start = Date.now();
    const response = await axios.get(targetUrl, {
      timeout: 30000, maxRedirects: 5, validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', 'Accept-Encoding': 'gzip, deflate, br' }
    });
    const ttfb = Date.now() - start;
    results.metrics.ttfb = ttfb;

    results.tests.push({ id: 'perf-ttfb', name: `TTFB: ${ttfb}ms`, status: ttfb < 200 ? 'pass' : ttfb < 600 ? 'warn' : 'fail', severity: ttfb > 600 ? 'medium' : 'info' });
    results.tests.push({ id: 'perf-ttfb-fast', name: 'TTFB < 200ms (fast)', status: ttfb < 200 ? 'pass' : 'info', severity: 'info' });
    results.tests.push({ id: 'perf-ttfb-acceptable', name: 'TTFB < 600ms (acceptable)', status: ttfb < 600 ? 'pass' : 'warn', severity: 'medium' });

    // Response size
    const contentLength = parseInt(response.headers['content-length'] || '0');
    const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
    const bodySize = Buffer.byteLength(body, 'utf8');
    results.metrics.responseSize = bodySize;
    results.tests.push({ id: 'perf-size', name: `Response size: ${(bodySize/1024).toFixed(1)}KB`, status: bodySize < 100000 ? 'pass' : bodySize < 500000 ? 'warn' : 'fail', severity: bodySize > 500000 ? 'medium' : 'info' });

    // Compression
    const contentEncoding = response.headers['content-encoding'];
    results.tests.push({ id: 'perf-gzip', name: 'Gzip compression enabled', status: contentEncoding && contentEncoding.includes('gzip') ? 'pass' : 'fail', severity: 'medium' });
    results.tests.push({ id: 'perf-brotli', name: 'Brotli compression enabled', status: contentEncoding && contentEncoding.includes('br') ? 'pass' : 'warn', severity: 'low' });

    // HTTP/2 check (via ALPN)
    results.tests.push({ id: 'perf-http2', name: 'HTTP/2 support', status: response.request?.res?.httpVersion === '2.0' ? 'pass' : 'warn', severity: 'low' });

    // Cache headers
    const cacheControl = response.headers['cache-control'] || '';
    const etag = response.headers['etag'];
    const lastModified = response.headers['last-modified'];
    const expires = response.headers['expires'];
    const vary = response.headers['vary'];

    results.tests.push({ id: 'perf-cache-control', name: 'Cache-Control header', status: cacheControl ? 'pass' : 'warn', severity: 'medium' });
    results.tests.push({ id: 'perf-etag', name: 'ETag header', status: etag ? 'pass' : 'warn', severity: 'low' });
    results.tests.push({ id: 'perf-last-modified', name: 'Last-Modified header', status: lastModified ? 'pass' : 'warn', severity: 'low' });
    results.tests.push({ id: 'perf-expires', name: 'Expires header', status: expires ? 'pass' : 'info', severity: 'info' });
    results.tests.push({ id: 'perf-vary', name: 'Vary header', status: vary ? 'pass' : 'info', severity: 'info' });

    if (cacheControl) {
      results.tests.push({ id: 'perf-no-store', name: 'Cache allows storing', status: !cacheControl.includes('no-store') ? 'pass' : 'info', severity: 'info' });
      results.tests.push({ id: 'perf-max-age', name: 'Cache max-age set', status: cacheControl.includes('max-age') ? 'pass' : 'warn', severity: 'low' });
      results.tests.push({ id: 'perf-public', name: 'Cache is public', status: cacheControl.includes('public') ? 'pass' : 'info', severity: 'info' });
    }

    // Keep-Alive
    const connection = response.headers['connection'];
    results.tests.push({ id: 'perf-keepalive', name: 'Keep-Alive enabled', status: connection !== 'close' ? 'pass' : 'warn', severity: 'low' });

    // Content-Type
    const contentType = response.headers['content-type'] || '';
    results.tests.push({ id: 'perf-charset', name: 'Charset specified', status: contentType.includes('charset') ? 'pass' : 'warn', severity: 'low' });

    // Multiple requests for consistency
    const responseTimes = [ttfb];
    for (let i = 0; i < 3; i++) {
      const s = Date.now();
      try {
        await axios.get(targetUrl, { timeout: 10000, validateStatus: () => true, headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' } });
        responseTimes.push(Date.now() - s);
      } catch { /* skip */ }
    }
    const avgTtfb = Math.round(responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length);
    const maxTtfb = Math.max(...responseTimes);
    const minTtfb = Math.min(...responseTimes);

    results.metrics.avgTtfb = avgTtfb;
    results.tests.push({ id: 'perf-avg-ttfb', name: `Average TTFB: ${avgTtfb}ms`, status: avgTtfb < 300 ? 'pass' : 'warn', severity: 'info' });
    results.tests.push({ id: 'perf-consistency', name: `Response time variance: ${maxTtfb - minTtfb}ms`, status: (maxTtfb - minTtfb) < 500 ? 'pass' : 'warn', severity: 'low' });

  } catch (err) {
    results.error = `Performance scan failed: ${err.message}`;
  }
  return { scanner: 'Performance & Caching', icon: '⚡', results, testCount: results.tests.length };
}

module.exports = { scan };
