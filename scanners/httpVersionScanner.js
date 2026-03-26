const https = require('https');
const http = require('http');
const tls = require('tls');

async function scan(targetUrl) {
  const results = { tests: [], protocols: {} };
  try {
    const u = new URL(targetUrl);
    const hostname = u.hostname;
    const isHttps = u.protocol === 'https:';

    // 1. Check TLS ALPN for HTTP/2 support
    if (isHttps) {
      const alpnResult = await new Promise((resolve) => {
        const socket = tls.connect({
          host: hostname,
          port: 443,
          ALPNProtocols: ['h2', 'http/1.1'],
          servername: hostname,
          timeout: 5000,
        }, () => {
          const proto = socket.alpnProtocol;
          socket.destroy();
          resolve(proto);
        });
        socket.on('error', () => resolve(null));
        socket.on('timeout', () => { socket.destroy(); resolve(null); });
      });

      if (alpnResult === 'h2') {
        results.protocols.http2 = true;
        results.tests.push({ id: 'http2-supported', name: 'HTTP/2 supported (ALPN h2)', status: 'pass', severity: 'info' });
      } else {
        results.protocols.http2 = false;
        results.tests.push({ id: 'http2-missing', name: 'HTTP/2 not supported', status: 'warn', severity: 'low' });
      }

      // Check for HTTP/3 via Alt-Svc header
      const resp = await new Promise((resolve) => {
        const req = https.get(targetUrl, {
          timeout: 5000,
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
        }, (res) => {
          res.resume();
          resolve(res);
        });
        req.on('error', () => resolve(null));
        req.on('timeout', () => { req.destroy(); resolve(null); });
      });

      if (resp) {
        const altSvc = resp.headers['alt-svc'] || '';
        if (altSvc.includes('h3')) {
          results.protocols.http3 = true;
          results.tests.push({ id: 'http3-supported', name: 'HTTP/3 supported (Alt-Svc h3)', status: 'pass', severity: 'info' });
        } else {
          results.protocols.http3 = false;
          results.tests.push({ id: 'http3-missing', name: 'HTTP/3 not advertised', status: 'info', severity: 'info' });
        }

        // HTTP version from response
        const httpVer = resp.httpVersion;
        results.tests.push({ id: 'http-version', name: `Response HTTP version: ${httpVer}`, status: 'pass', severity: 'info' });
      }
    } else {
      // HTTP (not HTTPS) — check basic response
      const resp = await new Promise((resolve) => {
        const req = http.get(targetUrl, { timeout: 5000 }, (res) => {
          res.resume();
          resolve(res);
        });
        req.on('error', () => resolve(null));
        req.on('timeout', () => { req.destroy(); resolve(null); });
      });

      results.tests.push({ id: 'http2-no-tls', name: 'HTTP/2 requires HTTPS — not applicable', status: 'info', severity: 'info' });
      if (resp) {
        results.tests.push({ id: 'http-version', name: `Response HTTP version: ${resp.httpVersion}`, status: 'pass', severity: 'info' });
      }
    }

  } catch (err) {
    results.error = err.message;
  }
  return { scanner: 'HTTP/2 & HTTP/3', icon: '🚀', results, testCount: results.tests.length };
}

module.exports = { scan };
