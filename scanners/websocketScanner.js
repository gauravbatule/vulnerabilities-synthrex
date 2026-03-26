const axios = require('axios');
const cheerio = require('cheerio');
const http = require('http');
const https = require('https');

async function scan(targetUrl) {
  const results = { tests: [], endpoints: [] };
  try {
    const u = new URL(targetUrl);
    const base = `${u.protocol}//${u.host}`;
    const isHttps = u.protocol === 'https:';

    // 1. Check page HTML for WebSocket URLs
    const r = await axios.get(targetUrl, {
      timeout: 10000, maxRedirects: 3, validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
    });
    const body = typeof r.data === 'string' ? r.data : '';

    // Look for ws:// or wss:// in source
    const wsUrls = body.match(/wss?:\/\/[^\s'"<>]+/gi) || [];
    const uniqueWs = [...new Set(wsUrls)];

    if (uniqueWs.length > 0) {
      for (const wsUrl of uniqueWs.slice(0, 10)) {
        const isInsecure = wsUrl.startsWith('ws://');
        results.endpoints.push({ url: wsUrl, secure: !isInsecure });

        if (isInsecure) {
          results.tests.push({ id: `ws-insecure-${results.tests.length}`, name: `Insecure WebSocket: ${wsUrl.substring(0, 60)}`, status: 'fail', severity: 'high' });
        } else {
          results.tests.push({ id: `ws-secure-${results.tests.length}`, name: `Secure WebSocket: ${wsUrl.substring(0, 60)}`, status: 'pass', severity: 'info' });
        }
      }
    }

    // 2. Look for WebSocket constructor usage
    const wsConstructors = (body.match(/new\s+WebSocket\s*\(/gi) || []).length;
    if (wsConstructors > 0) {
      results.tests.push({ id: 'ws-constructor', name: `${wsConstructors} WebSocket constructor(s) found in source`, status: 'info', severity: 'info' });
    }

    // 3. Look for Socket.IO usage
    const hasSocketIO = /socket\.io/i.test(body) || /io\s*\(\s*['"]/.test(body);
    if (hasSocketIO) {
      results.tests.push({ id: 'ws-socketio', name: 'Socket.IO library detected', status: 'info', severity: 'info' });
    }

    // 4. Look for SockJS
    const hasSockJS = /sockjs/i.test(body);
    if (hasSockJS) {
      results.tests.push({ id: 'ws-sockjs', name: 'SockJS library detected', status: 'info', severity: 'info' });
    }

    // 5. Check common WebSocket paths
    const wsPaths = ['/ws', '/websocket', '/socket', '/socket.io/', '/sockjs', '/cable', '/realtime', '/live', '/stream'];
    for (const path of wsPaths) {
      try {
        const checkUrl = `${base}${path}`;
        const resp = await axios.get(checkUrl, {
          timeout: 3000, maxRedirects: 0, validateStatus: () => true,
          headers: { 'Upgrade': 'websocket', 'Connection': 'Upgrade', 'User-Agent': 'Mozilla/5.0' }
        });
        if (resp.status === 101 || resp.status === 426 || resp.status === 200) {
          results.tests.push({ id: `ws-path-${path.replace(/[^a-z]/gi, '')}`, name: `WebSocket endpoint responds: ${path} (${resp.status})`, status: 'info', severity: 'info' });
          results.endpoints.push({ url: `${base}${path}`, status: resp.status });
        }
      } catch { /* skip */ }
    }

    // 6. Check if site uses Server-Sent Events (bonus)
    const hasSSE = /EventSource\s*\(/.test(body) || /text\/event-stream/i.test(body);
    if (hasSSE) {
      results.tests.push({ id: 'ws-sse', name: 'Server-Sent Events (SSE) detected', status: 'info', severity: 'info' });
    }

    if (results.tests.length === 0) {
      results.tests.push({ id: 'ws-none', name: 'No WebSocket usage detected', status: 'pass', severity: 'info' });
    }

  } catch (err) {
    results.error = err.message;
  }
  return { scanner: 'WebSocket Security', icon: '🔗', results, testCount: results.tests.length };
}

module.exports = { scan };
