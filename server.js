require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

// Import all scanners
const headerScanner = require('./scanners/headerScanner');
const sslScanner = require('./scanners/sslScanner');
const portScanner = require('./scanners/portScanner');
const corsScanner = require('./scanners/corsScanner');
const infoLeakScanner = require('./scanners/infoLeakScanner');
const techDetector = require('./scanners/techDetector');
const cookieScanner = require('./scanners/cookieScanner');
const dnsScanner = require('./scanners/dnsScanner');
const subdomainScanner = require('./scanners/subdomainScanner');
const xssScanner = require('./scanners/xssScanner');
const sqliScanner = require('./scanners/sqliScanner');
const clickjackScanner = require('./scanners/clickjackScanner');
const redirectScanner = require('./scanners/redirectScanner');
const formScanner = require('./scanners/formScanner');
const httpMethodScanner = require('./scanners/httpMethodScanner');
const wafScanner = require('./scanners/wafScanner');
const performanceScanner = require('./scanners/performanceScanner');
const injectionScanner = require('./scanners/injectionScanner');
const robotsScanner = require('./scanners/robotsScanner');
const directoryScanner = require('./scanners/directoryScanner');
const httpVersionScanner = require('./scanners/httpVersionScanner');
const emailSecScanner = require('./scanners/emailSecScanner');
const jsLibScanner = require('./scanners/jsLibScanner');
const apiDiscoveryScanner = require('./scanners/apiDiscoveryScanner');
const mixedContentScanner = require('./scanners/mixedContentScanner');
const contentSecScanner = require('./scanners/contentSecScanner');
const dnssecScanner = require('./scanners/dnssecScanner');
const websocketScanner = require('./scanners/websocketScanner');
const crlfScanner = require('./scanners/crlfScanner');
const rateLimitScanner = require('./scanners/rateLimitScanner');
const graphqlScanner = require('./scanners/graphqlScanner');
const jwtScanner = require('./scanners/jwtScanner');
const subdomainTakeoverScanner = require('./scanners/subdomainTakeoverScanner');
const cachePoisonScanner = require('./scanners/cachePoisonScanner');
const errorDisclosureScanner = require('./scanners/errorDisclosureScanner');

// AI Analyzer
const groqAnalyzer = require('./ai/groqAnalyzer');

// PDF Export (server-side with pdfkit)
const PDFDocument = require('pdfkit');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// ── Hide server identity ──
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// In-memory scan storage
const scans = new Map();

// All available scanners in execution order
const SCANNERS = [
  { id: 'headers', scanner: headerScanner, name: 'Security Headers', icon: '🛡️' },
  { id: 'ssl', scanner: sslScanner, name: 'SSL/TLS Analysis', icon: '🔒' },
  { id: 'waf', scanner: wafScanner, name: 'WAF Detection', icon: '🧱' },
  { id: 'tech', scanner: techDetector, name: 'Technology Detection', icon: '🔍' },
  { id: 'cookies', scanner: cookieScanner, name: 'Cookie Security', icon: '🍪' },
  { id: 'cors', scanner: corsScanner, name: 'CORS Misconfiguration', icon: '🌐' },
  { id: 'clickjack', scanner: clickjackScanner, name: 'Clickjacking Protection', icon: '🖱️' },
  { id: 'methods', scanner: httpMethodScanner, name: 'HTTP Methods', icon: '📡' },
  { id: 'redirect', scanner: redirectScanner, name: 'Redirect Security', icon: '↩️' },
  { id: 'forms', scanner: formScanner, name: 'Form Security', icon: '📝' },
  { id: 'dns', scanner: dnsScanner, name: 'DNS & Email Security', icon: '📡' },
  { id: 'ports', scanner: portScanner, name: 'Port Scanner', icon: '🔌' },
  { id: 'infoleak', scanner: infoLeakScanner, name: 'Information Leakage', icon: '📂' },
  { id: 'xss', scanner: xssScanner, name: 'XSS Testing', icon: '💉' },
  { id: 'sqli', scanner: sqliScanner, name: 'SQL Injection', icon: '🗄️' },
  { id: 'injections', scanner: injectionScanner, name: 'Advanced Injections', icon: '🔓' },
  { id: 'subdomains', scanner: subdomainScanner, name: 'Subdomain Enumeration', icon: '🌍' },
  { id: 'performance', scanner: performanceScanner, name: 'Performance & Caching', icon: '⚡' },
  { id: 'robots', scanner: robotsScanner, name: 'Robots & Sitemap', icon: '🤖' },
  { id: 'directories', scanner: directoryScanner, name: 'Directory Discovery', icon: '📁' },
  { id: 'httpver', scanner: httpVersionScanner, name: 'HTTP/2 & HTTP/3', icon: '🚀' },
  { id: 'emailsec', scanner: emailSecScanner, name: 'Email Security', icon: '📧' },
  { id: 'jslibs', scanner: jsLibScanner, name: 'JS Library Scanner', icon: '📚' },
  { id: 'apidiscovery', scanner: apiDiscoveryScanner, name: 'API Endpoint Discovery', icon: '🔌' },
  { id: 'mixedcontent', scanner: mixedContentScanner, name: 'Mixed Content', icon: '🔀' },
  { id: 'contentsec', scanner: contentSecScanner, name: 'Content Security', icon: '🔎' },
  { id: 'dnssec', scanner: dnssecScanner, name: 'DNSSEC Validation', icon: '🔐' },
  { id: 'websocket', scanner: websocketScanner, name: 'WebSocket Security', icon: '🔗' },
  { id: 'crlf', scanner: crlfScanner, name: 'CRLF Injection', icon: '💀' },
  { id: 'ratelimit', scanner: rateLimitScanner, name: 'Rate Limiting', icon: '⏱️' },
  { id: 'graphql', scanner: graphqlScanner, name: 'GraphQL Introspection', icon: '🔮' },
  { id: 'jwt', scanner: jwtScanner, name: 'JWT Security', icon: '🎟️' },
  { id: 'subdomaintakeover', scanner: subdomainTakeoverScanner, name: 'Subdomain Takeover', icon: '🏴' },
  { id: 'cachepoison', scanner: cachePoisonScanner, name: 'Cache Poisoning', icon: '💣' },
  { id: 'errordisclosure', scanner: errorDisclosureScanner, name: 'Error Disclosure', icon: '🐛' },
];

function normalizeUrl(input) {
  let url = input.trim();
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }
  return url;
}



// ── Authorization: check security.txt ──
const axios = require('axios');
const dns = require('dns');

// Validate domain exists (DNS + HTTP)
async function validateDomain(targetUrl) {
  try {
    const u = new URL(targetUrl);
    const hostname = u.hostname;

    // 1. DNS resolution
    await dns.promises.lookup(hostname);

    // 2. Quick HTTP reachability check  
    const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
    await axios.head(targetUrl, {
      timeout: 8000,
      maxRedirects: 5,
      validateStatus: () => true,
      headers: { 'User-Agent': ua }
    });

    return { valid: true };
  } catch (err) {
    if (err.code === 'ENOTFOUND' || err.code === 'EAI_AGAIN') {
      return { valid: false, error: `Domain does not exist: "${new URL(targetUrl).hostname}" could not be resolved.` };
    }
    if (err.code === 'ECONNREFUSED') {
      return { valid: false, error: `Target is unreachable: connection refused on "${new URL(targetUrl).hostname}".` };
    }
    if (err.code === 'ETIMEDOUT' || err.code === 'ECONNABORTED') {
      return { valid: false, error: `Target is unreachable: connection timed out for "${new URL(targetUrl).hostname}".` };
    }
    // Other errors (e.g. SSL issues) — domain exists but has issues; still allow scan
    return { valid: true };
  }
}

async function hasSecurityTxt(targetUrl) {
  const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
  const u = new URL(targetUrl);
  const hosts = [`https://${u.hostname}`, `http://${u.hostname}`];
  const paths = ['/.well-known/security.txt', '/security.txt'];
  for (const host of hosts) {
    for (const p of paths) {
      try {
        const checkUrl = `${host}${p}`;
        const r = await axios.get(checkUrl, {
          timeout: 8000,
          maxRedirects: 5,
          validateStatus: () => true,
          headers: { 'User-Agent': ua, 'Accept': 'text/plain, */*' }
        });
        if (r.status === 200 && typeof r.data === 'string' && r.data.length > 20) {
          const d = r.data.toLowerCase();
          if (d.includes('contact') || d.includes('policy') || d.includes('acknowledgment')) {
            console.log(`[precheck] security.txt found at ${checkUrl}`);
            return true;
          }
        }
      } catch { /* skip */ }
    }
  }
  console.log(`[precheck] No security.txt found for ${u.hostname}`);
  return false;
}

// ── Pre-check endpoint (frontend calls this first) ──
app.post('/api/precheck', async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Target URL is required' });
  const targetUrl = normalizeUrl(target);

  // Validate domain exists
  const validation = await validateDomain(targetUrl);
  if (!validation.valid) {
    return res.json({ allowed: false, reason: 'invalid_domain', error: validation.error });
  }

  // Check for security.txt
  const hasSec = await hasSecurityTxt(targetUrl);
  if (hasSec) {
    return res.json({ allowed: true, method: 'security_txt' });
  }

  // No security.txt → require access code
  return res.json({ allowed: false, reason: 'no_security_txt', requireCode: true });
});

// Start a scan
app.post('/api/scan', async (req, res) => {
  const { target, accessCode, precheckPassed } = req.body;
  if (!target) return res.status(400).json({ error: 'Target URL is required' });

  const targetUrl = normalizeUrl(target);

  // Validate domain exists
  const validation = await validateDomain(targetUrl);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.error });
  }

  // Authorization check: security.txt or access code
  // Skip if precheck already approved (avoids race conditions with security.txt)
  if (!precheckPassed) {
    const hasSec = await hasSecurityTxt(targetUrl);
    if (!hasSec && accessCode !== '9921') {
      return res.status(403).json({ error: 'Authorization required. Please provide a valid access code.' });
    }
  }

  const scanId = uuidv4();

  const scan = {
    id: scanId,
    target: targetUrl,
    status: 'running',
    startedAt: new Date().toISOString(),
    completedAt: null,
    progress: 0,
    currentScanner: '',
    results: [],
    totalTests: 0,
    totalPassed: 0,
    totalFailed: 0,
    totalWarnings: 0,
    aiAnalysis: null,
  };

  scans.set(scanId, scan);

  // Run scan asynchronously
  runScan(scanId, targetUrl);

  res.json({ scanId, target: targetUrl, status: 'running' });
});

// Per-scanner hard timeout to prevent any single scanner hanging the whole scan
function withTimeout(promise, ms, name) {
  return Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error(`${name} exceeded ${ms / 1000}s timeout`)), ms))
  ]);
}

async function runScan(scanId, targetUrl) {
  const scan = scans.get(scanId);
  if (!scan) return;

  for (let i = 0; i < SCANNERS.length; i++) {
    const { id, scanner, name, icon } = SCANNERS[i];
    scan.currentScanner = name;
    scan.progress = Math.round(((i) / SCANNERS.length) * 100);

    try {
      console.log(`[${scanId.substring(0,8)}] Running: ${name}...`);
      const result = await withTimeout(scanner.scan(targetUrl), 120000, name);
      scan.results.push(result);

      // Count test results
      const tests = result.results?.tests || [];
      scan.totalTests += tests.length;
      scan.totalPassed += tests.filter(t => t.status === 'pass').length;
      scan.totalFailed += tests.filter(t => t.status === 'fail').length;
      scan.totalWarnings += tests.filter(t => t.status === 'warn').length;

      console.log(`[${scanId.substring(0,8)}] ${name}: ${tests.length} tests (${tests.filter(t => t.status === 'fail').length} fails)`);
    } catch (err) {
      console.error(`[${scanId.substring(0,8)}] ${name} error:`, err.message);
      scan.results.push({
        scanner: name, icon,
        results: { error: err.message, tests: [] },
        testCount: 0
      });
    }
  }

  scan.status = 'completed';
  scan.progress = 100;
  scan.currentScanner = '';
  scan.completedAt = new Date().toISOString();

  // Compute security score (same logic as client)
  let cr=0,hi=0,me=0,lo=0;
  for(const r of scan.results){
    for(const t of (r.results?.tests||[])){
      if(t.status!=='fail'&&t.status!=='warn') continue;
      if(t.severity==='critical') cr++;
      else if(t.severity==='high') hi++;
      else if(t.severity==='medium') me++;
      else lo++;
    }
  }
  const penalty = cr*15 + hi*7 + me*3 + lo*1;
  scan.score = Math.max(0, Math.min(100, 100 - penalty));

  console.log(`[${scanId.substring(0,8)}] Scan completed. Score: ${scan.score}. Total: ${scan.totalTests} tests, ${scan.totalFailed} fails, ${scan.totalWarnings} warns`);
}

// Get scan status
app.get('/api/scan/:id', (req, res) => {
  const scan = scans.get(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  res.json(scan);
});

// AI Analysis
app.post('/api/ai-analyze', async (req, res) => {
  const { scanId } = req.body;
  const scan = scans.get(scanId);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  if (scan.status !== 'completed') return res.status(400).json({ error: 'Scan not yet completed' });

  try {
    console.log(`[${scanId.substring(0,8)}] Starting AI analysis...`);
    const analysis = await groqAnalyzer.analyze(scan.results, scan.target);
    scan.aiAnalysis = analysis;
    console.log(`[${scanId.substring(0,8)}] AI analysis completed`);
    res.json(analysis);
  } catch (err) {
    console.error('AI analysis error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Legacy Redirect for old PDF URL pattern
app.get('/export-pdf', (req, res) => {
  res.status(410).send(`
    <div style="font-family:sans-serif;padding:40px;text-align:center;">
      <h2>Outdated Link</h2>
      <p>This export link is from an older version of Synthrex.</p>
      <p>Please <b>Hard Refresh (Ctrl+Shift+R)</b> the main page and run a new scan to export.</p>
      <a href="/" style="color:#10b981;">Return to Dashboard</a>
    </div>
  `);
});

app.get('/api/export-pdf/:scanId/:filename?', (req, res) => {
  const scanId = req.params.scanId;
  const scan = scans.get(scanId);
  if (!scan) {
    console.error(`[PDF] Export failed: Scan ${scanId} not found`);
    return res.status(404).json({ error: 'Scan not found' });
  }
  if (scan.status !== 'completed') return res.status(400).json({ error: 'Scan not completed' });

  console.log(`[PDF] Generating report for ${scan.target} (ID: ${scanId.substring(0,8)})`);

  const filename = `Synthrex-Report-${new Date().toISOString().slice(0, 10)}.pdf`;
  res.setHeader('Content-Type', 'application/pdf');
  // Use both filename and filename* for maximum compatibility
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"; filename*=UTF-8''${encodeURIComponent(filename)}`);

  const doc = new PDFDocument({ size: 'A4', margin: 50, bufferPages: true });
  doc.pipe(res);

  const M = 50, PW = 495; // margins & page width
  const green = '#10b981', red = '#ef4444', amber = '#f59e0b', orange = '#f97316', gray = '#666666';

  // Helper: sanitize text (remove emoji/non-latin chars that pdfkit can't render)
  const clean = (s) => String(s || '').replace(/[^\x20-\x7E]/g, '').trim();

  // ── HEADER ──
  doc.fontSize(22).font('Helvetica-Bold').fillColor('#111')
    .text('Synthrex', M, 45, { continued: true })
    .fontSize(10).font('Helvetica').fillColor(gray)
    .text('  Security Report', { continued: false });
  doc.fontSize(9).text(new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }), M, 48, { align: 'right' });
  doc.moveTo(M, 68).lineTo(M + PW, 68).strokeColor(green).lineWidth(1).stroke();
  doc.y = 80;

  // ── SCORE ──
  const score = scan.score || 0;
  const scoreColor = score >= 75 ? green : score >= 40 ? amber : red;
  doc.roundedRect(M, doc.y, PW, 55, 5).fillColor('#f8f8f8').fill();

  const scoreY = doc.y;
  doc.fontSize(32).font('Helvetica-Bold').fillColor(scoreColor)
    .text(String(score), M, scoreY + 8, { width: 80, align: 'center' });
  doc.fontSize(7).font('Helvetica').fillColor(gray)
    .text('SCORE', M, scoreY + 42, { width: 80, align: 'center' });

  // Severity counts
  let cr = 0, hi = 0, me = 0, lo = 0;
  for (const r of scan.results) {
    for (const t of (r.results?.tests || [])) {
      if (t.status !== 'fail' && t.status !== 'warn') continue;
      if (t.severity === 'critical') cr++;
      else if (t.severity === 'high') hi++;
      else if (t.severity === 'medium') me++;
      else lo++;
    }
  }
  const sevs = [
    { label: 'Critical', val: cr, color: red },
    { label: 'High', val: hi, color: orange },
    { label: 'Medium', val: me, color: amber },
    { label: 'Low', val: lo, color: green },
  ];
  let sx = M + 100;
  for (const s of sevs) {
    doc.fontSize(14).font('Helvetica-Bold').fillColor(s.color).text(String(s.val), sx, scoreY + 12, { width: 60 });
    doc.fontSize(7).font('Helvetica').fillColor(gray).text(s.label, sx, scoreY + 28, { width: 60 });
    sx += 80;
  }

  doc.y = scoreY + 62;

  // Stats line
  doc.fontSize(9).font('Helvetica').fillColor(gray)
    .text(`Tests: ${scan.totalTests}  |  Passed: ${scan.totalPassed}  |  Failed: ${scan.totalFailed}  |  Warnings: ${scan.totalWarnings}`, M, doc.y);
  doc.y += 20;

  // ── AI ASSESSMENT ──
  if (scan.aiAnalysis && scan.aiAnalysis.analysis) {
    const rawAi = scan.aiAnalysis.analysis;
    if (rawAi.length > 10) {
      if (doc.y > 680) doc.addPage();
      doc.fontSize(14).font('Helvetica-Bold').fillColor('#111').text('AI Security Assessment', M, doc.y);
      doc.y += 3;
      doc.moveTo(M, doc.y).lineTo(M + PW, doc.y).strokeColor(green).lineWidth(1).stroke();
      doc.y += 10;

      // Helper: render a single line of text and advance doc.y by the measured height
      const renderText = (text, x, opts = {}) => {
        const font = opts.bold ? 'Helvetica-Bold' : 'Helvetica';
        const size = opts.size || 8;
        const color = opts.color || '#444';
        const w = opts.width || (PW - (x - M));
        doc.fontSize(size).font(font).fillColor(color);
        const h = doc.heightOfString(text, { width: w });
        doc.text(text, x, doc.y, { width: w });
        doc.y += h + (opts.gap || 2);
      };

      // Strip bold markers for simple rendering, detect if line has bold
      const stripBold = (s) => s.replace(/\*\*/g, '');
      const hasBold = (s) => /\*\*/.test(s);

      const lines = rawAi.split('\n');
      let inTable = false;

      for (const rawLine of lines) {
        const line = clean(rawLine);
        if (!line) { doc.y += 3; inTable = false; continue; }
        if (doc.y > 720) doc.addPage();

        // --- H1 ---
        if (line.startsWith('# ') && !line.startsWith('## ')) {
          doc.y += 4;
          renderText(stripBold(line.replace(/^#+\s*/, '')), M, { bold: true, size: 12, color: '#111', gap: 2 });
          doc.moveTo(M, doc.y).lineTo(M + PW, doc.y).strokeColor('#ddd').lineWidth(0.5).stroke();
          doc.y += 5;
          inTable = false;

        // --- H2 ---
        } else if (line.startsWith('## ') && !line.startsWith('### ')) {
          doc.y += 4;
          renderText(stripBold(line.replace(/^#+\s*/, '')), M, { bold: true, size: 10, color: '#222', gap: 2 });
          doc.moveTo(M, doc.y).lineTo(M + 180, doc.y).strokeColor('#e0e0e0').lineWidth(0.4).stroke();
          doc.y += 4;
          inTable = false;

        // --- H3/H4 ---
        } else if (/^#{3,}\s/.test(line)) {
          doc.y += 3;
          renderText(stripBold(line.replace(/^#+\s*/, '')), M, { bold: true, size: 9, color: '#333', gap: 3 });
          inTable = false;

        // --- Horizontal rule ---
        } else if (/^[-*_]{3,}$/.test(line)) {
          doc.y += 2;
          doc.moveTo(M, doc.y).lineTo(M + PW, doc.y).strokeColor('#e0e0e0').lineWidth(0.3).stroke();
          doc.y += 4;

        // --- Table rows ---
        } else if (line.startsWith('|') && line.endsWith('|')) {
          if (/^\|[\s\-:]+\|/.test(line) && !line.replace(/[\s|\-:]/g, '')) {
            inTable = true; continue;
          }
          const cells = line.split('|').filter(c => c.trim()).map(c => stripBold(clean(c)));
          if (cells.length === 0) continue;
          const colW = Math.floor(PW / cells.length);
          const isHeader = !inTable;
          if (isHeader) {
            doc.roundedRect(M, doc.y - 1, PW, 13, 2).fillColor('#f0f0f0').fill();
          }
          const font = isHeader ? 'Helvetica-Bold' : 'Helvetica';
          const fsize = 7;
          cells.forEach((cell, i) => {
            doc.fontSize(fsize).font(font).fillColor('#333')
              .text(cell.substring(0, 45), M + i * colW + 3, doc.y + 1, { width: colW - 6, lineBreak: false });
          });
          doc.y += 13;
          inTable = true;

        // --- Bullet points ---
        } else if (/^\s*[-*]\s/.test(rawLine)) {
          const indent = Math.min((rawLine.match(/^(\s*)/)[1].length || 0), 6);
          const bulletX = M + 8 + indent * 3;
          const text = stripBold(line.replace(/^[-*]\s*/, ''));
          doc.circle(bulletX, doc.y + 3, 1.5).fillColor('#666').fill();
          const isBold = hasBold(line);
          renderText(text, bulletX + 5, { bold: isBold, size: 8, width: PW - (bulletX + 5 - M) - 5, gap: 2 });
          inTable = false;

        // --- Numbered lists ---
        } else if (/^\d+[.)]\s/.test(line)) {
          const num = line.match(/^(\d+[.)])/)[1];
          const text = stripBold(line.replace(/^\d+[.)]\s*/, ''));
          doc.fontSize(8).font('Helvetica-Bold').fillColor('#555').text(num, M + 4, doc.y, { width: 18 });
          const isBold = hasBold(line);
          renderText(text, M + 22, { bold: isBold, size: 8, width: PW - 30, gap: 3 });
          inTable = false;

        // --- Regular paragraph ---
        } else {
          inTable = false;
          const isBold = hasBold(line);
          renderText(stripBold(line), M, { bold: isBold, size: 8, gap: 2 });
        }
      }
      doc.y += 10;
    }
  }

  // ── SCANNER RESULTS ──
  doc.fontSize(14).font('Helvetica-Bold').fillColor('#111').text('Scanner Results', M, doc.y);
  doc.y += 3;
  doc.moveTo(M, doc.y).lineTo(M + PW, doc.y).strokeColor(green).lineWidth(0.5).stroke();
  doc.y += 10;

  for (const r of scan.results) {
    const tests = r.results?.tests || [];
    const fails = tests.filter(t => t.status === 'fail');
    const warns = tests.filter(t => t.status === 'warn');
    const passes = tests.filter(t => t.status === 'pass');

    let badge;
    if (tests.length === 0) badge = 'No issues';
    else if (fails.length) badge = `${fails.length} fail${warns.length ? `, ${warns.length} warn` : ''}`;
    else if (warns.length) badge = `${warns.length} warn`;
    else badge = `${passes.length} passed`;

    // Check page space
    if (doc.y > 720) doc.addPage();

    // Scanner header bar
    doc.roundedRect(M, doc.y, PW, 18, 3).fillColor('#f8f8f8').fill();
    doc.fontSize(9).font('Helvetica-Bold').fillColor('#111')
      .text(clean(r.scanner || 'Unknown'), M + 5, doc.y + 5, { width: PW - 100 });
    const badgeColor = fails.length ? red : warns.length ? amber : green;
    doc.fontSize(7).font('Helvetica-Bold').fillColor(badgeColor)
      .text(badge, M + PW - 95, doc.y + 6, { width: 90, align: 'right' });
    doc.y += 22;

    // Test rows
    const show = [...fails, ...warns, ...passes.slice(0, 8)];
    const remaining = tests.length - show.length;

    if (tests.length === 0) {
      doc.fontSize(7.5).font('Helvetica-Oblique').fillColor(gray).text('No data returned', M + 10, doc.y);
      doc.y += 12;
    } else {
      for (const t of show) {
        if (doc.y > 740) doc.addPage();
        const dotColor = t.status === 'fail' ? red : t.status === 'warn' ? amber : green;
        doc.circle(M + 8, doc.y + 2, 2).fillColor(dotColor).fill();
        doc.fontSize(7.5).font('Helvetica').fillColor('#111')
          .text(clean(t.name).substring(0, 95), M + 14, doc.y - 1, { width: PW - 70 });
        const sevLabel = t.status === 'pass' ? 'INFO' : (t.severity || 'info').toUpperCase();
        doc.fontSize(6.5).font('Helvetica-Bold').fillColor(dotColor)
          .text(sevLabel, M + PW - 50, doc.y - 1, { width: 45, align: 'right' });
        doc.y += 11;
      }
      if (remaining > 0) {
        doc.fontSize(7).font('Helvetica-Oblique').fillColor(gray)
          .text(`+ ${remaining} more passed...`, M + 14, doc.y);
        doc.y += 11;
      }
    }
    doc.y += 5;
  }

  // ── FOOTER ──
  if (doc.y > 740) doc.addPage();
  doc.moveTo(M, doc.y).lineTo(M + PW, doc.y).strokeColor('#e0e0e0').lineWidth(0.5).stroke();
  doc.y += 8;
  doc.fontSize(8).font('Helvetica').fillColor(gray)
    .text('Synthrex Security Report  |  Built by Gaurav Batule  |  synthrex.in', M, doc.y, { width: PW, align: 'center' });

  // Page numbers
  const pages = doc.bufferedPageRange();
  for (let i = pages.start; i < pages.start + pages.count; i++) {
    doc.switchToPage(i);
    doc.fontSize(7).font('Helvetica').fillColor(gray)
      .text(`Page ${i + 1} of ${pages.count}`, M, 15, { width: PW, align: 'right' });
  }

  doc.end();
  console.log(`[PDF] Export successful for ${scan.target}`);
});

// Scanner list for UI
app.get('/api/scanners', (req, res) => {
  res.json(SCANNERS.map(s => ({ id: s.id, name: s.name, icon: s.icon })));

});

// Only listen locally (Vercel uses module.exports)
if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   ⚡ Synthrex — AI Security Scanner v2.0                 ║
║   ──────────────────────────────────────                 ║
║   Server running at http://localhost:${PORT}               ║
║                                                          ║
║   18 Scanner Modules | 1500+ Security Tests              ║
║   AI-Powered Analysis via Groq API                       ║
║   Built by Gaurav Batule                                 ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
    `);
  });
}

// Export for Vercel serverless
module.exports = app;
