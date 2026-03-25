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

// AI Analyzer
const groqAnalyzer = require('./ai/groqAnalyzer');

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
];

function normalizeUrl(input) {
  let url = input.trim();
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }
  return url;
}

// Blocked domains (require bypass)
const BLOCKED_DOMAINS = ['satkarya.in', 'www.satkarya.in'];

function isDomainBlocked(targetUrl) {
  try {
    const u = new URL(targetUrl);
    return BLOCKED_DOMAINS.includes(u.hostname.toLowerCase());
  } catch { return false; }
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
  const paths = ['/.well-known/security.txt', '/security.txt'];
  for (const p of paths) {
    try {
      const u = new URL(targetUrl);
      const checkUrl = `${u.protocol}//${u.host}${p}`;
      const r = await axios.get(checkUrl, { timeout: 5000, validateStatus: () => true, headers: { 'User-Agent': ua } });
      if (r.status === 200 && typeof r.data === 'string' && r.data.length > 20 && r.data.toLowerCase().includes('contact')) {
        return true;
      }
    } catch { /* skip */ }
  }
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

  // Blocked domains
  if (isDomainBlocked(targetUrl)) {
    const bypass = req.body.bypass;
    if (bypass !== '1') {
      return res.json({ allowed: false, reason: 'blocked' });
    }
    return res.json({ allowed: true, method: 'bypass' });
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
  const { target, bypass, accessCode } = req.body;
  if (!target) return res.status(400).json({ error: 'Target URL is required' });

  const targetUrl = normalizeUrl(target);

  // Validate domain exists
  const validation = await validateDomain(targetUrl);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.error });
  }

  // Block protected domains unless bypass=1
  if (isDomainBlocked(targetUrl) && bypass !== '1') {
    return res.status(403).json({ error: 'This domain is protected. Add ?=1 to the page URL to bypass.' });
  }

  // Authorization check: security.txt or access code
  if (!isDomainBlocked(targetUrl) || bypass === '1') {
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

async function runScan(scanId, targetUrl) {
  const scan = scans.get(scanId);
  if (!scan) return;

  for (let i = 0; i < SCANNERS.length; i++) {
    const { id, scanner, name, icon } = SCANNERS[i];
    scan.currentScanner = name;
    scan.progress = Math.round(((i) / SCANNERS.length) * 100);

    try {
      console.log(`[${scanId.substring(0,8)}] Running: ${name}...`);
      const result = await scanner.scan(targetUrl);
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
  console.log(`[${scanId.substring(0,8)}] Scan completed. Total: ${scan.totalTests} tests, ${scan.totalFailed} fails, ${scan.totalWarnings} warns`);
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
