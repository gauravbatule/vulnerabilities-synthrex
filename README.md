# Synthrex — AI-Powered Security Scanner

**Comprehensive website security scanning with 18 specialized modules and AI-powered analysis.**

Built by [Gaurav Batule](https://www.linkedin.com/in/gaurav-batule/) · Live at [synthrex.in](https://synthrex.in)

---

## Features

- **18 Security Modules** — Headers, SSL/TLS, XSS, SQL Injection, CORS, WAF Detection, Port Scanning, DNS, Subdomains, Clickjacking, Open Redirects, Form Security, Cookie Analysis, Technology Detection, Information Leakage, HTTP Methods, Advanced Injections (Command Injection, SSTI, LFI, SSRF, LDAP, XXE), Performance
- **AI Analysis** — Automated security assessment with actionable remediation via Groq API
- **PDF Reports** — Client-side report generation with full scan results
- **Authorization System** — Pre-scan `security.txt` check + access code verification (`9921`)
- **Domain Validation** — DNS resolution + HTTP reachability check before scanning
- **Identity Protection** — Standard Chrome User-Agent, stripped server headers, no tool fingerprinting
- **Production-Ready UI** — Dark theme, glassmorphism modals, circular progress ring, responsive design

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Node.js, Express |
| Frontend | Vanilla HTML/CSS/JS |
| Scanning | Axios, Cheerio, TLS, Net, DNS |
| AI | Groq API (LLaMA 3) |
| Styling | Inter + JetBrains Mono fonts |
| Reports | html2pdf.js, Marked.js |
| Deployment | Vercel (Serverless) |

## Quick Start

```bash
# Clone
git clone https://github.com/gauravbatule/vulnerabilities-synthrex.git
cd vulnerabilities-synthrex

# Install
npm install

# Configure
cp .env.example .env
# Add your GROQ_API_KEY to .env

# Run
node server.js
# Open http://localhost:3000
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GROQ_API_KEY` | Yes | API key from [console.groq.com](https://console.groq.com) |
| `PORT` | No | Server port (default: 3000) |

## Authorization Flow

1. User enters a domain and clicks **Scan**
2. Fullscreen loader appears — "Verifying target…"
3. Server validates DNS resolution and HTTP reachability
4. Server checks for `/.well-known/security.txt` or `/security.txt`
5. **If found** → scan proceeds automatically
6. **If not found** → user must enter access code `9921`
7. Scan runs across all 18 modules with live circular progress
8. AI analysis generates a security assessment report

## Security & Privacy

- **No analytics, cookies, or trackers**
- **No user accounts** — fully anonymous usage
- **In-memory only** — scan results cleared on server restart
- **PDF reports generated client-side** in the browser
- **Server identity hidden** — `X-Powered-By`, `Server` headers removed
- **Standard User-Agent** — all requests use Chrome 131 UA
- **Your IP is never exposed** — only the hosting server's IP appears in target logs

## Scanner Modules

| # | Module | Tests | Description |
|---|--------|-------|-------------|
| 1 | Security Headers | 25+ | CSP, HSTS, X-Frame-Options, Permissions-Policy |
| 2 | SSL/TLS | 25+ | Certificate validity, protocol version, cipher strength |
| 3 | Port Scanner | 50 | TCP connect scan on common service ports |
| 4 | CORS | 15+ | Origin reflection, wildcard, credential handling |
| 5 | Information Leakage | 285+ | Config files, VCS, backups, admin panels, API docs |
| 6 | Technology Detection | 20+ | CMS, frameworks, CDNs, analytics, libraries |
| 7 | Cookie Security | 10+ | Secure, HttpOnly, SameSite, Path, Expiry |
| 8 | DNS & Email | 15+ | DNSSEC, SPF, DKIM, DMARC, MX records |
| 9 | Subdomain Discovery | 50+ | Common subdomain enumeration |
| 10 | XSS | 80+ | Reflected payload testing across parameters |
| 11 | SQL Injection | 60+ | Error-based and time-based detection |
| 12 | Clickjacking | 10+ | X-Frame-Options, CSP frame-ancestors |
| 13 | Open Redirects | 28+ | Parameter and evasion payload testing |
| 14 | Form Security | 15+ | CSRF tokens, method, encoding, input validation |
| 15 | HTTP Methods | 10+ | Dangerous method detection (PUT, DELETE, TRACE) |
| 16 | WAF Detection | 15+ | Firewall identification and bypass testing |
| 17 | Performance | 10+ | TTFB, page size, compression, caching |
| 18 | Advanced Injections | 200+ | Command injection, SSTI, LFI, SSRF, LDAP, XXE |

## Deployment (Vercel)

```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel --prod
```

The `vercel.json` includes security headers and serverless function configuration.

## Legal

All responsibility for scanning lies with the user. See [Terms & Privacy](https://synthrex.in/privacy.html).

**Do not scan websites without explicit authorization.**

## License

MIT © [Gaurav Batule](https://www.linkedin.com/in/gaurav-batule/)
