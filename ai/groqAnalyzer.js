const axios = require('axios');

const GROQ_API_KEY = process.env.GROQ_API_KEY || '';
const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';
const MODEL = 'openai/gpt-oss-120b';

async function analyze(scanResults, targetUrl) {
  if (!GROQ_API_KEY) {
    return { success: false, error: 'GROQ_API_KEY not set in .env', fallbackAnalysis: generateFallbackAnalysis(scanResults, targetUrl) };
  }
  try {
    const summary = buildSummary(scanResults, targetUrl);
    const response = await axios.post(GROQ_API_URL, {
      messages: [
        {
          role: 'system',
          content: `You are an expert cybersecurity analyst and penetration tester. Analyze security scan results and provide:

1. **Executive Summary** — Brief overview of security posture
2. **Critical Findings** — Most severe vulnerabilities, sorted by risk
3. **Detailed Analysis** — Category-by-category breakdown with remediation
4. **Risk Score** — Rate 0-100 (100 = fully secure)
5. **Remediation Priority** — What to fix first
6. **Recommendations** — Specific improvement steps

Use: 🔴 Critical | 🟠 High | 🟡 Medium | 🔵 Low | ⚪ Info`
        },
        { role: 'user', content: `Analyze these security scan results for ${targetUrl}:\n\n${summary}` }
      ],
      model: MODEL, temperature: 0.7, max_completion_tokens: 8192, top_p: 1, stream: false, stop: null
    }, {
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${GROQ_API_KEY}` },
      timeout: 120000
    });
    return { success: true, analysis: response.data.choices[0].message.content, model: MODEL, usage: response.data.usage };
  } catch (err) {
    console.error('Groq API error:', err.response?.data || err.message);
    return { success: false, error: err.response?.data?.error?.message || err.message, fallbackAnalysis: generateFallbackAnalysis(scanResults, targetUrl) };
  }
}

function buildSummary(scanResults, targetUrl) {
  let s = `# Security Scan Report for ${targetUrl}\n\n`;
  let totalTests = 0, totalFails = 0, totalWarns = 0;
  for (const r of scanResults) {
    s += `## ${r.icon} ${r.scanner}\n`;
    const tests = r.results?.tests || [];
    totalTests += tests.length;
    const fails = tests.filter(t => t.status === 'fail');
    const warns = tests.filter(t => t.status === 'warn');
    totalFails += fails.length;
    totalWarns += warns.length;
    if (fails.length > 0) {
      s += `### Failures (${fails.length}):\n`;
      for (const f of fails.slice(0, 20)) s += `- [${f.severity.toUpperCase()}] ${f.name}\n`;
    }
    if (warns.length > 0) {
      s += `### Warnings (${warns.length}):\n`;
      for (const w of warns.slice(0, 10)) s += `- [${w.severity.toUpperCase()}] ${w.name}\n`;
    }
    if (r.results?.findings) { s += `### Findings:\n`; for (const f of r.results.findings.slice(0, 10)) s += `- ${JSON.stringify(f)}\n`; }
    if (r.results?.found) { s += `### Discovered:\n`; for (const f of r.results.found.slice(0, 15)) s += `- ${f.name || f.path}: severity=${f.severity}\n`; }
    if (r.results?.technologies) { s += `### Technologies:\n`; for (const t of r.results.technologies) s += `- ${t.name} (${t.category})\n`; }
    if (r.results?.open) { s += `### Open Ports:\n`; for (const p of r.results.open) s += `- Port ${p.port} (${p.service}): severity=${p.severity}\n`; }
    s += '\n';
  }
  s += `\n## Summary\n- Total tests: ${totalTests}\n- Failures: ${totalFails}\n- Warnings: ${totalWarns}\n`;
  return s;
}

function generateFallbackAnalysis(scanResults, targetUrl) {
  let totalTests = 0, fails = 0, warns = 0, criticals = 0;
  for (const r of scanResults) {
    const tests = r.results?.tests || [];
    totalTests += tests.length;
    fails += tests.filter(t => t.status === 'fail').length;
    warns += tests.filter(t => t.status === 'warn').length;
    criticals += tests.filter(t => t.status === 'fail' && t.severity === 'critical').length;
  }
  const score = Math.max(0, Math.min(100, 100 - (criticals * 15) - (fails * 3) - (warns * 1)));
  return `# Security Assessment for ${targetUrl}\n\n## Risk Score: ${score}/100\n\n- **${totalTests}** total tests\n- **${fails}** failures\n- **${warns}** warnings\n- **${criticals}** critical\n\n*Set GROQ_API_KEY in .env for full AI analysis.*`;
}

module.exports = { analyze };
