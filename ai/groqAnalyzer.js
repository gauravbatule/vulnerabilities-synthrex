const axios = require('axios');

const GROQ_API_KEY = process.env.GROQ_API_KEY || '';
const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';
// Primary and fallback models (verified working on Groq)
const MODELS = ['llama-3.3-70b-versatile', 'llama-3.1-8b-instant', 'gemma2-9b-it'];
const MODEL = MODELS[0];

async function analyze(scanResults, targetUrl, computedScore) {
  if (!GROQ_API_KEY) {
    return { success: false, error: 'GROQ_API_KEY not set in .env', fallbackAnalysis: generateFallbackAnalysis(scanResults, targetUrl) };
  }
  try {
    const summary = buildSummary(scanResults, targetUrl, computedScore);
    const response = await axios.post(GROQ_API_URL, {
      messages: [
        {
          role: 'system',
          content: `You are an expert cybersecurity analyst and penetration tester. Analyze security scan results and provide:

1. **Executive Summary** — Brief overview of security posture
2. **Critical Findings** — Most severe vulnerabilities, sorted by risk
3. **Detailed Analysis** — Category-by-category breakdown with remediation
4. **Risk Score** — The computed score is already calculated; use exactly ${computedScore !== undefined ? computedScore : 'N/A'}/100 in your report
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
    const errMsg = err.response?.data?.error?.message || err.message;
    console.error('Groq API error:', errMsg);
    
    // If primary model fails, try fallback models
    for (let i = 1; i < MODELS.length; i++) {
      try {
        console.log(`[AI] Retrying with fallback model: ${MODELS[i]}...`);
        const summary = buildSummary(scanResults, targetUrl, computedScore);
        const response = await axios.post(GROQ_API_URL, {
          messages: [
            {
              role: 'system',
              content: `You are an expert cybersecurity analyst and penetration tester. Analyze security scan results and provide:

1. **Executive Summary** — Brief overview of security posture
2. **Critical Findings** — Most severe vulnerabilities, sorted by risk
3. **Detailed Analysis** — Category-by-category breakdown with remediation
4. **Risk Score** — The computed score is already calculated; use exactly ${computedScore !== undefined ? computedScore : 'N/A'}/100 in your report
5. **Remediation Priority** — What to fix first
6. **Recommendations** — Specific improvement steps

Use: 🔴 Critical | 🟠 High | 🟡 Medium | 🔵 Low | ⚪ Info`
            },
            { role: 'user', content: `Analyze these security scan results for ${targetUrl}:\n\n${summary}` }
          ],
          model: MODELS[i], temperature: 0.7, max_completion_tokens: 8192, top_p: 1, stream: false, stop: null
        }, {
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${GROQ_API_KEY}` },
          timeout: 120000
        });
        return { success: true, analysis: response.data.choices[0].message.content, model: MODELS[i], usage: response.data.usage };
      } catch (retryErr) {
        console.error(`[AI] Fallback model ${MODELS[i]} also failed:`, retryErr.response?.data?.error?.message || retryErr.message);
      }
    }
    
    return { success: false, error: errMsg, fallbackAnalysis: generateFallbackAnalysis(scanResults, targetUrl) };
  }
}

function buildSummary(scanResults, targetUrl, computedScore) {
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
      for (const f of fails.slice(0, 20)) s += `- [${(f.severity || 'unknown').toUpperCase()}] ${f.name}\n`;
    }
    if (warns.length > 0) {
      s += `### Warnings (${warns.length}):\n`;
      for (const w of warns.slice(0, 10)) s += `- [${(w.severity || 'unknown').toUpperCase()}] ${w.name}\n`;
    }
    if (r.results?.findings) { s += `### Findings:\n`; for (const f of r.results.findings.slice(0, 10)) s += `- ${JSON.stringify(f)}\n`; }
    if (r.results?.found) { s += `### Discovered:\n`; for (const f of r.results.found.slice(0, 15)) s += `- ${f.name || f.path}: severity=${f.severity}\n`; }
    if (r.results?.technologies) { s += `### Technologies:\n`; for (const t of r.results.technologies) s += `- ${t.name} (${t.category})\n`; }
    if (r.results?.open) { s += `### Open Ports:\n`; for (const p of r.results.open) s += `- Port ${p.port} (${p.service}): severity=${p.severity}\n`; }
    s += '\n';
  }
  s += `\n## Summary\n- Total tests: ${totalTests}\n- Failures: ${totalFails}\n- Warnings: ${totalWarns}\n- Computed Security Score: ${computedScore !== undefined ? computedScore : 'N/A'}/100\n`;
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
  // Use per-scanner equal weighting to match server/client
  const scannerScores = [];
  for (const r of scanResults) {
    const tests = r.results?.tests || [];
    let sFails = 0, sTotal = tests.length;
    for (const t of tests) {
      if (t.status !== 'fail' && t.status !== 'warn') continue;
      if (t.status === 'fail') sFails += (t.severity === 'critical' ? 3 : t.severity === 'high' ? 2 : 1);
      else sFails += 0.5;
    }
    if (sTotal > 0) scannerScores.push(Math.max(0, 100 - ((sFails / Math.max(1, sTotal)) * 100)));
    else scannerScores.push(100);
  }
  const score = scannerScores.length > 0 ? Math.round(scannerScores.reduce((a, b) => a + b, 0) / scannerScores.length) : 100;
  return `# Security Assessment for ${targetUrl}\n\n## Risk Score: ${score}/100\n\n- **${totalTests}** total tests\n- **${fails}** failures\n- **${warns}** warnings\n- **${criticals}** critical\n\n*Set GROQ_API_KEY in .env for full AI analysis.*`;
}

module.exports = { analyze };
