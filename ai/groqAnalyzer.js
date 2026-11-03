const axios = require('axios');

const GROQ_API_KEY = process.env.GROQ_API_KEY || '';
const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';
const GROQ_MODELS_URL = 'https://api.groq.com/openai/v1/models';

// Prioritized list of supported Groq models
const PREFERRED_MODELS = [
  'openai/gpt-oss-120b',
  'qwen/qwen3.8-27b',
  'openai/gpt-oss-20b',
  'llama-3.3-70b-versatile',
  'llama-3.1-8b-instant'
];

let cachedAvailableModels = null;
let lastCacheTime = 0;

async function getAvailableModels(apiKey) {
  if (cachedAvailableModels && (Date.now() - lastCacheTime < 3600000)) {
    return cachedAvailableModels;
  }
  try {
    const res = await axios.get(GROQ_MODELS_URL, {
      headers: { 'Authorization': `Bearer ${apiKey}` },
      timeout: 8000
    });
    if (res.data && Array.isArray(res.data.data)) {
      const ids = new Set(res.data.data.map(m => m.id));
      const filtered = PREFERRED_MODELS.filter(m => ids.has(m));
      if (filtered.length > 0) {
        cachedAvailableModels = filtered;
        lastCacheTime = Date.now();
        return cachedAvailableModels;
      }
    }
  } catch (err) {
    // If listing models fails, use default list
  }
  return PREFERRED_MODELS;
}

async function analyze(scanResults, targetUrl, computedScore) {
  const apiKey = process.env.GROQ_API_KEY || GROQ_API_KEY;
  if (!apiKey) {
    return {
      success: false,
      error: 'GROQ_API_KEY not set',
      fallbackAnalysis: generateFallbackAnalysis(scanResults, targetUrl, computedScore, false)
    };
  }

  const models = await getAvailableModels(apiKey);
  const summary = buildSummary(scanResults, targetUrl, computedScore);

  let lastError = null;
  for (const model of models) {
    try {
      console.log(`[AI] Requesting security analysis using model: ${model}...`);
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
        model: model,
        temperature: 0.7,
        max_completion_tokens: 4096,
        top_p: 1,
        stream: false
      }, {
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
        timeout: 25000
      });

      if (response.data?.choices && response.data.choices[0]?.message?.content) {
        return {
          success: true,
          analysis: response.data.choices[0].message.content,
          model: model,
          usage: response.data.usage
        };
      }
    } catch (err) {
      lastError = err.response?.data?.error?.message || err.message;
      console.warn(`[AI] Model ${model} failed: ${lastError}`);
    }
  }

  return {
    success: false,
    error: lastError || 'AI analysis failed',
    fallbackAnalysis: generateFallbackAnalysis(scanResults, targetUrl, computedScore, true)
  };
}

function buildSummary(scanResults, targetUrl, computedScore) {
  let s = `# Security Scan Report for ${targetUrl}\n\n`;
  let totalTests = 0, totalFails = 0, totalWarns = 0;
  for (const r of scanResults) {
    s += `## ${r.icon || '🔍'} ${r.scanner}\n`;
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

function generateFallbackAnalysis(scanResults, targetUrl, computedScore, hasKey) {
  let totalTests = 0, fails = 0, warns = 0, criticals = 0;
  for (const r of scanResults) {
    const tests = r.results?.tests || [];
    totalTests += tests.length;
    fails += tests.filter(t => t.status === 'fail').length;
    warns += tests.filter(t => t.status === 'warn').length;
    criticals += tests.filter(t => t.status === 'fail' && t.severity === 'critical').length;
  }
  const score = computedScore !== undefined ? computedScore : 100;
  const note = hasKey
    ? '*Automated statistical summary. Live Groq model generation could not be completed.*'
    : '*Set GROQ_API_KEY in environment variables for full AI analysis.*';

  return `# Security Assessment for ${targetUrl}\n\n## Risk Score: ${score}/100\n\n- **${totalTests}** total tests\n- **${fails}** failures\n- **${warns}** warnings\n- **${criticals}** critical\n\n${note}`;
}

module.exports = { analyze };
