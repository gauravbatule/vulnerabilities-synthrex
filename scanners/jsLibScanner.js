const axios = require('axios');
const cheerio = require('cheerio');

// Known vulnerable library patterns
const VULN_LIBS = [
  { pattern: /jquery[\/.-](\d+\.\d+\.\d+)/i, name: 'jQuery', eol: '3.6.0' },
  { pattern: /angular[\/.-](\d+\.\d+\.\d+)/i, name: 'AngularJS', eol: '1.8.0' },
  { pattern: /bootstrap[\/.-](\d+\.\d+\.\d+)/i, name: 'Bootstrap', eol: '5.0.0' },
  { pattern: /react[\/.-](\d+\.\d+\.\d+)/i, name: 'React', eol: '18.0.0' },
  { pattern: /vue[\/.-](\d+\.\d+\.\d+)/i, name: 'Vue.js', eol: '3.0.0' },
  { pattern: /lodash[\/.-](\d+\.\d+\.\d+)/i, name: 'Lodash', eol: '4.17.21' },
  { pattern: /moment[\/.-](\d+\.\d+\.\d+)/i, name: 'Moment.js', eol: '2.29.0' },
  { pattern: /d3[\/.-]v?(\d+\.\d+\.\d+)/i, name: 'D3.js', eol: '7.0.0' },
  { pattern: /backbone[\/.-](\d+\.\d+\.\d+)/i, name: 'Backbone.js', eol: '1.4.0' },
  { pattern: /ember[\/.-](\d+\.\d+\.\d+)/i, name: 'Ember.js', eol: '4.0.0' },
  { pattern: /underscore[\/.-](\d+\.\d+\.\d+)/i, name: 'Underscore.js', eol: '1.13.0' },
  { pattern: /handlebars[\/.-](\d+\.\d+\.\d+)/i, name: 'Handlebars', eol: '4.7.0' },
  { pattern: /knockout[\/.-](\d+\.\d+\.\d+)/i, name: 'Knockout.js', eol: '3.5.0' },
  { pattern: /prototype[\/.-](\d+\.\d+\.\d+)/i, name: 'Prototype.js', eol: '1.7.3' },
  { pattern: /mootools[\/.-](\d+\.\d+\.\d+)/i, name: 'MooTools', eol: '1.6.0' },
];

// Known critically vulnerable versions
const KNOWN_VULNS = {
  'jQuery': [
    { below: '1.12.0', cve: 'CVE-2015-9251', severity: 'medium' },
    { below: '3.5.0', cve: 'CVE-2020-11022', severity: 'medium' },
  ],
  'AngularJS': [
    { below: '1.6.0', cve: 'CVE-2019-14863', severity: 'high' },
  ],
  'Bootstrap': [
    { below: '3.4.0', cve: 'CVE-2018-14040', severity: 'medium' },
  ],
  'Lodash': [
    { below: '4.17.12', cve: 'CVE-2019-10744', severity: 'critical' },
    { below: '4.17.21', cve: 'CVE-2021-23337', severity: 'high' },
  ],
};

function versionBelow(v1, v2) {
  const a = v1.split('.').map(Number);
  const b = v2.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((a[i] || 0) < (b[i] || 0)) return true;
    if ((a[i] || 0) > (b[i] || 0)) return false;
  }
  return false;
}

async function scan(targetUrl) {
  const results = { tests: [], libraries: [] };
  try {
    const r = await axios.get(targetUrl, {
      timeout: 10000, maxRedirects: 3, validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
    });
    const body = typeof r.data === 'string' ? r.data : '';
    const $ = cheerio.load(body);

    // Collect all script sources
    const scriptSrcs = [];
    $('script[src]').each((_, el) => scriptSrcs.push($(el).attr('src') || ''));
    const allText = body + '\n' + scriptSrcs.join('\n');

    // Detect libraries
    const detected = new Set();
    for (const lib of VULN_LIBS) {
      const match = allText.match(lib.pattern);
      if (match && !detected.has(lib.name)) {
        detected.add(lib.name);
        const version = match[1];
        results.libraries.push({ name: lib.name, version });

        // Check known vulns
        const vulns = KNOWN_VULNS[lib.name] || [];
        let hasVuln = false;
        for (const v of vulns) {
          if (versionBelow(version, v.below)) {
            results.tests.push({ id: `jslib-vuln-${lib.name}`, name: `${lib.name} ${version} — ${v.cve}`, status: 'fail', severity: v.severity });
            hasVuln = true;
            break;
          }
        }

        if (!hasVuln) {
          // Check if outdated (below recommended)
          if (versionBelow(version, lib.eol)) {
            results.tests.push({ id: `jslib-outdated-${lib.name}`, name: `${lib.name} ${version} (outdated, latest ≥${lib.eol})`, status: 'warn', severity: 'low' });
          } else {
            results.tests.push({ id: `jslib-ok-${lib.name}`, name: `${lib.name} ${version} — up to date`, status: 'pass', severity: 'info' });
          }
        }
      }
    }

    // Check for inline scripts (XSS surface)
    const inlineScripts = $('script:not([src])').length;
    if (inlineScripts > 5) {
      results.tests.push({ id: 'jslib-inline-many', name: `${inlineScripts} inline scripts (large attack surface)`, status: 'warn', severity: 'low' });
    } else {
      results.tests.push({ id: 'jslib-inline', name: `${inlineScripts} inline scripts`, status: 'pass', severity: 'info' });
    }

    // Check for source maps
    const hasSourceMaps = body.includes('sourceMappingURL') || body.includes('sourceURL');
    results.tests.push({ id: 'jslib-sourcemaps', name: 'JavaScript source maps exposed', status: hasSourceMaps ? 'warn' : 'pass', severity: hasSourceMaps ? 'low' : 'info' });

    if (detected.size === 0) {
      results.tests.push({ id: 'jslib-none', name: 'No known JS libraries detected in page source', status: 'pass', severity: 'info' });
    }

  } catch (err) {
    results.error = err.message;
  }
  return { scanner: 'JS Library Scanner', icon: '📚', results, testCount: results.tests.length };
}

module.exports = { scan };
