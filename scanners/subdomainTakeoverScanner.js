const axios = require('axios');
const dns = require('dns').promises;

// Subdomain Takeover Scanner
// Resolves CNAME records and checks if they point to unclaimed services
// FP prevention: Requires BOTH (1) CNAME to known service AND (2) service-specific "not found" fingerprint
// FN prevention: Checks 20+ subdomains × 15+ service fingerprints

const SUBDOMAINS_TO_CHECK = [
  'blog', 'shop', 'store', 'app', 'dev', 'staging', 'test', 'beta',
  'cdn', 'assets', 'static', 'media', 'img', 'images',
  'mail', 'email', 'support', 'help', 'docs', 'wiki',
  'api', 'status', 'portal', 'dashboard', 'admin',
];

// Service fingerprints: CNAME pattern + HTTP response fingerprint
const VULNERABLE_SERVICES = [
  {
    name: 'GitHub Pages',
    cnames: ['github.io', 'github.com'],
    fingerprints: ["There isn't a GitHub Pages site here", 'For root URLs (like http://example.com/)'],
  },
  {
    name: 'Amazon S3',
    cnames: ['s3.amazonaws.com', 's3-website', '.s3.', 's3.us-', 's3.eu-', 's3.ap-'],
    fingerprints: ['NoSuchBucket', 'The specified bucket does not exist'],
  },
  {
    name: 'Heroku',
    cnames: ['herokuapp.com', 'herokussl.com', 'herokudns.com'],
    fingerprints: ['No such app', 'no-such-app', 'herokucdn.com/error-pages'],
  },
  {
    name: 'Azure',
    cnames: ['azurewebsites.net', 'cloudapp.azure.com', 'blob.core.windows.net', 'azure-api.net', 'azureedge.net', 'trafficmanager.net'],
    fingerprints: ['404 Web Site not found', 'The resource you are looking for has been removed'],
  },
  {
    name: 'Shopify',
    cnames: ['myshopify.com'],
    fingerprints: ['Sorry, this shop is currently unavailable', 'Only one step left'],
  },
  {
    name: 'Fastly',
    cnames: ['fastly.net', 'fastlylb.net'],
    fingerprints: ['Fastly error: unknown domain'],
  },
  {
    name: 'Pantheon',
    cnames: ['pantheonsite.io'],
    fingerprints: ['404 error unknown site', 'The gods are wise'],
  },
  {
    name: 'Tumblr',
    cnames: ['domains.tumblr.com'],
    fingerprints: ["There's nothing here", "Whatever you were looking for doesn't currently exist"],
  },
  {
    name: 'WordPress.com',
    cnames: ['wordpress.com'],
    fingerprints: ["doesn't exist", 'Do you want to register'],
  },
  {
    name: 'Surge.sh',
    cnames: ['surge.sh'],
    fingerprints: ['project not found'],
  },
  {
    name: 'Bitbucket',
    cnames: ['bitbucket.io'],
    fingerprints: ['Repository not found'],
  },
  {
    name: 'Ghost',
    cnames: ['ghost.io'],
    fingerprints: ['The thing you were looking for is no longer here'],
  },
  {
    name: 'Netlify',
    cnames: ['netlify.app', 'netlify.com'],
    fingerprints: ['Not Found - Request ID'],
  },
  {
    name: 'Fly.io',
    cnames: ['fly.dev'],
    fingerprints: ['404 Not Found'],
  },
  {
    name: 'Vercel',
    cnames: ['vercel.app', 'now.sh', 'zeit.co'],
    fingerprints: ['The deployment could not be found', 'DEPLOYMENT_NOT_FOUND'],
  },
];

const SCANNER_TIMEOUT = 50000;

async function scan(targetUrl) {
  const results = { findings: [], tests: [] };
  const deadline = Date.now() + SCANNER_TIMEOUT;

  try {
    const url = new URL(targetUrl);
    const domain = url.hostname;

    let checkedCount = 0;
    let vulnerable = 0;

    for (const sub of SUBDOMAINS_TO_CHECK) {
      if (Date.now() > deadline) break;

      const fqdn = `${sub}.${domain}`;

      try {
        // Step 1: Resolve CNAME
        let cnames = [];
        try {
          cnames = await dns.resolveCname(fqdn);
        } catch (err) {
          // NXDOMAIN or no CNAME — skip
          if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') continue;
          continue;
        }

        if (cnames.length === 0) continue;
        checkedCount++;

        const cnameStr = cnames.join(', ').toLowerCase();

        // Step 2: Check if CNAME points to a known vulnerable service
        for (const service of VULNERABLE_SERVICES) {
          const matchesCname = service.cnames.some(c => cnameStr.includes(c.toLowerCase()));
          if (!matchesCname) continue;

          // Step 3: HTTP request to check for service "not found" fingerprint
          try {
            const httpResp = await axios.get(`http://${fqdn}`, {
              timeout: 6000, maxRedirects: 3, validateStatus: () => true,
              headers: { 'Host': fqdn, 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
            });

            const body = typeof httpResp.data === 'string' ? httpResp.data : '';
            const matchesFingerprint = service.fingerprints.some(fp => body.includes(fp));

            if (matchesFingerprint) {
              vulnerable++;
              results.findings.push({
                subdomain: fqdn, cname: cnameStr, service: service.name,
              });
              results.tests.push({
                id: `takeover-${sub}`,
                name: `TAKEOVER: ${fqdn} → ${service.name} (CNAME: ${cnameStr})`,
                status: 'fail', severity: 'critical'
              });
            } else {
              results.tests.push({
                id: `takeover-safe-${sub}`,
                name: `${fqdn} → ${service.name} (claimed/active)`,
                status: 'pass', severity: 'info'
              });
            }
          } catch {
            // HTTP failed — still report CNAME but don't confirm takeover
            results.tests.push({
              id: `takeover-cname-${sub}`,
              name: `${fqdn} has CNAME to ${service.name} (HTTP unreachable)`,
              status: 'warn', severity: 'high'
            });
          }
          break; // Only check first matching service
        }
      } catch { /* DNS/HTTP error — skip */ }
    }

    if (checkedCount === 0) {
      results.tests.push({ id: 'takeover-no-cnames', name: 'No CNAME subdomains found to check', status: 'pass', severity: 'info' });
    }

    // Summary test
    if (vulnerable > 0) {
      results.tests.push({
        id: 'takeover-summary',
        name: `${vulnerable} subdomain(s) vulnerable to takeover`,
        status: 'fail', severity: 'critical'
      });
    } else if (checkedCount > 0) {
      results.tests.push({
        id: 'takeover-summary',
        name: `${checkedCount} CNAME subdomain(s) checked — all claimed`,
        status: 'pass', severity: 'info'
      });
    }

  } catch (err) {
    results.error = `Subdomain takeover scan failed: ${err.message}`;
  }
  return { scanner: 'Subdomain Takeover', icon: '🏴', results, testCount: results.tests.length };
}

module.exports = { scan };
