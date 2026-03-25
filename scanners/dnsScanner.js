const dns = require('dns');
const { promisify } = require('util');

const resolve4 = promisify(dns.resolve4);
const resolve6 = promisify(dns.resolve6);
const resolveMx = promisify(dns.resolveMx);
const resolveNs = promisify(dns.resolveNs);
const resolveTxt = promisify(dns.resolveTxt);
const resolveCname = promisify(dns.resolveCname);
const resolveSoa = promisify(dns.resolveSoa);
const resolveSrv = promisify(dns.resolveSrv);
const resolveCaa = promisify(dns.resolveCaa);

async function safeResolve(fn, domain) {
  try { return await fn(domain); } catch { return null; }
}

async function scan(targetUrl) {
  const results = { records: {}, tests: [] };
  try {
    const url = new URL(targetUrl);
    const domain = url.hostname;

    // A records
    const aRecords = await safeResolve(resolve4, domain);
    results.records.A = aRecords;
    results.tests.push({ id: 'dns-a', name: 'A records exist', status: aRecords ? 'pass' : 'fail', severity: 'info' });
    if (aRecords) {
      for (const ip of aRecords) {
        results.tests.push({ id: `dns-a-${ip}`, name: `A record: ${ip}`, status: 'info', severity: 'info' });
        // Check for private IPs
        if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.16.') || ip === '127.0.0.1') {
          results.tests.push({ id: `dns-private-${ip}`, name: `Private IP exposed: ${ip}`, status: 'fail', severity: 'high' });
        }
      }
    }

    // AAAA records
    const aaaaRecords = await safeResolve(resolve6, domain);
    results.records.AAAA = aaaaRecords;
    results.tests.push({ id: 'dns-aaaa', name: 'AAAA (IPv6) records exist', status: aaaaRecords ? 'pass' : 'info', severity: 'info' });

    // MX records
    const mxRecords = await safeResolve(resolveMx, domain);
    results.records.MX = mxRecords;
    results.tests.push({ id: 'dns-mx', name: 'MX records configured', status: mxRecords && mxRecords.length > 0 ? 'pass' : 'info', severity: 'info' });
    if (mxRecords) {
      for (const mx of mxRecords) {
        results.tests.push({ id: `dns-mx-${mx.exchange}`, name: `MX: ${mx.exchange} (priority ${mx.priority})`, status: 'info', severity: 'info' });
      }
    }

    // NS records
    const nsRecords = await safeResolve(resolveNs, domain);
    results.records.NS = nsRecords;
    results.tests.push({ id: 'dns-ns', name: 'NS records configured', status: nsRecords && nsRecords.length >= 2 ? 'pass' : 'warn', severity: 'medium' });
    results.tests.push({ id: 'dns-ns-redundancy', name: 'Multiple NS servers (redundancy)', status: nsRecords && nsRecords.length >= 2 ? 'pass' : 'warn', severity: 'medium' });

    // TXT records (SPF, DMARC, DKIM)
    const txtRecords = await safeResolve(resolveTxt, domain);
    results.records.TXT = txtRecords;
    if (txtRecords) {
      const allTxt = txtRecords.map(r => r.join('')).join(' ');

      // SPF check
      const hasSPF = allTxt.includes('v=spf1');
      results.tests.push({ id: 'dns-spf', name: 'SPF record configured', status: hasSPF ? 'pass' : 'fail', severity: 'high' });
      if (hasSPF) {
        results.tests.push({ id: 'dns-spf-all', name: 'SPF -all (hard fail)', status: allTxt.includes('-all') ? 'pass' : 'warn', severity: 'medium' });
        results.tests.push({ id: 'dns-spf-softfail', name: 'SPF ~all (soft fail)', status: allTxt.includes('~all') ? 'warn' : 'pass', severity: 'low' });
        results.tests.push({ id: 'dns-spf-neutral', name: 'SPF ?all (neutral)', status: allTxt.includes('?all') ? 'fail' : 'pass', severity: 'medium' });
        results.tests.push({ id: 'dns-spf-pass-all', name: 'SPF +all (allow all)', status: allTxt.includes('+all') ? 'fail' : 'pass', severity: 'critical' });
      }

      // DMARC
      const dmarcRecords = await safeResolve(resolveTxt, `_dmarc.${domain}`);
      const hasDMARC = dmarcRecords && dmarcRecords.some(r => r.join('').includes('v=DMARC1'));
      results.tests.push({ id: 'dns-dmarc', name: 'DMARC record configured', status: hasDMARC ? 'pass' : 'fail', severity: 'high' });
      if (hasDMARC) {
        const dmarcStr = dmarcRecords.map(r => r.join('')).join(' ');
        results.tests.push({ id: 'dns-dmarc-policy', name: 'DMARC policy set', status: dmarcStr.includes('p=reject') ? 'pass' : dmarcStr.includes('p=quarantine') ? 'warn' : 'fail', severity: 'medium' });
        results.tests.push({ id: 'dns-dmarc-rua', name: 'DMARC reporting (rua)', status: dmarcStr.includes('rua=') ? 'pass' : 'warn', severity: 'low' });
        results.tests.push({ id: 'dns-dmarc-ruf', name: 'DMARC forensic reporting (ruf)', status: dmarcStr.includes('ruf=') ? 'pass' : 'info', severity: 'low' });
        results.tests.push({ id: 'dns-dmarc-pct', name: 'DMARC percentage (pct)', status: dmarcStr.includes('pct=100') ? 'pass' : 'warn', severity: 'low' });
      }

      // DKIM
      const commonSelectors = ['default', 'google', 'dkim', 'selector1', 'selector2', 'k1', 'k2', 'mail', 'smtp', 's1', 's2'];
      let dkimFound = false;
      for (const selector of commonSelectors) {
        const dkimRecords = await safeResolve(resolveTxt, `${selector}._domainkey.${domain}`);
        if (dkimRecords && dkimRecords.some(r => r.join('').includes('v=DKIM1'))) {
          dkimFound = true;
          results.tests.push({ id: `dns-dkim-${selector}`, name: `DKIM selector "${selector}" found`, status: 'pass', severity: 'info' });
          break;
        }
      }
      results.tests.push({ id: 'dns-dkim', name: 'DKIM record found', status: dkimFound ? 'pass' : 'warn', severity: 'medium' });

      // Other TXT records
      for (const txt of txtRecords) {
        const record = txt.join('');
        if (record.includes('google-site-verification')) results.tests.push({ id: 'dns-gsc', name: 'Google Search Console verified', status: 'info', severity: 'info' });
        if (record.includes('MS=')) results.tests.push({ id: 'dns-ms', name: 'Microsoft verification found', status: 'info', severity: 'info' });
        if (record.includes('facebook')) results.tests.push({ id: 'dns-fb', name: 'Facebook verification found', status: 'info', severity: 'info' });
        if (record.includes('docusign')) results.tests.push({ id: 'dns-docusign', name: 'DocuSign verification found', status: 'info', severity: 'info' });
      }
    }

    // SOA record
    const soaRecord = await safeResolve(resolveSoa, domain);
    results.records.SOA = soaRecord;
    if (soaRecord) {
      results.tests.push({ id: 'dns-soa', name: 'SOA record exists', status: 'pass', severity: 'info' });
      results.tests.push({ id: 'dns-soa-serial', name: `SOA serial: ${soaRecord.serial}`, status: 'info', severity: 'info' });
    }

    // CNAME record
    const cnameRecords = await safeResolve(resolveCname, domain);
    results.records.CNAME = cnameRecords;
    if (cnameRecords) {
      for (const cname of cnameRecords) {
        results.tests.push({ id: `dns-cname-${cname}`, name: `CNAME: ${cname}`, status: 'info', severity: 'info' });
      }
    }

    // CAA records
    const caaRecords = await safeResolve(resolveCaa, domain);
    results.records.CAA = caaRecords;
    results.tests.push({ id: 'dns-caa', name: 'CAA records configured', status: caaRecords && caaRecords.length > 0 ? 'pass' : 'warn', severity: 'medium' });

    // Zone transfer test (AXFR) - just report
    results.tests.push({ id: 'dns-zone-transfer', name: 'Zone transfer protection', status: 'info', severity: 'info' });

  } catch (err) {
    results.error = `DNS scan failed: ${err.message}`;
  }
  return { scanner: 'DNS & Email Security', icon: '📡', results, testCount: results.tests.length };
}

module.exports = { scan };
