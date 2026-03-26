const dns = require('dns').promises;

async function scan(targetUrl) {
  const results = { tests: [], findings: [] };
  try {
    const hostname = new URL(targetUrl).hostname.replace(/^www\./, '');

    // 1. SPF Record Analysis
    try {
      const txtRecords = await dns.resolveTxt(hostname);
      const spfRecords = txtRecords.filter(r => r.join('').toLowerCase().startsWith('v=spf1'));
      if (spfRecords.length === 0) {
        results.tests.push({ id: 'spf-missing', name: 'SPF record missing', status: 'fail', severity: 'high' });
      } else if (spfRecords.length > 1) {
        results.tests.push({ id: 'spf-multiple', name: 'Multiple SPF records found (invalid)', status: 'fail', severity: 'high' });
      } else {
        const spf = spfRecords[0].join('');
        results.tests.push({ id: 'spf-present', name: 'SPF record present', status: 'pass', severity: 'info' });

        // Check for +all (allows everything)
        if (spf.includes('+all')) {
          results.tests.push({ id: 'spf-plus-all', name: 'SPF uses +all (allows all senders!)', status: 'fail', severity: 'critical' });
        } else if (spf.includes('~all')) {
          results.tests.push({ id: 'spf-softfail', name: 'SPF uses ~all (softfail — should be -all)', status: 'warn', severity: 'medium' });
        } else if (spf.includes('-all')) {
          results.tests.push({ id: 'spf-hardfail', name: 'SPF uses -all (hardfail — good)', status: 'pass', severity: 'info' });
        } else if (spf.includes('?all')) {
          results.tests.push({ id: 'spf-neutral', name: 'SPF uses ?all (neutral — weak)', status: 'warn', severity: 'medium' });
        }

        // Check DNS lookups count (max 10 allowed)
        const lookupMechanisms = (spf.match(/(include:|a:|mx:|ptr:|exists:)/gi) || []).length;
        results.tests.push({ id: 'spf-lookups', name: `SPF DNS lookups: ${lookupMechanisms}/10`, status: lookupMechanisms > 10 ? 'fail' : lookupMechanisms > 7 ? 'warn' : 'pass', severity: lookupMechanisms > 10 ? 'high' : 'info' });

        // Check for ip4/ip6
        if (spf.includes('ip4:') || spf.includes('ip6:')) {
          results.tests.push({ id: 'spf-ip', name: 'SPF includes explicit IP ranges', status: 'pass', severity: 'info' });
        }
      }
    } catch {
      results.tests.push({ id: 'spf-lookup-fail', name: 'SPF lookup failed (no TXT records)', status: 'warn', severity: 'medium' });
    }

    // 2. DKIM Check (common selectors)
    const dkimSelectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'mail', 'dkim', 's1', 's2', 'smtp', 'mg', 'mandrill', 'everlytickey1', 'mesmtp'];
    let dkimFound = false;
    for (const sel of dkimSelectors) {
      try {
        const records = await dns.resolveTxt(`${sel}._domainkey.${hostname}`);
        if (records.length > 0) {
          const record = records[0].join('');
          dkimFound = true;
          results.tests.push({ id: `dkim-${sel}`, name: `DKIM found: ${sel}._domainkey`, status: 'pass', severity: 'info' });

          // Check key size hint
          if (record.includes('k=rsa')) {
            results.tests.push({ id: `dkim-rsa-${sel}`, name: `DKIM ${sel}: RSA key type`, status: 'pass', severity: 'info' });
          }
          break; // Found one is enough
        }
      } catch { /* not found */ }
    }
    if (!dkimFound) {
      results.tests.push({ id: 'dkim-missing', name: 'No DKIM records found (common selectors)', status: 'warn', severity: 'medium' });
    }

    // 3. DMARC Analysis
    try {
      const dmarcRecords = await dns.resolveTxt(`_dmarc.${hostname}`);
      const dmarc = dmarcRecords.find(r => r.join('').toLowerCase().startsWith('v=dmarc1'));
      if (dmarc) {
        const dmarcStr = dmarc.join('');
        results.tests.push({ id: 'dmarc-present', name: 'DMARC record present', status: 'pass', severity: 'info' });

        // Policy
        const policyMatch = dmarcStr.match(/p=(\w+)/i);
        if (policyMatch) {
          const policy = policyMatch[1].toLowerCase();
          if (policy === 'none') {
            results.tests.push({ id: 'dmarc-policy-none', name: 'DMARC policy: none (monitoring only)', status: 'warn', severity: 'medium' });
          } else if (policy === 'quarantine') {
            results.tests.push({ id: 'dmarc-policy-quarantine', name: 'DMARC policy: quarantine', status: 'pass', severity: 'info' });
          } else if (policy === 'reject') {
            results.tests.push({ id: 'dmarc-policy-reject', name: 'DMARC policy: reject (strongest)', status: 'pass', severity: 'info' });
          }
        }

        // Subdomain policy
        const spMatch = dmarcStr.match(/sp=(\w+)/i);
        if (spMatch) {
          results.tests.push({ id: 'dmarc-sp', name: `DMARC subdomain policy: ${spMatch[1]}`, status: 'pass', severity: 'info' });
        }

        // Reporting
        if (dmarcStr.includes('rua=')) {
          results.tests.push({ id: 'dmarc-rua', name: 'DMARC aggregate reports configured', status: 'pass', severity: 'info' });
        } else {
          results.tests.push({ id: 'dmarc-no-rua', name: 'DMARC aggregate reports not configured', status: 'warn', severity: 'low' });
        }

        // pct
        const pctMatch = dmarcStr.match(/pct=(\d+)/i);
        if (pctMatch && parseInt(pctMatch[1]) < 100) {
          results.tests.push({ id: 'dmarc-pct', name: `DMARC pct=${pctMatch[1]} (not 100%)`, status: 'warn', severity: 'low' });
        }
      } else {
        results.tests.push({ id: 'dmarc-missing', name: 'DMARC record missing', status: 'fail', severity: 'high' });
      }
    } catch {
      results.tests.push({ id: 'dmarc-missing', name: 'DMARC record missing', status: 'fail', severity: 'high' });
    }

    // 4. MTA-STS
    try {
      const mtsRecords = await dns.resolveTxt(`_mta-sts.${hostname}`);
      if (mtsRecords.some(r => r.join('').includes('v=STSv1'))) {
        results.tests.push({ id: 'mta-sts', name: 'MTA-STS configured', status: 'pass', severity: 'info' });
      } else {
        results.tests.push({ id: 'mta-sts-missing', name: 'MTA-STS not configured', status: 'info', severity: 'info' });
      }
    } catch {
      results.tests.push({ id: 'mta-sts-missing', name: 'MTA-STS not configured', status: 'info', severity: 'info' });
    }

  } catch (err) {
    results.error = err.message;
  }
  return { scanner: 'Email Security', icon: '📧', results, testCount: results.tests.length };
}

module.exports = { scan };
