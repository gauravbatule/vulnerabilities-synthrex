const dns = require('dns').promises;

const TIMEOUT = 5000;
function withTimeout(promise, ms) {
  return Promise.race([promise, new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), ms))]);
}

async function scan(targetUrl) {
  const results = { tests: [] };
  try {
    const hostname = new URL(targetUrl).hostname.replace(/^www\./, '');

    // 1. Check for DNSKEY records (DNSSEC signing keys)
    let hasDNSKEY = false;
    try {
      const keys = await withTimeout(dns.resolve(hostname, 'DNSKEY'), TIMEOUT);
      if (keys && keys.length > 0) {
        hasDNSKEY = true;
        results.tests.push({ id: 'dnssec-dnskey', name: 'DNSKEY records present', status: 'pass', severity: 'info' });
      }
    } catch {
      results.tests.push({ id: 'dnssec-dnskey', name: 'DNSKEY records not found', status: 'info', severity: 'info' });
    }

    // 2. Check for DS records in parent zone
    try {
      const ds = await withTimeout(dns.resolve(hostname, 'DS'), TIMEOUT);
      if (ds && ds.length > 0) {
        results.tests.push({ id: 'dnssec-ds', name: 'DS records present (delegation signed)', status: 'pass', severity: 'info' });
      }
    } catch {
      results.tests.push({ id: 'dnssec-ds', name: 'DS records not found in parent', status: 'info', severity: 'info' });
    }

    // 3. Check for RRSIG records
    try {
      const rrsig = await withTimeout(dns.resolve(hostname, 'RRSIG'), TIMEOUT);
      if (rrsig && rrsig.length > 0) {
        results.tests.push({ id: 'dnssec-rrsig', name: 'RRSIG records present (signatures exist)', status: 'pass', severity: 'info' });
      }
    } catch {
      results.tests.push({ id: 'dnssec-rrsig', name: 'RRSIG records not found', status: 'info', severity: 'info' });
    }

    // 4. Check for NSEC/NSEC3 records
    try {
      const nsec = await withTimeout(dns.resolve(hostname, 'NSEC'), TIMEOUT);
      if (nsec && nsec.length > 0) {
        results.tests.push({ id: 'dnssec-nsec', name: 'NSEC records present', status: 'pass', severity: 'info' });
      }
    } catch {
      // Try NSEC3
      try {
        const nsec3 = await withTimeout(dns.resolve(hostname, 'NSEC3'), TIMEOUT);
        if (nsec3 && nsec3.length > 0) {
          results.tests.push({ id: 'dnssec-nsec3', name: 'NSEC3 records present', status: 'pass', severity: 'info' });
        }
      } catch {
        results.tests.push({ id: 'dnssec-nsec', name: 'NSEC/NSEC3 records not found', status: 'info', severity: 'info' });
      }
    }

    // Overall DNSSEC assessment
    if (hasDNSKEY) {
      results.tests.push({ id: 'dnssec-enabled', name: 'DNSSEC appears to be enabled', status: 'pass', severity: 'info' });
    } else {
      results.tests.push({ id: 'dnssec-disabled', name: 'DNSSEC does not appear to be enabled', status: 'warn', severity: 'low' });
    }

    // 5. Check CAA records
    try {
      const caa = await withTimeout(dns.resolveCaa(hostname), TIMEOUT);
      if (caa && caa.length > 0) {
        results.tests.push({ id: 'dnssec-caa', name: `CAA records found (${caa.length} entries)`, status: 'pass', severity: 'info' });
        for (const record of caa.slice(0, 5)) {
          results.tests.push({ id: `dnssec-caa-${record.tag}`, name: `CAA ${record.tag}: ${record.value}`, status: 'pass', severity: 'info' });
        }
      } else {
        results.tests.push({ id: 'dnssec-caa-missing', name: 'CAA records not found', status: 'warn', severity: 'low' });
      }
    } catch {
      results.tests.push({ id: 'dnssec-caa-missing', name: 'CAA records not found', status: 'warn', severity: 'low' });
    }

  } catch (err) {
    results.error = err.message;
  }
  return { scanner: 'DNSSEC Validation', icon: '🔐', results, testCount: results.tests.length };
}

module.exports = { scan };
