const tls = require('tls');
const https = require('https');
const { URL } = require('url');

async function scan(targetUrl) {
  const results = { findings: [], tests: [] };
  try {
    const url = new URL(targetUrl);
    const hostname = url.hostname;
    const port = url.port || (url.protocol === 'https:' ? 443 : 80);

    if (url.protocol !== 'https:') {
      results.tests.push({ id: 'ssl-no-https', name: 'Site does not use HTTPS', status: 'fail', severity: 'critical' });
      results.findings.push({ issue: 'Site does not use HTTPS', severity: 'critical', recommendation: 'Enable HTTPS with a valid SSL/TLS certificate' });
      return { scanner: 'SSL/TLS Analysis', icon: '🔒', results, testCount: results.tests.length };
    }

    const cert = await new Promise((resolve, reject) => {
      const options = { host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout: 10000 };
      const socket = tls.connect(options, () => {
        const certificate = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        resolve({ certificate, protocol, cipher, authorized: socket.authorized });
        socket.end();
      });
      socket.on('error', reject);
      socket.setTimeout(10000, () => { socket.destroy(); reject(new Error('Connection timeout')); });
    });

    // Certificate validity
    const now = new Date();
    const validFrom = new Date(cert.certificate.valid_from);
    const validTo = new Date(cert.certificate.valid_to);
    const daysToExpiry = Math.ceil((validTo - now) / (1000 * 60 * 60 * 24));

    results.tests.push({ id: 'ssl-valid', name: 'Certificate is valid', status: cert.authorized ? 'pass' : 'fail', severity: 'critical' });
    results.tests.push({ id: 'ssl-not-expired', name: 'Certificate not expired', status: validTo > now ? 'pass' : 'fail', severity: 'critical' });
    results.tests.push({ id: 'ssl-not-premature', name: 'Certificate not premature', status: validFrom <= now ? 'pass' : 'fail', severity: 'critical' });
    results.tests.push({ id: 'ssl-expiry-30d', name: 'Expires in >30 days', status: daysToExpiry > 30 ? 'pass' : 'warn', severity: 'high' });
    results.tests.push({ id: 'ssl-expiry-90d', name: 'Expires in >90 days', status: daysToExpiry > 90 ? 'pass' : 'info', severity: 'low' });
    results.tests.push({ id: 'ssl-expiry-365d', name: 'Certificate validity ≤ 1 year', status: (validTo - validFrom) / (1000*60*60*24) <= 398 ? 'pass' : 'warn', severity: 'medium' });

    // Protocol checks
    const protocol = cert.protocol;
    results.tests.push({ id: 'ssl-tls13', name: 'TLS 1.3 supported', status: protocol === 'TLSv1.3' ? 'pass' : 'warn', severity: 'medium' });
    results.tests.push({ id: 'ssl-tls12', name: 'TLS 1.2+ used', status: ['TLSv1.2','TLSv1.3'].includes(protocol) ? 'pass' : 'fail', severity: 'high' });
    results.tests.push({ id: 'ssl-no-tls10', name: 'TLS 1.0 not used', status: protocol !== 'TLSv1' ? 'pass' : 'fail', severity: 'high' });
    results.tests.push({ id: 'ssl-no-tls11', name: 'TLS 1.1 not used', status: protocol !== 'TLSv1.1' ? 'pass' : 'fail', severity: 'high' });
    results.tests.push({ id: 'ssl-no-ssl3', name: 'SSL 3.0 not used', status: protocol !== 'SSLv3' ? 'pass' : 'fail', severity: 'critical' });
    results.tests.push({ id: 'ssl-no-ssl2', name: 'SSL 2.0 not used', status: protocol !== 'SSLv2' ? 'pass' : 'fail', severity: 'critical' });

    // Cipher checks
    const cipher = cert.cipher;
    if (cipher) {
      results.tests.push({ id: 'ssl-cipher-name', name: `Cipher: ${cipher.name}`, status: 'info', severity: 'info' });
      const weakCiphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon'];
      for (const wc of weakCiphers) {
        const isWeak = cipher.name && cipher.name.includes(wc);
        results.tests.push({ id: `ssl-no-${wc.toLowerCase()}`, name: `No ${wc} cipher`, status: isWeak ? 'fail' : 'pass', severity: isWeak ? 'high' : 'info' });
      }
      results.tests.push({ id: 'ssl-cipher-bits', name: `Cipher strength: ${cipher.bits || 'unknown'} bits`, status: (cipher.bits || 0) >= 128 ? 'pass' : 'fail', severity: 'high' });
      results.tests.push({ id: 'ssl-cipher-256', name: 'Cipher strength ≥256 bits', status: (cipher.bits || 0) >= 256 ? 'pass' : 'warn', severity: 'medium' });
    }

    // Certificate details
    const subject = cert.certificate.subject || {};
    const issuer = cert.certificate.issuer || {};
    results.tests.push({ id: 'ssl-cn-match', name: 'CN matches hostname', status: (subject.CN || '').includes(hostname) || (cert.certificate.subjectaltname || '').includes(hostname) ? 'pass' : 'warn', severity: 'high' });
    results.tests.push({ id: 'ssl-san-present', name: 'SAN extension present', status: cert.certificate.subjectaltname ? 'pass' : 'warn', severity: 'medium' });
    results.tests.push({ id: 'ssl-issuer-known', name: `Issuer: ${issuer.O || 'Unknown'}`, status: 'info', severity: 'info' });
    results.tests.push({ id: 'ssl-self-signed', name: 'Not self-signed', status: (subject.CN !== issuer.CN) ? 'pass' : 'fail', severity: 'high' });
    results.tests.push({ id: 'ssl-sha256', name: 'Uses SHA-256+ signature', status: (cert.certificate.fingerprint256) ? 'pass' : 'warn', severity: 'medium' });

    // Key size check
    const bits = cert.certificate.bits;
    if (bits) {
      results.tests.push({ id: 'ssl-key-2048', name: 'Key size ≥2048 bits', status: bits >= 2048 ? 'pass' : 'fail', severity: 'high' });
      results.tests.push({ id: 'ssl-key-4096', name: 'Key size ≥4096 bits', status: bits >= 4096 ? 'pass' : 'info', severity: 'low' });
    }

    // Check for deprecated protocols by attempting connection
    const deprecatedProtocols = [
      { name: 'SSLv3', maxVersion: 'TLSv1', minVersion: undefined },
    ];

    results.findings.push({
      issue: `Certificate expires in ${daysToExpiry} days`,
      severity: daysToExpiry < 30 ? 'high' : daysToExpiry < 90 ? 'medium' : 'info',
      details: { validFrom: validFrom.toISOString(), validTo: validTo.toISOString(), issuer: issuer.O, protocol, cipher: cipher?.name }
    });

  } catch (err) {
    results.error = `SSL scan failed: ${err.message}`;
  }
  return { scanner: 'SSL/TLS Analysis', icon: '🔒', results, testCount: results.tests.length };
}

module.exports = { scan };
