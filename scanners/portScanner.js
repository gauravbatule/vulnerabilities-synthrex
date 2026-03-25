const net = require('net');

const COMMON_PORTS = [
  { port: 21, service: 'FTP', severity: 'high' },
  { port: 22, service: 'SSH', severity: 'medium' },
  { port: 23, service: 'Telnet', severity: 'critical' },
  { port: 25, service: 'SMTP', severity: 'medium' },
  { port: 53, service: 'DNS', severity: 'medium' },
  { port: 80, service: 'HTTP', severity: 'info' },
  { port: 110, service: 'POP3', severity: 'medium' },
  { port: 111, service: 'RPCBind', severity: 'high' },
  { port: 135, service: 'MSRPC', severity: 'high' },
  { port: 139, service: 'NetBIOS', severity: 'high' },
  { port: 143, service: 'IMAP', severity: 'medium' },
  { port: 443, service: 'HTTPS', severity: 'info' },
  { port: 445, service: 'SMB', severity: 'critical' },
  { port: 465, service: 'SMTPS', severity: 'low' },
  { port: 587, service: 'SMTP Submission', severity: 'low' },
  { port: 993, service: 'IMAPS', severity: 'low' },
  { port: 995, service: 'POP3S', severity: 'low' },
  { port: 1433, service: 'MSSQL', severity: 'critical' },
  { port: 1434, service: 'MSSQL Browser', severity: 'critical' },
  { port: 1521, service: 'Oracle DB', severity: 'critical' },
  { port: 2049, service: 'NFS', severity: 'high' },
  { port: 2082, service: 'cPanel', severity: 'high' },
  { port: 2083, service: 'cPanel SSL', severity: 'high' },
  { port: 2086, service: 'WHM', severity: 'high' },
  { port: 2087, service: 'WHM SSL', severity: 'high' },
  { port: 3000, service: 'Node.js/Dev Server', severity: 'medium' },
  { port: 3306, service: 'MySQL', severity: 'critical' },
  { port: 3389, service: 'RDP', severity: 'critical' },
  { port: 4443, service: 'HTTPS Alt', severity: 'low' },
  { port: 5432, service: 'PostgreSQL', severity: 'critical' },
  { port: 5900, service: 'VNC', severity: 'critical' },
  { port: 5901, service: 'VNC-1', severity: 'critical' },
  { port: 6379, service: 'Redis', severity: 'critical' },
  { port: 6380, service: 'Redis SSL', severity: 'high' },
  { port: 8000, service: 'HTTP Alt', severity: 'medium' },
  { port: 8080, service: 'HTTP Proxy', severity: 'medium' },
  { port: 8443, service: 'HTTPS Alt', severity: 'low' },
  { port: 8888, service: 'HTTP Alt', severity: 'medium' },
  { port: 9090, service: 'Web Admin', severity: 'high' },
  { port: 9200, service: 'Elasticsearch', severity: 'critical' },
  { port: 9300, service: 'Elasticsearch Transport', severity: 'critical' },
  { port: 11211, service: 'Memcached', severity: 'critical' },
  { port: 27017, service: 'MongoDB', severity: 'critical' },
  { port: 27018, service: 'MongoDB Shard', severity: 'critical' },
  { port: 28017, service: 'MongoDB Web', severity: 'critical' },
  { port: 50000, service: 'SAP', severity: 'high' },
];

function checkPort(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);
    socket.on('connect', () => { socket.destroy(); resolve(true); });
    socket.on('timeout', () => { socket.destroy(); resolve(false); });
    socket.on('error', () => { socket.destroy(); resolve(false); });
    socket.connect(port, host);
  });
}

async function scan(targetUrl) {
  const results = { open: [], closed: [], tests: [] };
  try {
    const url = new URL(targetUrl);
    const hostname = url.hostname;

    const batchSize = 10;
    for (let i = 0; i < COMMON_PORTS.length; i += batchSize) {
      const batch = COMMON_PORTS.slice(i, i + batchSize);
      const checks = batch.map(p => checkPort(hostname, p.port).then(isOpen => ({ ...p, isOpen })));
      const batchResults = await Promise.all(checks);
      for (const r of batchResults) {
        if (r.isOpen) {
          results.open.push({ port: r.port, service: r.service, severity: r.severity });
          results.tests.push({ id: `port-open-${r.port}`, name: `Port ${r.port} (${r.service}) open`, status: ['critical','high'].includes(r.severity) ? 'fail' : 'warn', severity: r.severity });
        } else {
          results.tests.push({ id: `port-closed-${r.port}`, name: `Port ${r.port} (${r.service}) closed`, status: 'pass', severity: 'info' });
        }
      }
    }
  } catch (err) {
    results.error = `Port scan failed: ${err.message}`;
  }
  return { scanner: 'Port Scanner', icon: '🔌', results, testCount: results.tests.length };
}

module.exports = { scan };
