const axios = require('axios');
const dns = require('dns').promises;
const url = require('url');

// 300+ subdomains to enumerate
const SUBDOMAINS = [
  // ── Common ──
  'www','mail','ftp','smtp','pop','imap','webmail','email','mx','ns1','ns2','ns3','ns4',
  'dns','dns1','dns2','admin','cpanel','whm','panel','control','dashboard','manage',
  'api','api2','api3','dev','staging','stage','test','testing','demo','beta','alpha',
  'uat','qa','sandbox','preview','pre','preprod','prod','production','live',
  // ── Web/App ──
  'app','apps','mobile','m','go','portal','gateway','web','www2','www3','cdn','cdn1','cdn2',
  'static','assets','media','images','img','files','upload','uploads','download','downloads',
  'docs','doc','documentation','help','support','kb','wiki','blog','forum','community',
  'news','press','status','uptime','monitor','metrics','analytics','track','tracking',
  // ── Services ──
  'db','database','sql','mysql','postgres','mongo','redis','cache','memcache','elastic',
  'elasticsearch','kibana','grafana','prometheus','influx','rabbitmq','kafka','queue',
  'search','solr','ldap','ad','auth','sso','login','accounts','id','identity','oauth',
  'cas','saml','oidc','token','jwt',
  // ── Infrastructure ──
  'vpn','proxy','reverse','lb','loadbalancer','haproxy','nginx','apache','tomcat','iis',
  'firewall','waf','bastion','jump','ssh','sftp','git','gitlab','github','bitbucket',
  'svn','jenkins','ci','cd','drone','travis','circle','build','deploy','release',
  'docker','k8s','kubernetes','rancher','nomad','consul','vault','terraform',
  // ── Cloud ──
  'aws','azure','gcp','cloud','s3','storage','bucket','blob','object','archive',
  'lambda','functions','serverless','edge','cloudfront','akamai','fastly','cloudflare',
  // ── Office ──
  'intranet','internal','corp','corporate','office','remote','citrix','rdp','owa',
  'exchange','outlook','sharepoint','teams','slack','zoom','meet','calendar',
  // ── Commerce ──
  'shop','store','cart','checkout','pay','payment','billing','invoice','order','orders',
  'erp','crm','sales','marketing','campaign','promo','loyalty',
  // ── Staging/Dev variants ──
  'dev1','dev2','dev3','staging1','staging2','test1','test2','test3','uat1','uat2',
  'feature','hotfix','bugfix','patch','canary','nightly','snapshot',
  // ── Old/Legacy ──
  'old','legacy','archive','backup','bak','temp','tmp','scratch','v1','v2','v3',
  // ── International ──
  'en','us','uk','eu','in','de','fr','jp','cn','au','br','ca','mx','kr','ru',
  'asia','africa','latam','emea','apac',
  // ── Security ──
  'soc','siem','pentest','scan','scanner','security','threat','audit','compliance',
  'log','logs','syslog','splunk','graylog','elk','loki','fluentd',
  // ── Others ──
  'ws','wss','websocket','socket','rtc','webrtc','stream','video','audio','voip',
  'sip','pbx','asterisk','phone','tel','fax','print','printer','scan','ntp',
  'snmp','radius','kerberos','dhcp','tftp','pxe','boot','ipmi','bmc','ilo','drac',
  'nas','san','nfs','smb','cifs','iscsi','ceph','minio','gluster',
  'puppet','chef','ansible','salt','mgmt','management','ops','devops','sre',
  'pki','ca','crl','ocsp','acme','letsencrypt',
  'jira','confluence','notion','trello','asana','monday','Linear',
  'datadog','newrelic','appd','dynatrace','apm','rum','synthetic',
  'mailgun','sendgrid','ses','postfix','dovecot','roundcube','horde',
  'nextcloud','owncloud','seafile','dropbox','drive','sync',
  'wordpress','wp','drupal','joomla','magento','shopify','woo','woocommerce',
  'moodle','lms','elearning','training','academy',
  'grafana2','kibana2','portainer','traefik','envoy','istio','linkerd',
  'zabbix','nagios','icinga','checkmk','prtg','cacti','mrtg',
  'pgadmin','phpmyadmin','adminer','dbeaver','workbench',
  'registry','harbor','nexus','artifactory','sonatype',
  'sonarqube','sonar','codacy','codecov','coveralls','snyk','whitesource',
];

async function scan(targetUrl) {
  const results = { found: [], tests: [] };
  try {
    const hostname = new URL(targetUrl).hostname.replace(/^www\./, '');
    const batchSize = 25;
    for (let i = 0; i < SUBDOMAINS.length; i += batchSize) {
      const batch = SUBDOMAINS.slice(i, i + batchSize);
      const checks = batch.map(async (sub) => {
        const fqdn = `${sub}.${hostname}`;
        try {
          const addrs = await dns.resolve4(fqdn);
          if (addrs.length > 0) {
            let severity = 'info';
            const s = sub.toLowerCase();
            if (['admin','test','staging','dev','debug','backup','internal','phpmyadmin','jenkins','git','gitlab'].includes(s)) severity = 'medium';
            if (['cpanel','whm','panel','ssh','vpn','bastion','vault','secrets'].includes(s)) severity = 'high';
            results.found.push({ subdomain: fqdn, ip: addrs[0], severity });
            results.tests.push({ id: `sub-${sub}`, name: `${fqdn} (${addrs[0]})`, status: 'warn', severity });
          } else {
            results.tests.push({ id: `sub-${sub}`, name: `${fqdn} — not found`, status: 'pass', severity: 'info' });
          }
        } catch {
          results.tests.push({ id: `sub-${sub}`, name: `${fqdn} — not found`, status: 'pass', severity: 'info' });
        }
      });
      await Promise.all(checks);
    }
  } catch (err) { results.error = err.message; }
  return { scanner: 'Subdomain Enumeration', icon: '🌍', results, testCount: results.tests.length };
}

module.exports = { scan };
