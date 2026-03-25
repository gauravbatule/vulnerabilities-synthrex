const axios = require('axios');
const cheerio = require('cheerio');

const TECH_SIGNATURES = {
  servers: {
    'apache': { name: 'Apache', category: 'server' },
    'nginx': { name: 'Nginx', category: 'server' },
    'iis': { name: 'Microsoft IIS', category: 'server' },
    'litespeed': { name: 'LiteSpeed', category: 'server' },
    'cloudflare': { name: 'Cloudflare', category: 'cdn' },
    'openresty': { name: 'OpenResty', category: 'server' },
    'caddy': { name: 'Caddy', category: 'server' },
    'gunicorn': { name: 'Gunicorn', category: 'server' },
    'kestrel': { name: 'Kestrel (.NET)', category: 'server' },
    'tomcat': { name: 'Apache Tomcat', category: 'server' },
    'jetty': { name: 'Eclipse Jetty', category: 'server' },
    'cowboy': { name: 'Cowboy (Erlang)', category: 'server' },
    'envoy': { name: 'Envoy Proxy', category: 'proxy' },
    'traefik': { name: 'Traefik', category: 'proxy' },
    'haproxy': { name: 'HAProxy', category: 'proxy' },
    'varnish': { name: 'Varnish Cache', category: 'cache' },
  },
  poweredBy: {
    'php': { name: 'PHP', category: 'language' },
    'asp.net': { name: 'ASP.NET', category: 'framework' },
    'express': { name: 'Express.js', category: 'framework' },
    'next.js': { name: 'Next.js', category: 'framework' },
    'django': { name: 'Django', category: 'framework' },
    'flask': { name: 'Flask', category: 'framework' },
    'rails': { name: 'Ruby on Rails', category: 'framework' },
    'laravel': { name: 'Laravel', category: 'framework' },
    'spring': { name: 'Spring Boot', category: 'framework' },
    'nuxt': { name: 'Nuxt.js', category: 'framework' },
    'wp engine': { name: 'WP Engine', category: 'hosting' },
    'plesk': { name: 'Plesk', category: 'hosting' },
  },
  htmlSignatures: [
    { pattern: /wp-content|wp-includes|wordpress/i, name: 'WordPress', category: 'cms' },
    { pattern: /drupal|sites\/default/i, name: 'Drupal', category: 'cms' },
    { pattern: /joomla/i, name: 'Joomla', category: 'cms' },
    { pattern: /shopify/i, name: 'Shopify', category: 'ecommerce' },
    { pattern: /woocommerce/i, name: 'WooCommerce', category: 'ecommerce' },
    { pattern: /magento|mage/i, name: 'Magento', category: 'ecommerce' },
    { pattern: /squarespace/i, name: 'Squarespace', category: 'cms' },
    { pattern: /wix\.com/i, name: 'Wix', category: 'cms' },
    { pattern: /ghost/i, name: 'Ghost', category: 'cms' },
    { pattern: /webflow/i, name: 'Webflow', category: 'cms' },
    { pattern: /react/i, name: 'React', category: 'frontend' },
    { pattern: /vue\.js|vuejs/i, name: 'Vue.js', category: 'frontend' },
    { pattern: /angular/i, name: 'Angular', category: 'frontend' },
    { pattern: /svelte/i, name: 'Svelte', category: 'frontend' },
    { pattern: /jquery/i, name: 'jQuery', category: 'frontend' },
    { pattern: /bootstrap/i, name: 'Bootstrap', category: 'css' },
    { pattern: /tailwind/i, name: 'Tailwind CSS', category: 'css' },
    { pattern: /bulma/i, name: 'Bulma', category: 'css' },
    { pattern: /foundation/i, name: 'Foundation', category: 'css' },
    { pattern: /materialize/i, name: 'Materialize', category: 'css' },
    { pattern: /google-analytics|gtag|ga\.js|analytics\.js/i, name: 'Google Analytics', category: 'analytics' },
    { pattern: /gtm\.js|googletagmanager/i, name: 'Google Tag Manager', category: 'analytics' },
    { pattern: /facebook.*pixel|fbevents/i, name: 'Facebook Pixel', category: 'analytics' },
    { pattern: /hotjar/i, name: 'Hotjar', category: 'analytics' },
    { pattern: /cloudflare/i, name: 'Cloudflare', category: 'cdn' },
    { pattern: /akamai/i, name: 'Akamai', category: 'cdn' },
    { pattern: /fastly/i, name: 'Fastly', category: 'cdn' },
    { pattern: /recaptcha/i, name: 'reCAPTCHA', category: 'security' },
    { pattern: /hcaptcha/i, name: 'hCaptcha', category: 'security' },
    { pattern: /stripe/i, name: 'Stripe', category: 'payment' },
    { pattern: /paypal/i, name: 'PayPal', category: 'payment' },
    { pattern: /razorpay/i, name: 'Razorpay', category: 'payment' },
    { pattern: /webpack/i, name: 'Webpack', category: 'build' },
    { pattern: /vite/i, name: 'Vite', category: 'build' },
    { pattern: /gsap/i, name: 'GSAP', category: 'animation' },
    { pattern: /three\.js/i, name: 'Three.js', category: 'graphics' },
    { pattern: /socket\.io/i, name: 'Socket.IO', category: 'realtime' },
    { pattern: /firebase/i, name: 'Firebase', category: 'backend' },
    { pattern: /supabase/i, name: 'Supabase', category: 'backend' },
    { pattern: /sentry/i, name: 'Sentry', category: 'monitoring' },
    { pattern: /datadog/i, name: 'Datadog', category: 'monitoring' },
    { pattern: /newrelic/i, name: 'New Relic', category: 'monitoring' },
  ]
};

async function scan(targetUrl) {
  const results = { technologies: [], tests: [] };
  try {
    const response = await axios.get(targetUrl, {
      timeout: 15000, maxRedirects: 5, validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
    });

    const headers = response.headers;
    const html = typeof response.data === 'string' ? response.data : '';
    const detected = new Set();

    // Server header
    const server = (headers['server'] || '').toLowerCase();
    for (const [key, tech] of Object.entries(TECH_SIGNATURES.servers)) {
      const found = server.includes(key);
      if (found && !detected.has(tech.name)) {
        detected.add(tech.name);
        results.technologies.push({ ...tech, source: 'server-header', value: headers['server'] });
      }
      results.tests.push({ id: `tech-server-${key}`, name: `Server: ${tech.name}`, status: found ? 'info' : 'pass', severity: 'info' });
    }

    // X-Powered-By
    const poweredBy = (headers['x-powered-by'] || '').toLowerCase();
    for (const [key, tech] of Object.entries(TECH_SIGNATURES.poweredBy)) {
      const found = poweredBy.includes(key);
      if (found && !detected.has(tech.name)) {
        detected.add(tech.name);
        results.technologies.push({ ...tech, source: 'x-powered-by', value: headers['x-powered-by'] });
      }
      results.tests.push({ id: `tech-xpb-${key}`, name: `X-Powered-By: ${tech.name}`, status: found ? 'info' : 'pass', severity: 'info' });
    }

    // HTML signatures
    for (const sig of TECH_SIGNATURES.htmlSignatures) {
      const found = sig.pattern.test(html);
      if (found && !detected.has(sig.name)) {
        detected.add(sig.name);
        results.technologies.push({ name: sig.name, category: sig.category, source: 'html-analysis' });
      }
      results.tests.push({ id: `tech-html-${sig.name.replace(/\s/g,'-')}`, name: `Technology: ${sig.name}`, status: found ? 'info' : 'pass', severity: 'info' });
    }

    // Meta generator
    const $ = cheerio.load(html);
    const generator = $('meta[name="generator"]').attr('content');
    if (generator) {
      results.technologies.push({ name: generator, category: 'generator', source: 'meta-tag' });
      results.tests.push({ id: 'tech-meta-generator', name: `Meta generator: ${generator}`, status: 'info', severity: 'info' });
    }

  } catch (err) {
    results.error = `Tech detection failed: ${err.message}`;
  }
  return { scanner: 'Technology Detection', icon: '🔍', results, testCount: results.tests.length };
}

module.exports = { scan };
