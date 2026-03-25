const axios = require('axios');

// ============================================================
// MASSIVE INFO LEAK + CONTENT DISCOVERY SCANNER
// 250+ paths covering: config, VCS, backups, admin, PHP, node,
// Java, Python, Ruby, .NET, CI/CD, keys, logs, CMS, API, cloud,
// monitoring, database, IDE, temp, error pages, docs, and more
// ============================================================

const PATHS = [
  // ── Config files (40+) ──
  { path: '/.env', name: '.env', severity: 'critical', cat: 'config' },
  { path: '/.env.bak', name: '.env backup', severity: 'critical', cat: 'config' },
  { path: '/.env.local', name: '.env.local', severity: 'critical', cat: 'config' },
  { path: '/.env.production', name: '.env.production', severity: 'critical', cat: 'config' },
  { path: '/.env.development', name: '.env.dev', severity: 'critical', cat: 'config' },
  { path: '/.env.staging', name: '.env.staging', severity: 'critical', cat: 'config' },
  { path: '/.env.old', name: '.env.old', severity: 'critical', cat: 'config' },
  { path: '/.env.save', name: '.env.save', severity: 'critical', cat: 'config' },
  { path: '/.env.dist', name: '.env.dist', severity: 'high', cat: 'config' },
  { path: '/.env.example', name: '.env.example', severity: 'medium', cat: 'config' },
  { path: '/config.php', name: 'config.php', severity: 'critical', cat: 'config' },
  { path: '/config.php.bak', name: 'config.php backup', severity: 'critical', cat: 'config' },
  { path: '/config.yml', name: 'config.yml', severity: 'high', cat: 'config' },
  { path: '/config.yaml', name: 'config.yaml', severity: 'high', cat: 'config' },
  { path: '/config.json', name: 'config.json', severity: 'high', cat: 'config' },
  { path: '/config.xml', name: 'config.xml', severity: 'high', cat: 'config' },
  { path: '/config.inc', name: 'config.inc', severity: 'high', cat: 'config' },
  { path: '/config.inc.php', name: 'config.inc.php', severity: 'critical', cat: 'config' },
  { path: '/configuration.php', name: 'Joomla config', severity: 'critical', cat: 'config' },
  { path: '/wp-config.php', name: 'WP config', severity: 'critical', cat: 'config' },
  { path: '/wp-config.php.bak', name: 'WP config bak', severity: 'critical', cat: 'config' },
  { path: '/wp-config.php~', name: 'WP config temp', severity: 'critical', cat: 'config' },
  { path: '/wp-config.php.old', name: 'WP config old', severity: 'critical', cat: 'config' },
  { path: '/wp-config.php.save', name: 'WP config save', severity: 'critical', cat: 'config' },
  { path: '/settings.php', name: 'Drupal settings', severity: 'critical', cat: 'config' },
  { path: '/database.yml', name: 'Rails DB config', severity: 'critical', cat: 'config' },
  { path: '/application.yml', name: 'Spring config', severity: 'high', cat: 'config' },
  { path: '/application.properties', name: 'Spring props', severity: 'high', cat: 'config' },
  { path: '/appsettings.json', name: '.NET settings', severity: 'high', cat: 'config' },
  { path: '/appsettings.Development.json', name: '.NET dev settings', severity: 'critical', cat: 'config' },
  { path: '/web.config', name: 'IIS config', severity: 'high', cat: 'config' },
  { path: '/web.config.bak', name: 'IIS config bak', severity: 'critical', cat: 'config' },
  { path: '/.htaccess', name: 'Apache htaccess', severity: 'medium', cat: 'config' },
  { path: '/.htpasswd', name: 'Apache htpasswd', severity: 'critical', cat: 'config' },
  { path: '/nginx.conf', name: 'Nginx config', severity: 'critical', cat: 'config' },
  { path: '/httpd.conf', name: 'Apache config', severity: 'critical', cat: 'config' },
  { path: '/docker-compose.yml', name: 'Docker Compose', severity: 'high', cat: 'config' },
  { path: '/docker-compose.yaml', name: 'Docker Compose yaml', severity: 'high', cat: 'config' },
  { path: '/docker-compose.override.yml', name: 'Docker override', severity: 'high', cat: 'config' },
  { path: '/Dockerfile', name: 'Dockerfile', severity: 'medium', cat: 'config' },
  { path: '/.dockerignore', name: '.dockerignore', severity: 'low', cat: 'config' },
  { path: '/Vagrantfile', name: 'Vagrantfile', severity: 'high', cat: 'config' },
  { path: '/Procfile', name: 'Heroku Procfile', severity: 'medium', cat: 'config' },
  { path: '/Makefile', name: 'Makefile', severity: 'low', cat: 'config' },
  { path: '/Gruntfile.js', name: 'Gruntfile', severity: 'low', cat: 'config' },
  { path: '/Gulpfile.js', name: 'Gulpfile', severity: 'low', cat: 'config' },
  { path: '/webpack.config.js', name: 'Webpack config', severity: 'medium', cat: 'config' },
  { path: '/tsconfig.json', name: 'TypeScript config', severity: 'low', cat: 'config' },
  { path: '/babel.config.js', name: 'Babel config', severity: 'low', cat: 'config' },
  { path: '/next.config.js', name: 'Next.js config', severity: 'medium', cat: 'config' },
  { path: '/nuxt.config.js', name: 'Nuxt config', severity: 'medium', cat: 'config' },

  // ── VCS (15+) ──
  { path: '/.git/config', name: 'Git config', severity: 'critical', cat: 'vcs' },
  { path: '/.git/HEAD', name: 'Git HEAD', severity: 'critical', cat: 'vcs' },
  { path: '/.git/index', name: 'Git index', severity: 'critical', cat: 'vcs' },
  { path: '/.git/logs/HEAD', name: 'Git logs', severity: 'critical', cat: 'vcs' },
  { path: '/.git/packed-refs', name: 'Git packed-refs', severity: 'critical', cat: 'vcs' },
  { path: '/.git/refs/heads/main', name: 'Git main ref', severity: 'critical', cat: 'vcs' },
  { path: '/.git/refs/heads/master', name: 'Git master ref', severity: 'critical', cat: 'vcs' },
  { path: '/.gitignore', name: '.gitignore', severity: 'low', cat: 'vcs' },
  { path: '/.gitattributes', name: '.gitattributes', severity: 'low', cat: 'vcs' },
  { path: '/.svn/entries', name: 'SVN entries', severity: 'critical', cat: 'vcs' },
  { path: '/.svn/wc.db', name: 'SVN database', severity: 'critical', cat: 'vcs' },
  { path: '/.hg/hgrc', name: 'Mercurial config', severity: 'critical', cat: 'vcs' },
  { path: '/.bzr/README', name: 'Bazaar repo', severity: 'critical', cat: 'vcs' },
  { path: '/CVS/Entries', name: 'CVS entries', severity: 'high', cat: 'vcs' },
  { path: '/CVS/Root', name: 'CVS root', severity: 'high', cat: 'vcs' },

  // ── Backups (20+) ──
  { path: '/backup.sql', name: 'SQL backup', severity: 'critical', cat: 'backup' },
  { path: '/backup.zip', name: 'Backup zip', severity: 'critical', cat: 'backup' },
  { path: '/backup.tar.gz', name: 'Backup tar', severity: 'critical', cat: 'backup' },
  { path: '/backup.tar', name: 'Backup tar', severity: 'critical', cat: 'backup' },
  { path: '/backup.rar', name: 'Backup rar', severity: 'critical', cat: 'backup' },
  { path: '/db.sql', name: 'DB dump', severity: 'critical', cat: 'backup' },
  { path: '/db.sql.gz', name: 'DB dump gz', severity: 'critical', cat: 'backup' },
  { path: '/database.sql', name: 'Database backup', severity: 'critical', cat: 'backup' },
  { path: '/dump.sql', name: 'SQL dump', severity: 'critical', cat: 'backup' },
  { path: '/data.sql', name: 'Data SQL', severity: 'critical', cat: 'backup' },
  { path: '/site.tar.gz', name: 'Site backup', severity: 'critical', cat: 'backup' },
  { path: '/www.tar.gz', name: 'WWW backup', severity: 'critical', cat: 'backup' },
  { path: '/htdocs.tar.gz', name: 'htdocs backup', severity: 'critical', cat: 'backup' },
  { path: '/public_html.tar.gz', name: 'public_html backup', severity: 'critical', cat: 'backup' },
  { path: '/backup/', name: 'Backup dir', severity: 'high', cat: 'backup' },
  { path: '/backups/', name: 'Backups dir', severity: 'high', cat: 'backup' },
  { path: '/old/', name: 'Old dir', severity: 'medium', cat: 'backup' },
  { path: '/temp/', name: 'Temp dir', severity: 'medium', cat: 'backup' },
  { path: '/tmp/', name: 'Tmp dir', severity: 'medium', cat: 'backup' },
  { path: '/archive/', name: 'Archive dir', severity: 'medium', cat: 'backup' },
  { path: '/bak/', name: 'Bak dir', severity: 'medium', cat: 'backup' },

  // ── Admin panels (30+) ──
  { path: '/admin', name: 'Admin', severity: 'high', cat: 'admin' },
  { path: '/admin/', name: 'Admin dir', severity: 'high', cat: 'admin' },
  { path: '/admin/login', name: 'Admin login', severity: 'high', cat: 'admin' },
  { path: '/admin/dashboard', name: 'Admin dashboard', severity: 'high', cat: 'admin' },
  { path: '/administrator/', name: 'Joomla admin', severity: 'high', cat: 'admin' },
  { path: '/wp-admin/', name: 'WP admin', severity: 'medium', cat: 'admin' },
  { path: '/wp-login.php', name: 'WP login', severity: 'medium', cat: 'admin' },
  { path: '/login', name: 'Login', severity: 'info', cat: 'admin' },
  { path: '/signin', name: 'Sign in', severity: 'info', cat: 'admin' },
  { path: '/dashboard', name: 'Dashboard', severity: 'medium', cat: 'admin' },
  { path: '/cpanel', name: 'cPanel', severity: 'high', cat: 'admin' },
  { path: '/phpmyadmin/', name: 'phpMyAdmin', severity: 'critical', cat: 'admin' },
  { path: '/pma/', name: 'phpMyAdmin alt', severity: 'critical', cat: 'admin' },
  { path: '/mysql/', name: 'MySQL admin', severity: 'critical', cat: 'admin' },
  { path: '/adminer.php', name: 'Adminer', severity: 'critical', cat: 'admin' },
  { path: '/adminer/', name: 'Adminer dir', severity: 'critical', cat: 'admin' },
  { path: '/server-status', name: 'Apache status', severity: 'high', cat: 'admin' },
  { path: '/server-info', name: 'Apache info', severity: 'high', cat: 'admin' },
  { path: '/status', name: 'Status page', severity: 'medium', cat: 'admin' },
  { path: '/health', name: 'Health check', severity: 'low', cat: 'admin' },
  { path: '/healthz', name: 'K8s health', severity: 'low', cat: 'admin' },
  { path: '/readyz', name: 'K8s ready', severity: 'low', cat: 'admin' },
  { path: '/livez', name: 'K8s live', severity: 'low', cat: 'admin' },
  { path: '/metrics', name: 'Metrics', severity: 'high', cat: 'admin' },
  { path: '/debug', name: 'Debug', severity: 'critical', cat: 'admin' },
  { path: '/debug/', name: 'Debug dir', severity: 'critical', cat: 'admin' },
  { path: '/trace', name: 'Trace', severity: 'critical', cat: 'admin' },
  { path: '/console', name: 'Console', severity: 'critical', cat: 'admin' },
  { path: '/manager/', name: 'Tomcat manager', severity: 'critical', cat: 'admin' },
  { path: '/manager/html', name: 'Tomcat HTML manager', severity: 'critical', cat: 'admin' },
  { path: '/jmx-console/', name: 'JBoss JMX', severity: 'critical', cat: 'admin' },
  { path: '/web-console/', name: 'JBoss web console', severity: 'critical', cat: 'admin' },
  { path: '/actuator', name: 'Spring Actuator', severity: 'high', cat: 'admin' },
  { path: '/actuator/env', name: 'Actuator env', severity: 'critical', cat: 'admin' },
  { path: '/actuator/health', name: 'Actuator health', severity: 'medium', cat: 'admin' },
  { path: '/actuator/info', name: 'Actuator info', severity: 'medium', cat: 'admin' },
  { path: '/actuator/beans', name: 'Actuator beans', severity: 'high', cat: 'admin' },
  { path: '/actuator/configprops', name: 'Actuator config', severity: 'critical', cat: 'admin' },
  { path: '/actuator/mappings', name: 'Actuator mappings', severity: 'high', cat: 'admin' },
  { path: '/actuator/metrics', name: 'Actuator metrics', severity: 'medium', cat: 'admin' },
  { path: '/actuator/logfile', name: 'Actuator logfile', severity: 'high', cat: 'admin' },
  { path: '/actuator/threaddump', name: 'Actuator threaddump', severity: 'high', cat: 'admin' },
  { path: '/actuator/heapdump', name: 'Actuator heapdump', severity: 'critical', cat: 'admin' },
  { path: '/actuator/shutdown', name: 'Actuator shutdown', severity: 'critical', cat: 'admin' },
  { path: '/elmah.axd', name: 'ELMAH errors', severity: 'high', cat: 'admin' },
  { path: '/hangfire', name: 'Hangfire dashboard', severity: 'high', cat: 'admin' },
  { path: '/sidekiq', name: 'Sidekiq dashboard', severity: 'high', cat: 'admin' },
  { path: '/resque', name: 'Resque dashboard', severity: 'high', cat: 'admin' },
  { path: '/flower/', name: 'Celery Flower', severity: 'high', cat: 'admin' },
  { path: '/rabbitmq/', name: 'RabbitMQ management', severity: 'critical', cat: 'admin' },

  // ── API / Documentation (20+) ──
  { path: '/api', name: 'API root', severity: 'medium', cat: 'api' },
  { path: '/api/', name: 'API dir', severity: 'medium', cat: 'api' },
  { path: '/api/v1', name: 'API v1', severity: 'medium', cat: 'api' },
  { path: '/api/v2', name: 'API v2', severity: 'medium', cat: 'api' },
  { path: '/api/v3', name: 'API v3', severity: 'medium', cat: 'api' },
  { path: '/swagger', name: 'Swagger', severity: 'high', cat: 'api' },
  { path: '/swagger/', name: 'Swagger dir', severity: 'high', cat: 'api' },
  { path: '/swagger-ui.html', name: 'Swagger UI', severity: 'high', cat: 'api' },
  { path: '/swagger.json', name: 'Swagger JSON', severity: 'high', cat: 'api' },
  { path: '/swagger.yaml', name: 'Swagger YAML', severity: 'high', cat: 'api' },
  { path: '/api-docs', name: 'API docs', severity: 'high', cat: 'api' },
  { path: '/api-docs/', name: 'API docs dir', severity: 'high', cat: 'api' },
  { path: '/openapi.json', name: 'OpenAPI spec', severity: 'high', cat: 'api' },
  { path: '/openapi.yaml', name: 'OpenAPI YAML', severity: 'high', cat: 'api' },
  { path: '/graphql', name: 'GraphQL', severity: 'high', cat: 'api' },
  { path: '/graphiql', name: 'GraphiQL', severity: 'critical', cat: 'api' },
  { path: '/__graphql', name: 'GraphQL debug', severity: 'critical', cat: 'api' },
  { path: '/playground', name: 'GraphQL playground', severity: 'critical', cat: 'api' },
  { path: '/altair', name: 'Altair GraphQL', severity: 'critical', cat: 'api' },
  { path: '/rest/', name: 'REST dir', severity: 'medium', cat: 'api' },
  { path: '/redoc', name: 'Redoc', severity: 'high', cat: 'api' },
  { path: '/docs', name: 'Docs', severity: 'medium', cat: 'api' },
  { path: '/documentation', name: 'Documentation', severity: 'medium', cat: 'api' },
  { path: '/apidoc/', name: 'API doc dir', severity: 'high', cat: 'api' },

  // ── PHP (10+) ──
  { path: '/phpinfo.php', name: 'phpinfo()', severity: 'critical', cat: 'php' },
  { path: '/info.php', name: 'info.php', severity: 'critical', cat: 'php' },
  { path: '/test.php', name: 'test.php', severity: 'high', cat: 'php' },
  { path: '/php.ini', name: 'php.ini', severity: 'critical', cat: 'php' },
  { path: '/composer.json', name: 'Composer', severity: 'medium', cat: 'php' },
  { path: '/composer.lock', name: 'Composer lock', severity: 'medium', cat: 'php' },
  { path: '/vendor/', name: 'Vendor dir', severity: 'medium', cat: 'php' },
  { path: '/vendor/autoload.php', name: 'Autoload', severity: 'medium', cat: 'php' },
  { path: '/artisan', name: 'Laravel artisan', severity: 'high', cat: 'php' },
  { path: '/storage/logs/laravel.log', name: 'Laravel log', severity: 'high', cat: 'php' },

  // ── Node.js (10+) ──
  { path: '/package.json', name: 'package.json', severity: 'medium', cat: 'node' },
  { path: '/package-lock.json', name: 'package-lock', severity: 'low', cat: 'node' },
  { path: '/yarn.lock', name: 'yarn.lock', severity: 'low', cat: 'node' },
  { path: '/pnpm-lock.yaml', name: 'pnpm-lock', severity: 'low', cat: 'node' },
  { path: '/node_modules/', name: 'node_modules', severity: 'high', cat: 'node' },
  { path: '/.npmrc', name: '.npmrc', severity: 'high', cat: 'node' },
  { path: '/.yarnrc', name: '.yarnrc', severity: 'medium', cat: 'node' },

  // ── Keys/Creds (15+) ──
  { path: '/id_rsa', name: 'SSH private key', severity: 'critical', cat: 'keys' },
  { path: '/id_rsa.pub', name: 'SSH public key', severity: 'medium', cat: 'keys' },
  { path: '/id_ed25519', name: 'ED25519 key', severity: 'critical', cat: 'keys' },
  { path: '/.ssh/authorized_keys', name: 'SSH authorized', severity: 'critical', cat: 'keys' },
  { path: '/server.key', name: 'SSL private key', severity: 'critical', cat: 'keys' },
  { path: '/server.crt', name: 'SSL certificate', severity: 'medium', cat: 'keys' },
  { path: '/privatekey.pem', name: 'PEM key', severity: 'critical', cat: 'keys' },
  { path: '/credentials', name: 'Credentials', severity: 'critical', cat: 'keys' },
  { path: '/credentials.json', name: 'Creds JSON', severity: 'critical', cat: 'keys' },
  { path: '/.aws/credentials', name: 'AWS creds', severity: 'critical', cat: 'keys' },
  { path: '/secrets.yml', name: 'Secrets YAML', severity: 'critical', cat: 'keys' },
  { path: '/secrets.json', name: 'Secrets JSON', severity: 'critical', cat: 'keys' },
  { path: '/.gcloud/credentials.db', name: 'GCloud creds', severity: 'critical', cat: 'keys' },
  { path: '/firebase-adminsdk.json', name: 'Firebase admin SDK', severity: 'critical', cat: 'keys' },
  { path: '/service-account.json', name: 'Service account', severity: 'critical', cat: 'keys' },

  // ── Logs (10+) ──
  { path: '/error.log', name: 'Error log', severity: 'high', cat: 'logs' },
  { path: '/access.log', name: 'Access log', severity: 'high', cat: 'logs' },
  { path: '/debug.log', name: 'Debug log', severity: 'high', cat: 'logs' },
  { path: '/application.log', name: 'App log', severity: 'high', cat: 'logs' },
  { path: '/app.log', name: 'App log', severity: 'high', cat: 'logs' },
  { path: '/wp-content/debug.log', name: 'WP debug', severity: 'high', cat: 'logs' },
  { path: '/logs/', name: 'Logs dir', severity: 'high', cat: 'logs' },
  { path: '/log/', name: 'Log dir', severity: 'high', cat: 'logs' },
  { path: '/var/log/', name: 'Var log', severity: 'high', cat: 'logs' },

  // ── CMS / WordPress (15+) ──
  { path: '/wp-content/', name: 'WP content', severity: 'info', cat: 'cms' },
  { path: '/wp-includes/', name: 'WP includes', severity: 'info', cat: 'cms' },
  { path: '/wp-json/', name: 'WP REST API', severity: 'medium', cat: 'cms' },
  { path: '/wp-json/wp/v2/users', name: 'WP user enum', severity: 'high', cat: 'cms' },
  { path: '/wp-json/wp/v2/posts', name: 'WP posts API', severity: 'medium', cat: 'cms' },
  { path: '/xmlrpc.php', name: 'WP XML-RPC', severity: 'high', cat: 'cms' },
  { path: '/readme.html', name: 'WP readme', severity: 'medium', cat: 'cms' },
  { path: '/license.txt', name: 'License', severity: 'info', cat: 'cms' },
  { path: '/feed/', name: 'RSS feed', severity: 'info', cat: 'cms' },

  // ── CI/CD (10+) ──
  { path: '/.github/', name: 'GitHub', severity: 'medium', cat: 'cicd' },
  { path: '/.github/workflows/', name: 'GitHub Actions', severity: 'high', cat: 'cicd' },
  { path: '/.gitlab-ci.yml', name: 'GitLab CI', severity: 'high', cat: 'cicd' },
  { path: '/Jenkinsfile', name: 'Jenkinsfile', severity: 'high', cat: 'cicd' },
  { path: '/.travis.yml', name: 'Travis CI', severity: 'medium', cat: 'cicd' },
  { path: '/.circleci/config.yml', name: 'CircleCI', severity: 'medium', cat: 'cicd' },
  { path: '/bitbucket-pipelines.yml', name: 'Bitbucket CI', severity: 'medium', cat: 'cicd' },
  { path: '/azure-pipelines.yml', name: 'Azure Pipelines', severity: 'medium', cat: 'cicd' },
  { path: '/.drone.yml', name: 'Drone CI', severity: 'medium', cat: 'cicd' },
  { path: '/Earthfile', name: 'Earthfile', severity: 'low', cat: 'cicd' },

  // ── Crawl/SEO ──
  { path: '/robots.txt', name: 'robots.txt', severity: 'info', cat: 'crawl' },
  { path: '/sitemap.xml', name: 'Sitemap', severity: 'info', cat: 'crawl' },
  { path: '/sitemap_index.xml', name: 'Sitemap index', severity: 'info', cat: 'crawl' },
  { path: '/humans.txt', name: 'humans.txt', severity: 'info', cat: 'crawl' },
  { path: '/security.txt', name: 'security.txt', severity: 'info', cat: 'crawl' },
  { path: '/.well-known/security.txt', name: 'Well-known security.txt', severity: 'info', cat: 'crawl' },
  { path: '/crossdomain.xml', name: 'Cross-domain policy', severity: 'medium', cat: 'crawl' },
  { path: '/clientaccesspolicy.xml', name: 'Client access policy', severity: 'medium', cat: 'crawl' },
  { path: '/favicon.ico', name: 'Favicon', severity: 'info', cat: 'crawl' },
  { path: '/manifest.json', name: 'PWA manifest', severity: 'info', cat: 'crawl' },
  { path: '/browserconfig.xml', name: 'Browser config', severity: 'info', cat: 'crawl' },
  { path: '/ads.txt', name: 'ads.txt', severity: 'info', cat: 'crawl' },
  { path: '/app-ads.txt', name: 'app-ads.txt', severity: 'info', cat: 'crawl' },

  // ── Cloud / IDE / Misc ──
  { path: '/.idea/', name: 'IntelliJ IDEA', severity: 'medium', cat: 'ide' },
  { path: '/.idea/workspace.xml', name: 'IDEA workspace', severity: 'high', cat: 'ide' },
  { path: '/.vscode/', name: 'VS Code', severity: 'medium', cat: 'ide' },
  { path: '/.vscode/settings.json', name: 'VS Code settings', severity: 'medium', cat: 'ide' },
  { path: '/.vscode/launch.json', name: 'VS Code launch', severity: 'high', cat: 'ide' },
  { path: '/.DS_Store', name: 'macOS DS_Store', severity: 'low', cat: 'ide' },
  { path: '/Thumbs.db', name: 'Windows Thumbs.db', severity: 'low', cat: 'ide' },
  { path: '/.editorconfig', name: 'EditorConfig', severity: 'info', cat: 'ide' },
  { path: '/terraform.tfstate', name: 'Terraform state', severity: 'critical', cat: 'cloud' },
  { path: '/terraform.tfvars', name: 'Terraform vars', severity: 'critical', cat: 'cloud' },
  { path: '/ansible.cfg', name: 'Ansible config', severity: 'high', cat: 'cloud' },
  { path: '/vars.yml', name: 'Ansible vars', severity: 'high', cat: 'cloud' },
  { path: '/k8s/', name: 'K8s configs', severity: 'high', cat: 'cloud' },
  { path: '/kubernetes/', name: 'K8s dir', severity: 'high', cat: 'cloud' },
  { path: '/helm/', name: 'Helm charts', severity: 'medium', cat: 'cloud' },
  { path: '/Chart.yaml', name: 'Helm chart', severity: 'medium', cat: 'cloud' },

  // ── Error/Test pages ──
  { path: '/test', name: 'Test page', severity: 'medium', cat: 'test' },
  { path: '/test/', name: 'Test dir', severity: 'medium', cat: 'test' },
  { path: '/testing/', name: 'Testing dir', severity: 'high', cat: 'test' },
  { path: '/error', name: 'Error page', severity: 'low', cat: 'test' },
  { path: '/404', name: '404 page', severity: 'info', cat: 'test' },
  { path: '/500', name: '500 page', severity: 'low', cat: 'test' },
  { path: '/maintenance', name: 'Maintenance', severity: 'low', cat: 'test' },
];

async function scan(targetUrl) {
  const results = { found: [], notFound: [], tests: [] };
  try {
    const baseUrl = targetUrl.replace(/\/$/, '');
    const batchSize = 15;
    for (let i = 0; i < PATHS.length; i += batchSize) {
      const batch = PATHS.slice(i, i + batchSize);
      const checks = batch.map(async (item) => {
        try {
          const r = await axios.get(`${baseUrl}${item.path}`, {
            timeout: 6000, maxRedirects: 3, validateStatus: () => true,
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
          });
          const ok = r.status >= 200 && r.status < 400;
          const hasContent = r.data && (typeof r.data === 'string' ? r.data.length > 50 : true);
          if (ok && hasContent) {
            results.found.push({ path: item.path, name: item.name, severity: item.severity, status: r.status, cat: item.cat });
            results.tests.push({ id: `info-${item.path}`, name: `${item.name} accessible`, status: 'fail', severity: item.severity });
          } else {
            results.tests.push({ id: `info-${item.path}`, name: `${item.name} not found`, status: 'pass', severity: 'info' });
          }
        } catch { /* request failed — not counted as pass or fail */ }
      });
      await Promise.all(checks);
    }
  } catch (err) { results.error = err.message; }
  return { scanner: 'Information Leakage', icon: '📂', results, testCount: results.tests.length };
}

module.exports = { scan };
