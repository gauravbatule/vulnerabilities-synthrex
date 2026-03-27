const axios = require('axios');

// GraphQL Introspection Scanner
// Discovers GraphQL endpoints and tests for exposed introspection/schemas
// FP prevention: Validates response is valid JSON with data.__schema structure
// FN prevention: Checks 8+ common GraphQL paths and multiple query formats

const GRAPHQL_PATHS = [
  '/graphql', '/gql', '/api/graphql', '/api/gql',
  '/v1/graphql', '/v2/graphql', '/query', '/graphql/console',
];

const INTROSPECTION_QUERY = '{"query":"{ __schema { types { name } } }"}';
const FULL_INTROSPECTION = '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name } } } }"}';

const SCANNER_TIMEOUT = 40000;

async function scan(targetUrl) {
  const results = { findings: [], tests: [] };
  const deadline = Date.now() + SCANNER_TIMEOUT;
  const baseUrl = targetUrl.replace(/\/$/, '');

  try {
    let graphqlFound = false;
    let introspectionEnabled = false;

    for (const gqlPath of GRAPHQL_PATHS) {
      if (Date.now() > deadline) break;
      const url = `${baseUrl}${gqlPath}`;

      // Test 1: Probe for GraphQL endpoint (GET with simple query)
      try {
        const probeGet = await axios.get(`${url}?query={__typename}`, {
          timeout: 6000, maxRedirects: 3, validateStatus: () => true,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Accept': 'application/json'
          }
        });

        let isGraphQL = false;
        if (probeGet.status >= 200 && probeGet.status < 500) {
          const body = typeof probeGet.data === 'string' ? probeGet.data : JSON.stringify(probeGet.data);
          // GraphQL endpoints return JSON with "data" key or "errors" key
          try {
            const parsed = typeof probeGet.data === 'object' ? probeGet.data : JSON.parse(body);
            if (parsed && (parsed.data !== undefined || parsed.errors !== undefined)) {
              isGraphQL = true;
            }
          } catch { /* not JSON */ }
        }

        if (!isGraphQL) {
          // Try POST
          try {
            const probePost = await axios.post(url, '{"query":"{ __typename }"}', {
              timeout: 6000, maxRedirects: 3, validateStatus: () => true,
              headers: {
                'Content-Type': 'application/json',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json'
              }
            });
            if (probePost.status >= 200 && probePost.status < 500) {
              try {
                const parsed = typeof probePost.data === 'object' ? probePost.data : JSON.parse(typeof probePost.data === 'string' ? probePost.data : '');
                if (parsed && (parsed.data !== undefined || parsed.errors !== undefined)) {
                  isGraphQL = true;
                }
              } catch { /* not JSON */ }
            }
          } catch { /* skip */ }
        }

        if (!isGraphQL) continue;

        graphqlFound = true;
        results.tests.push({
          id: `gql-found-${gqlPath.replace(/\//g, '-')}`,
          name: `GraphQL endpoint found: ${gqlPath}`,
          status: 'warn', severity: 'medium'
        });

        // Test 2: Introspection query
        try {
          const introResp = await axios.post(url, INTROSPECTION_QUERY, {
            timeout: 8000, validateStatus: () => true,
            headers: {
              'Content-Type': 'application/json',
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            }
          });

          const introData = typeof introResp.data === 'object' ? introResp.data : (() => { try { return JSON.parse(introResp.data); } catch { return null; } })();

          if (introData && introData.data && introData.data.__schema) {
            introspectionEnabled = true;
            const typeCount = introData.data.__schema.types ? introData.data.__schema.types.length : 0;

            results.tests.push({
              id: `gql-introspection-${gqlPath.replace(/\//g, '-')}`,
              name: `Introspection enabled at ${gqlPath} (${typeCount} types exposed)`,
              status: 'fail', severity: 'high'
            });

            // Test 3: Full introspection for mutations
            try {
              const fullResp = await axios.post(url, FULL_INTROSPECTION, {
                timeout: 8000, validateStatus: () => true,
                headers: { 'Content-Type': 'application/json' }
              });
              const fullData = typeof fullResp.data === 'object' ? fullResp.data : (() => { try { return JSON.parse(fullResp.data); } catch { return null; } })();

              if (fullData && fullData.data && fullData.data.__schema) {
                const schema = fullData.data.__schema;
                if (schema.mutationType) {
                  results.tests.push({
                    id: `gql-mutations-${gqlPath.replace(/\//g, '-')}`,
                    name: `Mutations exposed at ${gqlPath} (type: ${schema.mutationType.name})`,
                    status: 'fail', severity: 'high'
                  });
                }

                // Check for sensitive type names
                const sensitiveTypes = (schema.types || []).filter(t =>
                  /user|auth|admin|token|password|secret|session|credential|payment/i.test(t.name) &&
                  !t.name.startsWith('__')
                );
                if (sensitiveTypes.length > 0) {
                  results.tests.push({
                    id: `gql-sensitive-types-${gqlPath.replace(/\//g, '-')}`,
                    name: `Sensitive types exposed: ${sensitiveTypes.map(t => t.name).slice(0, 5).join(', ')}`,
                    status: 'fail', severity: 'critical'
                  });
                }
              }
            } catch { /* full query failed */ }

          } else if (introData && introData.errors) {
            // Introspection disabled via errors
            results.tests.push({
              id: `gql-introspection-blocked-${gqlPath.replace(/\//g, '-')}`,
              name: `Introspection disabled at ${gqlPath}`,
              status: 'pass', severity: 'info'
            });
          }
        } catch { /* skip */ }

      } catch { /* endpoint unreachable */ }
    }

    if (!graphqlFound) {
      results.tests.push({
        id: 'gql-not-found',
        name: 'No GraphQL endpoint detected',
        status: 'pass', severity: 'info'
      });
    }

    // Test 4: GraphiQL / Playground UI exposure
    const playgrounds = ['/graphiql', '/__graphql', '/playground', '/altair', '/graphql/explorer'];
    for (const pg of playgrounds) {
      if (Date.now() > deadline) break;
      try {
        const r = await axios.get(`${baseUrl}${pg}`, {
          timeout: 5000, maxRedirects: 3, validateStatus: () => true,
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
        });
        if (r.status >= 200 && r.status < 400) {
          const body = typeof r.data === 'string' ? r.data : '';
          // Verify it's actually a GraphQL IDE, not just a random page
          if (body.includes('graphiql') || body.includes('GraphiQL') || body.includes('graphql-playground') ||
              body.includes('AltairGraphQL') || body.includes('GraphQL Playground')) {
            results.tests.push({
              id: `gql-ide-${pg.replace(/\//g, '-')}`,
              name: `GraphQL IDE exposed: ${pg}`,
              status: 'fail', severity: 'critical'
            });
          }
        }
      } catch { /* skip */ }
    }

  } catch (err) {
    results.error = `GraphQL scan failed: ${err.message}`;
  }
  return { scanner: 'GraphQL Introspection', icon: '🔮', results, testCount: results.tests.length };
}

module.exports = { scan };
