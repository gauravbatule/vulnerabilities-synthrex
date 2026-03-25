const axios = require('axios');
const cheerio = require('cheerio');

async function scan(targetUrl) {
  const results = { forms: [], tests: [] };
  try {
    const response = await axios.get(targetUrl, {
      timeout: 15000, maxRedirects: 5, validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
    });
    const html = typeof response.data === 'string' ? response.data : '';
    const $ = cheerio.load(html);

    const forms = $('form');
    results.tests.push({ id: 'form-count', name: `Forms found: ${forms.length}`, status: 'info', severity: 'info' });

    forms.each((i, form) => {
      const $form = $(form);
      const action = $form.attr('action') || '';
      const method = ($form.attr('method') || 'GET').toUpperCase();
      const enctype = $form.attr('enctype') || '';
      const formId = $form.attr('id') || $form.attr('name') || `form-${i}`;

      // CSRF token check
      const csrfInputs = $form.find('input[name*="csrf"], input[name*="token"], input[name*="_token"], input[name*="authenticity"], input[name*="nonce"], input[name*="xsrf"]');
      const hasCsrf = csrfInputs.length > 0;
      results.tests.push({ id: `form-csrf-${i}`, name: `${formId}: CSRF token present`, status: hasCsrf ? 'pass' : 'fail', severity: 'high' });

      // Method check
      results.tests.push({ id: `form-method-${i}`, name: `${formId}: Uses ${method} method`, status: method === 'POST' ? 'pass' : 'warn', severity: method === 'GET' ? 'medium' : 'info' });

      // Action check
      if (action.startsWith('http://')) {
        results.tests.push({ id: `form-action-http-${i}`, name: `${formId}: Action uses HTTP (not HTTPS)`, status: 'fail', severity: 'high' });
      } else if (action.startsWith('javascript:')) {
        results.tests.push({ id: `form-action-js-${i}`, name: `${formId}: Action uses javascript:`, status: 'fail', severity: 'high' });
      } else {
        results.tests.push({ id: `form-action-${i}`, name: `${formId}: Action URL safe`, status: 'pass', severity: 'info' });
      }

      // Check input types
      const inputs = $form.find('input, textarea, select');
      inputs.each((j, input) => {
        const $input = $(input);
        const type = ($input.attr('type') || 'text').toLowerCase();
        const inputName = $input.attr('name') || `input-${j}`;

        // Password fields
        if (type === 'password') {
          const hasAutocomplete = $input.attr('autocomplete');
          results.tests.push({ id: `form-pw-autocomplete-${i}-${j}`, name: `${formId}.${inputName}: Password autocomplete`, status: hasAutocomplete === 'off' || hasAutocomplete === 'new-password' ? 'pass' : 'warn', severity: 'medium' });

          // Check if form uses HTTPS
          if (action.startsWith('http://')) {
            results.tests.push({ id: `form-pw-http-${i}-${j}`, name: `${formId}.${inputName}: Password sent over HTTP`, status: 'fail', severity: 'critical' });
          }
        }

        // Email/phone fields
        if (type === 'email' || type === 'tel') {
          const hasAutocomplete = $input.attr('autocomplete');
          results.tests.push({ id: `form-pii-autocomplete-${i}-${j}`, name: `${formId}.${inputName}: PII autocomplete setting`, status: hasAutocomplete ? 'pass' : 'info', severity: 'low' });
        }

        // Hidden inputs (potential tokens or debug data)
        if (type === 'hidden') {
          results.tests.push({ id: `form-hidden-${i}-${j}`, name: `${formId}: Hidden input "${inputName}"`, status: 'info', severity: 'info' });
        }

        // File upload
        if (type === 'file') {
          const accept = $input.attr('accept');
          results.tests.push({ id: `form-file-${i}-${j}`, name: `${formId}.${inputName}: File upload field`, status: 'warn', severity: 'medium' });
          results.tests.push({ id: `form-file-accept-${i}-${j}`, name: `${formId}.${inputName}: File type restriction`, status: accept ? 'pass' : 'fail', severity: 'medium' });
        }

        // Maxlength check
        const maxlength = $input.attr('maxlength');
        if (!maxlength && (type === 'text' || type === 'password' || type === 'email')) {
          results.tests.push({ id: `form-maxlen-${i}-${j}`, name: `${formId}.${inputName}: No maxlength set`, status: 'warn', severity: 'low' });
        }
      });

      // Enctype check for file uploads
      if ($form.find('input[type="file"]').length > 0 && enctype !== 'multipart/form-data') {
        results.tests.push({ id: `form-enctype-${i}`, name: `${formId}: File upload without multipart encoding`, status: 'warn', severity: 'low' });
      }

      results.forms.push({ formId, action, method, hasCsrf, inputCount: inputs.length });
    });

    // Check for forms with sensitive actions
    const loginForms = $('form[action*="login"], form[action*="signin"], form[action*="auth"]');
    const registerForms = $('form[action*="register"], form[action*="signup"]');
    const paymentForms = $('form[action*="pay"], form[action*="checkout"], form[action*="purchase"]');

    if (loginForms.length > 0) results.tests.push({ id: 'form-login-detected', name: 'Login form detected', status: 'info', severity: 'info' });
    if (registerForms.length > 0) results.tests.push({ id: 'form-register-detected', name: 'Registration form detected', status: 'info', severity: 'info' });
    if (paymentForms.length > 0) results.tests.push({ id: 'form-payment-detected', name: 'Payment form detected', status: 'warn', severity: 'high' });

  } catch (err) {
    results.error = `Form scan failed: ${err.message}`;
  }
  return { scanner: 'Form Security', icon: '📝', results, testCount: results.tests.length };
}

module.exports = { scan };
