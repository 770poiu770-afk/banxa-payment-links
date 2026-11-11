'use strict';
// All configuration comes from environment variables (see .env.example).
// Secrets never leave the server: they are not rendered into any page or sent to the browser.

function req(name) {
  const v = process.env[name];
  if (!v || !String(v).trim()) throw new Error(`Missing required environment variable: ${name}`);
  return String(v).trim();
}
function opt(name, def = '') {
  const v = process.env[name];
  return v === undefined || v === '' ? def : String(v).trim();
}

const BANXA_HOSTS = {
  sandbox: { api: 'https://api.banxa-sandbox.com', checkoutHosts: ['banxa-sandbox.com'] },
  production: { api: 'https://api.banxa.com', checkoutHosts: ['banxa.com'] },
};

function load() {
  const env = opt('BANXA_ENV', 'sandbox');
  if (!BANXA_HOSTS[env]) throw new Error('BANXA_ENV must be "sandbox" or "production"');

  const productionApproved = opt('BANXA_PRODUCTION_APPROVED', 'false') === 'true';
  if (env === 'production' && !productionApproved) {
    throw new Error(
      'BANXA_ENV=production requires BANXA_PRODUCTION_APPROVED=true. ' +
      'Set it only after Banxa has approved your integration and issued production credentials.'
    );
  }

  const apiOverride = opt('BANXA_API_BASE_OVERRIDE');
  if (apiOverride && env === 'production') {
    throw new Error('BANXA_API_BASE_OVERRIDE is for local testing only and is refused in production.');
  }

  const publicBaseUrl = req('PUBLIC_BASE_URL').replace(/\/+$/, '');
  const isProdNode = opt('NODE_ENV') === 'production';
  if (isProdNode && !publicBaseUrl.startsWith('https://')) {
    throw new Error('PUBLIC_BASE_URL must be https:// when NODE_ENV=production');
  }

  const sessionSecret = req('SESSION_SECRET');
  if (sessionSecret.length < 32) throw new Error('SESSION_SECRET must be at least 32 characters');

  const webhookPath = opt('WEBHOOK_PATH', '/webhooks/banxa');
  if (!webhookPath.startsWith('/')) throw new Error('WEBHOOK_PATH must start with /');

  return Object.freeze({
    port: Number(opt('PORT', '3000')),
    isProdNode,
    trustProxy: opt('TRUST_PROXY', '1'),
    publicBaseUrl,
    secureCookies: publicBaseUrl.startsWith('https://'),
    sessionSecret,
    adminUsername: req('ADMIN_USERNAME'),
    adminPasswordHash: req('ADMIN_PASSWORD_HASH'),
    dbPath: opt('DB_PATH', './data/banxa-links.sqlite'),

    banxa: Object.freeze({
      env,
      productionApproved,
      apiBase: apiOverride || BANXA_HOSTS[env].api,
      usingOverride: Boolean(apiOverride),
      checkoutHosts: apiOverride
        ? [new URL(apiOverride).hostname] // local mock only
        : BANXA_HOSTS[env].checkoutHosts,
      partnerRef: opt('BANXA_PARTNER_REF'),
      apiKey: opt('BANXA_API_KEY'),            // v2 x-api-key (order create / lookup)
      hmacKey: opt('BANXA_HMAC_KEY'),          // HMAC key pair: used to verify webhooks
      hmacSecret: opt('BANXA_HMAC_SECRET'),
      blockchain: opt('BANXA_BLOCKCHAIN_CODE', 'TRON'),
      crypto: 'USDT',
      fiat: 'USD',
      paymentMethodId: 'debit-credit-card',   // Banxa: Visa & Mastercard
      timeoutMs: Number(opt('BANXA_TIMEOUT_MS', '15000')),
    }),

    webhookPath,
    minUsd: Number(opt('MIN_USD', '20')),
    maxUsd: Number(opt('MAX_USD', '10000')),
    defaultLinkTtlHours: Number(opt('LINK_TTL_HOURS', '24')),
    maxAttemptsPerLink: Number(opt('MAX_ATTEMPTS_PER_LINK', '3')),
    pollIntervalSec: Number(opt('POLL_INTERVAL_SEC', '120')),
    // After an ambiguous create (timeout/5xx), Banxa's order list may lag. "Not found" only counts
    // as proof that no order exists once this many seconds have passed since the attempt started.
    reconcileGraceSec: Number(opt('RECONCILE_GRACE_SEC', '90')),
    // Banxa FAQ: checkoutUrl is valid for 1 minute from Banxa's create-order response until first loaded.
    // We only ever redirect within (TTL - safety margin) of the moment we received that response.
    // There is no documented way to re-enter a checkout or obtain a new URL for an existing order.
    checkoutUrlTtlSec: Number(opt('CHECKOUT_URL_TTL_SEC', '60')),
    checkoutUrlMarginSec: Number(opt('CHECKOUT_URL_MARGIN_SEC', '15')),
    payRateLimit: Number(opt('PAY_RATE_LIMIT', '40')),      // per IP per 10 minutes on /pay
    loginRateLimit: Number(opt('LOGIN_RATE_LIMIT', '10')),  // per IP per 15 minutes
  });
}

module.exports = { load };
