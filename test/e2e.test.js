'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { startMockBanxa } = require('./mock-banxa');
const { hashPassword } = require('../src/auth');
const { signWebhook } = require('../src/banxa');
const { isValidTronAddress } = require('../src/tron');

// ---- helpers ----
const ALPHA = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58(buf) {
  let n = BigInt('0x' + buf.toString('hex')); let s = '';
  while (n > 0n) { s = ALPHA[Number(n % 58n)] + s; n /= 58n; }
  for (const b of buf) { if (b === 0) s = '1' + s; else break; }
  return s;
}
function tronAddr() {
  const p = Buffer.concat([Buffer.from([0x41]), crypto.randomBytes(20)]);
  const h = crypto.createHash('sha256').update(crypto.createHash('sha256').update(p).digest()).digest();
  return b58(Buffer.concat([p, h.subarray(0, 4)]));
}

const PARTNER = 'testpartner', API_KEY = 'k_' + crypto.randomBytes(8).toString('hex');
const HMAC_KEY = 'hk_test', HMAC_SECRET = crypto.randomBytes(16).toString('hex');
const PASSWORD = 'correct horse battery staple';

let mock, srv, base, cookie = '', csrf = '', db, svc, app;

test.before(async () => {
  mock = await startMockBanxa({ partnerRef: PARTNER, apiKey: API_KEY });
  Object.assign(process.env, {
    PUBLIC_BASE_URL: 'http://127.0.0.1:0', SESSION_SECRET: crypto.randomBytes(32).toString('hex'),
    ADMIN_USERNAME: 'admin', ADMIN_PASSWORD_HASH: hashPassword(PASSWORD), DB_PATH: ':memory:',
    BANXA_ENV: 'sandbox', BANXA_PARTNER_REF: PARTNER, BANXA_API_KEY: API_KEY,
    BANXA_HMAC_KEY: HMAC_KEY, BANXA_HMAC_SECRET: HMAC_SECRET, BANXA_API_BASE_OVERRIDE: mock.url, MIN_USD: '20', MAX_USD: '5000',
    BANXA_TIMEOUT_MS: '400', RECONCILE_GRACE_SEC: '1', MAX_ATTEMPTS_PER_LINK: '3', PAY_RATE_LIMIT: '100000',
    CHECKOUT_URL_TTL_SEC: '3', CHECKOUT_URL_MARGIN_SEC: '1', // 2s usable window in tests (production: 60s - 15s)
  });
  // start once to learn port, then rebuild config with the real public URL
  const http = require('http');
  const tmp = http.createServer(); await new Promise((r) => tmp.listen(0, '127.0.0.1', r));
  const port = tmp.address().port; await new Promise((r) => tmp.close(r));
  process.env.PUBLIC_BASE_URL = `http://127.0.0.1:${port}`;
  const cfg = require('../src/config').load();
  db = require('../src/db').open(':memory:');
  const banxa = require('../src/banxa').createClient(cfg);
  ({ app, svc } = require('../src/app').createApp({ cfg, db, banxa, log: { error() {}, warn() {}, log() {} } }));
  srv = await new Promise((r) => { const s = app.listen(port, '127.0.0.1', () => r(s)); });
  base = `http://127.0.0.1:${port}`;
});
test.beforeEach(() => mock && mock.reset());
test.after(async () => { await new Promise((r) => srv.close(r)); await mock.close(); });

const form = (o) => new URLSearchParams(o).toString();
async function req(path, { method = 'GET', body, headers = {}, raw } = {}) {
  const r = await fetch(base + path, {
    method, redirect: 'manual',
    headers: { ...(body ? { 'content-type': 'application/x-www-form-urlencoded' } : {}), ...(cookie ? { cookie } : {}), ...headers },
    body: raw ?? (body ? form(body) : undefined),
  });
  return { status: r.status, location: r.headers.get('location'), text: await r.text(), headers: r.headers };
}
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function webhook(payload, { tamper = false, auth } = {}) {
  const raw = JSON.stringify(payload);
  let a = auth || signWebhook({ path: '/webhooks/banxa', rawBody: raw, hmacKey: HMAC_KEY, hmacSecret: HMAC_SECRET });
  if (tamper) a = a.replace(/:([0-9a-f])/, (m, c) => ':' + (c === '0' ? '1' : '0'));
  const r = await fetch(base + '/webhooks/banxa', { method: 'POST', headers: { 'content-type': 'application/json', authorization: a }, body: raw });
  await wait(80);
  return r.status;
}
const linkRow = (pid) => db.prepare('SELECT * FROM payment_links WHERE public_id=?').get(pid);
const orderRow = (linkId) => db.prepare('SELECT * FROM orders WHERE link_id=? ORDER BY id DESC').get(linkId);

async function createLink(overrides = {}) {
  const r = await req('/admin/links', { method: 'POST', body: {
    _csrf: csrf, amount: '150', customer_name: 'Dana Levi', customer_email: 'dana@example.com',
    wallet: tronAddr(), wallet_attest: '1', description: 'Order #1001', ttl_hours: '24', ...overrides } });
  const url = (r.text.match(/id="linkUrl" value="([^"]+)"/) || [])[1];
  const pid = url ? db.prepare('SELECT public_id FROM payment_links WHERE token=?').get(url.split('/pay/')[1]).public_id : null;
  return { r, url, token: url && url.split('/pay/')[1], pid };
}
async function payThrough(token, extra = {}) {
  const page = await req(`/pay/${token}`);
  const ft = page.text.match(/name="ft" value="([^"]+)"/)[1];
  return req(`/pay/${token}`, { method: 'POST', body: { ft, own_wallet: '1', own_card: '1', ...extra } });
}

// ---- tests ----
test('TRON address validation uses checksum', () => {
  const a = tronAddr();
  assert.ok(isValidTronAddress(a));
  assert.ok(!isValidTronAddress(a.slice(0, -1) + (a.endsWith('a') ? 'b' : 'a')));
  assert.ok(!isValidTronAddress('0x1234'));
});

test('admin requires login; wrong password rejected', async () => {
  assert.equal((await req('/admin')).status, 303);
  assert.equal((await req('/admin/login', { method: 'POST', body: { username: 'admin', password: 'nope' } })).status, 401);
  const ok = await req('/admin/login', { method: 'POST', body: { username: 'admin', password: PASSWORD } });
  assert.equal(ok.status, 303);
  cookie = ok.headers.get('set-cookie').split(';')[0];
  const dash = await req('/admin');
  csrf = dash.text.match(/name="_csrf" value="([^"]+)"/)[1];
  assert.match(dash.text, /מודל התשלום המאושר/);
});

test('admin POST without CSRF token is refused', async () => {
  const r = await req('/admin/links', { method: 'POST', body: { amount: '50' } });
  assert.equal(r.status, 403);
});

test('blocked (business) wallet cannot be used as destination', async () => {
  const biz = tronAddr();
  await req('/admin/settings/blocked', { method: 'POST', body: { _csrf: csrf, address: biz, label: 'my business wallet' } });
  const { r, url } = await createLink({ wallet: biz });
  assert.equal(r.status, 400); assert.equal(url, undefined);
  assert.match(r.text, /ארנק חסום/);
});

test('validation: amount range, wallet checksum, attestation', async () => {
  assert.equal((await createLink({ amount: '5' })).r.status, 400);
  assert.equal((await createLink({ wallet: 'TXYZ' })).r.status, 400);
  assert.equal((await createLink({ wallet_attest: '' })).r.status, 400);
});

test('full flow: link -> Banxa order with locked params -> webhooks -> Completed; no reuse', async () => {
  const wallet = tronAddr();
  const { url, token, pid } = await createLink({ wallet, amount: '150.00' });
  assert.ok(url.startsWith(base + '/pay/'));
  assert.match(url, /\/pay\/[A-Za-z0-9_-]{43}$/);

  // customer page shows locked values and Banxa disclaimer; no editable wallet input
  const page = await req(`/pay/${token}?amount=1&walletAddress=TATTACKER&crypto=BTC`);
  assert.equal(page.status, 200);
  assert.match(page.text, /\$150\.00 USD/);
  assert.match(page.text, /Banxa, a separate third-party platform/);
  assert.doesNotMatch(page.text, /name="wallet/);

  // must confirm statements
  const ft = page.text.match(/name="ft" value="([^"]+)"/)[1];
  assert.equal((await req(`/pay/${token}`, { method: 'POST', body: { ft } })).status, 400);
  // forged form token rejected
  assert.equal((await req(`/pay/${token}`, { method: 'POST', body: { ft: 'x', own_wallet: '1', own_card: '1' } })).status, 403);

  // tampering attempt via extra POST fields is ignored -> redirect straight to Banxa checkout
  const go = await payThrough(token, { fiatAmount: '1', walletAddress: tronAddr(), crypto: 'BTC', blockchain: 'ETH' });
  assert.equal(go.status, 303);
  assert.ok(go.location.startsWith(mock.url + '/checkout/'));

  const sent = JSON.parse(mock.calls.filter((c) => c.url.endsWith('/v2/buy')).at(-1).body);
  assert.deepEqual(
    { crypto: sent.crypto, fiat: sent.fiat, fiatAmount: sent.fiatAmount, blockchain: sent.blockchain, walletAddress: sent.walletAddress, paymentMethodId: sent.paymentMethodId },
    { crypto: 'USDT', fiat: 'USD', fiatAmount: '150.00', blockchain: 'TRON', walletAddress: wallet, paymentMethodId: 'debit-credit-card' });
  assert.equal(mock.calls.filter((c) => c.url.endsWith('/v2/buy')).at(-1).headers['x-api-key'], API_KEY);

  const link = linkRow(pid); const order = orderRow(link.id);
  assert.equal(link.status, 'checkout');

  // second POST can't create a second order
  const again = await req(`/pay/${token}`, { method: 'POST', body: { ft, own_wallet: '1', own_card: '1' } });
  assert.equal(again.status, 303); assert.equal(again.location, `/pay/${token}`);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM orders WHERE link_id=?').get(link.id).n, 1);
  // reopening an open checkout resumes the same Banxa checkout URL
  const resume = await req(`/pay/${token}`);
  assert.equal(resume.status, 303); assert.equal(resume.location, order.checkout_url);

  // forged webhook rejected and has no effect
  assert.equal(await webhook({ order_id: order.banxa_order_id, status: 'complete' }, { tamper: true }), 401);
  assert.equal(await webhook({ order_id: order.banxa_order_id, status: 'complete' }, { auth: 'Bearer nope' }), 401);
  assert.equal(orderRow(link.id).banxa_status, 'pendingPayment');

  // genuine lifecycle
  const steps = [
    ['paymentReceived', 'Payment Completed'], ['extraVerification', 'Verification Pending'],
    ['inProgress', 'Processing'], ['cryptoTransferred', 'Processing'], ['complete', 'Completed'],
  ];
  const txHash = crypto.randomBytes(32).toString('hex');
  for (const [s, label] of steps) {
    const extra = ['cryptoTransferred', 'complete'].includes(s) ? { transactionHash: txHash } : {};
    mock.setStatus(order.banxa_order_id, s, extra);
    assert.equal(await webhook({ order_id: order.banxa_order_id, status: s, transaction_hash: extra.transactionHash, crypto_coin: 'USDT', fiat_currency: 'USD', fiat_amount: 150 }), 200);
    assert.equal(orderRow(link.id).banxa_status, s);
    const dash = await req('/admin');
    assert.match(dash.text, new RegExp(`pill s-${label.replace(/\s/g, '')}">${label}`));
  }
  const final = orderRow(link.id);
  assert.equal(final.tx_hash, txHash);
  assert.equal(final.mismatch, null);
  assert.equal(linkRow(pid).status, 'paid');

  // duplicate retry of same webhook is idempotent
  assert.equal(await webhook({ order_id: order.banxa_order_id, status: 'complete' }), 200);

  // link can't be reused after completion
  const after = await req(`/pay/${token}`);
  assert.equal(after.status, 200); assert.match(after.text, /Already paid/);
  const replay = await req(`/pay/${token}`, { method: 'POST', body: { ft, own_wallet: '1', own_card: '1' } });
  assert.equal(replay.status, 303); assert.equal(replay.location, `/pay/${token}`);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM orders WHERE link_id=?').get(link.id).n, 1);
});

test('mismatch reported later (lookup) blocks the link and removes the checkout URL', async () => {
  const { token, pid } = await createLink();
  assert.equal((await payThrough(token)).status, 303);
  const o = orderRow(linkRow(pid).id);
  mock.setStatus(o.banxa_order_id, 'paymentReceived', { fiatAmount: '999.00' });
  await webhook({ order_id: o.banxa_order_id, status: 'paymentReceived' });
  const after = orderRow(linkRow(pid).id);
  assert.match(after.mismatch, /fiatAmount 999/);
  assert.equal(after.local_state, 'blocked');
  assert.equal(after.checkout_url, null);
  assert.equal(linkRow(pid).status, 'blocked');
});

test('expired order allows retry up to the limit; cancelled ends the link', async () => {
  const { token, pid } = await createLink();
  await payThrough(token);
  let o = orderRow(linkRow(pid).id);
  mock.setStatus(o.banxa_order_id, 'expired');
  await webhook({ order_id: o.banxa_order_id, status: 'expired' });
  assert.equal(linkRow(pid).status, 'active');
  const second = await payThrough(token);
  assert.equal(second.status, 303);
  o = orderRow(linkRow(pid).id);
  assert.match(o.external_order_id, /-2$/);
  mock.setStatus(o.banxa_order_id, 'cancelled');
  await webhook({ order_id: o.banxa_order_id, status: 'cancelled' });
  assert.equal(linkRow(pid).status, 'failed');
  assert.match((await req(`/pay/${token}`)).text, /no longer valid/);
});

test('revoked and unknown links are refused; polling sync works without webhooks', async () => {
  const { token, pid } = await createLink();
  await req(`/admin/links/${pid}/revoke`, { method: 'POST', body: { _csrf: csrf } });
  assert.equal((await req(`/pay/${token}`)).status, 410);
  assert.equal((await req('/pay/' + 'A'.repeat(43))).status, 404);

  const l2 = await createLink();
  await payThrough(l2.token);
  const o = orderRow(linkRow(l2.pid).id);
  mock.setStatus(o.banxa_order_id, 'complete', { transactionHash: 'abc123' });
  const r = await fetch(base + '/admin/api/sync-all', { method: 'POST', headers: { cookie, 'x-csrf-token': csrf } });
  assert.equal(r.status, 200);
  assert.equal(orderRow(linkRow(l2.pid).id).banxa_status, 'complete');
  assert.equal(orderRow(linkRow(l2.pid).id).tx_hash, 'abc123');
});

test('verify-banxa reports USDT/TRON and card availability', async () => {
  const r = await req('/admin/verify-banxa', { method: 'POST', body: { _csrf: csrf } });
  assert.match(r.text, /✅ USDT/); assert.match(r.text, /debit-credit-card/);
});

test('no secrets leak into any rendered page', async () => {
  const pages = [await req('/admin'), await req('/admin/settings')];
  for (const p of pages) { assert.ok(!p.text.includes(API_KEY)); assert.ok(!p.text.includes(HMAC_SECRET)); }
});

test('production mode refuses to start without approval / with mock override', () => {
  const { load } = require('../src/config');
  const saved = { ...process.env };
  process.env.BANXA_ENV = 'production'; process.env.BANXA_PRODUCTION_APPROVED = 'false';
  assert.throws(load, /PRODUCTION_APPROVED/);
  process.env.BANXA_PRODUCTION_APPROVED = 'true';
  assert.throws(load, /refused in production/);
  Object.assign(process.env, saved); process.env.BANXA_ENV = 'sandbox';
});

// ======================================================================= failure scenarios
const buyCount = () => mock.buyCalls();
const countOrders = (linkId) => db.prepare('SELECT COUNT(*) n FROM orders WHERE link_id=? AND banxa_order_id IS NOT NULL').get(linkId).n;
async function expectBlocked(token, pid) {
  const l = linkRow(pid);
  assert.equal(l.status, 'blocked', 'link must be blocked');
  for (const o of db.prepare('SELECT * FROM orders WHERE link_id=?').all(l.id)) assert.equal(o.checkout_url, null, 'no checkout URL may remain');
  const g = await req(`/pay/${token}`);
  assert.equal(g.status, 409); assert.equal(g.location, null); assert.match(g.text, /stopped for a security check/);
  const before = buyCount();
  const ft = linkFormTokenFor(token);
  const p = await req(`/pay/${token}`, { method: 'POST', body: { ft, own_wallet: '1', own_card: '1' } });
  assert.notEqual(p.location && p.location.startsWith(mock.url), true, 'POST must never reach Banxa checkout');
  assert.equal(buyCount(), before, 'no new Banxa order after a block');
}
function linkFormTokenFor(token) {
  return require('../src/auth').linkFormToken(process.env.SESSION_SECRET, token);
}

const createMismatches = [
  ['fiatAmount', { fiatAmount: '1.00' }, /fiatAmount 1\.00/],
  ['fiat', { fiat: 'EUR' }, /fiat EUR/],
  ['crypto', { crypto: 'BTC' }, /crypto BTC/],
  ['blockchain', { blockchain: 'ETH' }, /blockchain ETH/],
  ['externalOrderId', { externalOrderId: 'someone-else' }, /externalOrderId someone-else/],
  ['externalCustomerId', { externalCustomerId: 'cus_other' }, /externalCustomerId cus_other/],
  ['checkoutUrl host', { checkoutUrl: 'https://evil.example.com/pay' }, /checkoutUrl is not a Banxa/],
];
for (const [name, override, re] of createMismatches) {
  test(`create-response mismatch (${name}) stops checkout before redirect`, async () => {
    const { token, pid } = await createLink();
    mock.ctl.createOverride = override;
    const r = await payThrough(token);
    assert.equal(r.status, 400); assert.equal(r.location, null);
    assert.match(r.text, /stopped for a security check/);
    assert.match(orderRow(linkRow(pid).id).mismatch, re);
    mock.ctl.createOverride = null;
    await expectBlocked(token, pid);
  });
}

const lookupMismatches = [
  ['walletAddress', () => ({ walletAddress: tronAddr() }), /walletAddress/],
  ['crypto.address', () => ({ walletAddress: undefined, crypto: { id: 'USDT', blockchain: 'TRON', address: tronAddr() } }), /walletAddress/],
  ['paymentMethodId', () => ({ paymentMethodId: 'apple-pay' }), /paymentMethod apple-pay/],
  ['crypto.blockchain', () => ({ crypto: { id: 'USDT', blockchain: 'BSC' } }), /blockchain BSC/],
  ['crypto.id', () => ({ crypto: { id: 'USDC', blockchain: 'TRON' } }), /crypto USDC/],
  ['fiat', () => ({ fiat: 'GBP' }), /fiat GBP/],
  ['orderType', () => ({ orderType: 'SELL' }), /orderType SELL/],
  ['walletAddressTag', () => ({ walletAddressTag: '12345' }), /walletAddressTag/],
];
for (const [name, mk, re] of lookupMismatches) {
  test(`order-lookup mismatch (${name}) blocks before the customer is redirected`, async () => {
    const { token, pid } = await createLink();
    // inject the override as soon as Banxa creates the order (before our verification lookup)
    const origSet = mock.orders.set.bind(mock.orders);
    mock.orders.set = (id, o) => { mock.ctl.lookupOverride.set(id, mk()); return origSet(id, o); };
    const r = await payThrough(token);
    mock.orders.set = origSet;
    assert.equal(r.status, 400); assert.equal(r.location, null);
    assert.match(orderRow(linkRow(pid).id).mismatch, re);
    await expectBlocked(token, pid);
  });
}

test('mismatch discovered when the customer reopens the link: no resume, URL erased', async () => {
  const { token, pid } = await createLink();
  const go = await payThrough(token);
  assert.ok(go.location.startsWith(mock.url));
  const o = orderRow(linkRow(pid).id);
  mock.ctl.lookupOverride.set(o.banxa_order_id, { walletAddress: tronAddr() });
  const g = await req(`/pay/${token}`);            // reopening triggers a fresh lookup -> mismatch
  assert.equal(g.status, 409); assert.equal(g.location, null);
  await expectBlocked(token, pid);
});

test('mismatch in a webhook is blocked even when the lookup is unavailable', async () => {
  const { token, pid } = await createLink();
  await payThrough(token);
  const o = orderRow(linkRow(pid).id);
  mock.ctl.failLookup = 100;
  await webhook({ order_id: o.banxa_order_id, status: 'paymentReceived', fiat_amount: '10.00', fiat_currency: 'USD', crypto_coin: 'USDT', external_id: o.external_order_id });
  assert.match(orderRow(linkRow(pid).id).mismatch, /webhook.*fiatAmount 10\.00/);
  assert.equal(linkRow(pid).status, 'blocked');
});

test('verification lookup failure: fail closed (no redirect), then resume once lookup works', async () => {
  const { token, pid } = await createLink();
  mock.ctl.failLookup = 1;
  const r = await payThrough(token);
  assert.equal(r.status, 202); assert.equal(r.location, null);
  assert.equal(orderRow(linkRow(pid).id).local_state, 'unverified');
  mock.ctl.failLookup = 2;                       // still down on reopen (both lookups) -> wait, still no redirect
  assert.equal((await req(`/pay/${token}`)).status, 202);
  const g = await req(`/pay/${token}`);         // lookup back -> verified -> redirect to the same order
  assert.equal(g.status, 303); assert.ok(g.location.startsWith(mock.url));
  assert.equal(buyCount() > 0 && countOrders(linkRow(pid).id), 1, 'still exactly one Banxa order');
});

test('timeout after Banxa created the order: reconciled by externalOrderId, never duplicated blindly', async () => {
  const { token, pid } = await createLink();
  mock.ctl.createMode = 'timeout-after-create';
  const before = buyCount();
  const r = await payThrough(token);
  assert.equal(r.status, 202);                   // wait page, no redirect
  assert.equal(buyCount(), before + 1);
  const l = linkRow(pid);
  const o = db.prepare('SELECT * FROM orders WHERE link_id=?').get(l.id);
  // reconciliation found the order Banxa created; its checkout URL was never exposed -> orphaned, tracked
  assert.equal(o.local_state, 'orphaned');
  assert.ok(o.banxa_order_id && mock.orders.has(o.banxa_order_id));
  assert.equal(o.checkout_url, null);
  assert.equal(l.status, 'active');
  // a listing call with start/end/externalCustomerId was used
  const list = mock.calls.filter((c) => c.url.includes('/v2/orders?')).at(-1);
  assert.match(list.url, /start=\d{4}-\d{2}-\d{2}&end=\d{4}-\d{2}-\d{2}/); assert.match(list.url, /externalCustomerId=cus_/);
  // customer retries: a new attempt with a NEW externalOrderId; only this URL is ever shown
  mock.ctl.createMode = 'ok';
  const r2 = await payThrough(token);
  assert.equal(r2.status, 303);
  const latest = orderRow(l.id);
  assert.match(latest.external_order_id, /-2$/);
  assert.ok(r2.location.includes(latest.banxa_order_id));
});

test('timeout where order lookup returns a valid checkoutUrl: existing order is reused (zero duplicates)', async () => {
  const { token, pid } = await createLink();
  mock.ctl.createMode = 'timeout-after-create';
  mock.ctl.includeCheckoutInLookup = true;
  const before = buyCount();
  assert.equal((await payThrough(token)).status, 202);
  const o = orderRow(linkRow(pid).id);
  assert.equal(o.local_state, 'open');
  const g = await req(`/pay/${token}`);
  assert.equal(g.status, 303); assert.ok(g.location.includes(o.banxa_order_id));
  assert.equal(buyCount(), before + 1, 'exactly one create call');
});

test('ambiguous 502 / malformed 2xx are treated like timeouts (reconcile, no blind retry)', async () => {
  for (const mode of ['500-after-create', 'malformed-after-create']) {
    const { token, pid } = await createLink();
    mock.ctl.createMode = mode;
    assert.equal((await payThrough(token)).status, 202, mode);
    const o = db.prepare('SELECT * FROM orders WHERE link_id=?').get(linkRow(pid).id);
    assert.equal(o.local_state, 'orphaned', mode);
    mock.ctl.createMode = 'ok';
  }
});

test('reconciliation lookup unavailable: link stays locked, no new Banxa order until resolved', async () => {
  const { token, pid } = await createLink();
  mock.ctl.createMode = 'timeout-after-create';
  mock.ctl.failList = 100;
  assert.equal((await payThrough(token)).status, 202);
  mock.ctl.createMode = 'ok';
  const before = buyCount();
  assert.equal(linkRow(pid).status, 'reconciling');
  assert.equal((await req(`/pay/${token}`)).status, 202);
  const ft = linkFormTokenFor(token);
  const p = await req(`/pay/${token}`, { method: 'POST', body: { ft, own_wallet: '1', own_card: '1' } });
  assert.equal(p.status, 303); assert.equal(p.location, `/pay/${token}`); // bounced, not sent to Banxa
  assert.equal(buyCount(), before, 'no create while unresolved');
  mock.ctl.failList = 0;
  await svc.reconcileAll();                       // background job resolves it
  assert.equal(db.prepare('SELECT local_state FROM orders WHERE link_id=?').get(linkRow(pid).id).local_state, 'orphaned');
  assert.equal(linkRow(pid).status, 'active');
});

test('ambiguous failure where Banxa did NOT create: "not found" only trusted after grace period', async () => {
  const { token, pid } = await createLink();
  mock.ctl.createMode = '500-no-create';
  assert.equal((await payThrough(token)).status, 202);
  const o = db.prepare('SELECT * FROM orders WHERE link_id=?').get(linkRow(pid).id);
  assert.equal(o.local_state, 'unknown');          // too early to conclude
  assert.equal(linkRow(pid).status, 'reconciling');
  await wait(1100);
  await svc.reconcileAll();
  assert.equal(svc.getOrderById(o.id).local_state, 'not_created');
  assert.equal(linkRow(pid).status, 'active');
  mock.ctl.createMode = 'ok';
  assert.equal((await payThrough(token)).status, 303);
});

test('list lag: order not yet visible is not mistaken for "not created"', async () => {
  const { token, pid } = await createLink();
  mock.ctl.createMode = '500-after-create';
  mock.ctl.listLagMs = 600;
  assert.equal((await payThrough(token)).status, 202);
  const id = db.prepare('SELECT id FROM orders WHERE link_id=?').get(linkRow(pid).id).id;
  assert.equal(svc.getOrderById(id).local_state, 'unknown');
  await wait(700);
  await svc.reconcileAll();
  assert.equal(svc.getOrderById(id).local_state, 'orphaned');
});

test('definitive 4xx from Banxa: nothing created, no reconciliation, customer can retry', async () => {
  const { token, pid } = await createLink();
  mock.ctl.createMode = '400';
  const r = await payThrough(token);
  assert.equal(r.status, 400);
  const o = db.prepare('SELECT * FROM orders WHERE link_id=?').get(linkRow(pid).id);
  assert.equal(o.local_state, 'rejected');
  assert.equal(linkRow(pid).status, 'active');
  mock.ctl.createMode = 'ok';
  assert.equal((await payThrough(token)).status, 303);
});

test('webhook for an order created during a timeout is adopted via external_id', async () => {
  const { token, pid } = await createLink();
  mock.ctl.createMode = 'timeout-after-create';
  mock.ctl.failList = 100;                        // reconciliation cannot run yet
  await payThrough(token);
  const o = db.prepare('SELECT * FROM orders WHERE link_id=?').get(linkRow(pid).id);
  assert.equal(o.local_state, 'unknown');
  const banxaId = [...mock.orders.values()].find((x) => x.externalId === o.external_order_id).id;
  mock.ctl.failList = 0;
  await webhook({ order_id: banxaId, status: 'pendingPayment', external_id: o.external_order_id });
  const after = svc.getOrderById(o.id);
  assert.equal(after.banxa_order_id, banxaId);
  assert.equal(after.local_state, 'orphaned');
});

test('webhook signature: missing, wrong key, wrong path, modified body, wrong secret are all rejected', async () => {
  const { token, pid } = await createLink();
  await payThrough(token);
  const o = orderRow(linkRow(pid).id);
  const raw = JSON.stringify({ order_id: o.banxa_order_id, status: 'complete' });
  const post = (auth, body = raw) => fetch(base + '/webhooks/banxa', { method: 'POST', headers: { 'content-type': 'application/json', ...(auth ? { authorization: auth } : {}) }, body }).then((r) => r.status);
  assert.equal(await post(null), 401);
  assert.equal(await post(signWebhook({ path: '/webhooks/banxa', rawBody: raw, hmacKey: 'other', hmacSecret: HMAC_SECRET })), 401);
  assert.equal(await post(signWebhook({ path: '/somewhere-else', rawBody: raw, hmacKey: HMAC_KEY, hmacSecret: HMAC_SECRET })), 401);
  assert.equal(await post(signWebhook({ path: '/webhooks/banxa', rawBody: raw, hmacKey: HMAC_KEY, hmacSecret: HMAC_SECRET }), raw.replace('complete', 'refunded')), 401);
  assert.equal(await post(signWebhook({ path: '/webhooks/banxa', rawBody: raw, hmacKey: HMAC_KEY, hmacSecret: 'wrong' })), 401);
  assert.equal(await post(`Bearer ${HMAC_KEY}:zz`), 401);
  await wait(50);
  assert.equal(orderRow(linkRow(pid).id).banxa_status, 'pendingPayment');
  assert.ok(db.prepare('SELECT COUNT(*) n FROM webhook_events WHERE signature_valid=0').get().n >= 6);
});

test('webhook processing failure is recovered later through order lookup', async () => {
  const { token, pid } = await createLink();
  await payThrough(token);
  const o = orderRow(linkRow(pid).id);
  mock.setStatus(o.banxa_order_id, 'complete', { transactionHash: 'feed01' });
  mock.ctl.failLookup = 100;
  assert.equal(await webhook({ order_id: o.banxa_order_id, status: 'paymentReceived' }), 200);
  let ev = db.prepare('SELECT * FROM webhook_events WHERE banxa_order_id=? AND status=?').get(o.banxa_order_id, 'paymentReceived');
  assert.equal(ev.processed, 0); assert.match(ev.last_error, /lookup failed/);
  assert.equal(orderRow(linkRow(pid).id).banxa_status, 'paymentReceived'); // applied from verified webhook meanwhile
  // Banxa retry while still failing: not lost, still pending
  assert.equal(await webhook({ order_id: o.banxa_order_id, status: 'paymentReceived' }), 200);
  mock.ctl.failLookup = 0;
  await svc.recoverWebhooks();
  ev = db.prepare('SELECT * FROM webhook_events WHERE id=?').get(ev.id);
  assert.equal(ev.processed, 1);
  const fin = orderRow(linkRow(pid).id);
  assert.equal(fin.banxa_status, 'complete'); assert.equal(fin.tx_hash, 'feed01');
});

test('duplicate processed webhook is ignored (no extra lookup); out-of-order webhook cannot regress', async () => {
  const { token, pid } = await createLink();
  await payThrough(token);
  const o = orderRow(linkRow(pid).id);
  mock.setStatus(o.banxa_order_id, 'complete', { transactionHash: 'aa11' });
  await webhook({ order_id: o.banxa_order_id, status: 'complete' });
  const lookups = () => mock.calls.filter((c) => c.method === 'GET' && c.url.endsWith(`/orders/${o.banxa_order_id}`)).length;
  const n = lookups();
  assert.equal(await webhook({ order_id: o.banxa_order_id, status: 'complete' }), 200);
  assert.equal(lookups(), n, 'duplicate must not trigger processing');
  mock.ctl.failLookup = 100;                     // late "paymentReceived" with lookup down
  await webhook({ order_id: o.banxa_order_id, status: 'paymentReceived' });
  assert.equal(orderRow(linkRow(pid).id).banxa_status, 'complete');
  assert.equal(linkRow(pid).status, 'paid');
});

test('webhook for an unknown order is stored safely and does not crash', async () => {
  assert.equal(await webhook({ order_id: 'deadbeef', status: 'complete' }), 200);
  const ev = db.prepare("SELECT * FROM webhook_events WHERE banxa_order_id='deadbeef'").get();
  assert.equal(ev.processed, 0); assert.equal(ev.last_error, 'unknown order');
  assert.equal((await req('/healthz')).status, 200);
});

test('Banxa endpoints match the Hosted Checkout v2 reference', async () => {
  mock.calls.length = 0;
  await req('/admin/verify-banxa', { method: 'POST', body: { _csrf: csrf } });
  const urls = mock.calls.map((c) => `${c.method} ${c.url}`);
  assert.ok(urls.includes(`GET /${PARTNER}/v2/crypto/buy`), urls.join('\n'));
  assert.ok(urls.includes(`GET /${PARTNER}/v2/payment-methods/buy?fiat=USD`));
  const { token } = await createLink();
  await payThrough(token);
  const all = mock.calls.map((c) => `${c.method} ${c.url.split('?')[0]}`);
  assert.ok(all.includes(`POST /${PARTNER}/v2/buy`));
  assert.ok(all.some((u) => new RegExp(`^GET /${PARTNER}/v2/orders/[a-f0-9]+$`).test(u)));
  for (const c of mock.calls) assert.equal(c.headers['x-api-key'], API_KEY);
});

test('customer page shows the full destination wallet clearly before confirmation', async () => {
  const wallet = tronAddr();
  const { token } = await createLink({ wallet });
  const page = await req(`/pay/${token}`);
  assert.match(page.text, /Your USDT will be sent to this wallet/);
  const plain = page.text.replace(/<[^>]+>/g, '').replace(/\s+/g, '');
  assert.ok(plain.includes(wallet), 'full address visible');
  assert.match(page.text, new RegExp(`ending in <code class="mono">${wallet.slice(-6)}</code>`));
  assert.match(page.text, /title="[^"]*"/);
});

// ======================================================================= checkout URL validity (Banxa: 1 minute)
const WINDOW_PLUS = 2100; // just past the 2s usable window configured for tests
const pageOf = async (token) => req(`/pay/${token}`);
function assertNoRedirect(r) { assert.equal(r.location, null, `unexpected redirect to ${r.location}`); }

test('checkout URL: repeated visits inside the window reuse the same URL; after it, never redirected and never re-created', async () => {
  const { token, pid } = await createLink();
  const first = await payThrough(token);
  assert.equal(first.status, 303);
  const o = orderRow(linkRow(pid).id);
  assert.ok(o.checkout_url_issued_at && o.redirected_at);
  for (let i = 0; i < 3; i++) {                     // second tab / refresh within the window
    const again = await pageOf(token);
    assert.equal(again.status, 303); assert.equal(again.location, first.location);
  }
  const creates = buyCount();
  await wait(WINDOW_PLUS);
  for (let i = 0; i < 3; i++) {                     // repeated visits after the window
    const r = await pageOf(token);
    assert.equal(r.status, 409); assertNoRedirect(r);
    assert.match(r.text, /Checkout session expired/); assert.match(r.text, /do not pay again/);
  }
  const ft = linkFormTokenFor(token);
  const p = await req(`/pay/${token}`, { method: 'POST', body: { ft, own_wallet: '1', own_card: '1' } });
  assert.equal(p.location, `/pay/${token}`);       // bounced to the status page, not to Banxa
  assert.equal(buyCount(), creates, 'no new Banxa order while the old one may be pending');
  const after = orderRow(linkRow(pid).id);
  assert.equal(after.local_state, 'url_expired'); assert.equal(after.checkout_url, null);
  assert.equal(linkRow(pid).status, 'stalled');
});

test('delayed verification: lookup succeeds only after the window -> customer is NOT redirected', async () => {
  const { token, pid } = await createLink();
  mock.ctl.failLookup = 1;
  const r = await payThrough(token);
  assert.equal(r.status, 202); assertNoRedirect(r);
  assert.equal(orderRow(linkRow(pid).id).local_state, 'unverified');
  await wait(WINDOW_PLUS);
  const g = await pageOf(token);                   // lookup now works, but the URL may have expired
  assert.equal(g.status, 409); assertNoRedirect(g);
  assert.equal(orderRow(linkRow(pid).id).local_state, 'url_expired');
  assert.equal(orderRow(linkRow(pid).id).redirected_at, null, 'URL was never handed out');
});

test('delayed verification inside the window still redirects (no false stops)', async () => {
  const { token, pid } = await createLink();
  mock.ctl.failLookup = 1;
  assert.equal((await payThrough(token)).status, 202);
  await wait(300);
  const g = await pageOf(token);
  assert.equal(g.status, 303); assert.ok(g.location.includes(orderRow(linkRow(pid).id).banxa_order_id));
});

test('stalled link: Banxa later reports expired -> a NEW order is allowed on the same link', async () => {
  const { token, pid } = await createLink();
  await payThrough(token);
  const o1 = orderRow(linkRow(pid).id);
  await wait(WINDOW_PLUS);
  assert.equal((await pageOf(token)).status, 409);
  mock.setStatus(o1.banxa_order_id, 'expired');
  await webhook({ order_id: o1.banxa_order_id, status: 'expired' });
  assert.equal(linkRow(pid).status, 'active');
  const page = await pageOf(token);
  assert.equal(page.status, 200); assert.match(page.text, /Continue to secure payment with Banxa/);
  const r = await payThrough(token);
  assert.equal(r.status, 303);
  const o2 = orderRow(linkRow(pid).id);
  assert.notEqual(o2.banxa_order_id, o1.banxa_order_id);
  assert.match(o2.external_order_id, /-2$/);
});

test('stalled link while customer is paying in the loaded tab (waitingPayment): no new order, no redirect', async () => {
  const { token, pid } = await createLink();
  await payThrough(token);
  const o = orderRow(linkRow(pid).id);
  await wait(WINDOW_PLUS);
  mock.setStatus(o.banxa_order_id, 'waitingPayment');
  const creates = buyCount();
  const r = await pageOf(token);
  assert.equal(r.status, 200); assertNoRedirect(r);
  assert.match(r.text, /Payment in progress/); assert.match(r.text, /Do not pay again/);
  assert.equal(buyCount(), creates);
});

test('stalled link: payment completes in the loaded tab -> link becomes paid', async () => {
  const { token, pid } = await createLink();
  await payThrough(token);
  const o = orderRow(linkRow(pid).id);
  await wait(WINDOW_PLUS);
  assert.equal((await pageOf(token)).status, 409);
  mock.setStatus(o.banxa_order_id, 'complete', { transactionHash: 'cc77' });
  await webhook({ order_id: o.banxa_order_id, status: 'complete' });
  assert.equal(linkRow(pid).status, 'paid');
  assert.match((await pageOf(token)).text, /Already paid/);
});

test('reconciliation never adopts a checkout URL that may already be expired', async () => {
  const { token, pid } = await createLink();
  mock.ctl.createMode = 'timeout-after-create';
  mock.ctl.includeCheckoutInLookup = true;
  mock.ctl.failList = 100;
  assert.equal((await payThrough(token)).status, 202);
  mock.ctl.createMode = 'ok';
  await wait(WINDOW_PLUS);
  mock.ctl.failList = 0;
  const creates = buyCount();
  const g = await pageOf(token);                   // reconciliation finds the order + its URL, but it's too old
  assertNoRedirect(g);
  assert.equal(g.status, 409);
  const o = db.prepare('SELECT * FROM orders WHERE link_id=?').get(linkRow(pid).id);
  assert.equal(o.local_state, 'url_expired'); assert.equal(o.checkout_url, null);
  assert.equal(buyCount(), creates, 'no new order while the adopted one is pending');
});

test('background sweep expires stale checkout URLs and the admin sees the stalled state', async () => {
  const { token, pid } = await createLink();
  await payThrough(token);
  await wait(WINDOW_PLUS);
  await svc.syncPending();
  const o = orderRow(linkRow(pid).id);
  assert.equal(o.local_state, 'url_expired'); assert.equal(o.checkout_url, null);
  assert.equal(linkRow(pid).status, 'stalled');
  const dash = await req('/admin');
  assert.match(dash.text, /קישור ה-Checkout פג/);
  const detail = await req(`/admin/links/${pid}`);
  assert.match(detail.text, /לא קיים מנגנון מתועד לחזרה לאותו Checkout/);
  // admin can revoke the stalled link
  await req(`/admin/links/${pid}/revoke`, { method: 'POST', body: { _csrf: csrf } });
  assert.equal(linkRow(pid).status, 'revoked');
  assert.equal((await pageOf(token)).status, 410);
});

test('usableCheckoutUrl refuses missing issuance time, future timestamps and non-pending orders', () => {
  const base0 = { local_state: 'open', checkout_url: 'https://x.banxa.com/c', banxa_status: 'pendingPayment' };
  assert.equal(svc.usableCheckoutUrl({ ...base0, checkout_url_issued_at: null }), null);
  assert.equal(svc.usableCheckoutUrl({ ...base0, checkout_url_issued_at: new Date(Date.now() + 60e3).toISOString() }), null);
  assert.equal(svc.usableCheckoutUrl({ ...base0, checkout_url_issued_at: new Date().toISOString(), banxa_status: 'paymentReceived' }), null);
  assert.equal(svc.usableCheckoutUrl({ ...base0, checkout_url_issued_at: new Date().toISOString(), local_state: 'unverified' }), null);
  assert.equal(svc.usableCheckoutUrl({ ...base0, checkout_url_issued_at: new Date().toISOString() }), base0.checkout_url);
});
