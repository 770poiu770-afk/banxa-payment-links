'use strict';
// LOCAL TEST DOUBLE of Banxa Hosted Checkout v2 — used only by the automated tests.
// Mimics the documented endpoints and can inject failures (timeouts, 5xx, tampered fields, list lag).
const http = require('http');
const crypto = require('crypto');

function startMockBanxa({ partnerRef, apiKey }) {
  const orders = new Map();
  const calls = [];
  const ctl = {
    createMode: 'ok',          // ok | timeout-after-create | 500-after-create | 500-no-create | 400 | malformed-after-create
    createDelayMs: 0,
    createOverride: null,      // fields merged into the create RESPONSE (simulate tampered/incorrect data)
    lookupOverride: new Map(), // id -> fields merged into GET /orders/{id} and list items
    failLookup: 0,             // next N GET /orders/{id} return 500
    failList: 0,               // next N GET /orders (list) return 500
    listLagMs: 0,              // orders become visible in list only after this delay
    includeCheckoutInLookup: false,
  };
  const reset = () => Object.assign(ctl, { createMode: 'ok', createDelayMs: 0, createOverride: null, failLookup: 0,
    failList: 0, listLagMs: 0, includeCheckoutInLookup: false }) && ctl.lookupOverride.clear();

  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      calls.push({ method: req.method, url: req.url, headers: req.headers, body });
      const send = (code, obj) => { if (res.writableEnded || res.destroyed) return; res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(typeof obj === 'string' ? obj : JSON.stringify(obj)); };
      const base = `http://127.0.0.1:${server.address().port}`;
      if (req.url.startsWith('/checkout/')) { res.writeHead(200); return res.end('MOCK BANXA CHECKOUT'); }
      if (req.headers['x-api-key'] !== apiKey) return send(401, { message: 'unauthorized' });
      const prefix = `/${partnerRef}/v2`;
      if (!req.url.startsWith(prefix)) return send(404, { message: 'partner not found' });
      const u = new URL(req.url.slice(prefix.length), 'http://x');
      const p = u.pathname;
      const view = (o) => { const { request, visibleAt, ...pub } = o; const out = { ...pub, ...(ctl.lookupOverride.get(o.id) || {}) };
        if (!ctl.includeCheckoutInLookup) delete out.checkoutUrl; return out; };

      if (req.method === 'POST' && p === '/buy') {
        const b = JSON.parse(body);
        if (ctl.createMode === '400') return send(400, { message: 'invalid walletAddress' });
        if (ctl.createMode === '500-no-create') return send(500, { message: 'internal error' });
        for (const f of ['crypto', 'fiat', 'walletAddress', 'redirectUrl', 'externalCustomerId']) {
          if (!b[f]) return send(400, { message: `${f} is required` });
        }
        const id = crypto.randomBytes(16).toString('hex');
        const o = {
          id, externalId: b.externalOrderId, externalCustomerId: b.externalCustomerId, orderType: 'BUY', status: 'pendingPayment',
          crypto: { id: b.crypto, blockchain: b.blockchain, address: b.walletAddress }, fiat: b.fiat, fiatAmount: b.fiatAmount,
          cryptoAmount: (Number(b.fiatAmount) * 0.97).toFixed(6), paymentMethodId: b.paymentMethodId, walletAddress: b.walletAddress,
          transactionHash: null, metadata: b.metadata, createdAt: new Date().toISOString(),
          checkoutUrl: `${base}/checkout/${id}?signature=x`, request: b, visibleAt: Date.now() + ctl.listLagMs,
        };
        orders.set(id, o);
        if (ctl.createMode === 'timeout-after-create') return setTimeout(() => send(201, {}), 5000);
        if (ctl.createMode === '500-after-create') return send(502, 'Bad Gateway');
        if (ctl.createMode === 'malformed-after-create') return send(200, { ok: true });
        const resp = { checkoutUrl: o.checkoutUrl, id, externalOrderId: b.externalOrderId, externalCustomerId: b.externalCustomerId,
          fiat: b.fiat, fiatAmount: b.fiatAmount, crypto: b.crypto, cryptoAmount: o.cryptoAmount, blockchain: b.blockchain, ...(ctl.createOverride || {}) };
        return setTimeout(() => send(201, resp), ctl.createDelayMs);
      }
      if (req.method === 'GET' && p === '/orders') {
        if (!u.searchParams.get('start') || !u.searchParams.get('end')) return send(400, { message: 'start and end are required' });
        if (ctl.failList > 0) { ctl.failList--; return send(503, { message: 'unavailable' }); }
        const cid = u.searchParams.get('externalCustomerId');
        const list = [...orders.values()].filter((o) => Date.now() >= o.visibleAt && (!cid || o.externalCustomerId === cid)).map(view);
        const page = Number(u.searchParams.get('page') || 1), limit = Number(u.searchParams.get('limit') || 100);
        const slice = list.slice((page - 1) * limit, page * limit);
        return send(200, { orders: slice, pageTotal: slice.length, total: list.length });
      }
      const m = p.match(/^\/orders\/([a-f0-9]+)$/);
      if (req.method === 'GET' && m) {
        if (ctl.failLookup > 0) { ctl.failLookup--; return send(500, { message: 'lookup unavailable' }); }
        const o = orders.get(m[1]);
        if (!o) return send(404, { message: 'not found' });
        return send(200, view(o));
      }
      if (req.method === 'GET' && p === '/crypto/buy') return send(200, [{ id: 'USDT', blockchains: [{ code: 'TRON' }, { code: 'ETH' }] }]);
      if (req.method === 'GET' && p === '/payment-methods/buy') return send(200, [{ id: 'debit-credit-card', name: 'Visa/Mastercard' }]);
      send(404, { message: 'no route' });
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    server, orders, calls, ctl, reset, url: `http://127.0.0.1:${server.address().port}`,
    setStatus(id, status, extra = {}) { Object.assign(orders.get(id), { status }, extra); },
    buyCalls: () => calls.filter((c) => c.method === 'POST' && c.url.endsWith('/v2/buy')).length,
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }),
  })));
}

module.exports = { startMockBanxa };
