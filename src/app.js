'use strict';
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { verifyWebhook } = require('./banxa');
const { verifyPassword, sessionManager, linkFormToken } = require('./auth');
const { isValidTronAddress } = require('./tron');
const { createService, UserError } = require('./service');
const { now } = require('./db');
const V = require('./views');

function createApp({ cfg, db, banxa, log = console }) {
  const app = express();
  const svc = createService({ db, cfg, banxa, log });
  const sessions = sessionManager(cfg);
  app.set('trust proxy', /^\d+$/.test(cfg.trustProxy) ? Number(cfg.trustProxy) : cfg.trustProxy);
  app.disable('x-powered-by');

  const checkoutOrigins = cfg.banxa.usingOverride
    ? [new URL(cfg.banxa.apiBase).origin]
    : cfg.banxa.checkoutHosts.flatMap((h) => [`https://${h}`, `https://*.${h}`]);
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], frameAncestors: ["'none'"],
        formAction: ["'self'", ...checkoutOrigins],   // allows the 303 redirect to Banxa checkout after form submit
        upgradeInsecureRequests: cfg.secureCookies ? [] : null,
      },
    },
    crossOriginEmbedderPolicy: false,
    hsts: cfg.secureCookies,
  }));
  app.use((req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });

  // ---------- Banxa webhook (raw body needed for HMAC) ----------
  app.post(cfg.webhookPath, express.raw({ type: '*/*', limit: '256kb' }), (req, res) => {
    const rawBody = req.body && req.body.length ? req.body.toString('utf8') : '';
    const v = verifyWebhook({
      authorization: req.headers.authorization, method: 'POST', path: cfg.webhookPath, rawBody,
      hmacKey: cfg.banxa.hmacKey, hmacSecret: cfg.banxa.hmacSecret,
    });
    let body = null;
    try { body = JSON.parse(rawBody); } catch { /* ignore */ }
    if (!v.ok) {
      db.prepare('INSERT INTO webhook_events (received_at, banxa_order_id, status, signature_valid, reason, body) VALUES (?,?,?,0,?,?)')
        .run(now(), body?.order_id ? String(body.order_id) : null, body?.status || null, v.reason, rawBody.slice(0, 4000));
      log.warn('[webhook] rejected:', v.reason);
      return res.status(401).json({ error: 'invalid signature' });
    }
    if (!body || typeof body !== 'object') return res.status(200).end(); // signed but not JSON: nothing to do

    // Persist the verified event BEFORE acknowledging, so a crash after the 200 can be recovered.
    const orderId = body.order_id ? String(body.order_id) : null;
    let eventId = null;
    try {
      const ins = db.prepare(`INSERT OR IGNORE INTO webhook_events (received_at, banxa_order_id, external_id, status, signature_valid, body)
        VALUES (?,?,?,?,1,?)`).run(now(), orderId, body.external_id ? String(body.external_id) : null, body.status || null, rawBody.slice(0, 8000));
      if (ins.changes) eventId = ins.lastInsertRowid;
      else if (orderId) {
        // Duplicate delivery (Banxa retries with identical payload). Re-process only if it never completed.
        const ex = db.prepare('SELECT id, processed FROM webhook_events WHERE banxa_order_id=? AND status IS ? AND signature_valid=1').get(orderId, body.status || null);
        if (ex && !ex.processed) eventId = ex.id;
      }
      if (!orderId && ins.changes) db.prepare('UPDATE webhook_events SET processed=1 WHERE id=?').run(eventId); // KYC/EDD/account events: stored only
    } catch (e) {
      log.error('[webhook] store failed', e);
      return res.status(500).json({ error: 'retry' }); // Banxa retries on non-200
    }
    res.status(200).json({ ok: true }); // acknowledge immediately, process async (per Banxa docs)
    if (orderId && eventId) {
      setImmediate(() => svc.processWebhookEvent(eventId).catch((e) => log.error('[webhook] processing error', e)));
    }
  });

  app.use(express.urlencoded({ extended: false, limit: '20kb' }));
  app.use(express.json({ limit: '20kb' }));
  app.use('/static', express.static(path.join(__dirname, '..', 'public'), { maxAge: '1h' }));

  app.get('/', (req, res) => res.redirect(302, '/admin'));
  app.get('/healthz', (req, res) => res.json({ ok: true, env: cfg.banxa.env }));

  // ---------- Admin auth ----------
  const loginLimiter = rateLimit({ windowMs: 15 * 60e3, limit: cfg.loginRateLimit, standardHeaders: true, legacyHeaders: false });
  app.get('/admin/login', (req, res) => res.send(V.loginPage()));
  app.post('/admin/login', loginLimiter, (req, res) => {
    const { username = '', password = '' } = req.body || {};
    const okUser = username === cfg.adminUsername;
    const okPass = verifyPassword(password, cfg.adminPasswordHash); // always computed: no timing hint on username
    if (!okUser || !okPass) {
      svc.audit('anonymous', 'admin.login.fail', { ip: req.ip });
      return res.status(401).send(V.loginPage('פרטי כניסה שגויים'));
    }
    sessions.issue(res, cfg.adminUsername);
    svc.audit(cfg.adminUsername, 'admin.login', { ip: req.ip });
    res.redirect(303, '/admin');
  });

  const admin = express.Router();
  admin.use(sessions.requireAdmin);

  admin.post('/logout', (req, res) => { sessions.clear(res); res.redirect(303, '/admin/login'); });

  admin.get('/', (req, res) => {
    res.send(V.dashboard({ cfg, csrf: req.session.csrf, links: svc.listLinks() }));
  });

  admin.post('/links', (req, res) => {
    try {
      const { link, url } = svc.createLink({
        amount: req.body.amount, customerName: req.body.customer_name, customerEmail: req.body.customer_email,
        wallet: req.body.wallet, walletAttest: req.body.wallet_attest === '1',
        description: req.body.description, ttlHours: req.body.ttl_hours,
      }, req.session.u);
      res.send(V.linkCreated({ cfg, csrf: req.session.csrf, link, url }));
    } catch (e) {
      if (!(e instanceof UserError)) throw e;
      res.status(400).send(V.dashboard({
        cfg, csrf: req.session.csrf, links: svc.listLinks(), flash: { type: 'bad', html: `<strong>שגיאה:</strong> ${V.esc(e.message)}` },
      }));
    }
  });

  admin.get('/links/:pid', (req, res) => {
    const link = svc.getLinkByPublicId(req.params.pid);
    if (!link) return res.status(404).send('Not found');
    const orders = db.prepare('SELECT * FROM orders WHERE link_id=? ORDER BY id DESC').all(link.id);
    const ids = orders.map((o) => o.banxa_order_id);
    const events = ids.length ? db.prepare(`SELECT * FROM webhook_events WHERE banxa_order_id IN (${ids.map(() => '?').join(',')}) ORDER BY id DESC`).all(...ids) : [];
    const audit = db.prepare(`SELECT * FROM audit_log WHERE details LIKE ? ORDER BY id DESC LIMIT 100`).all(`%${link.public_id}%`);
    res.send(V.linkDetail({ cfg, csrf: req.session.csrf, link, orders, events, audit, url: svc.linkUrl(link.token) }));
  });

  admin.post('/links/:pid/sync', async (req, res) => {
    const link = svc.getLinkByPublicId(req.params.pid);
    if (!link) return res.status(404).send('Not found');
    const o = svc.latestOrder(link.id);
    if (o) await svc.syncOrder(o.banxa_order_id).catch((e) => log.error('[sync]', e.message));
    res.redirect(303, `/admin/links/${link.public_id}`);
  });

  admin.post('/links/:pid/revoke', (req, res) => {
    svc.revoke(req.params.pid, req.session.u);
    res.redirect(303, `/admin/links/${encodeURIComponent(req.params.pid)}`);
  });

  admin.post('/api/sync-all', async (req, res) => {
    const n = await svc.syncPending();
    res.json({ synced: n });
  });

  admin.post('/verify-banxa', async (req, res) => {
    const lines = [];
    let ok = true;
    try {
      const c = JSON.stringify(await banxa.listCrypto());
      const hasUsdt = /"USDT"/i.test(c);
      const hasChain = new RegExp(`"${cfg.banxa.blockchain}"`, 'i').test(c);
      lines.push(`${hasUsdt ? '✅' : '❌'} USDT קיים ברשימת המטבעות של החשבון`);
      lines.push(`${hasChain ? '✅' : '❌'} קוד הרשת "${V.esc(cfg.banxa.blockchain)}" נמצא בתגובה (אם לא — עדכן BANXA_BLOCKCHAIN_CODE לפי הקוד ש-Banxa מחזירה ל-USDT על TRON)`);
      ok = ok && hasUsdt && hasChain;
    } catch (e) { ok = false; lines.push(`❌ GET /v2/crypto: ${V.esc(e.message)}`); }
    try {
      const m = JSON.stringify(await banxa.listCardMethods());
      const hasCard = m.includes('debit-credit-card');
      lines.push(`${hasCard ? '✅' : '❌'} אמצעי תשלום debit-credit-card (Visa/Mastercard) זמין ל-USD בחשבון`);
      ok = ok && hasCard;
    } catch (e) { ok = false; lines.push(`❌ GET /v2/payment-methods/buy?fiat=USD: ${V.esc(e.message)}`); }
    svc.audit(req.session.u, 'banxa.verify', { ok });
    res.send(V.dashboard({ cfg, csrf: req.session.csrf, links: svc.listLinks(), verify: { ok, html: `<ul>${lines.map((l) => `<li>${l}</li>`).join('')}</ul>` } }));
  });

  admin.get('/settings', (req, res) => {
    res.send(V.settingsPage({ cfg, csrf: req.session.csrf, blocked: db.prepare('SELECT * FROM blocked_wallets ORDER BY created_at DESC').all() }));
  });
  admin.post('/settings/blocked', (req, res) => {
    const address = String(req.body.address || '').trim();
    let flash;
    if (!isValidTronAddress(address)) flash = { type: 'bad', html: 'כתובת TRC20 לא תקינה' };
    else {
      db.prepare('INSERT OR IGNORE INTO blocked_wallets (address, label, created_at) VALUES (?,?,?)').run(address, String(req.body.label || '').slice(0, 100), now());
      svc.audit(req.session.u, 'blocked.add', { address });
      flash = { type: 'ok', html: 'נוסף' };
    }
    res.send(V.settingsPage({ cfg, csrf: req.session.csrf, flash, blocked: db.prepare('SELECT * FROM blocked_wallets ORDER BY created_at DESC').all() }));
  });
  admin.post('/settings/blocked/delete', (req, res) => {
    db.prepare('DELETE FROM blocked_wallets WHERE address=?').run(String(req.body.address || ''));
    svc.audit(req.session.u, 'blocked.remove', { address: req.body.address });
    res.redirect(303, '/admin/settings');
  });

  app.use('/admin', admin);

  // ---------- Customer flow ----------
  // Every transaction parameter comes from the DB row for this token. Query strings and extra form fields are ignored.
  const payLimiter = rateLimit({ windowMs: 10 * 60e3, limit: cfg.payRateLimit, standardHeaders: true, legacyHeaders: false });
  const sandbox = cfg.banxa.env !== 'production';
  const msg = (res, code, title, text) => res.status(code).send(V.payMessage({ title, text, sandbox }));
  const tokenOk = (t) => typeof t === 'string' && /^[A-Za-z0-9_-]{43}$/.test(t);

  const STOPPED = ['Payment stopped', 'This payment has been stopped for a security check. Please contact the sender of this link.'];
  const WAIT = ['Preparing your payment', 'We are confirming your payment session with Banxa. This page refreshes automatically.'];
  // No documented way exists to re-enter a Banxa checkout or get a new URL for an existing order,
  // and a new order must not be created while the old one may still be pending. So: stop safely.
  function stalledPage(res, order) {
    if (order && order.banxa_status === 'waitingPayment') {
      return msg(res, 200, 'Payment in progress', 'Your payment details were submitted and Banxa is confirming the payment. You will receive updates from Banxa by email. Do not pay again.');
    }
    return msg(res, 409, 'Checkout session expired',
      'For security, Banxa checkout links are only valid for a short time and this one can no longer be opened. '
      + 'If you already completed the payment on Banxa, you will receive a confirmation email from Banxa — do not pay again. '
      + 'Otherwise, please contact the sender of this link: they can check the order and send you a new payment link if needed.');
  }
  const waitPage = (res) => res.status(202).send(V.payMessage({ title: WAIT[0], text: WAIT[1], sandbox, refreshSec: 10 }));

  /** Bring the link up to date with Banxa (reconcile unknown creates, verify/sync the latest order). */
  async function refreshLink(link) {
    const orders = db.prepare('SELECT * FROM orders WHERE link_id=? ORDER BY id DESC').all(link.id);
    for (const o of orders) {
      if (o.local_state === 'unknown') await svc.reconcileAttempt(o.id).catch(() => {});
    }
    const latest = db.prepare('SELECT * FROM orders WHERE link_id=? AND banxa_order_id IS NOT NULL ORDER BY id DESC LIMIT 1').get(link.id);
    let synced = false;
    if (latest && ['open', 'unverified', 'orphaned', 'url_expired'].includes(latest.local_state)) {
      synced = await svc.syncOrder(latest.banxa_order_id).then(() => true).catch((e) => { log.error('[pay] sync', e.message); return false; });
    }
    return { link: svc.getLinkByToken(link.token), order: latest && svc.getOrderById(latest.id), synced };
  }

  app.get('/pay/:token', payLimiter, async (req, res) => {
    if (!tokenOk(req.params.token)) return msg(res, 404, 'Link not found', 'This payment link is not valid.');
    let link = svc.getLinkByToken(req.params.token);
    if (!link) return msg(res, 404, 'Link not found', 'This payment link is not valid.');
    const st = await refreshLink(link); link = st.link;
    if (link.status === 'blocked') return msg(res, 409, ...STOPPED);
    if (link.status === 'paid') return msg(res, 200, 'Already paid', 'This payment has already been completed. The link cannot be used again.');
    if (link.status === 'revoked') return msg(res, 410, 'Link cancelled', 'This payment link was cancelled by the sender.');
    if (link.status === 'failed') return msg(res, 410, 'Link no longer valid', 'This payment could not be completed. Please contact the sender for a new link.');
    if (link.status === 'reconciling' || link.status === 'creating') return waitPage(res);
    if (link.status === 'checkout') {
      const o = st.order;
      if (!o) return waitPage(res);
      // Fail closed: a redirect needs a fresh successful lookup AND a URL still inside Banxa's 1-minute window.
      if (!st.synced && o.local_state === 'open') return waitPage(res);
      try {
        const r = await svc.verifyAndGetCheckout(o.id);
        if (r.checkoutUrl) return res.redirect(303, r.checkoutUrl);
        if (r.wait) return waitPage(res);
      } catch (e) {
        if (e instanceof UserError) return msg(res, 409, ...STOPPED);
        throw e;
      }
      link = svc.getLinkByToken(link.token);
      if (link.status === 'active') return res.send(V.payPage({ link, formToken: linkFormToken(cfg.sessionSecret, link.token), sandbox }));
      if (link.status === 'paid') return msg(res, 200, 'Already paid', 'This payment has already been completed. The link cannot be used again.');
    }
    if (link.status === 'stalled' || link.status === 'checkout') return stalledPage(res, svc.latestOrder(link.id));
    if (svc.isExpired(link)) return msg(res, 410, 'Link expired', 'This payment link has expired. Please contact the sender for a new link.');
    res.send(V.payPage({ link, formToken: linkFormToken(cfg.sessionSecret, link.token), sandbox }));
  });

  app.post('/pay/:token', payLimiter, async (req, res) => {
    if (!tokenOk(req.params.token)) return msg(res, 404, 'Link not found', 'This payment link is not valid.');
    const link = svc.getLinkByToken(req.params.token);
    if (!link) return msg(res, 404, 'Link not found', 'This payment link is not valid.');
    if (req.body.ft !== linkFormToken(cfg.sessionSecret, link.token)) return msg(res, 403, 'Invalid request', 'Please open the payment link again.');
    if (req.body.own_wallet !== '1' || req.body.own_card !== '1') {
      return res.status(400).send(V.payPage({ link, formToken: linkFormToken(cfg.sessionSecret, link.token), sandbox, error: 'Please confirm both statements to continue.' }));
    }
    if (link.status !== 'active') return res.redirect(303, `/pay/${link.token}`);
    try {
      const r = await svc.startCheckout(link, req.ip);
      if (r.checkoutUrl) return res.redirect(303, r.checkoutUrl); // straight to Banxa's official hosted card checkout
      if (r.wait) return waitPage(res);
      return res.redirect(303, `/pay/${link.token}`);
    } catch (e) {
      if (e instanceof UserError) return msg(res, 400, 'Unable to continue', e.message);
      throw e;
    }
  });

  app.get('/pay/:token/return', payLimiter, async (req, res) => {
    if (!tokenOk(req.params.token)) return msg(res, 404, 'Link not found', 'This payment link is not valid.');
    const link = svc.getLinkByToken(req.params.token);
    if (!link) return msg(res, 404, 'Link not found', 'This payment link is not valid.');
    const { link: l2, order } = await refreshLink(link);
    if (l2.status === 'blocked') return msg(res, 409, ...STOPPED);
    const s = order?.banxa_status;
    if (s === 'complete') return msg(res, 200, 'Payment complete', 'Your USDT has been sent to your wallet.');
    if (['cancelled', 'declined', 'expired'].includes(s)) return msg(res, 200, 'Payment not completed', 'The payment was not completed. You can reopen the link to try again if it is still valid.');
    return msg(res, 200, 'Thank you', 'Banxa is processing your order. You will receive updates from Banxa by email.');
  });

  app.use((err, req, res, _next) => {
    log.error('[error]', err);
    res.status(500).send('Internal error');
  });

  return { app, svc };
}

module.exports = { createApp };
