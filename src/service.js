'use strict';
const crypto = require('crypto');
const { now } = require('./db');
const { isValidTronAddress } = require('./tron');
const { display, TERMINAL, RETRYABLE_FAILURES, SUCCESS } = require('./status');

const rand = (n) => crypto.randomBytes(n).toString('base64url');

// Ordering used ONLY for webhook-delivered statuses, so a late/duplicate webhook can't move an
// order backwards. Order lookup results are authoritative and always applied as-is.
const RANK = {
  pendingPayment: 1, waitingPayment: 2, expired: 2, extraVerification: 3, paymentReceived: 4,
  inProgress: 5, cryptoTransferred: 6, complete: 9, cancelled: 9, declined: 9, refunded: 10,
};
// Orders whose state means "a Banxa order may be live for this link": block new creation.
const LIVE_LOCAL = new Set(['creating', 'unknown', 'unverified', 'open', 'url_expired']);
const LIVE_SQL = `('creating','unknown','unverified','open','url_expired')`;
// Banxa statuses after which the order can no longer take a payment through its checkout
const CLOSED_SQL = `('expired','declined','cancelled','complete','refunded')`;

class UserError extends Error {}

function createService({ db, cfg, banxa, log = console }) {
  const audit = (actor, action, details) =>
    db.prepare('INSERT INTO audit_log (at, actor, action, details) VALUES (?,?,?,?)')
      .run(now(), actor, action, details ? JSON.stringify(details) : null);

  const linkUrl = (token) => `${cfg.publicBaseUrl}/pay/${token}`;
  const isBlocked = (address) => Boolean(db.prepare('SELECT 1 FROM blocked_wallets WHERE address = ?').get(address));
  const isExpired = (link) => Date.parse(link.expires_at) < Date.now();
  const getLinkById = (id) => db.prepare('SELECT * FROM payment_links WHERE id=?').get(id);
  const getOrderById = (id) => db.prepare('SELECT * FROM orders WHERE id=?').get(id);
  const setLinkStatus = (linkId, status) =>
    db.prepare('UPDATE payment_links SET status=?, updated_at=? WHERE id=?').run(status, now(), linkId);
  const setOrder = (id, fields) => {
    const keys = Object.keys(fields);
    db.prepare(`UPDATE orders SET ${keys.map((k) => `${k}=@${k}`).join(', ')}, updated_at=@__ts WHERE id=@__id`)
      .run({ ...fields, __ts: now(), __id: id });
  };

  // ------------------------------------------------------------------ link creation (admin)
  function normalizeAmount(v) {
    const n = Number(String(v).trim());
    if (!Number.isFinite(n)) throw new UserError('סכום לא תקין');
    const cents = Math.round(n * 100);
    if (Math.abs(n * 100 - cents) > 1e-6) throw new UserError('עד 2 ספרות אחרי הנקודה');
    if (n < cfg.minUsd || n > cfg.maxUsd) throw new UserError(`הסכום חייב להיות בין ${cfg.minUsd} ל-${cfg.maxUsd} USD`);
    return (cents / 100).toFixed(2);
  }

  function upsertCustomer(name, email) {
    email = String(email || '').trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new UserError('אימייל לא תקין');
    const ex = db.prepare('SELECT * FROM customers WHERE email = ?').get(email);
    if (ex) {
      if (name && name !== ex.name) db.prepare('UPDATE customers SET name = ? WHERE id = ?').run(name, ex.id);
      return ex.id;
    }
    const id = 'cus_' + rand(12);
    db.prepare('INSERT INTO customers (id, name, email, created_at) VALUES (?,?,?,?)').run(id, name, email, now());
    return id;
  }

  /** All transaction parameters are fixed here and never read from the customer's browser. */
  function createLink({ amount, customerName, customerEmail, wallet, walletAttest, description, ttlHours }, actor) {
    const fiatAmount = normalizeAmount(amount);
    const name = String(customerName || '').trim().slice(0, 120);
    if (!name) throw new UserError('יש להזין שם לקוח');
    wallet = String(wallet || '').trim();
    if (!isValidTronAddress(wallet)) throw new UserError('כתובת TRC20 לא תקינה (נבדק checksum)');
    if (isBlocked(wallet)) throw new UserError('הכתובת מסומנת כארנק חסום (ארנק עסקי/שלך). לפי תנאי Banxa הקריפטו חייב להגיע לארנק של הלקוח.');
    if (!walletAttest) throw new UserError('יש לאשר שהכתובת שייכת ללקוח');
    const ttl = Math.min(Math.max(Number(ttlHours) || cfg.defaultLinkTtlHours, 1), 168);

    const customerId = upsertCustomer(name, customerEmail);
    const token = rand(32);
    const publicId = 'PL-' + rand(6).replace(/[-_]/g, 'x').toUpperCase();
    const ts = now();
    const expires = new Date(Date.now() + ttl * 3600e3).toISOString();
    db.prepare(`INSERT INTO payment_links (public_id, token, customer_id, environment, fiat, fiat_amount, crypto, blockchain,
      payment_method, prefilled_wallet, description, status, attempts, expires_at, created_at, updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,'active',0,?,?,?)`).run(
      publicId, token, customerId, cfg.banxa.env, cfg.banxa.fiat, fiatAmount, cfg.banxa.crypto, cfg.banxa.blockchain,
      cfg.banxa.paymentMethodId, wallet, String(description || '').slice(0, 500) || null, expires, ts, ts);
    audit(actor, 'link.create', { publicId, fiatAmount, wallet, customerId });
    return { link: getLinkByPublicId(publicId), url: linkUrl(token) };
  }

  const getLinkByToken = (token) => db.prepare(
    'SELECT l.*, c.name customer_name, c.email customer_email FROM payment_links l JOIN customers c ON c.id = l.customer_id WHERE l.token = ?').get(token);
  const getLinkByPublicId = (pid) => db.prepare(
    'SELECT l.*, c.name customer_name, c.email customer_email FROM payment_links l JOIN customers c ON c.id = l.customer_id WHERE l.public_id = ?').get(pid);
  const latestOrder = (linkId) => db.prepare('SELECT * FROM orders WHERE link_id = ? ORDER BY id DESC LIMIT 1').get(linkId);

  // ------------------------------------------------------------------ validation
  /**
   * Normalise any Banxa order representation (create response, order lookup, list item, webhook)
   * into one shape. Fields Banxa did not return stay undefined and are not compared.
   */
  function normalize(src, kind) {
    const o = (src && (src.order || src.data?.order || src.data)) || src || {};
    if (kind === 'webhook') {
      return {
        id: o.order_id, status: o.status, externalId: o.external_id,
        fiat: o.fiat_currency, fiatAmount: o.fiat_amount, crypto: o.crypto_coin, blockchain: o.crypto_blockchain,
        cryptoAmount: o.crypto_amount, paymentMethod: o.payment_method, orderType: o.order_type,
        txHash: o.transaction_hash || undefined,
      };
    }
    const c = o.crypto;
    return {
      id: o.id, status: o.status,
      externalId: o.externalOrderId ?? o.externalId,
      externalCustomerId: o.externalCustomerId,
      fiat: o.fiat, fiatAmount: o.fiatAmount,
      crypto: c && typeof c === 'object' ? c.id : c,
      blockchain: c && typeof c === 'object' ? c.blockchain : o.blockchain,
      wallet: o.walletAddress ?? (c && typeof c === 'object' ? c.address : undefined),
      walletTag: o.walletAddressTag,
      paymentMethod: o.paymentMethodId,
      orderType: o.orderType,
      cryptoAmount: o.cryptoAmount,
      txHash: o.transactionHash || undefined,
      checkoutUrl: o.checkoutUrl,
    };
  }

  const present = (v) => v !== undefined && v !== null && v !== '';
  const eqCI = (a, b) => String(a).trim().toUpperCase() === String(b).trim().toUpperCase();

  /**
   * Compare every field Banxa returned against the order we locked server-side.
   * Returns an array of human-readable differences (empty = all good).
   */
  function compareFields(link, order, n) {
    const d = [];
    if (present(n.fiatAmount) && (!Number.isFinite(Number(n.fiatAmount)) || Number(n.fiatAmount).toFixed(2) !== Number(link.fiat_amount).toFixed(2))) {
      d.push(`fiatAmount ${n.fiatAmount} ≠ ${link.fiat_amount}`);
    }
    if (present(n.fiat) && !eqCI(n.fiat, link.fiat)) d.push(`fiat ${n.fiat} ≠ ${link.fiat}`);
    if (present(n.crypto) && !eqCI(n.crypto, link.crypto)) d.push(`crypto ${n.crypto} ≠ ${link.crypto}`);
    if (present(n.blockchain) && !eqCI(n.blockchain, link.blockchain)) d.push(`blockchain ${n.blockchain} ≠ ${link.blockchain}`);
    if (present(n.wallet) && String(n.wallet).trim() !== link.prefilled_wallet) d.push(`walletAddress ${n.wallet} ≠ ${link.prefilled_wallet}`);
    if (present(n.walletTag)) d.push(`unexpected walletAddressTag ${n.walletTag}`);
    if (present(n.paymentMethod) && !eqCI(n.paymentMethod, link.payment_method)) d.push(`paymentMethod ${n.paymentMethod} ≠ ${link.payment_method}`);
    if (present(n.orderType) && !eqCI(n.orderType, 'BUY')) d.push(`orderType ${n.orderType} ≠ BUY`);
    if (present(n.externalId) && order && n.externalId !== order.external_order_id) d.push(`externalOrderId ${n.externalId} ≠ ${order.external_order_id}`);
    if (present(n.externalCustomerId) && n.externalCustomerId !== link.customer_id) d.push(`externalCustomerId ${n.externalCustomerId} ≠ ${link.customer_id}`);
    if (order && order.banxa_order_id && present(n.id) && String(n.id) !== order.banxa_order_id) d.push(`order id ${n.id} ≠ ${order.banxa_order_id}`);
    return d;
  }

  /** Mismatch = stop. Checkout URL is erased, link is permanently blocked, admin sees the reason. */
  function blockOrder(order, link, diffs, source) {
    const reason = `Mismatch (${source}): ${diffs.join('; ')}`;
    setOrder(order.id, { local_state: 'blocked', checkout_url: null, mismatch: reason });
    if (!['paid', 'revoked'].includes(link.status)) setLinkStatus(link.id, 'blocked');
    audit('system', 'order.blocked', { link: link.public_id, banxaOrderId: order.banxa_order_id, reason });
    log.error('[security] order blocked', link.public_id, reason);
  }

  // ------------------------------------------------------------------ checkout start (customer)
  /**
   * 1. atomically claim the link, 2. write the attempt row (externalOrderId) BEFORE calling Banxa,
   * 3. create, 4. validate create response, 5. verify ALL fields via order lookup, 6. only then redirect.
   * Returns { checkoutUrl } or { wait: true } (still verifying/reconciling).
   */
  async function startCheckout(linkIn, ip) {
    let link = getLinkById(linkIn.id);
    if (link.environment !== cfg.banxa.env) throw new UserError('This link belongs to a different environment.');
    if (isExpired(link)) throw new UserError('This payment link has expired.');
    if (isBlocked(link.prefilled_wallet)) throw new UserError('This payment link can no longer be used.');

    // Never create while a previous attempt might still be live at Banxa
    const live = db.prepare(`SELECT * FROM orders WHERE link_id=? AND local_state IN ${LIVE_SQL}`).all(link.id);
    for (const o of live) {
      if (o.local_state === 'unknown') await reconcileAttempt(o.id).catch(() => {});
    }
    link = getLinkById(link.id);
    // An order that may still be pending at Banxa (including one whose URL expired) blocks a new order.
    const stillLive = db.prepare(`SELECT COUNT(*) n FROM orders WHERE link_id=? AND local_state IN ${LIVE_SQL}
      AND (banxa_status IS NULL OR banxa_status NOT IN ${CLOSED_SQL})`).get(link.id).n;
    if (stillLive) return { wait: true };
    if (link.attempts >= cfg.maxAttemptsPerLink) throw new UserError('This payment link can no longer be used.');

    const claim = db.prepare(`UPDATE payment_links SET status='creating', attempts=attempts+1, updated_at=?
      WHERE id=? AND status='active'`).run(now(), link.id);
    if (claim.changes !== 1) throw new UserError('This payment link is already in use.');

    const attempt = link.attempts + 1;
    const externalOrderId = `${link.public_id}-${attempt}`;
    const ts = now();
    const ins = db.prepare(`INSERT INTO orders (link_id, external_order_id, local_state, wallet_address, fiat_amount,
      payment_method, attestation_ip, attested_at, created_at, updated_at) VALUES (?,?,'creating',?,?,?,?,?,?,?)`)
      .run(link.id, externalOrderId, link.prefilled_wallet, link.fiat_amount, link.payment_method, ip, ts, ts, ts);
    const orderId = ins.lastInsertRowid;
    audit('customer', 'order.attempt', { link: link.public_id, externalOrderId, ip });

    let r;
    try {
      r = await banxa.createBuyOrder({
        fiatAmount: link.fiat_amount,
        walletAddress: link.prefilled_wallet,
        externalCustomerId: link.customer_id,
        externalOrderId,
        email: linkIn.customer_email,
        redirectUrl: `${linkUrl(link.token)}/return`,
        metadata: JSON.stringify({ link: link.public_id, attempt }),
      });
    } catch (e) {
      if (e.ambiguous) {
        // Banxa may have created the order. Do NOT retry blindly: reconcile by externalOrderId first.
        setOrder(orderId, { local_state: 'unknown', last_error: e.message });
        setLinkStatus(link.id, 'reconciling');
        audit('system', 'order.create.ambiguous', { link: link.public_id, externalOrderId, error: e.message });
        log.error('[banxa] ambiguous create', externalOrderId, e.message);
        await reconcileAttempt(orderId).catch(() => {});
        return { wait: true };
      }
      setOrder(orderId, { local_state: 'rejected', last_error: e.message });
      setLinkStatus(link.id, 'active');
      audit('system', 'order.create.rejected', { link: link.public_id, externalOrderId, error: e.message });
      log.error('[banxa] create rejected', e.message);
      throw new UserError('Payment could not be started right now. Please try again in a few minutes.');
    }

    // Created. Record id + the start of the 1-minute checkoutUrl window first, then validate.
    const issuedAt = now();
    setOrder(orderId, { banxa_order_id: String(r.id), local_state: 'unverified', banxa_status: 'pendingPayment', checkout_url_issued_at: issuedAt,
      crypto_amount: r.cryptoAmount != null ? String(r.cryptoAmount) : null });
    setLinkStatus(link.id, 'checkout');
    audit('customer', 'order.create', { link: link.public_id, banxaOrderId: r.id, externalOrderId });

    let order = getOrderById(orderId);
    const diffs = compareFields(link, order, normalize(r, 'create'));
    if (!present(r.checkoutUrl) || !banxa.isBanxaCheckoutUrl(r.checkoutUrl)) diffs.push('checkoutUrl is not a Banxa checkout URL');
    if (diffs.length) {
      blockOrder(order, getLinkById(link.id), diffs, 'create-response');
      throw new UserError('This payment has been stopped for a security check. Please contact the sender of this link.');
    }
    setOrder(orderId, { checkout_url: r.checkoutUrl });
    return verifyAndGetCheckout(orderId);
  }

  /**
   * Full-field verification through GET /v2/orders/{id} (wallet, payment method, blockchain, ...).
   * Redirect only if it succeeds. If the lookup fails, fail closed and ask the customer to retry.
   */
  async function verifyAndGetCheckout(orderId) {
    let order = getOrderById(orderId);
    try {
      await syncOrder(order.banxa_order_id);
    } catch (e) {
      setOrder(orderId, { last_error: `verify lookup failed: ${e.message}` });
      return { wait: true };
    }
    order = getOrderById(orderId);
    const link = getLinkById(order.link_id);
    if (order.local_state === 'blocked' || link.status === 'blocked') {
      throw new UserError('This payment has been stopped for a security check. Please contact the sender of this link.');
    }
    if (order.local_state === 'unverified') {
      setOrder(orderId, { local_state: 'open', verified_at: now() });
      order = getOrderById(orderId);
    }
    const url = usableCheckoutUrl(order);
    if (url) {
      if (!order.redirected_at) setOrder(orderId, { redirected_at: now() });
      return { checkoutUrl: url };
    }
    expireCheckoutUrl(order);
    const l = getLinkById(order.link_id);
    return l.status === 'stalled' ? { stalled: true } : { status: getOrderById(orderId).banxa_status };
  }

  // ------------------------------------------------------------------ checkout URL validity (Banxa: 1 minute)
  const urlWindowMs = () => Math.max(0, cfg.checkoutUrlTtlSec - cfg.checkoutUrlMarginSec) * 1000;

  /** The checkout URL, or null if it is not certainly still valid. Never guess in the customer's favour. */
  function usableCheckoutUrl(order) {
    if (!order || order.local_state !== 'open' || !order.checkout_url || !order.checkout_url_issued_at) return null;
    if (!['pendingPayment', 'waitingPayment'].includes(order.banxa_status)) return null;
    const age = Date.now() - Date.parse(order.checkout_url_issued_at);
    if (!(age >= 0 && age < urlWindowMs())) return null;
    return order.checkout_url;
  }

  /**
   * The URL's window has passed (or can't be proven open). Erase it. The Banxa order itself may still be
   * pending (the customer may have loaded it in time and be paying), so the link becomes 'stalled':
   * no redirect and no new order until Banxa reports a closed status.
   */
  function expireCheckoutUrl(order) {
    if (!order) return;
    if (['open', 'unverified'].includes(order.local_state)) {
      setOrder(order.id, { local_state: 'url_expired', checkout_url: null });
      audit('system', 'order.checkout_url_expired', { banxaOrderId: order.banxa_order_id, issuedAt: order.checkout_url_issued_at, redirectedAt: order.redirected_at });
    }
    const fresh = getOrderById(order.id);
    const link = getLinkById(order.link_id);
    const closed = fresh.banxa_status && CLOSED_SQL.includes(`'${fresh.banxa_status}'`);
    if (!closed && link.status === 'checkout') setLinkStatus(link.id, 'stalled');
  }

  /** Background sweep: expire every open URL whose window has passed. */
  function sweepExpiredCheckoutUrls() {
    const cutoff = new Date(Date.now() - urlWindowMs()).toISOString();
    const rows = db.prepare(`SELECT * FROM orders WHERE local_state IN ('open','unverified') AND checkout_url_issued_at IS NOT NULL AND checkout_url_issued_at <= ?`).all(cutoff);
    for (const o of rows) expireCheckoutUrl(o);
    return rows.length;
  }

  // ------------------------------------------------------------------ duplicate-order reconciliation
  /**
   * Resolve an attempt whose create outcome is unknown, using externalOrderId via GET /v2/orders.
   *  found     -> adopt (validate all fields). If lookup gives a valid checkoutUrl and it's pending, reuse it;
   *               otherwise mark 'orphaned' (its URL was never exposed, so it can't be paid) and keep tracking it.
   *  not found -> after the grace period, mark 'not_created' and allow a new attempt.
   *  error     -> stay 'unknown'; no new order may be created until resolved.
   */
  async function reconcileAttempt(orderId) {
    const order = getOrderById(orderId);
    if (!order || order.local_state !== 'unknown') return order && order.local_state;
    const link = getLinkById(order.link_id);
    let found;
    try {
      found = await banxa.findOrderByExternalId({
        externalOrderId: order.external_order_id, externalCustomerId: link.customer_id, around: order.created_at,
      });
    } catch (e) {
      setOrder(orderId, { last_error: `reconcile lookup failed: ${e.message}` });
      return 'unknown';
    }
    if (!found) {
      const ageSec = (Date.now() - Date.parse(order.created_at)) / 1000;
      if (ageSec < cfg.reconcileGraceSec) return 'unknown';
      setOrder(orderId, { local_state: 'not_created' });
      if (link.status === 'reconciling') setLinkStatus(link.id, 'active');
      audit('system', 'order.reconcile.not_found', { link: link.public_id, externalOrderId: order.external_order_id });
      return 'not_created';
    }
    const n = normalize(found, 'lookup');
    const clash = db.prepare('SELECT id FROM orders WHERE banxa_order_id=? AND id<>?').get(String(n.id), orderId);
    if (clash) {
      setOrder(orderId, { local_state: 'blocked', mismatch: `Banxa order ${n.id} already linked to another attempt` });
      setLinkStatus(link.id, 'blocked');
      return 'blocked';
    }
    setOrder(orderId, { banxa_order_id: String(n.id), banxa_status: n.status || null, local_state: 'orphaned' });
    audit('system', 'order.reconcile.found', { link: link.public_id, externalOrderId: order.external_order_id, banxaOrderId: n.id });
    const diffs = compareFields(link, getOrderById(orderId), n);
    if (diffs.length) { blockOrder(getOrderById(orderId), link, diffs, 'reconcile'); return 'blocked'; }
    if (present(n.checkoutUrl) && banxa.isBanxaCheckoutUrl(n.checkoutUrl) && ['pendingPayment', 'waitingPayment'].includes(n.status)) {
      // Banxa responded at some unknown moment after our request started: use the request start as the
      // (earliest possible) issuance time, so the window can only be under-estimated, never over-estimated.
      setOrder(orderId, { local_state: 'open', checkout_url: n.checkoutUrl, verified_at: now(), checkout_url_issued_at: order.created_at });
      setLinkStatus(link.id, 'checkout');
      if (!usableCheckoutUrl(getOrderById(orderId))) { expireCheckoutUrl(getOrderById(orderId)); return 'url_expired'; }
      return 'open';
    }
    // Orphan: no usable checkout URL. Track it; let applyUpdate decide the link status.
    applyUpdate(getOrderById(orderId), n, 'lookup');
    const l2 = getLinkById(link.id);
    if (l2.status === 'reconciling') setLinkStatus(link.id, l2.attempts < cfg.maxAttemptsPerLink && !isExpired(l2) ? 'active' : 'failed');
    return 'orphaned';
  }

  async function reconcileAll() {
    const rows = db.prepare(`SELECT id FROM orders WHERE local_state='unknown'`).all();
    for (const r of rows) await reconcileAttempt(r.id).catch((e) => log.error('[reconcile]', e.message));
    return rows.length;
  }

  // ------------------------------------------------------------------ status updates
  /**
   * Apply a normalised Banxa snapshot. source = 'lookup' (authoritative) | 'webhook' (monotonic only).
   * Every available field is re-validated; any mismatch blocks the order.
   */
  function applyUpdate(order, n, source) {
    const link = getLinkById(order.link_id);
    const diffs = compareFields(link, order, n);
    if (diffs.length && order.local_state !== 'blocked') blockOrder(order, link, diffs, source);

    let status = n.status;
    if (status && source === 'webhook' && order.banxa_status) {
      const cur = RANK[order.banxa_status] ?? 0, nxt = RANK[status] ?? 0;
      if (nxt < cur || (TERMINAL.has(order.banxa_status) && status !== 'refunded')) status = undefined; // ignore regressions
    }
    const fields = {};
    if (status) fields.banxa_status = status;
    if (present(n.cryptoAmount)) fields.crypto_amount = String(n.cryptoAmount);
    if (n.txHash) fields.tx_hash = String(n.txHash);
    if (source === 'lookup') fields.last_synced_at = now();
    const finalState = status || order.banxa_status;
    if (finalState && (TERMINAL.has(finalState) || finalState === 'expired')) {
      fields.checkout_url = null; // checkout finished: never hand out this URL again
    }
    if (Object.keys(fields).length) setOrder(order.id, fields);

    // Link lifecycle (never touches blocked/revoked)
    const cur = getLinkById(link.id);
    if (!['blocked', 'revoked'].includes(cur.status) && finalState) {
      let next = cur.status;
      if (SUCCESS.has(finalState) || finalState === 'refunded') next = 'paid';
      else if (finalState === 'cancelled') next = 'failed';
      else if (RETRYABLE_FAILURES.has(finalState) && ['checkout', 'reconciling', 'stalled'].includes(cur.status)) {
        const otherLive = db.prepare(`SELECT COUNT(*) n FROM orders WHERE link_id=? AND id<>? AND local_state IN ${LIVE_SQL}
          AND (banxa_status IS NULL OR banxa_status NOT IN ${CLOSED_SQL})`).get(link.id, order.id).n;
        if (!otherLive) next = cur.attempts < cfg.maxAttemptsPerLink && !isExpired(cur) ? 'active' : 'failed';
      }
      if (next !== cur.status) setLinkStatus(link.id, next);
    }
    if (status && status !== order.banxa_status) {
      audit(source === 'webhook' ? 'banxa-webhook' : 'banxa-lookup', 'order.status', { link: link.public_id, banxaOrderId: order.banxa_order_id, from: order.banxa_status, to: status });
    }
    return getOrderById(order.id);
  }

  async function syncOrder(banxaOrderId) {
    const order = db.prepare('SELECT * FROM orders WHERE banxa_order_id = ?').get(String(banxaOrderId));
    if (!order) return null;
    const r = await banxa.getOrder(banxaOrderId);
    return applyUpdate(order, normalize(r, 'lookup'), 'lookup');
  }

  // ------------------------------------------------------------------ webhooks
  /**
   * Process a verified webhook event row. Lookup is authoritative; the event is only marked processed
   * after a successful lookup. If lookup fails, webhook data is applied monotonically and the event
   * stays unprocessed so the recovery job retries it.
   */
  async function processWebhookEvent(eventId) {
    const ev = db.prepare('SELECT * FROM webhook_events WHERE id=?').get(eventId);
    if (!ev || ev.processed) return;
    db.prepare('UPDATE webhook_events SET attempts=attempts+1 WHERE id=?').run(eventId);
    const body = JSON.parse(ev.body);
    const n = normalize(body, 'webhook');
    let order = db.prepare('SELECT * FROM orders WHERE banxa_order_id=?').get(String(n.id));
    if (!order && n.externalId) {
      // Order created during an ambiguous create: adopt via our externalOrderId
      const pend = db.prepare(`SELECT * FROM orders WHERE external_order_id=? AND banxa_order_id IS NULL`).get(String(n.externalId));
      if (pend) {
        await reconcileAttempt(pend.id).catch(() => {});
        order = db.prepare('SELECT * FROM orders WHERE banxa_order_id=?').get(String(n.id));
      }
    }
    if (!order) {
      db.prepare('UPDATE webhook_events SET last_error=? WHERE id=?').run('unknown order', eventId);
      return;
    }
    try {
      await syncOrder(order.banxa_order_id);
      db.prepare('UPDATE webhook_events SET processed=1, last_error=NULL WHERE id=?').run(eventId);
    } catch (e) {
      applyUpdate(order, n, 'webhook');
      db.prepare('UPDATE webhook_events SET last_error=? WHERE id=?').run(`lookup failed: ${e.message}`, eventId);
    }
  }

  async function recoverWebhooks() {
    const rows = db.prepare(`SELECT id FROM webhook_events WHERE signature_valid=1 AND processed=0 AND attempts < 30
      AND banxa_order_id IS NOT NULL AND received_at > ?`).all(new Date(Date.now() - 3 * 86400e3).toISOString());
    for (const r of rows) await processWebhookEvent(r.id).catch((e) => log.error('[webhook-recover]', e.message));
    return rows.length;
  }

  // ------------------------------------------------------------------ periodic job
  async function syncPending() {
    await reconcileAll();
    const rows = db.prepare(`SELECT banxa_order_id FROM orders WHERE banxa_order_id IS NOT NULL AND (banxa_status IS NULL OR banxa_status NOT IN
      ('complete','cancelled','declined','refunded')) AND created_at > ?`).all(new Date(Date.now() - 7 * 86400e3).toISOString());
    let n = 0;
    for (const r of rows) {
      try { await syncOrder(r.banxa_order_id); n++; } catch (e) { log.error('[sync]', r.banxa_order_id, e.message); }
    }
    // Unverified orders are NOT promoted here: promotion only happens in verifyAndGetCheckout, right before
    // a redirect, and only inside the URL window. Anything past its window is expired.
    sweepExpiredCheckoutUrls();
    await recoverWebhooks();
    return n;
  }

  // ------------------------------------------------------------------ admin listing
  function listLinks(limit = 300) {
    const rows = db.prepare(`SELECT l.*, l.status link_status, c.name customer_name, c.email customer_email,
      o.banxa_order_id, o.banxa_status, o.tx_hash, o.crypto_amount, o.mismatch, o.local_state,
      (SELECT mismatch FROM orders WHERE link_id=l.id AND local_state='blocked' ORDER BY id DESC LIMIT 1) block_reason
      FROM payment_links l JOIN customers c ON c.id=l.customer_id
      LEFT JOIN orders o ON o.id = (SELECT MAX(id) FROM orders WHERE link_id = l.id AND banxa_order_id IS NOT NULL)
      ORDER BY l.id DESC LIMIT ?`).all(limit);
    return rows.map((r) => ({
      ...r,
      wallet: r.prefilled_wallet,
      expired: isExpired(r),
      url: linkUrl(r.token),
      display_status: r.link_status === 'revoked' && !r.banxa_status ? 'Failed' : display(r.banxa_status),
    }));
  }

  function revoke(publicId, actor) {
    const r = db.prepare(`UPDATE payment_links SET status='revoked', updated_at=? WHERE public_id=? AND status IN ('active','checkout','stalled','failed','reconciling')`)
      .run(now(), publicId);
    if (r.changes) {
      const l = getLinkByPublicId(publicId);
      db.prepare(`UPDATE orders SET checkout_url=NULL, updated_at=? WHERE link_id=?`).run(now(), l.id);
      audit(actor, 'link.revoke', { publicId });
    }
    return r.changes === 1;
  }

  return {
    createLink, getLinkByToken, getLinkByPublicId, latestOrder, startCheckout, verifyAndGetCheckout, syncOrder, syncPending,
    reconcileAttempt, reconcileAll, processWebhookEvent, usableCheckoutUrl, expireCheckoutUrl, sweepExpiredCheckoutUrls, recoverWebhooks, applyUpdate, normalize, compareFields,
    listLinks, revoke, audit, isExpired, linkUrl, isBlocked, getOrderById, getLinkById, TERMINAL, LIVE_LOCAL,
  };
}

module.exports = { createService, UserError };
