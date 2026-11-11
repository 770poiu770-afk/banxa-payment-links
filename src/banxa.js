'use strict';
const crypto = require('crypto');

/**
 * Banxa Hosted Checkout v2 client (official API).
 *   Create buy order : POST {base}/{partnerRef}/v2/buy          (x-api-key)
 *   Get order        : GET  {base}/{partnerRef}/v2/orders/{id}  (x-api-key)
 *   Reference data   : GET  {base}/{partnerRef}/v2/crypto, /v2/payment-methods/buy?fiat=USD
 * Webhooks are verified with the HMAC key pair (NOT the v2 x-api-key).
 */
class BanxaError extends Error {
  /**
   * ambiguous = true when we cannot know whether Banxa acted on the request
   * (timeout, network drop, 5xx, malformed 2xx). For order creation this means
   * an order MAY exist and must be reconciled before any new attempt.
   */
  constructor(message, status, body, ambiguous = false) {
    super(message); this.status = status; this.body = body; this.ambiguous = ambiguous;
  }
}

function createClient(cfg) {
  const b = cfg.banxa;

  function assertConfigured() {
    if (!b.partnerRef || !b.apiKey) {
      throw new BanxaError('Banxa API is not configured (BANXA_PARTNER_REF / BANXA_API_KEY missing)', 0);
    }
  }

  async function call(method, pathAndQuery, body) {
    assertConfigured();
    const url = `${b.apiBase}/${encodeURIComponent(b.partnerRef)}${pathAndQuery}`;
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), b.timeoutMs);
    let res, text;
    try {
      res = await fetch(url, {
        method,
        headers: {
          'x-api-key': b.apiKey,
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: ctrl.signal,
      });
      text = await res.text();
    } catch (e) {
      throw new BanxaError(`Banxa request failed: ${e.name === 'AbortError' ? 'timeout' : e.message}`, 0, null, true);
    } finally {
      clearTimeout(t);
    }
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }
    if (!res.ok) {
      const msg = (json && (json.message || json.error || (json.errors && JSON.stringify(json.errors)))) || text?.slice(0, 300);
      // 4xx (incl. 429) = Banxa rejected the request, nothing created; 5xx/408 = outcome unknown
      const ambiguous = res.status >= 500 || res.status === 408;
      throw new BanxaError(`Banxa API ${res.status}: ${msg}`, res.status, json || text, ambiguous);
    }
    if (text && json === null) throw new BanxaError('Non-JSON success response from Banxa', res.status, text, true);
    return json;
  }

  async function createBuyOrder(p) {
    const payload = {
      crypto: b.crypto,
      fiat: b.fiat,
      fiatAmount: p.fiatAmount,
      blockchain: b.blockchain,
      walletAddress: p.walletAddress,
      paymentMethodId: b.paymentMethodId,
      externalCustomerId: p.externalCustomerId,
      externalOrderId: p.externalOrderId,
      redirectUrl: p.redirectUrl,
      metadata: p.metadata,
    };
    if (p.email) payload.email = p.email;
    const r = await call('POST', '/v2/buy', payload);
    // 2xx without an id: Banxa may still have created the order -> ambiguous, reconcile.
    if (!r || !r.id) throw new BanxaError('Unexpected create-order response from Banxa', 0, r, true);
    return r; // checkoutUrl host + all fields are validated by the service before any redirect
  }

  /** Validate a checkout URL without throwing. */
  function isBanxaCheckoutUrl(u) {
    try { assertCheckoutUrl(u); return true; } catch { return false; }
  }

  /** Only ever redirect customers to a genuine Banxa checkout host over HTTPS (or the local mock). */
  function assertCheckoutUrl(u) {
    let parsed;
    try { parsed = new URL(u); } catch { throw new BanxaError('Invalid checkoutUrl from Banxa', 0); }
    const okHost = b.checkoutHosts.some((h) => parsed.hostname === h || parsed.hostname.endsWith('.' + h));
    const okProto = parsed.protocol === 'https:' || (b.usingOverride && parsed.protocol === 'http:');
    if (!okHost || !okProto) throw new BanxaError(`Refusing non-Banxa checkoutUrl host: ${parsed.hostname}`, 0);
  }

  const getOrder = (id) => call('GET', `/v2/orders/${encodeURIComponent(id)}`);
  // Hosted Checkout v2 reference data: /v2/crypto/{orderType}, /v2/payment-methods/{orderType}
  const listCrypto = () => call('GET', '/v2/crypto/buy');
  const listCardMethods = () => call('GET', `/v2/payment-methods/buy?fiat=${encodeURIComponent(b.fiat)}`);

  /** GET /v2/orders (start, end required; externalCustomerId, page, limit optional). Returns all pages (capped). */
  async function listOrders({ start, end, externalCustomerId }) {
    const out = [];
    for (let page = 1; page <= 20; page++) {
      const q = new URLSearchParams({ start, end, page: String(page), limit: '100' });
      if (externalCustomerId) q.set('externalCustomerId', externalCustomerId);
      const r = await call('GET', `/v2/orders?${q}`);
      const orders = Array.isArray(r) ? r : (r && (r.orders || r.data?.orders)) || [];
      out.push(...orders);
      const total = r && Number(r.total);
      if (!orders.length || orders.length < 100 || (Number.isFinite(total) && out.length >= total)) break;
    }
    return out;
  }

  /**
   * Find an order we may have created, by our externalOrderId (Banxa returns it as `externalId`).
   * Returns the order object, or null if Banxa definitively has no such order in the window.
   * Throws if the lookup itself fails (caller must treat as still-unknown).
   */
  async function findOrderByExternalId({ externalOrderId, externalCustomerId, around }) {
    const day = 86400e3, t = Date.parse(around) || Date.now();
    const iso = (ms) => new Date(ms).toISOString().slice(0, 10);
    const orders = await listOrders({ start: iso(t - day), end: iso(t + day), externalCustomerId });
    const hits = orders.filter((o) => (o.externalId ?? o.externalOrderId) === externalOrderId);
    if (hits.length > 1) throw new BanxaError(`Multiple Banxa orders share externalOrderId ${externalOrderId}`, 0, hits, true);
    return hits[0] || null;
  }

  return { createBuyOrder, getOrder, listOrders, findOrderByExternalId, listCrypto, listCardMethods, assertCheckoutUrl, isBanxaCheckoutUrl };
}

/**
 * Verify a Banxa webhook.
 * Header: Authorization: Bearer {API_KEY}:{SIGNATURE}:{NONCE}
 * Signed string: "POST\n{ourWebhookPath}\n{nonce}\n{rawBody}" -> HMAC-SHA256(secret) hex.
 * Nonce is treated as an opaque string (per Banxa docs).
 */
function verifyWebhook({ authorization, method, path, rawBody, hmacKey, hmacSecret }) {
  if (!hmacKey || !hmacSecret) return { ok: false, reason: 'HMAC key pair not configured' };
  if (typeof authorization !== 'string' || !authorization.startsWith('Bearer ')) {
    return { ok: false, reason: 'missing Bearer authorization' };
  }
  const parts = authorization.slice(7).split(':');
  if (parts.length !== 3) return { ok: false, reason: 'malformed authorization' };
  const [key, signature, nonce] = parts;
  if (!safeEqual(key, hmacKey)) return { ok: false, reason: 'unknown key' };
  const signed = `${method}\n${path}\n${nonce}\n${rawBody}`;
  const expected = crypto.createHmac('sha256', hmacSecret).update(signed).digest('hex');
  if (!safeEqual(signature.toLowerCase(), expected)) return { ok: false, reason: 'bad signature' };
  return { ok: true, nonce };
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

/** Helper used by tests / tooling to produce a valid signature. */
function signWebhook({ path, rawBody, hmacKey, hmacSecret, nonce }) {
  const n = nonce || String(Date.now() * 1000);
  const sig = crypto.createHmac('sha256', hmacSecret).update(`POST\n${path}\n${n}\n${rawBody}`).digest('hex');
  return `Bearer ${hmacKey}:${sig}:${n}`;
}

module.exports = { createClient, verifyWebhook, signWebhook, BanxaError };
