'use strict';
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

// NOTE: no card data, CVV, 3DS/OTP codes or KYC documents are ever stored here.
// Card entry and verification happen only on Banxa's hosted checkout.
const SCHEMA = `
CREATE TABLE IF NOT EXISTS customers (
  id TEXT PRIMARY KEY,               -- stable externalCustomerId sent to Banxa
  name TEXT,
  email TEXT,
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS customers_email ON customers(email) WHERE email IS NOT NULL;

CREATE TABLE IF NOT EXISTS payment_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_id TEXT NOT NULL UNIQUE,    -- short reference shown in the panel
  token TEXT NOT NULL UNIQUE,        -- 256-bit random token in the customer URL
  customer_id TEXT NOT NULL REFERENCES customers(id),
  environment TEXT NOT NULL,
  fiat TEXT NOT NULL,
  fiat_amount TEXT NOT NULL,
  crypto TEXT NOT NULL,
  blockchain TEXT NOT NULL,
  payment_method TEXT NOT NULL,
  prefilled_wallet TEXT,             -- customer's own wallet, if they supplied it in advance
  description TEXT,
  status TEXT NOT NULL,              -- active | creating | reconciling | checkout | stalled | paid | failed | blocked | revoked
  attempts INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  link_id INTEGER NOT NULL REFERENCES payment_links(id),
  external_order_id TEXT NOT NULL UNIQUE,  -- written BEFORE calling Banxa: our idempotency anchor
  banxa_order_id TEXT UNIQUE,        -- NULL until Banxa confirms / reconciliation finds it
  checkout_url TEXT,                 -- NULL whenever it must not be used (blocked, orphaned, closed)
  -- local_state:
  --   creating    request in flight
  --   unknown     ambiguous create (timeout/5xx): must be reconciled before any new attempt
  --   unverified  created, but full-field lookup verification not yet successful (no redirect)
  --   open        verified; checkout_url may be used ONLY inside its validity window (see checkout_url_issued_at)
  --   url_expired order exists at Banxa but its checkoutUrl may have expired: never redirect, never auto-recreate
  --               while Banxa still reports it as pending
  --   orphaned    found by reconciliation; its checkout URL was never shown to anyone
  --   not_created reconciliation proved Banxa has no such order
  --   rejected    Banxa returned 4xx: nothing created
  --   blocked     parameter mismatch: checkout disabled permanently
  local_state TEXT NOT NULL,
  wallet_address TEXT NOT NULL,
  banxa_status TEXT,
  fiat_amount TEXT,
  crypto_amount TEXT,
  tx_hash TEXT,
  payment_method TEXT,
  mismatch TEXT,                     -- description of any differing field
  last_error TEXT,
  attestation_ip TEXT,
  attested_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  verified_at TEXT,
  checkout_url_issued_at TEXT,       -- when we received Banxa's create response (start of the 1-minute window)
  redirected_at TEXT,                -- first time we sent the customer to the checkout URL
  last_synced_at TEXT
);
CREATE INDEX IF NOT EXISTS orders_link ON orders(link_id);

CREATE TABLE IF NOT EXISTS webhook_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  received_at TEXT NOT NULL,
  banxa_order_id TEXT,
  external_id TEXT,
  status TEXT,
  signature_valid INTEGER NOT NULL,
  processed INTEGER NOT NULL DEFAULT 0,  -- 1 only after authoritative lookup succeeded
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  reason TEXT,
  body TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS webhook_dedupe ON webhook_events(banxa_order_id, status) WHERE signature_valid = 1;
CREATE INDEX IF NOT EXISTS webhook_pending ON webhook_events(processed) WHERE signature_valid = 1;

CREATE TABLE IF NOT EXISTS blocked_wallets (
  address TEXT PRIMARY KEY,
  label TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  details TEXT
);
`;

function open(dbPath) {
  if (dbPath !== ':memory:') fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  const cols = db.prepare("SELECT name FROM pragma_table_info('orders')").all().map((c) => c.name);
  if (cols.length && (!cols.includes('local_state') || !cols.includes('checkout_url_issued_at'))) {
    throw new Error(`Database ${dbPath} was created by a pre-release build (no real data). Delete it and restart.`);
  }
  db.exec(SCHEMA);
  return db;
}

const now = () => new Date().toISOString();

module.exports = { open, now };
