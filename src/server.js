'use strict';
const { load } = require('./config');
const { open } = require('./db');
const { createClient } = require('./banxa');
const { createApp } = require('./app');

const cfg = load();
const db = open(cfg.dbPath);
const banxa = createClient(cfg);
const { app, svc } = createApp({ cfg, db, banxa });

const server = app.listen(cfg.port, () => {
  console.log(`[banxa-links] listening on :${cfg.port} | Banxa env=${cfg.banxa.env} api=${cfg.banxa.apiBase}`);
  console.log(`[banxa-links] webhook URL to register in Banxa dashboard: ${cfg.publicBaseUrl}${cfg.webhookPath}`);
  if (!cfg.banxa.hmacKey) console.warn('[banxa-links] WARNING: HMAC key pair missing — webhooks will be rejected; status relies on polling.');
});

// Backup to webhooks: poll non-final orders via the official order lookup endpoint
const timer = setInterval(() => {
  svc.syncPending().catch((e) => console.error('[poll]', e.message));
}, cfg.pollIntervalSec * 1000);

function shutdown() { clearInterval(timer); server.close(() => { db.close(); process.exit(0); }); }
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
