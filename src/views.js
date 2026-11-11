'use strict';
const { display } = require('./status');

const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const CSS = `
:root{--bg:#f6f7f9;--card:#fff;--ink:#14171c;--muted:#5d6673;--line:#e3e6eb;--brand:#1f5eff;--ok:#0f8a4b;--warn:#b26b00;--bad:#c62828;--info:#5b4bd6}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:var(--bg);color:var(--ink)}
header{background:#101828;color:#fff;padding:14px 24px;display:flex;gap:16px;align-items:center;justify-content:space-between}
header a{color:#cbd5e1;text-decoration:none}main{max-width:1200px;margin:24px auto;padding:0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin-bottom:20px}
h1,h2{margin:0 0 12px}h2{font-size:18px}label{display:block;font-weight:600;margin:10px 0 4px}
input,textarea,select{width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:8px;font:inherit}
input[readonly]{background:#f1f3f6;color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
button,.btn{background:var(--brand);color:#fff;border:0;border-radius:8px;padding:10px 16px;font:inherit;font-weight:600;cursor:pointer;text-decoration:none;display:inline-block}
.btn.sec{background:#eef2ff;color:var(--brand)}.btn.danger{background:#fdecec;color:var(--bad)}.btn.sm{padding:5px 10px;font-size:13px}
table{width:100%;border-collapse:collapse;font-size:13.5px}th,td{padding:8px;border-bottom:1px solid var(--line);text-align:start;vertical-align:top}
th{color:var(--muted);font-weight:600}.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;word-break:break-all}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12.5px;font-weight:600;white-space:nowrap}
.s-Pending{background:#fff4dd;color:var(--warn)}.s-Payment.Completed,.s-PaymentCompleted{background:#e6f4ff;color:#0b63c5}
.s-VerificationPending{background:#efeaff;color:var(--info)}.s-Processing{background:#e6f4ff;color:#0b63c5}
.s-Completed{background:#e5f6ec;color:var(--ok)}.s-Failed{background:#fdecec;color:var(--bad)}.s-Refunded{background:#eceff3;color:#444}
.notice{border-inline-start:4px solid var(--warn);background:#fffaf0}.notice.ok{border-color:var(--ok);background:#f2fbf5}.notice.bad{border-color:var(--bad);background:#fff5f5}
.muted{color:var(--muted)}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.err{color:var(--bad);font-weight:600}
.envbadge{padding:3px 10px;border-radius:999px;font-weight:700;font-size:12px}.env-sandbox{background:#fde68a;color:#7c4a03}.env-production{background:#fecaca;color:#7f1d1d}
.check{display:flex;gap:8px;align-items:flex-start;font-weight:400}.check input{width:auto;margin-top:4px}
.pay{max-width:480px;margin:40px auto}.walletbox{border:2px solid var(--brand);border-radius:10px;padding:12px;margin:14px 0;background:#f5f8ff}
.walletaddr{font:600 16px/1.6 ui-monospace,Menlo,Consolas,monospace;letter-spacing:.5px;direction:ltr;word-spacing:2px}
.walletaddr b{color:var(--brand);font-weight:800;white-space:nowrap}.walletaddr span{white-space:nowrap}.badge-blocked{background:#c62828;color:#fff}.kv{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--line)}
`;

function layout({ title, body, dir = 'rtl', lang = 'he', admin = false, csrf = '', env = '', refreshSec = 0 }) {
  return `<!doctype html><html lang="${lang}" dir="${dir}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer">${refreshSec ? `<meta http-equiv="refresh" content="${Number(refreshSec)}">` : ''}
<title>${esc(title)}</title><style>${CSS}</style></head><body>
${admin ? `<header><div class="row"><strong>Banxa Payment Links</strong><span class="envbadge env-${esc(env)}">${esc(env.toUpperCase())}</span></div>
<nav class="row"><a href="/admin">לוח בקרה</a><a href="/admin/settings">הגדרות</a>
<form method="post" action="/admin/logout" style="margin:0"><input type="hidden" name="_csrf" value="${esc(csrf)}"><button class="btn sm sec">יציאה</button></form></nav></header>` : ''}
<main>${body}</main>${admin ? `<script src="/static/admin.js" defer></script>` : ''}</body></html>`;
}

function loginPage(error) {
  return layout({
    title: 'כניסה',
    body: `<div class="card pay"><h1>כניסה לפאנל ניהול</h1>
${error ? `<p class="err">${esc(error)}</p>` : ''}
<form method="post" action="/admin/login"><label>שם משתמש</label><input name="username" autocomplete="username" required>
<label>סיסמה</label><input name="password" type="password" autocomplete="current-password" required>
<p><button>כניסה</button></p></form></div>`,
  });
}

function complianceNotice() {
  return `<div class="card notice"><h2>מודל התשלום המאושר לפי תנאי Banxa</h2>
<p>לפי תנאי השימוש של Banxa, כתובת הארנק שמקבלת את הקריפטו חייבת להיות <strong>בבעלותו ובשליטתו הבלעדית של הלקוח שמשלם</strong>,
והלקוח רוכש <strong>עבור עצמו בלבד ולא עבור צד שלישי</strong> (Terms of Use, Part A cl. 4.2(f); Part B cl. 3(b), 4(a)).
לכן המערכת <strong>לא מאפשרת</strong> לשלוח את ה-USDT לארנק העסקי שלך כשהלקוח משלם בכרטיס.</p>
<p>המודל שהמערכת מיישמת: הלקוח מוסר לך את כתובת ה-TRC20 <strong>שלו</strong>, אתה מגדיר אותה בקישור יחד עם סכום קבוע,
והלקוח משלם בכרטיס שעל שמו ומקבל את ה-USDT לארנק שלו. כתובות שמוגדרות ב"ארנקים חסומים" (למשל הארנקים העסקיים שלך) נדחות אוטומטית.
מבנה אחר (תשלום לעסק) אפשרי רק עם אישור מפורש ובכתב מ-Banxa בהסכם ה-Partner.</p></div>`;
}

function healthCard(cfg) {
  const b = cfg.banxa;
  const item = (ok, text) => `<li>${ok ? '✅' : '⚠️'} ${text}</li>`;
  return `<div class="card"><h2>מצב חיבור ל-Banxa</h2><ul style="margin:0;padding-inline-start:18px">
${item(true, `סביבה: <strong>${esc(b.env)}</strong> (${esc(b.apiBase)})${b.usingOverride ? ' — <span class="err">MOCK לבדיקות מקומיות</span>' : ''}`)}
${item(b.partnerRef && b.apiKey, 'Partner Ref + API Key (x-api-key) ליצירת הזמנות')}
${item(b.hmacKey && b.hmacSecret, 'HMAC key pair לאימות Webhooks')}
${item(true, `Webhook URL להגדרה ב-Partner Dashboard: <span class="mono">${esc(cfg.publicBaseUrl + cfg.webhookPath)}</span>`)}
${item(b.env === 'production' ? b.productionApproved : true, b.env === 'production' ? 'Production מאושר' : 'Production לא פעיל — עובדים ב-Sandbox')}
</ul><form method="post" action="/admin/verify-banxa" style="margin-top:12px"><input type="hidden" name="_csrf" value="__CSRF__">
<button class="btn sec sm">בדיקת הגדרות מול Banxa (USDT/TRON + כרטיס USD)</button></form></div>`;
}

function dashboard({ cfg, csrf, links, flash, verify }) {
  const rows = links.map(linkRow).join('') || `<tr><td colspan="9" class="muted">אין עדיין קישורים</td></tr>`;
  const body = `
${flash ? `<div class="card notice ${flash.type || 'ok'}">${flash.html}</div>` : ''}
${verify ? `<div class="card notice ${verify.ok ? 'ok' : 'bad'}"><h2>תוצאת בדיקה מול Banxa</h2>${verify.html}</div>` : ''}
${complianceNotice()}
${healthCard(cfg).replace('__CSRF__', esc(csrf))}
<div class="card"><h2>יצירת קישור תשלום</h2>
<form method="post" action="/admin/links"><input type="hidden" name="_csrf" value="${esc(csrf)}">
<div class="grid">
<div><label>סכום לתשלום (USD)</label><input name="amount" type="number" step="0.01" min="${cfg.minUsd}" max="${cfg.maxUsd}" required>
<span class="muted">טווח: ${cfg.minUsd}–${cfg.maxUsd} USD</span></div>
<div><label>מטבע לקבלה</label><input value="USDT" readonly dir="ltr"></div>
<div><label>רשת</label><input value="TRON (TRC20) — ${esc(cfg.banxa.blockchain)}" readonly dir="ltr"></div>
<div><label>אמצעי תשלום</label><input value="Visa / Mastercard (debit-credit-card)" readonly dir="ltr"></div>
</div>
<div class="grid">
<div><label>שם הלקוח</label><input name="customer_name" required maxlength="120"></div>
<div><label>אימייל הלקוח</label><input name="customer_email" type="email" required maxlength="200"></div>
<div><label>תוקף הקישור (שעות)</label><input name="ttl_hours" type="number" min="1" max="168" value="${cfg.defaultLinkTtlHours}"></div>
</div>
<label>כתובת ארנק TRC20 של הלקוח (שהלקוח מסר לך)</label>
<input name="wallet" dir="ltr" class="mono" required pattern="T[1-9A-HJ-NP-Za-km-z]{33}" placeholder="T...">
<label class="check"><input type="checkbox" name="wallet_attest" value="1" required>
הלקוח מסר לי את הכתובת הזו והיא בבעלותו ובשליטתו. זו אינה כתובת שלי או של העסק שלי.</label>
<label>פרטי ההזמנה / תיאור</label><textarea name="description" rows="2" maxlength="500"></textarea>
<p><button>Create Payment Link</button></p></form></div>

<div class="card"><div class="row" style="justify-content:space-between"><h2>עסקאות</h2>
<button class="btn sec sm" id="refreshAll" data-csrf="${esc(csrf)}">רענון סטטוסים</button></div>
<div style="overflow-x:auto"><table><thead><tr><th>נוצר</th><th>קישור</th><th>לקוח</th><th>סכום</th><th>ארנק הלקוח</th><th>סטטוס</th>
<th>Transaction ID (Banxa)</th><th>Blockchain Tx Hash</th><th>פעולות</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
  return layout({ title: 'פאנל ניהול', body, admin: true, csrf, env: cfg.banxa.env });
}

function linkRow(l) {
  const st = l.display_status;
  const tx = l.tx_hash
    ? `<a class="mono" href="https://tronscan.org/#/transaction/${encodeURIComponent(l.tx_hash)}" target="_blank" rel="noopener">${esc(l.tx_hash)}</a>` : '<span class="muted">—</span>';
  return `<tr>
<td><span dir="ltr">${esc(l.created_at.slice(0, 16).replace('T', ' '))}</span></td>
<td><a href="/admin/links/${esc(l.public_id)}" class="mono">${esc(l.public_id)}</a><div class="muted">${esc(l.link_status)}</div></td>
<td>${esc(l.customer_name)}<div class="muted">${esc(l.customer_email)}</div></td>
<td>$${esc(l.fiat_amount)}${l.crypto_amount ? `<div class="muted">${esc(l.crypto_amount)} USDT</div>` : ''}</td>
<td class="mono">${esc(l.wallet || '')}</td>
<td><span class="pill s-${esc(st.replace(/\s/g, ''))}">${esc(st)}</span>${l.banxa_status ? `<div class="muted mono">${esc(l.banxa_status)}</div>` : ''}
${l.link_status === 'blocked' ? `<div><span class="pill badge-blocked">⛔ BLOCKED</span></div><div class="err">${esc(l.block_reason || l.mismatch || '')}</div>`
    : (l.mismatch ? `<div class="err">⚠ ${esc(l.mismatch)}</div>` : '')}
${l.link_status === 'reconciling' ? '<div class="muted">⏳ בבדיקת כפילות מול Banxa</div>' : ''}
${l.link_status === 'stalled' ? '<div class="err">⌛ קישור ה-Checkout פג (תוקף של דקה). ההזמנה עדיין פתוחה ב-Banxa ולא תיווצר הזמנה חדשה</div>' : ''}</td>
<td class="mono">${esc(l.banxa_order_id || '—')}</td><td>${tx}</td>
<td><div class="row">${['active', 'checkout'].includes(l.link_status) && !l.expired
    ? `<button class="btn sm sec copy" data-url="${esc(l.url)}">Copy Link</button>` : ''}</div></td></tr>`;
}

function linkCreated({ cfg, csrf, link, url }) {
  const msg = encodeURIComponent(`קישור לתשלום מאובטח דרך Banxa על סך $${link.fiat_amount}: ${url}`);
  const body = `<div class="card notice ok"><h2>הקישור נוצר</h2>
<p>סכום: <strong>$${esc(link.fiat_amount)}</strong> · USDT · TRON (TRC20) · כרטיס אשראי · תוקף עד ${esc(link.expires_at.slice(0, 16).replace('T', ' '))} UTC</p>
<input class="mono" dir="ltr" id="linkUrl" value="${esc(url)}" readonly>
<div class="row" style="margin-top:12px"><button class="btn copy" data-url="${esc(url)}">Copy Link</button>
<a class="btn sec" target="_blank" rel="noopener" href="https://wa.me/?text=${msg}">שליחה ב-WhatsApp</a>
<a class="btn sec" target="_blank" rel="noopener" href="https://t.me/share/url?url=${encodeURIComponent(url)}&text=${encodeURIComponent(`תשלום $${link.fiat_amount} דרך Banxa`)}">שליחה ב-Telegram</a>
<a class="btn sec" href="/admin">חזרה לפאנל</a></div>
<p class="muted">הקישור ייחודי להזמנה הזו. ההזמנה ב-Banxa נוצרת ברגע שהלקוח פותח את הקישור, כך שהלקוח תמיד מקבל קישור Checkout טרי.</p></div>`;
  return layout({ title: 'קישור נוצר', body, admin: true, csrf, env: cfg.banxa.env });
}

function linkDetail({ cfg, csrf, link, orders, events, audit, url }) {
  const ord = orders.map((o) => `<tr><td class="mono">${esc(o.banxa_order_id)}</td><td class="mono">${esc(o.external_order_id)}</td>
<td><span class="pill s-${esc(display(o.banxa_status).replace(/\s/g, ''))}">${esc(display(o.banxa_status))}</span> <span class="mono muted">${esc(o.banxa_status || '')}</span></td>
<td>${esc(o.crypto_amount || '')}</td><td class="mono">${esc(o.tx_hash || '—')}</td>
<td><span class="mono">${esc(o.local_state)}</span>${o.local_state === 'blocked' ? ' <span class="pill badge-blocked">⛔</span>' : ''}<div class="err">${esc(o.mismatch || '')}</div><div class="muted">${esc(o.last_error || '')}</div></td>
<td>${esc(o.created_at)}</td><td>${esc(o.last_synced_at || '')}</td></tr>`).join('');
  const blockedNote = link.status === 'blocked'
    ? `<div class="card notice bad"><h2>⛔ הקישור נחסם</h2><p>נתוני ההזמנה ש-Banxa החזירה לא תאמו את ההזמנה שנשמרה בשרת. קישור ה-Checkout נמחק ולא יוצג ללקוח. אל תספק שירות על סמך הזמנה זו ובדוק מול Banxa (אין endpoint מתועד לביטול הזמנה, ולכן ההזמנה עצמה תפוג אצל Banxa).</p></div>` : '';
  const ev = events.map((e) => `<tr><td>${esc(e.received_at)}</td><td class="mono">${esc(e.status || '')}</td>
<td>${e.signature_valid ? '✅' : '❌ ' + esc(e.reason || '')}</td><td>${e.signature_valid ? (e.processed ? '✅ אומת מול lookup' : `⏳ ממתין לשחזור (${e.attempts}) ${esc(e.last_error || '')}`) : '—'}</td></tr>`).join('');
  const au = audit.map((a) => `<tr><td>${esc(a.at)}</td><td>${esc(a.actor)}</td><td>${esc(a.action)}</td><td class="mono">${esc(a.details || '')}</td></tr>`).join('');
  const canRevoke = ['active', 'checkout', 'stalled', 'failed', 'reconciling'].includes(link.status);
  const stalledNote = link.status === 'stalled'
    ? `<div class="card notice"><h2>⌛ קישור ה-Checkout של Banxa פג</h2><p>לפי Banxa, קישור Checkout תקף לדקה אחת מרגע יצירת ההזמנה ועד הטעינה הראשונה. לא קיים מנגנון מתועד לחזרה לאותו Checkout. ההזמנה ב-Banxa עדיין במצב פתוח, ולכן המערכת לא יוצרת הזמנה נוספת כדי למנוע תשלום כפול. ייתכן שהלקוח טען את הקישור בזמן ועדיין משלם.</p>
<p><strong>מה לעשות:</strong> המתן לעדכון מ-Banxa (Webhook או סנכרון). אם ההזמנה תסומן expired/declined, הלקוח יוכל לנסות שוב באותו קישור. אם צריך מיד קישור חדש, בדוק קודם את ההזמנה בדשבורד של Banxa או מול התמיכה שלהם, בטל את הקישור הזה וצור קישור חדש.</p></div>` : '';
  const body = `${blockedNote}${stalledNote}<div class="card"><h2>קישור ${esc(link.public_id)}</h2>
<div class="grid"><div><strong>לקוח:</strong> ${esc(link.customer_name)} (${esc(link.customer_email)})<br><strong>externalCustomerId:</strong> <span class="mono">${esc(link.customer_id)}</span></div>
<div><strong>סכום:</strong> $${esc(link.fiat_amount)} → USDT (${esc(link.blockchain)})<br><strong>סטטוס קישור:</strong> ${esc(link.status)} · ניסיונות: ${link.attempts}</div>
<div><strong>ארנק הלקוח:</strong> <span class="mono">${esc(link.prefilled_wallet)}</span><br><strong>תוקף:</strong> ${esc(link.expires_at)}</div></div>
<p>${esc(link.description || '')}</p>
<div class="row"><button class="btn sm sec copy" data-url="${esc(url)}">Copy Link</button>
<form method="post" action="/admin/links/${esc(link.public_id)}/sync" style="margin:0"><input type="hidden" name="_csrf" value="${esc(csrf)}"><button class="btn sm sec">סנכרון מול Banxa</button></form>
${canRevoke ? `<form method="post" action="/admin/links/${esc(link.public_id)}/revoke" style="margin:0"><input type="hidden" name="_csrf" value="${esc(csrf)}"><button class="btn sm danger">ביטול קישור</button></form>` : ''}</div></div>
<div class="card"><h2>הזמנות Banxa</h2><div style="overflow-x:auto"><table><thead><tr><th>Banxa Order ID</th><th>External ID</th><th>סטטוס</th><th>USDT</th><th>Tx Hash</th><th>מצב מקומי / אי-התאמה</th><th>נוצר</th><th>סונכרן</th></tr></thead>
<tbody>${ord || '<tr><td colspan="8" class="muted">הלקוח עוד לא פתח את הקישור</td></tr>'}</tbody></table></div></div>
<div class="card"><h2>Webhooks שהתקבלו</h2><table><thead><tr><th>זמן</th><th>סטטוס</th><th>חתימה</th><th>עיבוד</th></tr></thead><tbody>${ev || '<tr><td colspan="4" class="muted">—</td></tr>'}</tbody></table></div>
<div class="card"><h2>יומן פעולות</h2><table><thead><tr><th>זמן</th><th>מבצע</th><th>פעולה</th><th>פרטים</th></tr></thead><tbody>${au}</tbody></table></div>`;
  return layout({ title: link.public_id, body, admin: true, csrf, env: cfg.banxa.env });
}

function settingsPage({ cfg, csrf, blocked, flash }) {
  const rows = blocked.map((b) => `<tr><td class="mono">${esc(b.address)}</td><td>${esc(b.label || '')}</td>
<td><form method="post" action="/admin/settings/blocked/delete" style="margin:0"><input type="hidden" name="_csrf" value="${esc(csrf)}">
<input type="hidden" name="address" value="${esc(b.address)}"><button class="btn sm danger">הסרה</button></form></td></tr>`).join('');
  const body = `${flash ? `<div class="card notice ${flash.type || 'ok'}">${flash.html}</div>` : ''}
<div class="card"><h2>ארנקים חסומים כיעד</h2>
<p class="muted">הוסף כאן את הארנקים שלך ושל העסק. המערכת תסרב ליצור קישור שמעביר אליהם קריפטו, כי לפי תנאי Banxa הארנק חייב להיות של הלקוח.</p>
<form method="post" action="/admin/settings/blocked" class="grid"><input type="hidden" name="_csrf" value="${esc(csrf)}">
<div><label>כתובת TRC20</label><input name="address" class="mono" required></div><div><label>תיאור</label><input name="label"></div>
<div style="align-self:end"><button>הוספה</button></div></form>
<table style="margin-top:12px"><thead><tr><th>כתובת</th><th>תיאור</th><th></th></tr></thead><tbody>${rows || '<tr><td colspan="3" class="muted">אין</td></tr>'}</tbody></table></div>`;
  return layout({ title: 'הגדרות', body, admin: true, csrf, env: cfg.banxa.env });
}

// ---------- Customer-facing pages (English, LTR) ----------
function groupAddr(a) {
  // T X Y Z . . . : first/last 6 characters emphasised, groups of 4 for easy visual comparison
  const s = String(a);
  const head = s.slice(0, 6), tail = s.slice(-6), mid = s.slice(6, -6);
  const groups = (mid.match(/.{1,4}/g) || []).map((g) => `<span>${esc(g)}</span>`).join(' ');
  return `<b>${esc(head)}</b> ${groups} <b>${esc(tail)}</b>`;
}

function payPage({ link, formToken, error, sandbox }) {
  const w = link.prefilled_wallet;
  const body = `<div class="card pay">
${sandbox ? '<p class="envbadge env-sandbox">TEST MODE — no real payment</p>' : ''}
<h1>Payment</h1>
<div class="kv"><span>Amount</span><strong>$${esc(link.fiat_amount)} USD</strong></div>
<div class="kv"><span>You receive</span><strong>USDT</strong></div>
<div class="kv"><span>Network</span><strong>TRON (TRC20)</strong></div>
<div class="kv"><span>Payment method</span><strong>Visa / Mastercard</strong></div>
<div class="walletbox"><div style="font-weight:700;margin-bottom:6px">Your USDT will be sent to this wallet:</div>
<div class="walletaddr" title="${esc(w)}">${groupAddr(w)}</div>
<div class="muted" style="font-size:13px;margin-top:8px">Check the <b>first and last 6 characters</b> against the TRC20 receiving address in your own wallet app.
This must be <b>your</b> TRON (TRC20) address. Banxa will show the same address on its checkout.</div></div>
${link.description ? `<p class="muted">${esc(link.description)}</p>` : ''}
${error ? `<p class="err">${esc(error)}</p>` : ''}
<form method="post"><input type="hidden" name="ft" value="${esc(formToken)}">
<label class="check"><input type="checkbox" name="own_wallet" value="1" required>
<span>I checked the address above (ending in <code class="mono">${esc(w.slice(-6))}</code>). It is my own TRC20 wallet, under my sole control, and I am buying for myself.</span></label>
<label class="check"><input type="checkbox" name="own_card" value="1" required>
<span>I will pay with a card issued in my own name.</span></label>
<p class="muted" style="font-size:13px">Services related to card payments are provided by Banxa, a separate third-party platform.
By proceeding, you acknowledge that you have read and agree to Banxa's
<a href="https://banxa.com/terms-of-use" target="_blank" rel="noopener">Terms of Use</a> and
<a href="https://banxa.com/privacy-and-cookies-policy" target="_blank" rel="noopener">Privacy and Cookies Policy</a>.</p>
<button style="width:100%">Continue to secure payment with Banxa</button></form>
<p class="muted" style="font-size:12px">If this is not your wallet address, do not continue. Contact the sender of this link and give them your correct TRC20 address.</p></div>`;
  return layout({ title: 'Payment', body, dir: 'ltr', lang: 'en' });
}

function payMessage({ title, text, sandbox, refreshSec = 0 }) {
  const body = `<div class="card pay">${sandbox ? '<p class="envbadge env-sandbox">TEST MODE</p>' : ''}<h1>${esc(title)}</h1><p>${esc(text)}</p></div>`;
  return layout({ title, body, dir: 'ltr', lang: 'en', refreshSec });
}

module.exports = { esc, loginPage, dashboard, linkCreated, linkDetail, settingsPage, payPage, payMessage };
