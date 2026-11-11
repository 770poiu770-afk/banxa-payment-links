'use strict';
const crypto = require('crypto');

// Password hash format: scrypt$N$r$p$saltB64$hashB64  (generate with: npm run hash-password)
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const N = 16384, r = 8, p = 1;
  const hash = crypto.scryptSync(password, salt, 64, { N, r, p });
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

function verifyPassword(password, stored) {
  try {
    const [alg, N, r, p, saltB64, hashB64] = stored.split('$');
    if (alg !== 'scrypt') return false;
    const expected = Buffer.from(hashB64, 'base64');
    const got = crypto.scryptSync(String(password), Buffer.from(saltB64, 'base64'), expected.length, {
      N: Number(N), r: Number(r), p: Number(p),
    });
    return crypto.timingSafeEqual(expected, got);
  } catch {
    return false;
  }
}

function sessionManager(cfg) {
  const COOKIE = cfg.secureCookies ? '__Host-sid' : 'sid';
  const TTL_MS = 8 * 60 * 60 * 1000;
  const sign = (data) => crypto.createHmac('sha256', cfg.sessionSecret).update(data).digest('base64url');

  function issue(res, username) {
    const payload = Buffer.from(JSON.stringify({
      u: username, exp: Date.now() + TTL_MS, csrf: crypto.randomBytes(24).toString('base64url'),
    })).toString('base64url');
    const value = `${payload}.${sign(payload)}`;
    res.setHeader('Set-Cookie', `${COOKIE}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${TTL_MS / 1000}` +
      (cfg.secureCookies ? '; Secure' : ''));
  }

  function clear(res) {
    res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0` + (cfg.secureCookies ? '; Secure' : ''));
  }

  function read(req) {
    const raw = (req.headers.cookie || '').split(';').map((s) => s.trim()).find((s) => s.startsWith(COOKIE + '='));
    if (!raw) return null;
    const [payload, sig] = raw.slice(COOKIE.length + 1).split('.');
    if (!payload || !sig) return null;
    const exp = sign(payload);
    if (exp.length !== sig.length || !crypto.timingSafeEqual(Buffer.from(exp), Buffer.from(sig))) return null;
    try {
      const s = JSON.parse(Buffer.from(payload, 'base64url').toString());
      if (s.exp < Date.now() || s.u !== cfg.adminUsername) return null;
      return s;
    } catch { return null; }
  }

  function requireAdmin(req, res, next) {
    const s = read(req);
    if (!s) {
      if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'unauthorized' });
      return res.redirect(303, '/admin/login');
    }
    req.session = s;
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      const token = (req.body && req.body._csrf) || req.headers['x-csrf-token'];
      if (!token || token !== s.csrf) return res.status(403).send('CSRF check failed');
    }
    next();
  }

  return { issue, clear, read, requireAdmin };
}

/** Per-link form token so the customer's POST must come from our page. */
function linkFormToken(secret, linkToken) {
  return crypto.createHmac('sha256', secret).update('pay-form:' + linkToken).digest('base64url');
}

module.exports = { hashPassword, verifyPassword, sessionManager, linkFormToken };
