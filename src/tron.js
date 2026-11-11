'use strict';
const crypto = require('crypto');

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Decode(str) {
  let num = 0n;
  for (const ch of str) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) return null;
    num = num * 58n + BigInt(idx);
  }
  let hex = num.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  let bytes = num === 0n ? Buffer.alloc(0) : Buffer.from(hex, 'hex');
  let leading = 0;
  for (const ch of str) { if (ch === '1') leading++; else break; }
  return Buffer.concat([Buffer.alloc(leading), bytes]);
}

const sha256 = (b) => crypto.createHash('sha256').update(b).digest();

/** Validates a TRON mainnet (TRC20) address with full Base58Check checksum. */
function isValidTronAddress(addr) {
  if (typeof addr !== 'string' || !/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(addr)) return false;
  const raw = base58Decode(addr);
  if (!raw || raw.length !== 25 || raw[0] !== 0x41) return false;
  const payload = raw.subarray(0, 21);
  const checksum = raw.subarray(21);
  return sha256(sha256(payload)).subarray(0, 4).equals(checksum);
}

module.exports = { isValidTronAddress };
