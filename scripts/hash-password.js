'use strict';
// Usage: npm run hash-password -- 'YourStrongPassword'   -> paste output into ADMIN_PASSWORD_HASH
const { hashPassword } = require('../src/auth');
const pw = process.argv[2];
if (!pw || pw.length < 12) { console.error('Provide a password of at least 12 characters.'); process.exit(1); }
console.log(hashPassword(pw));
