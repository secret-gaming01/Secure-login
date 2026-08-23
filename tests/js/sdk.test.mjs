// Smoke test SDK JS — exécutable avec Node >= 18 sans transpilation :
//   node tests/js/sdk.test.mjs
// La vérification de types complète est faite par `tsc --noEmit` (CI).
import { readFileSync } from 'node:fs';
import assert from 'node:assert';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const src = readFileSync(join(root, 'sdk', 'js', 'src', 'index.ts'), 'utf8');

// Méthodes obligatoires de la spécification
for (const m of ['login', 'logout', 'register', 'refreshToken', 'getCurrentUser', 'checkPermission']) {
  assert.ok(src.includes(`async ${m}(`), `méthode manquante dans le SDK : ${m}`);
}

// Endpoints clés couverts
for (const ep of ['/auth/register', '/auth/login', '/auth/mfa/verify', '/auth/token/refresh',
  '/auth/logout', '/auth/me', '/auth/passkey/login']) {
  assert.ok(src.includes(ep), `endpoint manquant : ${ep}`);
}

assert.ok(src.includes('class SecureAuthError'), 'classe SecureAuthError manquante');
assert.ok(src.includes('Bearer'), 'Authorization Bearer manquant');

console.log('OK sdk/js smoke tests passed');
