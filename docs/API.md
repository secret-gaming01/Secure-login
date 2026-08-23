# Documentation API REST — Secure-Login

Base URL : `http://localhost:8080` (dev). Toutes les réponses sont en JSON.
Authentification : header `Authorization: Bearer <access_token>`.

## Codes d'erreur standard

| Code | Signification |
|------|---------------|
| 400  | Validation (`{"error": "..."}`) |
| 401  | Non authentifié / token invalide |
| 403  | Interdit (scope manquant, IP bloquée, CSRF) |
| 404  | Ressource introuvable |
| 409  | Conflit (email déjà pris…) |
| 429  | Rate limited / cooldown bruteforce (+ `Retry-After`) |

---

## Endpoints publics

### POST /auth/register
```json
{ "email": "user@example.com", "password": "Str0ngPassw0rd!" }
```
→ `201 { "user_id", "message" }` + email de vérification (24 h).

### POST /auth/verify-email
`{ "token": "<lien reçu par email>" }` → `{ "verified": true }`

### POST /auth/resend-verification
`{ "email" }` → réponse identique que le compte existe ou non (anti-énumération).

### POST /auth/login
```json
{ "email": "...", "password": "...", "captcha_token": null }
```
→ succès : `{ access_token, refresh_token, token_type:"Bearer", expires_in:900, user }`
→ MFA actif : `{ "mfa_required": true, "mfa_token": "<5 min>" }` → finaliser via `/auth/mfa/verify`.

### POST /auth/mfa/verify  *(double usage)*
- **Finaliser un login** : `{ "mfa_token": "...", "code": "123456" }` → tokens.
- **Confirmer l'activation** (session active) : `{ "code": "123456" }` →
  `{ enabled:true, recovery_codes:["XXXX-XXXX", …8] }` *(affichés une seule fois)*.

### POST /auth/passkey/login/options
`{ "email" }` → `{ challenge_id, publicKey:{challenge,…} }` (WebAuthn `get()`).

### POST /auth/passkey/login
`{ "challenge_id", "response": <PublicKeyCredential> }` → tokens de session.

### POST /auth/token/refresh
`{ "refresh_token" }` → nouveaux tokens (rotation).
⚠️ Réutilisation d'un refresh déjà consommé ⇒ **révocation immédiate de toutes les sessions** du compte.

### GET /health
`{ "status":"ok", "version":"0.1.0" }`

---

## Endpoints authentifiés

### POST /auth/mfa/enable
→ `{ otpauth_url, secret }` (scanner avec Google Authenticator/Authy…).

### POST /auth/passkey/register/options
→ `CreationChallengeResponse` WebAuthn (`navigator.credentials.create`).

### POST /auth/passkey/register
`{ "name": "MacBook", "response": <attestation> }` → `{ id, registered:true }`.

### GET /auth/me
→ `{ user:{id,email,role,email_verified,…}, scopes:[...], mfa_enabled, session_id }`.

### POST /auth/logout
Révoque la session courante + blackliste le jti du JWT.

### POST /auth/logout-all
Révoque toutes les sessions du compte.

### GET /auth/sessions
Liste des sessions (device, IP, pays, dates, flag `current`).

### DELETE /auth/sessions/{id}
Révoque une session précise (si elle appartient à l'utilisateur).

### POST /auth/change-password
`{ "current_password", "new_password" }` → les autres sessions sont révoquées.

### POST /auth/forgot-password
`{ "email" }` → toujours 200 ; lien reset (1 h) si le compte existe.

### POST /auth/reset-password
`{ "token", "new_password" }` → toutes les sessions révoquées.

### POST /auth/change-email
`{ "password", "new_email" }` → re-vérification requise sur la nouvelle adresse.

### DELETE /auth/account
`{ "password" }` → suppression soft + anonymisation email + révocation totale.

### GET /auth/csrf
Émet un cookie `csrf` (SameSite=Lax) + `{ csrf_token }`.
Les requêtes mutantes « navigateur » doivent renvoyer `X-CSRF-Token` identique.

---

## Scopes & rôles

| Rôle  | Scopes |
|-------|--------|
| user  | profile.read/write, sessions.manage, mfa.manage, passkeys.manage |
| admin | + users.read/write, ips.read/write, logs.read, sessions.admin, stats.read, config.read |
| owner | + users.delete, config.write |

Le rôle est attribué en base (`UPDATE users SET role='admin' WHERE id=...`).
Le premier utilisateur créé peut être promu owner manuellement.

---

## Endpoints admin

| Méthode | Route | Scope | Description |
|---------|-------|-------|-------------|
| GET    | /admin/users?q&limit&offset | users.read | liste paginée |
| DELETE | /admin/users/{id}           | users.delete (owner) | soft-delete |
| POST   | /admin/block-ip             | ips.write | `{ip, mode:blacklist\|whitelist, reason?, expires_in_minutes?}` |
| DELETE | /admin/block-ip/{ip}        | ips.write | retire l'entrée |
| GET    | /admin/blocked-ips          | ips.read  | liste de blocage |
| GET    | /admin/suspicious-ips       | ips.read  | agrégat échecs 24 h ≥ seuil |
| GET    | /admin/double-accounts      | ips.read  | groupes ≥ N comptes même IP |
| GET    | /admin/sessions             | sessions.admin | sessions actives |
| DELETE | /admin/sessions/{id}        | sessions.admin | révoque |
| GET    | /admin/logs?limit&offset    | logs.read | logs sécurité (détails déchiffrés) |
| GET    | /admin/stats/activity?days  | stats.read | séries journalières |
| GET    | /admin/overview             | stats.read | compteurs dashboard |
| GET/POST | /admin/config             | config.read/write | paramètres runtime |
