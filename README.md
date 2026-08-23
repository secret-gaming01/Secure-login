# 🔐 Secure-Login

**Système d'authentification universel, ultra-sécurisé et intégrable dans n'importe quel projet.**

Backend **Rust / Axum / SQLx**, base **PostgreSQL ou SQLite**, MFA TOTP, Passkeys WebAuthn,
JWT HS512 avec rotation de refresh tokens, anti-bruteforce, détection d'IP suspectes,
dashboard admin complet et **SDKs JavaScript/TypeScript, Python, C# et Rust**.

> ⚠️ Par défaut le serveur démarre avec des secrets *dev*. Définissez
> `JWT_SECRET`, `ENCRYPTION_KEY` et `PASSWORD_PEPPER` avant toute utilisation réelle.

---

## Sommaire

1. [Fonctionnalités](#fonctionnalités)
2. [Installation rapide](#installation-rapide)
3. [Configuration](#configuration)
4. [API REST](#api-rest)
5. [SDKs](#sdks)
6. [Exemples d'intégration](#exemples-dintégration)
7. [Dashboard admin](#dashboard-admin)
8. [Sécurité expliquée](#sécurité-expliquée)
9. [Architecture & schémas](#architecture--schémas)
10. [Structure du repo](#structure-du-repo)
11. [Tests & CI](#tests--ci)
12. [Crédits](#crédits)

---

## Fonctionnalités

### Authentification
- ✅ Création de compte + vérification email (token à usage unique, exp. 24 h)
- ✅ Reset de mot de passe sécurisé (token hashé HMAC, 1 h)
- ✅ Suppression de compte (soft-delete + anonymisation)
- ✅ Modification email + mot de passe (avec révocation des sessions)

### Sécurité avancée
- ✅ Argon2id + salt unique + **pepper globale** (jamais en base)
- ✅ MFA / 2FA TOTP (RFC 6238) + **8 codes de récupération** à usage unique
- ✅ **Passkeys WebAuthn** (connexion sans mot de passe, FIDO2)
- ✅ Détection d'IP suspectes (agrégat des échecs 24 h)
- ✅ Détection de doubles comptes sur une même IP
- ✅ Blacklist / whitelist IP (expiration possible)
- ✅ Anti-bruteforce : limite de tentatives + cooldown exponentiel + captcha adaptatif
- ✅ Géolocalisation approximative des IP (ip-api.com, cache 1 h)
- ✅ Détection de connexions inhabituelles (nouveau pays / nouveau device)

### Chiffrement & réseau
- ✅ AES-256-GCM au repos : secrets TOTP, codes de récupération, passkeys, logs sensibles
- ✅ Tokens sensibles stockés uniquement en HMAC-SHA256(pepper)
- ✅ Sessions chiffrées côté transport (HTTPS) + refresh jamais stocké en clair
- ✅ Protection anti-replay : rotation + détection de réutilisation
- ✅ CSRF double-submit pour les navigateurs
- ✅ XSS : CSP stricte + sanitisation + échappement dashboard
- ✅ SQL injection : requêtes 100 % paramétrées (sqlx)

### Tokens & sessions
- ✅ JWT HS512 courts (15 min) avec `jti` blacklistable
- ✅ Refresh tokens opaques avec **rotation automatique**
- ✅ Blacklist persistante des tokens compromis (`revoked_jti`)
- ✅ Device tracking + IP tracking par session
- ✅ Déconnexion globale (`logout-all`) et par device

### Permissions
- ✅ Rôles `user` / `admin` / `owner`
- ✅ Scopes granulaires (`users.read`, `ips.write`, …)
- ✅ Vérification simple côté API + middleware

---

## Installation rapide

### Docker Compose (le plus simple)

```bash
git clone https://github.com/secret-gaming01/Secure-login.git
cd Secure-login
cp .env.example .env    # renseignez vos secrets
docker compose up -d --build
```

→ API : http://localhost:8080 · Dashboard : http://localhost:8080/dashboard/

### Manuel (Rust stable requis)

```bash
cd api
DATABASE_URL=sqlite://./secure-login.db \
JWT_SECRET=$(openssl rand -hex 32) \
ENCRYPTION_KEY=$(openssl rand -hex 32) \
PASSWORD_PEPPER=$(openssl rand -hex 24) \
cargo run --release
```

Les migrations PostgreSQL **et** SQLite sont embarquées et appliquées au démarrage.

---

## Configuration

Toutes les variables sont documentées dans [`.env.example`](.env.example).
Détails de déploiement production (nginx, HTTPS, création du premier owner,
branchement SMTP) : [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

Secrets critiques :

| Variable | Rôle |
|---|---|
| `JWT_SECRET` | signature des JWT (HS512) |
| `ENCRYPTION_KEY` | chiffrement AES-256-GCM au repos |
| `PASSWORD_PEPPER` | pepper ajoutée avant Argon2id |

---

## API REST

Documentation complète : **[`docs/API.md`](docs/API.md)**

| Méthode | Endpoint | Description |
|---|---|---|
| POST | `/auth/register` | création de compte |
| POST | `/auth/verify-email` | vérification email |
| POST | `/auth/login` | connexion (+ challenge MFA) |
| POST | `/auth/mfa/enable` | init TOTP (otpauth URL) |
| POST | `/auth/mfa/verify` | active MFA / finalise login MFA |
| POST | `/auth/passkey/register/options` + `/auth/passkey/register` | enregistrement passkey |
| POST | `/auth/passkey/login/options` + `/auth/passkey/login` | connexion passkey |
| POST | `/auth/token/refresh` | rotation refresh token |
| POST | `/auth/logout`, `/auth/logout-all` | déconnexion |
| GET  | `/auth/me` | profil + scopes |
| GET/DELETE | `/auth/sessions[/{id}]` | gestion des devices |
| POST | `/auth/change-password` · `/auth/change-email` · `/auth/forgot-password` · `/auth/reset-password` | compte |
| DELETE | `/auth/account` | suppression de compte |
| GET | `/admin/users` | liste utilisateurs |
| POST/DELETE | `/admin/block-ip[/{ip}]` | blacklist/whitelist IP |
| GET | `/admin/suspicious-ips` | IP suspectes (24 h) |
| GET | `/admin/double-accounts` | multi-comptes par IP |
| GET | `/admin/logs` · `/admin/stats/activity` · `/admin/config` | observabilité |

---

## SDKs

Chaque SDK expose : `login()`, `logout()`, `register()`, `refreshToken()`,
`getCurrentUser()`, `checkPermission()` (+ bonus MFA/passkeys/admin).

### JavaScript / TypeScript (`sdk/js`)
```ts
import { SecureAuthClient } from "@secure-login/sdk";
const auth = new SecureAuthClient("https://auth.exemple.com");
await auth.register("user@ex.com", "Str0ngPassw0rd!");
const r = await auth.login("user@ex.com", "Str0ngPassw0rd!");
if (r.mfa_required) await auth.loginMfa(r.mfa_token, "123456");
await auth.refreshToken();
console.log(await auth.getCurrentUser());
if (await auth.checkPermission("users.read")) { /* … */ }
await auth.logout();
```
Build : `npm install && npm run build`

### Python (`sdk/python`)
```python
from secure_auth import SecureAuthClient
auth = SecureAuthClient("https://auth.exemple.com")
r = auth.login("user@ex.com", "Str0ngPassw0rd!")
if r.get("mfa_required"):
    r = auth.login_mfa(r["mfa_token"], "123456")
auth.refresh_token()
print(auth.get_current_user())
assert auth.check_permission("profile.read")
```

### C# (`sdk/csharp`)
```csharp
var auth = new SecureLogin.SecureAuthClient("https://auth.exemple.com");
var r = await auth.Login("user@ex.com", "Str0ngPassw0rd!");
// si mfa_required → await auth.LoginMfa(mfaToken, code);
await auth.RefreshToken();
var me = await auth.GetCurrentUser();
bool ok = await auth.CheckPermission("profile.read");
```

### Rust (`sdk/rust`)
```rust,ignore
let auth = SecureAuthClient::new("https://auth.exemple.com");
let r = auth.login("user@ex.com", "Str0ngPassw0rd!").await?;
if r["mfa_required"] == json!(true) {
    auth.login_mfa(r["mfa_token"].as_str().unwrap(), "123456").await?;
}
let me = auth.get_current_user().await?;
```

Exemples d'intégration supplémentaires : [`docs/API.md`](docs/API.md).

---

## Dashboard admin

Servi par l'API sur **`/dashboard/`** (SPA vanilla JS + Chart.js) :

- vue d'ensemble : compteurs + graphique d'activité (14 jours)
- utilisateurs : recherche, suppression
- sessions actives : device, IP, pays, révocation
- sécurité : blocage IP (blacklist/whitelist), IP suspectes, doubles comptes
- logs de sécurité avec détails déchiffrés
- page configuration : seuils runtime modifiables à chaud

Connexion avec un compte `admin`/`owner` (MFA supporté).

---

## Sécurité expliquée

Détail complet (modèle de menaces, rotation des clés, checklist prod) :
[`docs/SECURITY.md`](docs/SECURITY.md).

**Pourquoi c'est solide :**

1. **Mots de passe** — Argon2id (vainqueur du Password Hashing Competition) avec
   salt unique par utilisateur. La *pepper* globale est concaténée avant hash et
   vit uniquement dans l'environnement : une base volée seule est inexploitable.
2. **Chiffrement au repos** — tout ce qui est réutilisable par un attaquant
   (secret TOTP, codes de récupération, credentials WebAuthn, détails de logs)
   est chiffré AES-256-GCM (authentifié) avec une clé dérivée de `ENCRYPTION_KEY`.
3. **Tokens à épreuve de rejeu** — access JWT 15 min signés HS512 ; chaque
   refresh token n'est utilisé qu'**une fois** (rotation). Sa réutilisation est
   une preuve de compromission ⇒ toutes les sessions sont révoquées immédiatement.
4. **Anti-bruteforce en profondeur** — rate-limit global par IP (fenêtre glissante),
   verrouillage persistant exponentiel par email+IP, captcha adaptatif si configuré,
   égalisation de timing contre l'énumération d'emails.
5. **Renseignement réseau** — blacklist/whitelist IP appliquée en tête de requête,
   agrégation des échecs pour repérer les IP suspectes, détection multi-comptes,
   alertes sur pays/device inédits.
6. **Défenses web standard** — CSRF double-submit, CSP stricte, nosniff, DENY iframe,
   SQL 100 % paramétré, corps limités à 1 Mo.

---

## Architecture & schémas

Diagrammes Mermaid complets (composants, ER, séquences login/MFA/refresh/passkey) :
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

```
Clients ──HTTPS──▶ Middlewares ──▶ Routes ──▶ Services ──▶ PostgreSQL/SQLite
                    (IP firewall,      (auth,       (users, sessions,
                     rate-limit,        admin)       tokens, mfa, passkeys,
                     CSRF, headers)                  audit, ipintel)
```

8 tables métier : `users`, `sessions`, `tokens`, `blocked_ips`, `passkeys`,
`mfa`, `security_logs`, `login_attempts` (+ `revoked_jti` anti-replay).

---

## Structure du repo

```
Secure-login/
├── api/                  # Backend Rust / Axum / SQLx
│   ├── src/              #   config, crypto, db, middlewares, routes, services
│   └── migrations/       #   postgres/ et sqlite/
├── sdk/
│   ├── js/               # TypeScript (fetch)
│   ├── python/           # Python (urllib stdlib)
│   ├── csharp/           # .NET Standard 2.0
│   └── rust/             # crate reqwest
├── dashboard/            # SPA admin (HTML/CSS/JS + Chart.js)
├── docs/                 # API, sécurité, architecture, déploiement
├── tests/                # tests SDK + CI
├── docker-compose.yml    # API + PostgreSQL
├── Dockerfile
└── README.md
```

---

## Tests & CI

```bash
node tests/js/sdk.test.mjs          # smoke test SDK JS
python tests/python/test_sdk.py     # smoke test SDK Python
cd sdk/rust && cargo test           # tests SDK Rust
cd api && cargo check --all-targets # compilation backend (CI)
cd sdk/js && npx tsc --noEmit       # typage SDK JS (CI)
```

GitHub Actions (`.github/workflows/ci.yml`) vérifie backend + les 4 SDKs à chaque push.

---

## Crédits

- Conçu et développé par **secret-gaming01**
- Écosystème : [Axum](https://github.com/tokio-rs/axum), [SQLx](https://github.com/launchbadge/sqlx),
  [argon2](https://github.com/RustCrypto/password-hashes), [jsonwebtoken](https://github.com/Keats/jsonwebtoken),
  [webauthn-rs](https://github.com/kanidm/webauthn-rs), [aes-gcm](https://github.com/RustCrypto/AEADs),
  [Chart.js](https://www.chartjs.org)
- Licence : [MIT](LICENSE)

## ⚠️ Limitations connues (transparence)

| Élément | État | Pourquoi |
|---|---|---|
| Envoi SMTP réel | Non implémenté | nécessite identifiants SMTP/provider ; mode console + point d'extension fournis (`services/mailer.rs`) |
| Vérification locale `cargo` | Non exécutée sur la machine de génération | toolchain Rust absente ; CI GitHub compile le backend (`cargo check`) |
| Challenges WebAuthn | En mémoire (10 min) | store partagé (Redis) requis pour un déploiement multi-instances |
| Rate limit & cache géoIP | En mémoire | idem multi-instances ; interface simple à remplacer |
| QR code MFA | Non rendu serveur | l'URL `otpauth://` est fournie ; le client affiche le QR (dashboard/lib externe) |
| Récupération de compte sans email | Hors périmètre | dépend du SMTP réel ; les codes de récupération MFA couvrent la perte du 2FA |


