# ðŸ” Secure-Login

**SystÃ¨me d'authentification universel, ultra-sÃ©curisÃ© et intÃ©grable dans n'importe quel projet.**

Backend **Rust / Axum / SQLx**, base **PostgreSQL ou SQLite**, MFA TOTP, Passkeys WebAuthn,
JWT HS512 avec rotation de refresh tokens, anti-bruteforce, dÃ©tection d'IP suspectes,
dashboard admin complet et **SDKs JavaScript/TypeScript, Python, C# et Rust**.

> âš ï¸ Par dÃ©faut le serveur dÃ©marre avec des secrets *dev*. DÃ©finissez
> `JWT_SECRET`, `ENCRYPTION_KEY` et `PASSWORD_PEPPER` avant toute utilisation rÃ©elle.

---

## ðŸŽ¯ Ã€ quoi Ã§a sert ?

Secure-Login s'installe **une seule fois** et prend en charge toute la partie
Â« comptes utilisateurs Â» de n'importe quel projet (site vitrine, boutique,
app web, API, jeuâ€¦). ConcrÃ¨tement, vous n'avez **plus jamais besoin de coder
un Ã©cran de connexion vous-mÃªme** :

- ðŸ“ Inscription + email de vÃ©rification
- ðŸ”‘ Connexion par mot de passe (stockÃ© de faÃ§on inviolable : Argon2id)
- ðŸ“² Double authentification optionnelle (code Ã  6 chiffres type Google Authenticator)
- ðŸ‘† Connexion par empreinte digitale / Face ID (Passkeys WebAuthn)
- ðŸ›¡ï¸ Blocage automatique des attaques par force brute et des IP malveillantes
- ðŸ‘® Dashboard admin : voir les utilisateurs, leurs sessions, bloquer, supprimer

## âš™ï¸ Comment Ã§a fonctionne ? (en 30 secondes)

```
Navigateur du visiteur          Votre site            Secure-Login (ce repo)
      â”‚                            â”‚                            â”‚
      â”‚â”€â”€ saisit email+mdp â”€â”€â”€â”€â”€â”€â”€â–¶â”‚â”€â”€ POST /auth/login â”€â”€â”€â”€â”€â”€â”€â–¶â”‚
      â”‚                            â”‚                            â”‚ vÃ©rifie le mot de passe
      â”‚â—€â”€â”€â”€â”€â”€â”€â”€ jetons â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”‚â—€â”€â”€ access_token (15 min) â”€â”€â”‚ crÃ©e une session
      â”‚        (localStorage)      â”‚     refresh_token (30 j)   â”‚
      â”‚                            â”‚                            â”‚
      â”‚â”€â”€ visite page privÃ©e â”€â”€â”€â”€â”€â–¶â”‚ GET /auth/me + jeton â”€â”€â”€â”€â”€â–¶â”‚ dit qui c'est âœ…/âŒ
```

1. Le serveur Secure-Login tourne Ã  part (ex. `http://localhost:8080`) avec sa base.
2. Votre site appelle son API quand quelqu'un s'inscrit / se connecte.
3. L'API renvoie **deux jetons** : un court (15 min) qui prouve l'identitÃ©, et un
   long (30 jours) pour se reconnecter sans retaper le mot de passe.
4. Chaque page privÃ©e prÃ©sente le jeton court ; expirÃ© ? le long en obtient un
   nouveau automatiquement â€” l'utilisateur ne voit rien.

ðŸ‘‰ **Guide d'intÃ©gration complet avec code copier-coller : [`docs/INTEGRATION.md`](docs/INTEGRATION.md)**

---

## Sommaire

1. [Ã€ quoi Ã§a sert / Comment Ã§a marche](#-Ã -quoi-Ã§a-sert)
2. [Installation rapide](#installation-rapide)
3. [Configuration](#configuration)
4. [API REST](#api-rest)
5. [SDKs](#sdks)
6. [Exemples d'intÃ©gration](#exemples-dintÃ©gration)
7. [Dashboard admin](#dashboard-admin)
8. [SÃ©curitÃ© expliquÃ©e](#sÃ©curitÃ©-expliquÃ©e)
9. [Architecture & schÃ©mas](#architecture--schÃ©mas)
10. [Structure du repo](#structure-du-repo)
11. [Tests & CI](#tests--ci)
12. [CrÃ©dits](#crÃ©dits)

---

## FonctionnalitÃ©s

### Authentification
- âœ… CrÃ©ation de compte + vÃ©rification email (token Ã  usage unique, exp. 24 h)
- âœ… Reset de mot de passe sÃ©curisÃ© (token hashÃ© HMAC, 1 h)
- âœ… Suppression de compte (soft-delete + anonymisation)
- âœ… Modification email + mot de passe (avec rÃ©vocation des sessions)

### SÃ©curitÃ© avancÃ©e
- âœ… Argon2id + salt unique + **pepper globale** (jamais en base)
- âœ… MFA / 2FA TOTP (RFC 6238) + **8 codes de rÃ©cupÃ©ration** Ã  usage unique
- âœ… **Passkeys WebAuthn** (connexion sans mot de passe, FIDO2)
- âœ… DÃ©tection d'IP suspectes (agrÃ©gat des Ã©checs 24 h)
- âœ… DÃ©tection de doubles comptes sur une mÃªme IP
- âœ… Blacklist / whitelist IP (expiration possible)
- âœ… Anti-bruteforce : limite de tentatives + cooldown exponentiel + captcha adaptatif
- âœ… GÃ©olocalisation approximative des IP (ip-api.com, cache 1 h)
- âœ… DÃ©tection de connexions inhabituelles (nouveau pays / nouveau device)

### Chiffrement & rÃ©seau
- âœ… AES-256-GCM au repos : secrets TOTP, codes de rÃ©cupÃ©ration, passkeys, logs sensibles
- âœ… Tokens sensibles stockÃ©s uniquement en HMAC-SHA256(pepper)
- âœ… Sessions chiffrÃ©es cÃ´tÃ© transport (HTTPS) + refresh jamais stockÃ© en clair
- âœ… Protection anti-replay : rotation + dÃ©tection de rÃ©utilisation
- âœ… CSRF double-submit pour les navigateurs
- âœ… XSS : CSP stricte + sanitisation + Ã©chappement dashboard
- âœ… SQL injection : requÃªtes 100 % paramÃ©trÃ©es (sqlx)

### Tokens & sessions
- âœ… JWT HS512 courts (15 min) avec `jti` blacklistable
- âœ… Refresh tokens opaques avec **rotation automatique**
- âœ… Blacklist persistante des tokens compromis (`revoked_jti`)
- âœ… Device tracking + IP tracking par session
- âœ… DÃ©connexion globale (`logout-all`) et par device

### Permissions
- âœ… RÃ´les `user` / `admin` / `owner`
- âœ… Scopes granulaires (`users.read`, `ips.write`, â€¦)
- âœ… VÃ©rification simple cÃ´tÃ© API + middleware

---

## Installation rapide

### Docker Compose (le plus simple)

```bash
git clone https://github.com/secret-gaming01/Secure-login.git
cd Secure-login
cp .env.example .env    # renseignez vos secrets
docker compose up -d --build
```

â†’ API : http://localhost:8080 Â· Dashboard : http://localhost:8080/dashboard/

### Manuel (Rust stable requis)

```bash
cd api
DATABASE_URL=sqlite://./secure-login.db \
JWT_SECRET=$(openssl rand -hex 32) \
ENCRYPTION_KEY=$(openssl rand -hex 32) \
PASSWORD_PEPPER=$(openssl rand -hex 24) \
cargo run --release
```

Les migrations PostgreSQL **et** SQLite sont embarquÃ©es et appliquÃ©es au dÃ©marrage.

---

## Configuration

Toutes les variables sont documentÃ©es dans [`.env.example`](.env.example).
DÃ©tails de dÃ©ploiement production (nginx, HTTPS, crÃ©ation du premier owner,
branchement SMTP) : [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

Secrets critiques :

| Variable | RÃ´le |
|---|---|
| `JWT_SECRET` | signature des JWT (HS512) |
| `ENCRYPTION_KEY` | chiffrement AES-256-GCM au repos |
| `PASSWORD_PEPPER` | pepper ajoutÃ©e avant Argon2id |

---

## API REST

Documentation complÃ¨te : **[`docs/API.md`](docs/API.md)**

| MÃ©thode | Endpoint | Description |
|---|---|---|
| POST | `/auth/register` | crÃ©ation de compte |
| POST | `/auth/verify-email` | vÃ©rification email |
| POST | `/auth/login` | connexion (+ challenge MFA) |
| POST | `/auth/mfa/enable` | init TOTP (otpauth URL) |
| POST | `/auth/mfa/verify` | active MFA / finalise login MFA |
| POST | `/auth/passkey/register/options` + `/auth/passkey/register` | enregistrement passkey |
| POST | `/auth/passkey/login/options` + `/auth/passkey/login` | connexion passkey |
| POST | `/auth/token/refresh` | rotation refresh token |
| POST | `/auth/logout`, `/auth/logout-all` | dÃ©connexion |
| GET  | `/auth/me` | profil + scopes |
| GET/DELETE | `/auth/sessions[/{id}]` | gestion des devices |
| POST | `/auth/change-password` Â· `/auth/change-email` Â· `/auth/forgot-password` Â· `/auth/reset-password` | compte |
| DELETE | `/auth/account` | suppression de compte |
| GET | `/admin/users` | liste utilisateurs |
| POST/DELETE | `/admin/block-ip[/{ip}]` | blacklist/whitelist IP |
| GET | `/admin/suspicious-ips` | IP suspectes (24 h) |
| GET | `/admin/double-accounts` | multi-comptes par IP |
| GET | `/admin/logs` Â· `/admin/stats/activity` Â· `/admin/config` | observabilitÃ© |

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
if (await auth.checkPermission("users.read")) { /* â€¦ */ }
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
// si mfa_required â†’ await auth.LoginMfa(mfaToken, code);
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

Exemples d'intÃ©gration supplÃ©mentaires : [`docs/API.md`](docs/API.md).

---

## Dashboard admin

Servi par l'API sur **`/dashboard/`** (SPA vanilla JS + Chart.js) :

- vue d'ensemble : compteurs + graphique d'activitÃ© (14 jours)
- utilisateurs : recherche, suppression
- sessions actives : device, IP, pays, rÃ©vocation
- sÃ©curitÃ© : blocage IP (blacklist/whitelist), IP suspectes, doubles comptes
- logs de sÃ©curitÃ© avec dÃ©tails dÃ©chiffrÃ©s
- page configuration : seuils runtime modifiables Ã  chaud

Connexion avec un compte `admin`/`owner` (MFA supportÃ©).

---

## SÃ©curitÃ© expliquÃ©e

DÃ©tail complet (modÃ¨le de menaces, rotation des clÃ©s, checklist prod) :
[`docs/SECURITY.md`](docs/SECURITY.md).

**Pourquoi c'est solide :**

1. **Mots de passe** â€” Argon2id (vainqueur du Password Hashing Competition) avec
   salt unique par utilisateur. La *pepper* globale est concatÃ©nÃ©e avant hash et
   vit uniquement dans l'environnement : une base volÃ©e seule est inexploitable.
2. **Chiffrement au repos** â€” tout ce qui est rÃ©utilisable par un attaquant
   (secret TOTP, codes de rÃ©cupÃ©ration, credentials WebAuthn, dÃ©tails de logs)
   est chiffrÃ© AES-256-GCM (authentifiÃ©) avec une clÃ© dÃ©rivÃ©e de `ENCRYPTION_KEY`.
3. **Tokens Ã  Ã©preuve de rejeu** â€” access JWT 15 min signÃ©s HS512 ; chaque
   refresh token n'est utilisÃ© qu'**une fois** (rotation). Sa rÃ©utilisation est
   une preuve de compromission â‡’ toutes les sessions sont rÃ©voquÃ©es immÃ©diatement.
4. **Anti-bruteforce en profondeur** â€” rate-limit global par IP (fenÃªtre glissante),
   verrouillage persistant exponentiel par email+IP, captcha adaptatif si configurÃ©,
   Ã©galisation de timing contre l'Ã©numÃ©ration d'emails.
5. **Renseignement rÃ©seau** â€” blacklist/whitelist IP appliquÃ©e en tÃªte de requÃªte,
   agrÃ©gation des Ã©checs pour repÃ©rer les IP suspectes, dÃ©tection multi-comptes,
   alertes sur pays/device inÃ©dits.
6. **DÃ©fenses web standard** â€” CSRF double-submit, CSP stricte, nosniff, DENY iframe,
   SQL 100 % paramÃ©trÃ©, corps limitÃ©s Ã  1 Mo.

---

## Architecture & schÃ©mas

Diagrammes Mermaid complets (composants, ER, sÃ©quences login/MFA/refresh/passkey) :
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

```
Clients â”€â”€HTTPSâ”€â”€â–¶ Middlewares â”€â”€â–¶ Routes â”€â”€â–¶ Services â”€â”€â–¶ PostgreSQL/SQLite
                    (IP firewall,      (auth,       (users, sessions,
                     rate-limit,        admin)       tokens, mfa, passkeys,
                     CSRF, headers)                  audit, ipintel)
```

8 tables mÃ©tier : `users`, `sessions`, `tokens`, `blocked_ips`, `passkeys`,
`mfa`, `security_logs`, `login_attempts` (+ `revoked_jti` anti-replay).

---

## Structure du repo

```
Secure-login/
â”œâ”€â”€ api/                  # Backend Rust / Axum / SQLx
â”‚   â”œâ”€â”€ src/              #   config, crypto, db, middlewares, routes, services
â”‚   â””â”€â”€ migrations/       #   postgres/ et sqlite/
â”œâ”€â”€ sdk/
â”‚   â”œâ”€â”€ js/               # TypeScript (fetch)
â”‚   â”œâ”€â”€ python/           # Python (urllib stdlib)
â”‚   â”œâ”€â”€ csharp/           # .NET Standard 2.0
â”‚   â””â”€â”€ rust/             # crate reqwest
â”œâ”€â”€ dashboard/            # SPA admin (HTML/CSS/JS + Chart.js)
â”œâ”€â”€ docs/                 # API, sÃ©curitÃ©, architecture, dÃ©ploiement
â”œâ”€â”€ tests/                # tests SDK + CI
â”œâ”€â”€ docker-compose.yml    # API + PostgreSQL
â”œâ”€â”€ Dockerfile
â””â”€â”€ README.md
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

GitHub Actions (`.github/workflows/ci.yml`) vÃ©rifie backend + les 4 SDKs Ã  chaque push.

---

## CrÃ©dits

- ConÃ§u et dÃ©veloppÃ© par **secret-gaming01**
- Ã‰cosystÃ¨me : [Axum](https://github.com/tokio-rs/axum), [SQLx](https://github.com/launchbadge/sqlx),
  [argon2](https://github.com/RustCrypto/password-hashes), [jsonwebtoken](https://github.com/Keats/jsonwebtoken),
  [webauthn-rs](https://github.com/kanidm/webauthn-rs), [aes-gcm](https://github.com/RustCrypto/AEADs),
  [Chart.js](https://www.chartjs.org)
- Licence : [MIT](LICENSE)

## âš ï¸ Limitations connues (transparence)

| Ã‰lÃ©ment | Ã‰tat | Pourquoi |
|---|---|---|
| Envoi SMTP rÃ©el | Non implÃ©mentÃ© | nÃ©cessite identifiants SMTP/provider ; mode console + point d'extension fournis (`services/mailer.rs`) |
| VÃ©rification locale `cargo` | Non exÃ©cutÃ©e sur la machine de gÃ©nÃ©ration | toolchain Rust absente ; CI GitHub compile le backend (`cargo check`) |
| Challenges WebAuthn | En mÃ©moire (10 min) | store partagÃ© (Redis) requis pour un dÃ©ploiement multi-instances |
| Rate limit & cache gÃ©oIP | En mÃ©moire | idem multi-instances ; interface simple Ã  remplacer |
| QR code MFA | Non rendu serveur | l'URL `otpauth://` est fournie ; le client affiche le QR (dashboard/lib externe) |
| RÃ©cupÃ©ration de compte sans email | Hors pÃ©rimÃ¨tre | dÃ©pend du SMTP rÃ©el ; les codes de rÃ©cupÃ©ration MFA couvrent la perte du 2FA |


