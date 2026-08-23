# 🔐 Secure-Login

**Système d'authentification universel, ultra-sécurisé et intégrable dans n'importe quel projet.**

Backend **Rust / Axum / SQLx**, base **PostgreSQL ou SQLite**, MFA TOTP avec QR code,
Passkeys WebAuthn, JWT HS512 avec rotation de refresh tokens, anti-bruteforce,
détection d'IP suspectes, emails SMTP réels, mode multi-instances Redis,
dashboard admin complet et **SDKs JavaScript/TypeScript, Python, C# et Rust**.

> ⚠️ Par défaut le serveur démarre avec des secrets *dev*. Définissez
> `JWT_SECRET`, `ENCRYPTION_KEY` et `PASSWORD_PEPPER` avant toute utilisation réelle.

---

## 🎯 À quoi ça sert ?

Secure-Login s'installe **une seule fois** et prend en charge toute la partie
« comptes utilisateurs » de n'importe quel projet (site vitrine, boutique,
app web, API, jeu…). Concrètement, vous n'avez **plus jamais besoin de coder
un écran de connexion vous-même** :

- 📝 Inscription + email de vérification
- 🔑 Connexion par mot de passe (stocké de façon inviolable : Argon2id)
- 📲 Double authentification optionnelle (code à 6 chiffres type Google Authenticator, QR code fourni)
- 👆 Connexion par empreinte digitale / Face ID (Passkeys WebAuthn)
- 🛡️ Blocage automatique des attaques par force brute et des IP malveillantes
- ✉️ Emails transactionnels réels (SMTP) : vérification, reset, alertes
- 👮 Dashboard admin : utilisateurs, sessions actives, IP suspectes, logs, configuration

## ⚙️ Comment ça fonctionne ? (en 30 secondes)

```
Navigateur du visiteur          Votre site            Secure-Login (ce repo)
      │                            │                            │
      │── saisit email+mdp ───────▶│── POST /auth/login ───────▶│
      │                            │                            │ vérifie le mot de passe
      │◀─────── jetons ────────────│◀── access_token (15 min) ──│ crée une session
      │        (localStorage)      │     refresh_token (30 j)   │
      │                            │                            │
      │── visite page privée ─────▶│ GET /auth/me + jeton ─────▶│ dit qui c'est ✅/❌
```

1. Le serveur Secure-Login tourne à part (ex. `http://localhost:8080`) avec sa base.
2. Votre site appelle son API quand quelqu'un s'inscrit / se connecte.
3. L'API renvoie **deux jetons** : un court (15 min) qui prouve l'identité, et un
   long (30 jours) pour se reconnecter sans retaper le mot de passe.
4. Chaque page privée présente le jeton court ; expiré ? le long en obtient un
   nouveau automatiquement — l'utilisateur ne voit rien.

👉 **Guide d'intégration complet avec code copier-coller : [`docs/INTEGRATION.md`](docs/INTEGRATION.md)**

---

## Sommaire

1. [À quoi ça sert / Comment ça marche](#-à-quoi-ça-sert)
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
12. [Changelog](CHANGELOG.md)
13. [Crédits](#crédits)

---

## Installation rapide

### Docker Compose (le plus simple)

```bash
git clone https://github.com/secret-gaming01/Secure-login.git
cd Secure-login
cp .env.example .env    # renseignez vos secrets + OWNER_EMAIL
docker compose up -d --build
```

→ API : http://localhost:8080 · Dashboard : http://localhost:8080/dashboard/

Au premier démarrage, si `OWNER_EMAIL` est défini et la base vide, un compte
**owner** est créé automatiquement : le mot de passe temporaire s'affiche une
seule fois dans les logs (`docker compose logs api`).

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
Points clés :

| Variable | Rôle |
|---|---|
| `DATABASE_URL` | `postgres://…` ou `sqlite://…` |
| `JWT_SECRET` / `ENCRYPTION_KEY` / `PASSWORD_PEPPER` | secrets critiques |
| `EMAIL_MODE` | `console` (dev) ou `smtp` (+ `SMTP_HOST/PORT/USER/PASS`) |
| `OWNER_EMAIL` | bootstrap du premier owner (base vide uniquement) |
| `REDIS_URL` | acte le mode multi-instances (rate-limit + WebAuthn partagés) |
| `TRUST_PROXY` / `CORS_ORIGINS` | reverse-proxy & CORS production |

Détails : [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)

---

## API REST

Documentation complète : **[`docs/API.md`](docs/API.md)**

| Méthode | Endpoint | Description |
|---|---|---|
| POST | `/auth/register` | création de compte |
| POST | `/auth/verify-email` | vérification email |
| POST | `/auth/login` | connexion (+ challenge MFA) |
| POST | `/auth/mfa/enable` | init TOTP (otpauth URL) |
| GET  | `/auth/mfa/qrcode` | QR code SVG du secret en attente |
| POST | `/auth/mfa/verify` | active MFA / finalise login MFA |
| POST | `/auth/passkey/register/options` + `/auth/passkey/register` | enregistrement passkey |
| POST | `/auth/passkey/login/options` + `/auth/passkey/login` | connexion passkey |
| POST | `/auth/token/refresh` | rotation refresh token |
| POST | `/auth/logout`, `/auth/logout-all` | déconnexion |
| GET  | `/auth/me` | profil + scopes |
| GET/DELETE | `/auth/sessions[/{id}]` | gestion des devices |
| POST | `/auth/change-password` · `/auth/change-email` · `/auth/forgot-password` · `/auth/reset-password` | compte |
| DELETE | `/auth/account` | suppression de compte |
| POST | `/admin/users/{id}/reset-link` | récupération assistée (admin) |
| GET | `/admin/users` · `/admin/logs` · `/admin/stats/activity` · `/admin/config` | observabilité |
| POST/DELETE | `/admin/block-ip[/{ip}]` · `/admin/suspicious-ips` · `/admin/double-accounts` | sécurité réseau |

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

Exemples d'intégration supplémentaires : [`docs/INTEGRATION.md`](docs/INTEGRATION.md).

---

## Dashboard admin

Servi par l'API sur **`/dashboard/`** (SPA vanilla JS + Chart.js) :

- vue d'ensemble : compteurs + graphique d'activité (14 jours)
- utilisateurs : recherche, suppression, lien de récupération assistée
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
4. **Anti-bruteforce en profondeur** — rate-limit global par IP (fenêtre fixe
   mémoire ou Redis), verrouillage persistant exponentiel par email+IP,
   captcha adaptatif si configuré, égalisation de timing contre l'énumération.
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
                     CSRF, headers)                  audit, ipintel, mailer)
                                                       │
                                            Redis (optionnel, multi-instance)
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
├── docs/                 # API, SECURITY, ARCHITECTURE, DEPLOYMENT, INTEGRATION
├── tests/                # tests SDK + CI
├── docker-compose.yml    # API + PostgreSQL + Redis (optionnel)
├── Dockerfile
├── CHANGELOG.md
└── README.md
```

---

## Tests & CI

```bash
node tests/js/sdk.test.mjs          # smoke test SDK JS
python tests/python/test_sdk.py     # smoke test SDK Python
cd sdk/rust && cargo test           # tests SDK Rust
cd api && cargo check --all-targets # compilation backend (CI)
cd api && cargo check --no-default-features  # build sans webauthn/redis
```

GitHub Actions (`.github/workflows/ci.yml`) vérifie backend + les 4 SDKs à chaque push.

---

## Limitations — état v1.1.0

| Élément | Statut |
|---|---|
| Envoi SMTP réel | ✅ Implémenté (`lettre` + rustls). `EMAIL_MODE=smtp` + `SMTP_*`. Fallback console si indisponible. |
| Multi-instances | ✅ Store partagé mémoire/**Redis** (`REDIS_URL`) : rate-limit global + états WebAuthn. Fail-open documenté si Redis tombe. |
| QR code MFA serveur | ✅ `GET /auth/mfa/qrcode` (SVG, aucune dépendance C). |
| Récupération sans email | ✅ `POST /admin/users/{id}/reset-link` (lien 1 h, audit CRITICAL). |
| Compte owner initial | ✅ Bootstrap automatique via `OWNER_EMAIL` (base vide uniquement). |
| Compilation sur machine Windows verrouillée | ℹ️ Contrôle applicatif de l'environnement de génération (hors code) — validation continue par la CI Linux. |

---

## Crédits

- Conçu et développé par **secret-gaming01**
- Écosystème : [Axum](https://github.com/tokio-rs/axum), [SQLx](https://github.com/launchbadge/sqlx),
  [argon2](https://github.com/RustCrypto/password-hashes), [jsonwebtoken](https://github.com/Keats/jsonwebtoken),
  [webauthn-rs](https://github.com/kanidm/webauthn-rs), [aes-gcm](https://github.com/RustCrypto/AEADs),
  [lettre](https://github.com/lettre/lettre), [qrcodegen](https://github.com/nayuki/QR-Code-generator),
  [redis-rs](https://github.com/redis-rs/redis-rs), [Chart.js](https://www.chartjs.org)
- Licence : [MIT](LICENSE)



