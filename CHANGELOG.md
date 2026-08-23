# Changelog

Toutes les évolutions notables de Secure-Login sont documentées ici.
Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
versionnement [SemVer](https://semver.org/lang/fr/).

---

## [1.0.0] — 2026-08-23

Première version stable. 🎉

### Authentification
- Inscription + vérification email (token usage unique, expiration 24 h)
- Connexion mot de passe (Argon2id + salt + pepper)
- Reset / changement de mot de passe, changement d'email, suppression de compte
- MFA TOTP (RFC 6238) + 8 codes de récupération à usage unique
- Passkeys WebAuthn (connexion sans mot de passe)

### Tokens & sessions
- JWT HS512 courts (15 min) avec `jti` blacklistable
- Refresh tokens opaques avec rotation automatique
- Détection anti-replay : réutilisation ⇒ révocation globale des sessions
- Device tracking, IP tracking, déconnexion par device et globale

### Sécurité réseau & anti-abus
- Blacklist / whitelist IP (expiration possible) appliquée en tête de requête
- Anti-bruteforce persistant : verrouillage exponentiel + captcha adaptatif
  (Turnstile / hCaptcha / reCAPTCHA)
- Détection d'IP suspectes (agrégat 24 h) et de doubles comptes sur même IP
- Géolocalisation approximative (ip-api.com, cache mémoire)
- Détection de connexions inhabituelles (nouveau pays / nouveau device)
- CSRF double-submit, CSP stricte, anti-XSS, SQL 100 % paramétré, corps ≤ 1 Mo

### API REST
- Endpoints `/auth/*` : register, verify-email, login (+MFA), mfa/enable,
  mfa/verify, passkey/register(/options), passkey/login(/options),
  token/refresh, logout, logout-all, me, sessions CRUD,
  change-password, forgot/reset-password, change-email, account (DELETE), csrf
- Endpoints `/admin/*` : users, block-ip, blocked-ips, suspicious-ips,
  double-accounts, sessions, logs, stats/activity, overview, config

### Plateforme
- Backend Rust / Axum / SQLx — PostgreSQL **et** SQLite (migrations embarquées)
- Feature flag `webauthn` (build sans dépendances C possible)
- Dashboard admin SPA (utilisateurs, sessions, sécurité, logs, graphiques, config runtime)
- SDKs officiels : JavaScript/TypeScript · Python · C# (.NET Standard 2.0) · Rust
- Dockerfile multi-stage + docker-compose (API + PostgreSQL)
- CI GitHub Actions : compilation backend, builds des 4 SDKs, tests SDK Rust
- Documentation : README, API, SECURITY, ARCHITECTURE (Mermaid), DEPLOYMENT,
  INTEGRATION (guide pas-à-pas débutant)

### Limitations connues (v1)
- Envoi SMTP réel non implémenté (mode console + point d'extension `mailer.rs`)
- Challenges WebAuthn / rate-limit / cache géoIP en mémoire (mono-instance)
- QR code MFA non rendu côté serveur (URL `otpauth://` fournie)
