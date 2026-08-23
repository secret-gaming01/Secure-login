# Sécurité — Secure-Login

## Modèle de menaces couvert

| Menace | Contre-mesure |
|---|---|
| Fuite de la base | Argon2id + pepper (hors DB), secrets TOTP/passkeys/logs chiffrés AES-256-GCM |
| Crack de mots de passe | Argon2id v19 (m≈19 MiB, t=2, p=1), salt unique, politique ≥10 car / 3 classes |
| Vol d'access token | TTL 15 min, jti blacklistable, HS512 sur secret ≥ 64 chars |
| Vol/rejeu du refresh token | Rotation à chaque usage + détection de réutilisation → révocation globale immédiate |
| Bruteforce login | Compteur persistant (15 min), verrouillage exponentiel (base ×2ⁿ, cap 24 h), captcha adaptatif si configuré |
| Énumération d'emails | Réponses génériques + égalisation de timing (hash factice) |
| IP malveillantes | Blacklist/whitelist en base avec expiration, contrôle à chaque requête |
| Multi-comptes | Agrégation `last_login_ip` exposée aux admins (`/admin/double-accounts`) |
| Connexions inhabituelles | Comparaison pays/device vs historique sessions → événements `unusual_login_*` |
| CSRF | Double-submit cookie : cookie `csrf` + header `X-CSRF-Token` obligatoire pour les requêtes navigateur mutantes (présence d'Origin/Referer) |
| XSS | CSP stricte, JSON uniquement, sanitisation des chaînes stockées, dashboard échappé |
| SQL injection | Requêtes 100 % paramétrées (sqlx), zéro concaténation utilisateur |
| Clickjacking | X-Frame-Options: DENY + frame-ancestors 'none' |
| Sniffing de contenu | X-Content-Type-Options: nosniff |

## Secrets & clés

| Secret | Usage | Stockage recommandé |
|---|---|---|
| `JWT_SECRET` | signature HS512 | secret manager / env |
| `ENCRYPTION_KEY` | AES-256-GCM (TOTP, passkeys, logs) | secret manager |
| `PASSWORD_PEPPER` | ajouté avant hash Argon2id | **jamais** en base ; HSM/KMS idéalement |

Rotation : changer `JWT_SECRET` invalide tous les access tokens (re-login) ;
changer `ENCRYPTION_KEY` rend les données chiffrées irrécupérables — procédure de
re-chiffrement à prévoir avant rotation.

## Tokens

```
access  = JWT HS512 {sub, sid, role, scopes[], jti, typ:"access"} exp 900s
mfa     = JWT HS512 {typ:"mfa"} exp 300s   (finalisation de connexion seulement)
refresh = 48 octets aléatoires (hex) — stocké UNIQUEMENT en HMAC-SHA256(pepper)
```

- Logout / logout-all ⇒ blacklist du `jti` + révocation de session.
- Chaque `/auth/token/refresh` consomme l'ancien refresh (trace `refresh_rotated`)
  et en émet un nouveau lié à la même session.
- Si un refresh déjà tourné réapparaît ⇒ compromission supposée :
  toutes les sessions sont révoquées et l'événement est loggé `critical`.

## Passkeys (WebAuthn)

- Attestation/assertion vérifiées par `webauthn-rs` (origin + RP ID stricts).
- Le credential sérialisé (clé publique, compteur) est chiffré au repos.
- Les challenges sont gardés 10 min max en mémoire.

## Limites connues (voir README)

- Envoi SMTP réel non implémenté (mode console).
- Challenges WebAuthn en mémoire : store partagé requis en multi-instance.
- Rate limit global en mémoire (par instance).

## Checklist de déploiement production

- [ ] `JWT_SECRET`, `ENCRYPTION_KEY`, `PASSWORD_PEPPER` forts et uniques
- [ ] HTTPS obligatoire devant l'API (HSTS côté reverse-proxy)
- [ ] `TRUST_PROXY=true` derrière nginx/traefik + purge des headers entrants
- [ ] `CORS_ORIGINS` explicite (pas de `*`)
- [ ] Captcha configuré (Turnstile/hCaptcha)
- [ ] Sauvegardes chiffrées de la base + test de restauration
- [ ] Supervision des logs `security_logs` severity=critical
