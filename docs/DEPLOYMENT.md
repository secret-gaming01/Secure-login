# Déploiement — Secure-Login

## Option 1 : Docker Compose (recommandé)

```bash
git clone https://github.com/secret-gaming01/Secure-login.git
cd Secure-login
cp .env.example .env        # renseigner les secrets !
docker compose up -d --build
```

- API : http://localhost:8080
- Dashboard : http://localhost:8080/dashboard/
- PostgreSQL exposé sur 5432 (à désactiver en prod derrière un réseau privé).

## Option 2 : binaire natif

```bash
# Prérequis : Rust stable, PostgreSQL (ou rien pour SQLite)
cd api
export DATABASE_URL="postgres://user:pass@localhost:5432/secure_login"
export JWT_SECRET="$(openssl rand -hex 32)"
export ENCRYPTION_KEY="$(openssl rand -hex 32)"
export PASSWORD_PEPPER="$(openssl rand -hex 24)"
cargo run --release
```

SQLite (dev / embarqué) :
```bash
DATABASE_URL=sqlite://./secure-login.db cargo run --release
```

Les migrations sont embarquées dans le binaire et appliquées au démarrage.

## Variables d'environnement

Voir `.env.example` (commenté intégralement). Les plus critiques :

| Variable | Rôle |
|---|---|
| DATABASE_URL | `postgres://…` ou `sqlite://…` |
| JWT_SECRET | signature HS512 (≥64 chars) |
| ENCRYPTION_KEY | chiffrement au repos AES-256-GCM |
| PASSWORD_PEPPER | pepper Argon2id (hors base) |
| TRUST_PROXY | `true` derrière reverse-proxy |
| CORS_ORIGINS | liste explicite en prod |

## Reverse-proxy nginx (exemple)

```nginx
server {
    listen 443 ssl http2;
    server_name auth.exemple.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;
    }
    add_header Strict-Transport-Security "max-age=63072000" always;
}
```
Avec `TRUST_PROXY=true`, l'API lira `X-Forwarded-For`.

## Créer le premier admin

```bash
# 1) s'inscrire via l'API ou le dashboard
curl -X POST localhost:8080/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"owner@exemple.com","password":"Str0ngPassw0rd!"}'
# 2) vérifier l'email (lien affiché en console si EMAIL_MODE=console)
# 3) promouvoir :
docker compose exec db psql -U secure -d secure_login \
  -c "UPDATE users SET role='owner' WHERE email='owner@exemple.com';"
```

## Branchement SMTP

Le mode `EMAIL_MODE=console` affiche les liens de vérification/reset dans les
logs. Pour l'envoi réel, brancher le crate `lettre` dans
`api/src/services/mailer.rs` (`send_link`) avec vos identifiants SMTP, ou
router vers un provider HTTP (Postmark, SES…). Point d'extension unique prévu.
