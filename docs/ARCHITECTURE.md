# Architecture — Secure-Login

## Vue d'ensemble

```mermaid
flowchart LR
    subgraph Clients
        W[Web / SPA]
        S1[SDK JS/TS]
        S2[SDK Python]
        S3[SDK C#]
        S4[SDK Rust]
    end

    subgraph Server["Axum (Rust)"]
        MW[middlewares: IP firewall, rate-limit, CSRF, headers]
        AUTH[/routes auth/]
        ADM[/routes admin/]
        DASH[dashboard statique]
        SVC[services: users, sessions, tokens, mfa, passkeys, audit, ipintel]
    end

    subgraph Data
        DB[(PostgreSQL ou SQLite)]
        MEM[mémoire: geo-cache, challenges WebAuthn, buckets rate-limit]
    end

    GEO[ip-api.com géoIP]
    CAP[Captcha provider]

    Clients -->|HTTPS JSON| MW
    MW --> AUTH --> SVC
    MW --> ADM --> SVC
    MW --> DASH
    SVC --> DB
    SVC -.-> MEM
    SVC -.->|optionnel| GEO
    SVC -.->|si configuré| CAP
```

## Schéma de données (ER)

```mermaid
erDiagram
    USERS ||--o{ SESSIONS : possède
    USERS ||--o{ TOKENS : reçoit
    USERS ||--o{ PASSKEYS : enregistre
    USERS ||--|| MFA : active
    USERS ||--o{ SECURITY_LOGS : génère
    LOGIN_ATTEMPTS }o..|| BLOCKED_IPS : "ip"

    USERS {
        text id PK
        text email UK_lower
        text password_hash "Argon2id+pepper"
        text salt
        bool email_verified
        text role "user|admin|owner"
        datetime last_login_at
        text last_login_ip
    }
    SESSIONS {
        text id PK
        text user_id FK
        text refresh_hash "HMAC"
        text device
        text fingerprint
        text ip
        text country
        bool revoked
    }
    TOKENS {
        text id PK
        text user_id FK
        text kind "email_verify|pw_reset|refresh_rotated"
        text value_hash UK
        datetime expires_at
        datetime used_at
    }
    BLOCKED_IPS {
        text ip UK
        text mode "blacklist|whitelist"
        datetime expires_at
    }
    PASSKEYS {
        text id PK
        text credential_id UK
        text public_key_enc "AES-GCM"
        bigint counter
    }
    MFA {
        text user_id PK_FK
        text secret_enc "AES-GCM"
        bool enabled
        text recovery_codes_enc "AES-GCM"
    }
    SECURITY_LOGS {
        text event
        text severity "info|warn|critical"
        text details_enc "AES-GCM"
        datetime created_at
    }
    LOGIN_ATTEMPTS {
        text email
        text ip
        bool success
        datetime created_at
    }
```

## Flux de connexion (avec MFA)

```mermaid
sequenceDiagram
    autonumber
    C->>A: POST /auth/login {email,password}
    A->>A: lockout ? captcha ? IP bloquée ?
    A->>DB: Argon2id(pepper+pwd) vs hash
    A->>C: {mfa_required, mfa_token(5min)}
    C->>A: POST /auth/mfa/verify {mfa_token, code}
    A->>A: TOTP ±30s OU code récupération (usage unique)
    A->>DB: INSERT session (device, ip, pays) + refresh HMAC
    A->>C: access JWT 15min + refresh opaque
```

## Rotation du refresh token & anti-replay

```mermaid
sequenceDiagram
    autonumber
    C->>A: POST /auth/token/refresh (RT1)
    A->>A: RT1 jamais tourné ?
    A->>DB: trace refresh_rotated(RT1), session ← RT2
    A-->>C: nouvel access + RT2
    Note over A: si RT1 réapparaît →<br/>toutes sessions révoquées (critical)
```

## Passkeys

```mermaid
sequenceDiagram
    autonumber
    C->>A: POST /auth/passkey/login/options {email}
    A-->>C: challenge + challenge_id
    C->>C: navigator.credentials.get(publicKey)
    C->>A: POST /auth/passkey/login {challenge_id, assertion}
    A->>A: webauthn-rs vérifie origin/RP/signature/compteur
    A-->>C: session + tokens
```
