# Intégrer Secure-Login sur VOTRE site — guide pas à pas

Ce guide part de zéro. Aucune connaissance en sécurité n'est requise.

---

## 0. De quoi avez-vous besoin ?

- **Docker Desktop** installé (ou Rust si vous préférez compiler)
- Votre site, quel qu'il soit : HTML statique, PHP, WordPress, React, Next.js…
  → il communiquera avec Secure-Login simplement en **HTTP/JSON**, comme un formulaire classique.

---

## 1. Lancer le serveur d'authentification (5 min)

```bash
git clone https://github.com/secret-gaming01/Secure-login.git
cd Secure-login
cp .env.example .env        # Windows : copy .env.example .env
```

Ouvrez `.env` et remplacez les 3 lignes CHANGE_ME :

```
JWT_SECRET=collez_ici_64_caracteres_aleatoires
ENCRYPTION_KEY=collez_ici_autre_chaine_aleatoire
PASSWORD_PEPPER=encore_une_autre_chaine_secrete
```

Astuce génération : https://www.random.org/strings/ ou `openssl rand -hex 32`.

```bash
docker compose up -d --build
```

Vérification : http://localhost:8080/health doit répondre `{"status":"ok"}`.
Dashboard admin : http://localhost:8080/dashboard/

---

## 2. Créer votre compte administrateur

1. Inscrivez-vous (remplacez email/mot de passe) :

```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"moi@monsite.com","password":"MonMotDePasse123!"}'
```

2. Le lien de vérification apparaît **dans les logs** (mode console) :

```bash
docker compose logs api | grep "verification"
```
Ouvrez ce lien dans le navigateur.

3. Promouvez ce compte en propriétaire :

```bash
docker compose exec db psql -U secure -d secure_login \
  -c "UPDATE users SET role='owner' WHERE email='moi@monsite.com';"
```

4. Connectez-vous ensuite sur `/dashboard/` : vous gérez tout visuellement
   (utilisateurs, sessions, IP suspectes, logs…).

---

## 3. Brancher votre site : page de connexion complète (copier-coller)

Créez `login.html` chez vous :

```html
<form id="f">
  <input id="email" type="email" placeholder="Email">
  <input id="pass" type="password" placeholder="Mot de passe">
  <button>Se connecter</button>
</form>
<pre id="out"></pre>

<script>
const AUTH = "http://localhost:8080";

document.getElementById("f").onsubmit = async (e) => {
  e.preventDefault();
  const email = document.getElementById("email").value;
  const password = document.getElementById("pass").value;

  const r = await fetch(AUTH + "/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password })
  });
  const data = await r.json();

  if (data.mfa_required) {
    // l'utilisateur a activé la double authentification
    const code = prompt("Code à 6 chiffres :");
    const r2 = await fetch(AUTH + "/auth/mfa/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mfa_token: data.mfa_token, code })
    });
    Object.assign(data, await r2.json());
  }

  if (!data.access_token) {
    document.getElementById("out").textContent = data.error || "Erreur";
    return;
  }

  // On garde les jetons puis on entre dans l'espace membre
  localStorage.setItem("access",  data.access_token);
  localStorage.setItem("refresh", data.refresh_token);
  location.href = "/membre.html";
};
</script>
```

Inscription : même principe avec `/auth/register` (un email de vérification est envoyé).

---

## 4. Espace membre protégé (`membre.html`)

```html
<h1>Espace membre</h1>
<div id="profil">Chargement…</div>

<script>
const AUTH = "http://localhost:8080";
async function moi() {
  let r = await fetch(AUTH + "/auth/me", {
    headers: { Authorization: "Bearer " + localStorage.getItem("access") }
  });

  if (r.status === 401) {
    // jeton expiré (15 min) -> on le renouvelle silencieusement
    const rr = await fetch(AUTH + "/auth/token/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: localStorage.getItem("refresh") })
    });
    if (!rr.ok) return location.href = "/login.html"; // session réellement finie
    const t = await rr.json();
    localStorage.setItem("access", t.access_token);
    localStorage.setItem("refresh", t.refresh_token);
    r = await fetch(AUTH + "/auth/me", {
      headers: { Authorization: "Bearer " + t.access_token }
    });
  }
  const me = await r.json();
  document.getElementById("profil").textContent =
    "Bonjour " + me.user.email + " (" + me.user.role + ")";
}
moi();

// Déconnexion
function logout() {
  fetch(AUTH + "/auth/logout", { method:"POST",
    headers:{Authorization:"Bearer "+localStorage.getItem("access")} });
  localStorage.clear(); location.href="/login.html";
}
</script>
<button onclick="logout()">Déconnexion</button>
```

---

## 5. ⚠️ Protection côté serveur (obligatoire en production)

Un utilisateur peut vider son `localStorage` : **le navigateur seul ne protège rien.**
Si votre contenu est généré par un backend (PHP, Node…), validez le jeton AVANT
d'envoyer une page privée — un simple appel suffit :

```php
// PHP — avant de servir la page privée
$tok = $_SERVER["HTTP_AUTHORIZATION"] ?? "";           // "Bearer xxx"
$r = file_get_contents("http://127.0.0.1:8080/auth/me", false,
     stream_context_create(["http"=>["header"=>"Authorization: $tok"]]));
if ($r === false) { http_response_code(401); exit("Connexion requise"); }
$user = json_decode($r, true);
```

Même principe en Node/Express : middleware qui appelle `/auth/me` et refuse en 401.

---

## 6. Activer la double authentification (MFA)

Depuis une session connectée :

```js
const s = await fetch(AUTH+"/auth/mfa/enable",{method:"POST",
  headers:{Authorization:"Bearer "+localStorage.getItem("access")}}).then(r=>r.json());
// s.otpauth_url : à transformer en QR code (lib "qrcode" côté client)
// l'utilisateur l'ajoute dans Google Authenticator puis :
await fetch(AUTH+"/auth/mfa/verify",{method:"POST",
  headers:{"Content-Type":"application/json",Authorization:"Bearer "+s.access},
  body:JSON.stringify({code:prompt("Code affiché par l'app :")})});
// réponse : 8 codes de récupération à conserver précieusement
```

Passkeys (empreinte/Visage) : flux WebAuthn standard — voir `docs/API.md`.

---

## 7. Checklist mise en production

- [ ] Domaine + HTTPS devant l'API (nginx/Caddy), `TRUST_PROXY=true` dans `.env`
- [ ] `CORS_ORIGINS=https://votresite.com` (jamais `*`)
- [ ] Captcha configuré (`CAPTCHA_PROVIDER=turnstile` + clés)
- [ ] Les 3 secrets `.env` sont forts et sauvegardés hors du serveur
- [ ] Premier compte `owner` créé, mot de passe long
- [ ] Sauvegardes automatiques du volume PostgreSQL

Guide détaillé : `docs/DEPLOYMENT.md` · Référence API : `docs/API.md`
