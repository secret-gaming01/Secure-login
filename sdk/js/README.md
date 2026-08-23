# @secure-login/sdk (JavaScript / TypeScript)

Client universel (navigateur + Node 18+) pour l'API Secure-Login.

```ts
import { SecureAuthClient } from "./src/index";

const auth = new SecureAuthClient("http://localhost:8080");
await auth.register("user@ex.com", "Str0ngPassw0rd!");
const r = await auth.login("user@ex.com", "Str0ngPassw0rd!");
if (r.mfa_required) await auth.loginMfa(r.mfa_token, "123456");

await auth.refreshToken();
console.log(await auth.getCurrentUser());
console.log(await auth.checkPermission("profile.read"));
await auth.logout();
```

Build : `npm install && npm run build` · Test : `node tests/js/sdk.test.mjs`
