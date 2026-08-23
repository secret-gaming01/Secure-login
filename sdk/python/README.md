# Secure-Login SDK — Python

```bash
pip install .
```

```python
from secure_auth import SecureAuthClient

auth = SecureAuthClient("http://localhost:8080")
auth.register("user@ex.com", "Str0ngPassw0rd!")
r = auth.login("user@ex.com", "Str0ngPassw0rd!")
if r.get("mfa_required"):
    r = auth.login_mfa(r["mfa_token"], "123456")
print(auth.get_current_user())
auth.logout()
```

API complète : voir `/docs/API.md`. Test : `python tests/python/test_sdk.py`
