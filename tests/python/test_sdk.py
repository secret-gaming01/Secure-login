"""Tests SDK Python — sans reseau (validation des contrats du client).

Executer :  python tests/python/test_sdk.py
"""

import ast
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = (ROOT / "sdk" / "python" / "secure_auth" / "__init__.py").read_text(encoding="utf-8")

# 1) Le module compile
ast.parse(SRC)

# 2) Methodes obligatoires de la specification
sys.path.insert(0, str(ROOT / "sdk" / "python"))
from secure_auth import SecureAuthClient, SecureAuthError  # noqa: E402

client = SecureAuthClient("http://localhost:8080/")
assert client.base_url == "http://localhost:8080", "base_url doit etre trimmee"

for method in ("login", "logout", "register", "refresh_token",
               "get_current_user", "check_permission"):
    assert callable(getattr(client, method)), f"methode manquante : {method}"

# 3) Erreur typee
err = SecureAuthError(401, {"error": "Unauthorized"})
assert err.status == 401
assert "Unauthorized" in str(err)

print("OK sdk/python smoke tests passed")
