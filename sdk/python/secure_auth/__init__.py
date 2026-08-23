"""Secure-Login SDK â€” Python.

Client synchrone (requests) pour l'API secure-auth-api.

Exemple :
    from secure_auth import SecureAuthClient

    client = SecureAuthClient("http://localhost:8080")
    result = client.login("admin@example.com", "Str0ngPassw0rd!")
    if result.get("mfa_required"):
        result = client.login_mfa(result["mfa_token"], "123456")
    print(client.get_current_user())
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

import urllib.error
import urllib.request


class SecureAuthError(Exception):
    """Erreur renvoyee par l'API Secure-Login."""

    def __init__(self, status: int, body: Dict[str, Any]):
        self.status = status
        self.body = body
        super().__init__(body.get("error", f"HTTP {status}"))


class SecureAuthClient:
    def __init__(self, base_url: str, timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.__access: Optional[str] = None
        self.__refresh: Optional[str] = None

    # ------------------------------------------------------------------ utils
    def _request(self, path: str, method: str = "GET", body: Optional[Dict] = None,
                 authed: bool = True) -> Dict[str, Any]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        if authed and self.__access:
            req.add_header("Authorization", f"Bearer {self.__access}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            try:
                payload = json.loads(e.read().decode() or "{}")
            except Exception:
                payload = {}
            raise SecureAuthError(e.code, payload) from None

    def _store_tokens(self, result: Dict[str, Any]) -> None:
        if result.get("access_token"):
            self.__access = result["access_token"]
            self.__refresh = result.get("refresh_token")

    # ------------------------------------------------------------- core API
    def register(self, email: str, password: str) -> Dict[str, Any]:
        """Cree un compte. Un email de verification est envoye."""
        return self._request("/auth/register", "POST",
                             {"email": email, "password": password}, authed=False)

    def login(self, email: str, password: str,
              captcha_token: Optional[str] = None) -> Dict[str, Any]:
        """Connexion. Si MFA actif : mfa_required=True + mfa_token."""
        result = self._request("/auth/login", "POST", {
            "email": email, "password": password, "captcha_token": captcha_token,
        }, authed=False)
        self._store_tokens(result)
        return result

    def login_mfa(self, mfa_token: str, code: str) -> Dict[str, Any]:
        """Finalise une connexion protegee par MFA."""
        result = self._request("/auth/mfa/verify", "POST",
                               {"mfa_token": mfa_token, "code": code}, authed=False)
        self._store_tokens(result)
        return result

    def refresh_token(self) -> Dict[str, Any]:
        """Rotation du refresh token (ancien invalide, nouveau stocke)."""
        if not self.__refresh:
            raise SecureAuthError(401, {"error": "No refresh token"})
        result = self._request("/auth/token/refresh", "POST",
                               {"refresh_token": self.__refresh}, authed=False)
        self._store_tokens(result)
        return result

    def get_current_user(self) -> Dict[str, Any]:
        """Profil courant : user, scopes, mfa_enabled."""
        return self._request("/auth/me")

    def logout(self) -> None:
        """Deconnexion de la session courante."""
        try:
            self._request("/auth/logout", "POST", {})
        finally:
            self.__access = None
            self.__refresh = None

    def check_permission(self, scope: str) -> bool:
        """True si le scope/permission fait partie des scopes courants."""
        try:
            me = self.get_current_user()
        except SecureAuthError:
            return False
        return scope in (me.get("scopes") or [])

    # ---------------------------------------------------------------- bonus
    def logout_all(self) -> Dict[str, Any]:
        return self._request("/auth/logout-all", "POST", {})

    def verify_email(self, token: str) -> Dict[str, Any]:
        return self._request("/auth/verify-email", "POST", {"token": token}, authed=False)

    def forgot_password(self, email: str) -> Dict[str, Any]:
        return self._request("/auth/forgot-password", "POST", {"email": email}, authed=False)

    def reset_password(self, token: str, new_password: str) -> Dict[str, Any]:
        return self._request("/auth/reset-password", "POST",
                             {"token": token, "new_password": new_password}, authed=False)

    def change_password(self, current_password: str, new_password: str) -> Dict[str, Any]:
        return self._request("/auth/change-password", "POST", {
            "current_password": current_password, "new_password": new_password})

    def change_email(self, password: str, new_email: str) -> Dict[str, Any]:
        return self._request("/auth/change-email", "POST",
                             {"password": password, "new_email": new_email})

    def delete_account(self, password: str) -> Dict[str, Any]:
        result = self._request("/auth/account", "DELETE", {"password": password})
        self.__access = None
        self.__refresh = None
        return result

    def list_sessions(self) -> Dict[str, Any]:
        return self._request("/auth/sessions")

    # ---- MFA / Passkeys
    def enable_mfa(self) -> Dict[str, Any]:
        return self._request("/auth/mfa/enable", "POST")

    def confirm_mfa(self, code: str) -> Dict[str, Any]:
        return self._request("/auth/mfa/verify", "POST", {"code": code})

    def passkey_register_options(self) -> Dict[str, Any]:
        return self._request("/auth/passkey/register/options", "POST")

    def passkey_login_options(self, email: str) -> Dict[str, Any]:
        return self._request("/auth/passkey/login/options", "POST",
                             {"email": email}, authed=False)

    # ---- Admin
    def admin_list_users(self, q: str = "", limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        return self._request(f"/admin/users?q={q}&limit={limit}&offset={offset}")

    def admin_block_ip(self, ip: str, mode: str = "blacklist",
                       reason: Optional[str] = None,
                       expires_in_minutes: Optional[int] = None) -> Dict[str, Any]:
        return self._request("/admin/block-ip", "POST", {
            "ip": ip, "mode": mode, "reason": reason,
            "expires_in_minutes": expires_in_minutes})

    def admin_suspicious_ips(self) -> Dict[str, Any]:
        return self._request("/admin/suspicious-ips")

    def admin_double_accounts(self) -> Dict[str, Any]:
        return self._request("/admin/double-accounts")


__all__ = ["SecureAuthClient", "SecureAuthError"]
__version__ = "0.1.0"
