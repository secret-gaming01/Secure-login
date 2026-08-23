using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace SecureLogin
{
    /// <summary>Erreur renvoyee par l'API Secure-Login.</summary>
    public class SecureAuthException : Exception
    {
        public int Status { get; }
        public string Body { get; }

        public SecureAuthException(int status, string body)
            : base($"HTTP {status}: {body}")
        {
            Status = status;
            Body = body;
        }
    }

    /// <summary>
    /// Client officiel Secure-Login pour .NET / C#.
    /// </summary>
    public class SecureAuthClient
    {
        private readonly HttpClient _http;
        private readonly string _baseUrl;
        private string _accessToken;
        private string _refreshToken;

        public SecureAuthClient(string baseUrl, HttpClient httpClient = null)
        {
            _baseUrl = baseUrl.TrimEnd('/');
            _http = httpClient ?? new HttpClient();
        }

        // ------------------------------------------------------------- utils

        private void SetTokens(string access, string refresh)
        {
            _accessToken = access;
            if (!string.IsNullOrEmpty(refresh)) _refreshToken = refresh;
        }

        private async Task<string> RequestAsync(
            HttpMethod method, string path, string jsonBody, bool authed)
        {
            var req = new HttpRequestMessage(method, _baseUrl + path);
            if (!string.IsNullOrEmpty(jsonBody))
                req.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
            if (authed && !string.IsNullOrEmpty(_accessToken))
                req.Headers.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _accessToken);

            var resp = await _http.SendAsync(req);
            var body = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode)
                throw new SecureAuthException((int)resp.StatusCode, body);
            return body;
        }

        private static string Json(Dictionary<string, object> dict)
        {
            var sb = new StringBuilder("{");
            int i = 0;
            foreach (var kv in dict)
            {
                if (i++ > 0) sb.Append(',');
                sb.Append('"').Append(Escape(kv.Key)).Append("\":");
                sb.Append(kv.Value == null ? "null"
                    : kv.Value is string s ? "\"" + Escape(s) + "\""
                    : kv.Value is bool b ? (b ? "true" : "false")
                    : Convert.ToString(kv.Value, System.Globalization.CultureInfo.InvariantCulture));
            }
            return sb.Append('}').ToString();
        }

        private static string Escape(string s) => s
            .Replace("\\", "\\\\").Replace("\"", "\\\"")
            .Replace("\n", "\\n").Replace("\r", "\\r").Replace("\t", "\\t");

        // ---------------------------------------------------------- core API

        /// <summary>Cree un compte.</summary>
        public Task<string> Register(string email, string password) =>
            RequestAsync(HttpMethod.Post, "/auth/register",
                Json(new Dictionary<string, object> { ["email"] = email, ["password"] = password }),
                authed: false);

        /// <summary>Connexion. Si MFA : reponse contenant mfa_required + mfa_token.</summary>
        public async Task<string> Login(string email, string password)
        {
            var body = await RequestAsync(HttpMethod.Post, "/auth/login",
                Json(new Dictionary<string, object> { ["email"] = email, ["password"] = password }),
                authed: false);
            ExtractTokens(body);
            return body;
        }

        /// <summary>Finalise une connexion MFA.</summary>
        public async Task<string> LoginMfa(string mfaToken, string code)
        {
            var body = await RequestAsync(HttpMethod.Post, "/auth/mfa/verify",
                Json(new Dictionary<string, object> { ["mfa_token"] = mfaToken, ["code"] = code }),
                authed: false);
            ExtractTokens(body);
            return body;
        }

        /// <summary>Rotation du refresh token.</summary>
        public async Task<string> RefreshToken()
        {
            var body = await RequestAsync(HttpMethod.Post, "/auth/token/refresh",
                Json(new Dictionary<string, object> { ["refresh_token"] = _refreshToken }),
                authed: false);
            ExtractTokens(body);
            return body;
        }

        /// <summary>Profil courant (user + scopes + mfa_enabled).</summary>
        public Task<string> GetCurrentUser() =>
            RequestAsync(HttpMethod.Get, "/auth/me", null, authed: true);

        /// <summary>Deconnexion de la session courante.</summary>
        public async Task<string> Logout()
        {
            var result = await RequestAsync(HttpMethod.Post, "/auth/logout", "{}", authed: true);
            _accessToken = null; _refreshToken = null;
            return result;
        }

        /// <summary>True si le scope fait partie des permissions courantes.</summary>
        public async Task<bool> CheckPermission(string scope)
        {
            try
            {
                var me = await GetCurrentUser();
                return me != null && me.Contains("\"" + scope + "\"");
            }
            catch
            {
                return false;
            }
        }

        private void ExtractTokens(string body)
        {
            // extraction legere sans dependance JSON externe
            var access = ExtractString(body, "access_token");
            var refresh = ExtractString(body, "refresh_token");
            if (access != null) SetTokens(access, refresh);
        }

        private static string ExtractString(string json, string key)
        {
            var needle = "\"" + key + "\":";
            var idx = json.IndexOf(needle, StringComparison.Ordinal);
            if (idx < 0) return null;
            var start = json.IndexOf('"', idx + needle.Length);
            if (start < 0) return null;
            var end = json.IndexOf('"', start + 1);
            if (end < 0) return null;
            return json.Substring(start + 1, end - start - 1);
        }

        // ------------------------------------------------------------- bonus

        public Task<string> LogoutAll() =>
            RequestAsync(HttpMethod.Post, "/auth/logout-all", "{}", authed: true);

        public Task<string> EnableMfa() =>
            RequestAsync(HttpMethod.Post, "/auth/mfa/enable", null, authed: true);

        public Task<string> ListSessions() =>
            RequestAsync(HttpMethod.Get, "/auth/sessions", null, authed: true);

        public Task<string> AdminSuspiciousIps() =>
            RequestAsync(HttpMethod.Get, "/admin/suspicious-ips", null, authed: true);

        public Task<string> AdminDoubleAccounts() =>
            RequestAsync(HttpMethod.Get, "/admin/double-accounts", null, authed: true);
    }
}
