//! Test SDK Rust : le client se construit et stocke les tokens.

use secure_login_sdk::SecureAuthClient;

#[test]
fn client_basics() {
    let c = SecureAuthClient::new("http://localhost:8080/");
    assert!(c.access_token().is_none());

    c.set_tokens("access-abc", Some("refresh-def".into()));
    assert_eq!(c.access_token().as_deref(), Some("access-abc"));
}

#[tokio::test]
async fn check_permission_fails_gracefully_offline() {
    // Aucun serveur : check_permission doit retourner false, pas paniquer.
    let c = SecureAuthClient::new("http://127.0.0.1:1");
    assert!(!c.check_permission("users.read").await.unwrap_or(true));
}
