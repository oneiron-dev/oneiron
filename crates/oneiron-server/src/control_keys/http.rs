//! Optional private control-plane router; tenant bearer auth remains separate.
use super::{ControlKeys, KeyError, KeyRecord};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use serde::Deserialize;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Hosts mount this on their private control-plane listener. No route is added
/// to the tenant's memory API, and pepper provisioning stays with Host::secret.
pub fn router(keys: Arc<ControlKeys>) -> Router {
    Router::new()
        .route("/verify", post(verify))
        .route("/rotate", post(rotate))
        .route("/revoke", post(revoke))
        .with_state(keys)
}
fn credential(headers: &HeaderMap) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or("")
            .as_bytes()
            .to_vec(),
    )
}
fn refusal(error: KeyError) -> StatusCode {
    match error {
        KeyError::ScopeDenied => StatusCode::FORBIDDEN,
        KeyError::Duplicate => StatusCode::CONFLICT,
        KeyError::Invalid => StatusCode::BAD_REQUEST,
        KeyError::Storage(_) | KeyError::Corrupt => StatusCode::SERVICE_UNAVAILABLE,
        KeyError::Rejected => StatusCode::UNAUTHORIZED,
    }
}
async fn verify(
    State(keys): State<Arc<ControlKeys>>,
    headers: HeaderMap,
) -> Result<Json<KeyRecord>, StatusCode> {
    keys.verify(
        &credential(&headers),
        "control:verify",
        oneiron_vault_contract::now_ts(),
    )
    .await
    .map(Json)
    .map_err(refusal)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rotate {
    new_key: String,
}
async fn rotate(
    State(keys): State<Arc<ControlKeys>>,
    headers: HeaderMap,
    Json(input): Json<Rotate>,
) -> Result<Json<KeyRecord>, StatusCode> {
    let new = Zeroizing::new(input.new_key);
    let old = credential(&headers);
    let now = oneiron_vault_contract::now_ts();
    keys.verify(&old, "control:rotate", now)
        .await
        .map_err(refusal)?;
    keys.rotate(&old, new.as_bytes(), now)
        .map(Json)
        .map_err(refusal)
}
async fn revoke(
    State(keys): State<Arc<ControlKeys>>,
    headers: HeaderMap,
) -> Result<StatusCode, StatusCode> {
    let key = credential(&headers);
    keys.verify(&key, "control:revoke", oneiron_vault_contract::now_ts())
        .await
        .map_err(refusal)?;
    keys.revoke(&key).map_err(refusal)?;
    Ok(StatusCode::NO_CONTENT)
}
#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;
    #[tokio::test]
    async fn private_router_reads_database_each_call_and_scopes_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let vault =
            Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
        let keys = Arc::new(ControlKeys::new(vault, Zeroizing::new(vec![19; 32])).unwrap());
        let raw = "12345678901234567890123456789012";
        keys.insert(
            raw.as_bytes(),
            ["control:verify", "control:revoke"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            oneiron_vault_contract::now_ts(),
            None,
        )
        .unwrap();
        let app = router(keys.clone());
        let request = |route| {
            axum::http::Request::builder()
                .method("POST")
                .uri(route)
                .header("Authorization", format!("Bearer {raw}"))
                .body(axum::body::Body::empty())
                .unwrap()
        };
        assert_eq!(
            app.clone()
                .oneshot(request("/verify"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone()
                .oneshot(request("/revoke"))
                .await
                .unwrap()
                .status(),
            StatusCode::NO_CONTENT
        );
        let start = std::time::Instant::now();
        assert_eq!(
            app.oneshot(request("/verify")).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(start.elapsed() >= super::super::FAILURE_FLOOR);
    }
}
