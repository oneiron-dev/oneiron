//! Owner-grade HTTP edit/read proof for resident inference policy rows.
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use oneiron::{CallPurpose, ModelTierRef, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::test]
async fn owner_can_edit_inference_defaults_over_http_without_rebuilding() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let server = SyncServer::new(
        vault.clone(),
        SyncServerConfig {
            auth_secret: Some("owner".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let router = build_app(Arc::new(server));
    let get = |credential: &str| {
        Request::get("/v1/llm/defaults")
            .header("authorization", format!("Bearer {credential}"))
            .body(Body::empty())
            .unwrap()
    };
    let response = router.clone().oneshot(get("owner")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let mut table = oneiron::llm::PurposeDefaultTable::from_json(&bytes).unwrap();
    table
        .purposes
        .get_mut(&CallPurpose::Consolidation)
        .unwrap()
        .tier = ModelTierRef("http-resident".into());
    let put = |credential: &str, table: &oneiron::llm::PurposeDefaultTable| {
        Request::put("/v1/llm/defaults")
            .header("authorization", format!("Bearer {credential}"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(table).unwrap()))
            .unwrap()
    };
    assert_ne!(
        router
            .clone()
            .oneshot(put("wrong", &table))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        router
            .clone()
            .oneshot(put("owner", &table))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let mut incomplete = table.clone();
    incomplete.purposes.remove(&CallPurpose::Eval);
    assert_eq!(
        router
            .clone()
            .oneshot(put("owner", &incomplete))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST,
    );
    let response = router.oneshot(get("owner")).await.unwrap();
    let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    assert_eq!(
        oneiron::llm::PurposeDefaultTable::from_json(&bytes).unwrap(),
        table
    );
    assert_eq!(
        vault.purpose_default_table().unwrap().purposes[&CallPurpose::Consolidation]
            .tier
            .as_str(),
        "http-resident"
    );
}
