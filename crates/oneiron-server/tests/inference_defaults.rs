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
    let dir = tempfile::tempdir().expect("inference defaults fixture");
    let vault = Arc::new(
        Vault::open(dir.path(), VaultConfig::device()).expect("inference defaults fixture"),
    );
    let server = SyncServer::new(
        vault.clone(),
        SyncServerConfig {
            auth_secret: Some("owner".into()),
            ..Default::default()
        },
    )
    .expect("inference defaults fixture");
    let router = build_app(Arc::new(server));
    let get = |credential: &str| {
        Request::get("/v1/llm/defaults")
            .header("authorization", format!("Bearer {credential}"))
            .body(Body::empty())
            .expect("inference defaults fixture")
    };
    let response = router
        .clone()
        .oneshot(get("owner"))
        .await
        .expect("inference defaults fixture");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 16 * 1024)
        .await
        .expect("inference defaults fixture");
    let mut table =
        oneiron::llm::PurposeDefaultTable::from_json(&bytes).expect("inference defaults fixture");
    table
        .purposes
        .get_mut(&CallPurpose::Consolidation)
        .expect("inference defaults fixture")
        .tier = ModelTierRef("http-resident".into());
    let put = |credential: &str, table: &oneiron::llm::PurposeDefaultTable| {
        Request::put("/v1/llm/defaults")
            .header("authorization", format!("Bearer {credential}"))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(table).expect("inference defaults fixture"),
            ))
            .expect("inference defaults fixture")
    };
    assert_ne!(
        router
            .clone()
            .oneshot(put("wrong", &table))
            .await
            .expect("inference defaults fixture")
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        router
            .clone()
            .oneshot(put("owner", &table))
            .await
            .expect("inference defaults fixture")
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
            .expect("inference defaults fixture")
            .status(),
        StatusCode::BAD_REQUEST,
    );
    let response = router
        .oneshot(get("owner"))
        .await
        .expect("inference defaults fixture");
    let bytes = to_bytes(response.into_body(), 16 * 1024)
        .await
        .expect("inference defaults fixture");
    assert_eq!(
        oneiron::llm::PurposeDefaultTable::from_json(&bytes).expect("inference defaults fixture"),
        table
    );
    assert_eq!(
        vault
            .purpose_default_table()
            .expect("inference defaults fixture")
            .purposes[&CallPurpose::Consolidation]
            .tier
            .as_str(),
        "http-resident"
    );
}
