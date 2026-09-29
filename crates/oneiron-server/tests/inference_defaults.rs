//! Owner-grade HTTP edit/read proof for resident inference policy rows.
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, request::Builder},
};
use oneiron::{CallPurpose, ModelTierRef, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use std::sync::Arc;
use tower::ServiceExt;

/// The owner presents the logged host-root slip with a fresh holder proof;
/// the configured host secret is issuer key material, never a bearer.
fn owner(vault: &Vault) -> Builder {
    let issuer =
        oneiron::authority::HostSlipIssuer::from_secret(b"owner").expect("host slip issuer");
    let slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("host root slip");
    let timestamp = vault.capability_slip_now().expect("authority clock");
    let nonce = oneiron::EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature: String = issuer
        .binding_proof(&slip, challenge.as_bytes())
        .expect("holder proof")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Request::builder()
        .header(
            "authorization",
            format!("Bearer {}", slip.to_token().expect("slip token")),
        )
        .header(
            "x-oneiron-binding",
            serde_json::json!({"timestamp":timestamp,"nonce":nonce,"signature":signature})
                .to_string(),
        )
}

fn bearer(credential: &str) -> Builder {
    Request::builder().header("authorization", format!("Bearer {credential}"))
}

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
    let get = |request: Builder| {
        request
            .method("GET")
            .uri("/v1/llm/defaults")
            .body(Body::empty())
            .expect("inference defaults fixture")
    };
    let response = router
        .clone()
        .oneshot(get(owner(&vault)))
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
    let put = |request: Builder, table: &oneiron::llm::PurposeDefaultTable| {
        request
            .method("PUT")
            .uri("/v1/llm/defaults")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(table).expect("inference defaults fixture"),
            ))
            .expect("inference defaults fixture")
    };
    // A wrong bearer and the retired verbatim host secret are both refused.
    for credential in ["wrong", "owner"] {
        assert_ne!(
            router
                .clone()
                .oneshot(put(bearer(credential), &table))
                .await
                .expect("inference defaults fixture")
                .status(),
            StatusCode::OK,
            "{credential}"
        );
    }
    assert_eq!(
        router
            .clone()
            .oneshot(put(owner(&vault), &table))
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
            .oneshot(put(owner(&vault), &incomplete))
            .await
            .expect("inference defaults fixture")
            .status(),
        StatusCode::BAD_REQUEST,
    );
    for missing in [Some(CallPurpose::Extraction), None] {
        let mut malformed = table.clone();
        if let Some(purpose) = missing {
            malformed.purposes.remove(&purpose);
        } else {
            malformed.purposes.clear();
        }
        assert_eq!(
            router
                .clone()
                .oneshot(put(owner(&vault), &malformed))
                .await
                .expect("malformed policy response")
                .status(),
            StatusCode::BAD_REQUEST,
        );
    }
    let response = router
        .oneshot(get(owner(&vault)))
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
