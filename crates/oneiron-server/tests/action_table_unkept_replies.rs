//! The app's action table offers no verb-table row whose answer an invocation
//! never keeps (FIX ACTION-REPLAY-SERVES-UNKEPT-VERB-ANSWERS). An action keeps
//! its row's answer in its replay record and answers the same key from that
//! record again, and no row door judges the caller anew. So, as an action, a
//! starter whose workload approval was revoked would read the old workload
//! again, and a personal booking link's raw token would be held and answered
//! again. Those rows stay callable as direct rows; a row whose answer is kept
//! stays an action.
//!
//! Run on the fleet, never on a workstation:
//! cargo test --locked -p oneiron-server --all-features --test action_table_unkept_replies

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use oneiron::authority::HostSlipIssuer;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::actions::SharedActionExecutor;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The rows whose answer an invocation never keeps
/// (`api::facade::invocations::UNKEPT_REPLY_VERBS` at this test's writing).
const UNKEPT_REPLY_ROWS: [&str; 7] = [
    "vault.inquire",
    "vault.inquiry.edge.prepare_join",
    "vault.members.accept_with_inquiry_edge",
    "vault.members.inquiry_edge.attach",
    "vault.booking.personal_link.mint",
    "vault.jobs.workloads.get",
    "vault.jobs.workloads.list",
];

/// A verb-table row whose answer is kept, which a REST route runs as an action
/// (`execute_facade_row_held`).
const KEPT_ROW: &str = "vault.artifacts.create";

#[test]
fn the_action_table_offers_no_row_whose_answer_is_never_kept() {
    let app = SharedActionExecutor::app().expect("the app's action table builds");
    let offered: BTreeSet<&str> = app
        .definitions()
        .map(|definition| definition.id.as_str())
        .collect();
    let still_offered: Vec<&str> = UNKEPT_REPLY_ROWS
        .iter()
        .copied()
        .filter(|row| offered.contains(row))
        .collect();
    assert!(
        still_offered.is_empty(),
        "rows whose answer is never kept are still offered as actions: {still_offered:?}"
    );
    assert!(
        offered.contains(KEPT_ROW),
        "{KEPT_ROW}, a kept row, is no longer an action"
    );
}

/// The row this test calls: the owner's list of pinned workloads, with an
/// empty input, which answers on a fresh vault.
const WITHDRAWN_ROW: &str = "vault.jobs.workloads.list";

/// `body` posted to `path` as the owner: the host-root slip with a fresh
/// holder proof.
async fn as_owner(app: &Router, vault: &Vault, path: &str, body: Value) -> (StatusCode, Value) {
    let issuer = HostSlipIssuer::from_secret(b"owner").expect("host slip issuer");
    let slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("host root slip");
    let timestamp = vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature: String = issuer
        .binding_proof(&slip, challenge.as_bytes())
        .expect("holder proof")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let request = Request::post(path)
        .header(
            "authorization",
            format!("Bearer {}", slip.to_token().expect("slip token")),
        )
        .header(
            "x-oneiron-binding",
            json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string(),
        )
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("owner request");
    let response = app.clone().oneshot(request).await.expect("owner response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("owner response body");
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, body)
}

/// The owner calls the withdrawn row as an action, then again under the same
/// idempotency key, as a replay: each answers "unknown action verb", so no
/// answer is kept or served again. The same row called directly still
/// answers the owner.
#[tokio::test]
async fn a_withdrawn_row_is_an_unknown_action_and_its_direct_row_answers() {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("owner".into()),
            ..Default::default()
        },
    )
    .expect("create server");
    let app = build_app(Arc::new(server));
    let action = format!("/v1/core/actions/{WITHDRAWN_ROW}");
    let call = json!({
        "args": [{"kind": "json", "value": {}}],
        "idempotencyKey": "unkept-replies-workloads-list",
    });
    for attempt in ["the first call", "its replay under the same key"] {
        let (status, body) = as_owner(&app, &vault, &action, call.clone()).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{attempt} of {WITHDRAWN_ROW} as an action: {body}"
        );
        assert!(
            body.to_string().contains("unknown action verb"),
            "{attempt} of {WITHDRAWN_ROW} as an action: {body}"
        );
    }
    let (status, body) = as_owner(
        &app,
        &vault,
        &format!("/v1/core/facade/{WITHDRAWN_ROW}"),
        json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{WITHDRAWN_ROW} called directly: {body}"
    );
}
