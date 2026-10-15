use super::*;
use tower::ServiceExt;

#[test]
fn router_can_be_constructed_before_entering_a_runtime() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
    let server = Arc::new(crate::server::SyncServer::new(vault, Default::default()).unwrap());
    let router = crate::build_app(server);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let response = runtime.block_on(async {
        router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    });
    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

/// Review r2 (Sol, P2): the reap freeze kept the call-volume window but not
/// a limit question asked since the last observation tick, and every flush
/// after the freeze keeps nothing, so the question went with the vault.
#[test]
fn a_question_asked_just_before_the_reap_freeze_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
    let telemetry = WireTelemetry::new(vault);
    telemetry
        .limit_questions()
        .ask(LimitRow::GitExchanges, 2_048, 2_049);
    let asked = telemetry
        .limit_questions()
        .latest(LimitRow::GitExchanges)
        .expect("asked");

    telemetry.freeze_and_flush().unwrap();
    let window = asked.raised_at / LIMIT_QUESTION_WINDOW_SECS * LIMIT_QUESTION_WINDOW_SECS;
    assert_eq!(
        telemetry
            .limit_question(LimitRow::GitExchanges, window)
            .unwrap(),
        Some(asked),
        "the freeze keeps what was asked before it"
    );
}
