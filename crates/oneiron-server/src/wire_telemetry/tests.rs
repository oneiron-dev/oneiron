use super::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fifty_thousand_agents_are_observed_not_refused_and_manifest_is_live() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
    use tower::ServiceExt;
    let config = crate::config::SyncServerConfig {
        auth_secret: Some("test-secret".into()),
        ..Default::default()
    };
    let server = Arc::new(crate::server::SyncServer::new(vault, config).unwrap());
    let router = axum::Router::new()
        .route(
            "/recall",
            axum::routing::get(|| async { axum::http::StatusCode::OK }),
        )
        .layer(axum::middleware::from_fn_with_state(
            server.clone(),
            observe_http,
        ));
    let counter = &server.wire_telemetry;
    counter
        .set_thresholds(&WireThresholds {
            window_secs: 86_400,
            ..Default::default()
        })
        .unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    for i in 1..=50_000 {
        let router = router.clone();
        let token = crate::auth::mint_core_token_v2(
            "test-secret",
            &format!("scope=core:read;principal_ref={i:032x}"),
        );
        tasks.spawn(async move {
            let request = axum::http::Request::builder()
                .uri("/recall")
                .header("Authorization", format!("Bearer {token}"))
                .body(axum::body::Body::empty())
                .unwrap();
            router.oneshot(request).await.unwrap().status()
        });
    }
    while let Some(task) = tasks.join_next().await {
        assert_eq!(task.unwrap(), axum::http::StatusCode::OK);
    }
    counter.flush().unwrap();
    let start = counter.snapshot().unwrap().unwrap().started_at;
    let receipt = counter.receipt(start).unwrap().unwrap();
    assert_eq!(receipt.by_verb["GET /recall"], 50_000);
    assert_eq!(receipt.by_actor.len(), 50_000);
    assert!(receipt.by_actor.values().all(|count| *count == 1));
    assert!(counter.question(start).unwrap().is_none());
    counter
        .set_thresholds(&WireThresholds {
            window_secs: 86_400,
            per_verb: 50_000,
            per_actor: 1_000_000,
        })
        .unwrap();
    counter
        .record("GET /recall", "agent:next", start + 1)
        .unwrap();
    let hook = counter.question(start).unwrap().unwrap();
    assert_eq!(hook.kind, WireQuestionKind::InspectCallVolume);
    assert_eq!(hook.evidence.by_verb["GET /recall"], 50_001);
    counter
        .record("GET /recall", "agent:again", start + 2)
        .unwrap();
    assert_eq!(counter.question(start).unwrap().unwrap(), hook);
    counter
        .record("write", "agent:again", start + 86_401)
        .unwrap();
    assert_eq!(
        counter.receipt(start).unwrap().unwrap().by_verb["GET /recall"],
        50_002
    );
}
