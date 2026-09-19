use super::*;
use tower::ServiceExt;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fifty_thousand_agents_are_observed_not_refused_and_manifest_is_live() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
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
    let receipt = counter.receipt(start, start + 86_400).unwrap().unwrap();
    assert_eq!(receipt.by_verb["GET /recall"], 50_000);
    assert_eq!(receipt.by_actor.len(), 50_000);
    assert!(receipt.by_actor.values().all(|count| *count == 1));
    assert!(counter.question(start, start + 86_400).unwrap().is_none());
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
    let hook = counter.question(start, start + 86_400).unwrap().unwrap();
    assert_eq!(hook.kind, WireQuestionKind::InspectCallVolume);
    assert_eq!(hook.evidence.by_verb["GET /recall"], 50_001);
    counter
        .record("GET /recall", "agent:again", start + 2)
        .unwrap();
    assert_eq!(
        counter.question(start, start + 86_400).unwrap().unwrap(),
        hook
    );
    counter
        .record("write", "agent:again", start + 86_401)
        .unwrap();
    assert_eq!(
        counter
            .receipt(start, start + 86_400)
            .unwrap()
            .unwrap()
            .by_verb["GET /recall"],
        50_002
    );
}

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

#[test]
fn restart_restores_the_active_wire_window_and_threshold_question() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
    let before = WireTelemetry::new(vault.clone());
    before
        .set_thresholds(&WireThresholds {
            window_secs: 60,
            per_verb: 2,
            per_actor: 100,
        })
        .unwrap();
    before.record("recall", "reader", 121).unwrap();
    before.record("recall", "reader", 122).unwrap();
    before.flush().unwrap();
    drop(before);
    let after = WireTelemetry::new(vault.clone());
    after.record("recall", "reader", 123).unwrap();
    let snapshot = after.snapshot().unwrap().unwrap();
    assert_eq!(snapshot.by_verb["recall"], 3);
    assert_eq!(snapshot.by_actor["reader"], 3);
    let question = after.question(120, 180).unwrap().unwrap();
    assert_eq!(question.evidence, snapshot);
    after.flush().unwrap();
    assert_eq!(after.receipt(120, 180).unwrap(), Some(snapshot));
    drop(after);
    let again = WireTelemetry::new(vault);
    again.record("write", "other", 124).unwrap();
    again.flush().unwrap();
    assert_eq!(
        again.receipt(120, 180).unwrap().unwrap().by_verb["recall"],
        3
    );
    assert_eq!(
        again.receipt(120, 180).unwrap().unwrap().by_actor["other"],
        1
    );
    assert_eq!(again.question(120, 180).unwrap(), Some(question));
}

#[test]
fn duration_change_preserves_both_receipts_and_questions_at_shared_start() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
    let counter = WireTelemetry::new(vault.clone());
    counter
        .set_thresholds(&WireThresholds {
            window_secs: 60,
            per_verb: 1,
            per_actor: 1,
        })
        .unwrap();
    counter.record("old", "reader", 121).unwrap();
    counter.record("old", "reader", 122).unwrap();
    counter
        .set_thresholds(&WireThresholds {
            window_secs: 120,
            per_verb: 1,
            per_actor: 1,
        })
        .unwrap();
    counter.record("new", "writer", 130).unwrap();
    counter.record("new", "writer", 131).unwrap();
    counter.flush().unwrap();
    let old = counter.receipt(120, 180).unwrap().unwrap();
    let new = counter.receipt(120, 240).unwrap().unwrap();
    assert_eq!(old.by_verb, BTreeMap::from([("old".to_owned(), 2)]));
    assert_eq!(new.by_verb, BTreeMap::from([("new".to_owned(), 2)]));
    let old_question = counter.question(120, 180).unwrap().unwrap();
    let new_question = counter.question(120, 240).unwrap().unwrap();
    assert_eq!(old_question.evidence, old);
    assert_eq!(new_question.evidence, new);
    drop(counter);
    let restarted = WireTelemetry::new(vault);
    restarted.record("new", "writer", 132).unwrap();
    restarted.flush().unwrap();
    assert_eq!(restarted.receipt(120, 180).unwrap(), Some(old));
    assert_eq!(
        restarted.receipt(120, 240).unwrap().unwrap().by_verb["new"],
        3
    );
    assert_eq!(restarted.question(120, 180).unwrap(), Some(old_question));
    assert_eq!(restarted.question(120, 240).unwrap(), Some(new_question));
}
