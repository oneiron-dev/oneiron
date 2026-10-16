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

/// Review r4 (Sol, P2): a row's first crossing in a new minute replaced its
/// question for the minute before even when that one was not kept yet (its
/// write failed, or the minute turned between two ticks), so the earlier
/// minute's crossings were never kept.
#[test]
fn a_question_not_kept_yet_outlasts_the_next_minutes_crossing() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
    let telemetry = WireTelemetry::new(vault);
    let questions = telemetry.limit_questions();
    questions.ask_at(LimitRow::GitExchanges, 2_048, 2_049, 600);
    questions.ask_at(LimitRow::GitExchanges, 2_048, 2_050, 630);
    questions.ask_at(LimitRow::GitExchanges, 2_048, 2_049, 660);

    telemetry.flush().unwrap();
    let earlier = telemetry
        .limit_question(LimitRow::GitExchanges, 600)
        .unwrap()
        .expect("the earlier minute is kept");
    assert_eq!((earlier.crossings, earlier.observed), (2, 2_050));
    assert!(
        telemetry
            .limit_question(LimitRow::GitExchanges, 660)
            .unwrap()
            .is_some()
    );
}

/// Review r5 (Sol R5-4, P2): a server started again within a minute wrote
/// its question for that minute over the one the run before it kept, so that
/// run's crossings were lost.
#[test]
fn a_restart_within_a_minute_keeps_the_crossings_the_last_run_kept() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
    let before = WireTelemetry::new(Arc::clone(&vault));
    before
        .limit_questions()
        .ask_at(LimitRow::GitExchanges, 2_048, 2_050, 600);
    before
        .limit_questions()
        .ask_at(LimitRow::GitExchanges, 2_048, 2_049, 610);
    before.flush().unwrap();
    drop(before);

    let after = WireTelemetry::new(vault);
    after
        .limit_questions()
        .ask_at(LimitRow::GitExchanges, 2_048, 2_049, 630);
    after.flush().unwrap();
    let kept = after
        .limit_question(LimitRow::GitExchanges, 600)
        .unwrap()
        .expect("kept");
    assert_eq!(
        (kept.crossings, kept.observed, kept.raised_at),
        (3, 2_050, 600),
        "both runs' crossings count in the minute's question"
    );
}

/// Review r5 (Astra R5-1, P2): the observation tick wrote pending limit
/// questions under the lock every request's record takes, so while another
/// write held the vault's writer, every request waited on the question.
#[test]
fn a_question_waiting_for_the_vaults_writer_holds_no_request_back() {
    use std::sync::mpsc;
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
    let telemetry = Arc::new(WireTelemetry::new(Arc::clone(&vault)));
    let now = oneiron_vault_contract::now_ts();
    // The request's window is open, so recording it again writes nothing.
    telemetry.record("GET /api/health", "caller", now).unwrap();
    telemetry
        .limit_questions()
        .ask(LimitRow::GitExchanges, 2_048, 2_049);
    let asked = telemetry
        .limit_questions()
        .latest(LimitRow::GitExchanges)
        .expect("asked");

    let (held, writer_held) = mpsc::channel();
    let (release, released) = mpsc::channel::<()>();
    let writer = {
        let vault = Arc::clone(&vault);
        std::thread::spawn(move || {
            vault.with_write_txn(|_| {
                held.send(()).unwrap();
                let _ = released.recv();
                Ok(())
            })
        })
    };
    writer_held.recv().unwrap();
    let tick = {
        let telemetry = Arc::clone(&telemetry);
        std::thread::spawn(move || telemetry.flush_if_expired(now))
    };
    // Time for the tick to reach the writer it waits for.
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !tick.is_finished(),
        "the question's write waits for the writer"
    );

    let (recorded, record_returned) = mpsc::channel();
    let request = {
        let telemetry = Arc::clone(&telemetry);
        std::thread::spawn(move || {
            let result = telemetry.record("GET /api/health", "caller", now);
            let _ = recorded.send(());
            result
        })
    };
    let waited = record_returned.recv_timeout(Duration::from_secs(10));
    release.send(()).unwrap();
    writer.join().unwrap().unwrap();
    tick.join().unwrap().unwrap();
    request.join().unwrap().unwrap();
    assert!(
        waited.is_ok(),
        "a request is recorded while the question waits for the writer"
    );
    let window = asked.raised_at / LIMIT_QUESTION_WINDOW_SECS * LIMIT_QUESTION_WINDOW_SECS;
    assert!(
        telemetry
            .limit_question(LimitRow::GitExchanges, window)
            .unwrap()
            .is_some(),
        "the question is kept once the writer is free"
    );
}
