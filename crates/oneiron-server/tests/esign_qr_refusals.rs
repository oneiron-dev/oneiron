//! Guesses at a QR page capability (ARCH-0064a section 6: enumeration
//! signals go to counters, with no rate refusal; FIX
//! [ESIGN-QR-CAPABILITY-PAGE] part 2): each refused report counts in the
//! wire window under no caller, beside the call that carried it, and past
//! the per-verb row the refusals ask the call-volume question. Every guess
//! gets the same answer, and none is refused for its rate. The QR PDF
//! download route (RULING ESIGN-QR-POSSESSION-FACTOR B) refuses and counts
//! the same way.
//!
//! Fleet command: `cargo test --locked -p oneiron-server --all-features
//! --test esign_qr_refusals`.
use axum::body::Body;
use axum::http::{Request, StatusCode};
use oneiron_server::wire_telemetry::{WireTelemetry, WireThresholds};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use std::sync::Arc;
use tower::ServiceExt;

/// The report route as the wire window names it.
const REPORT: &str = "POST /esign/verify/report";
/// The QR PDF download route as the wire window names it.
const PDF: &str = "POST /esign/verify/pdf";

/// The router runs on threads sized as the server sizes its own.
fn run_on_engine_stack(name: &str, test: impl std::future::Future<Output = ()> + Send + 'static) {
    let run = std::thread::Builder::new()
        .name(name.into())
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .expect("engine-sized test runtime")
                .block_on(test)
        })
        .expect("spawn the engine-sized test thread");
    if let Err(panic) = run.join() {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn refused_qr_reports_count_in_the_wire_window_and_ask_past_the_per_verb_row() {
    run_on_engine_stack("esign-qr-refusals", refused_reports());
}

/// A server on a fresh vault whose wire window asks past `per_verb` calls.
fn serve(
    dir: &tempfile::TempDir,
    window_secs: u64,
    per_verb: u64,
) -> (Arc<oneiron::Vault>, Arc<SyncServer>) {
    let vault = Arc::new(
        oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).expect("open the vault"),
    );
    let observer = WireTelemetry::new(Arc::clone(&vault));
    observer
        .set_thresholds(&WireThresholds {
            window_secs,
            per_verb,
            per_actor: u64::MAX,
        })
        .expect("set the wire rows");
    drop(observer);
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                lease_vault_id: 1,
                ..Default::default()
            },
        )
        .expect("start the server"),
    );
    (vault, server)
}

async fn refused_reports() {
    let dir = tempfile::tempdir().expect("create the vault directory");
    let window_secs = 604_800;
    let (vault, server) = serve(&dir, window_secs, 2);
    let app = build_app(Arc::clone(&server));
    // Two well-formed capabilities no seal printed, a malformed one, and a
    // report with no capability at all.
    let guesses = [
        Some("ab".repeat(32)),
        Some("cd".repeat(32)),
        Some("not-a-capability".to_owned()),
        None,
    ];
    let mut answers = Vec::new();
    for guess in &guesses {
        let mut request = Request::builder()
            .method("POST")
            .uri("/esign/verify/report");
        if let Some(guess) = guess {
            request = request.header("x-oneiron-esign-qr-capability", guess.as_str());
        }
        let answer = app
            .clone()
            .oneshot(
                request
                    .body(Body::empty())
                    .expect("build the report request"),
            )
            .await
            .expect("route the report");
        assert_eq!(
            answer.status(),
            StatusCode::NOT_FOUND,
            "every guess gets the one refusal, never a rate refusal"
        );
        let body = axum::body::to_bytes(answer.into_body(), 1 << 16)
            .await
            .expect("read the refusal");
        answers.push(body);
    }
    assert!(
        answers.iter().all(|body| *body == answers[0]),
        "one answer for every guess"
    );
    drop(app);
    drop(server); // the server's own counter keeps the window on drop

    let observer = WireTelemetry::new(vault);
    let now = oneiron_vault_contract::now_ts();
    let start = now / window_secs * window_secs;
    let receipt = observer
        .receipt(start, start + window_secs)
        .expect("read the window")
        .expect("the window was kept");
    assert_eq!(
        receipt.by_verb.get(REPORT).copied(),
        Some(4),
        "each report counts as a call"
    );
    assert_eq!(
        receipt.capability_refusals.get(REPORT).copied(),
        Some(4),
        "each refusal counts beside its call, under no caller"
    );
    assert!(
        receipt
            .by_verb
            .keys()
            .chain(receipt.capability_refusals.keys())
            .all(|key| !key.contains(&"ab".repeat(32))),
        "no guess is kept"
    );
    let question = observer
        .question(start, start + window_secs)
        .expect("read the window's question")
        .expect("the window asked");
    assert!(
        question.crossed.capability_refusals.contains(REPORT),
        "past the per-verb row the refusals ask: {:?}",
        question.crossed
    );
    assert_eq!(
        question.evidence.capability_refusals.get(REPORT).copied(),
        Some(3),
        "the question keeps the refusals as they stood when they crossed"
    );
}

#[test]
fn refused_qr_pdf_downloads_count_beside_their_route() {
    run_on_engine_stack("esign-qr-pdf-refusals", refused_pdf_downloads());
}

async fn refused_pdf_downloads() {
    let dir = tempfile::tempdir().expect("create the vault directory");
    let window_secs = 604_800;
    let (vault, server) = serve(&dir, window_secs, u64::MAX);
    let app = build_app(Arc::clone(&server));
    // A capability no seal printed, no capability at all, and a body that
    // names no item.
    let guesses = [
        (Some("ab".repeat(32)), r#"{"item":0}"#),
        (None, r#"{"item":0}"#),
        (Some("cd".repeat(32)), "not json"),
    ];
    let mut answers = Vec::new();
    for (guess, body) in &guesses {
        let mut request = Request::builder().method("POST").uri("/esign/verify/pdf");
        if let Some(guess) = guess {
            request = request.header("x-oneiron-esign-qr-capability", guess.as_str());
        }
        let answer = app
            .clone()
            .oneshot(
                request
                    .body(Body::from(*body))
                    .expect("build the download request"),
            )
            .await
            .expect("route the download");
        assert_eq!(
            answer.status(),
            StatusCode::NOT_FOUND,
            "every guess gets the one refusal, never a rate refusal"
        );
        assert_ne!(
            answer
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/pdf"),
            "a refusal carries no PDF"
        );
        answers.push(
            axum::body::to_bytes(answer.into_body(), 1 << 16)
                .await
                .expect("read the refusal"),
        );
    }
    assert!(
        answers.iter().all(|body| *body == answers[0]),
        "one answer for every guess"
    );
    drop(app);
    drop(server); // the server's own counter keeps the window on drop

    let observer = WireTelemetry::new(vault);
    let now = oneiron_vault_contract::now_ts();
    let start = now / window_secs * window_secs;
    let receipt = observer
        .receipt(start, start + window_secs)
        .expect("read the window")
        .expect("the window was kept");
    assert_eq!(
        receipt.by_verb.get(PDF).copied(),
        Some(3),
        "each download counts as a call"
    );
    assert_eq!(
        receipt.capability_refusals.get(PDF).copied(),
        Some(3),
        "each refused download counts beside its call, under no caller"
    );
    assert_eq!(
        receipt.capability_refusals.get(REPORT).copied(),
        None,
        "a download is counted on its own route"
    );
}
