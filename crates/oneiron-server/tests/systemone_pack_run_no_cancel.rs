//! [SYSTEMONE-PACK-RUN-NO-CANCEL] (FIX-LIST l26281): a caller-run pack decide
//! whose work is cancelled while the seat call is pending returns at once with
//! the same answer the caller-run single decide gives on cancel. It does not
//! wait the seat call out.
//!
//! Each case binds the System One rung to a stub seat that reads one request
//! and holds it past the call's own time left, then cancels the work under the
//! pending call. Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --test systemone_pack_run_no_cancel`.
#![cfg(oneiron_test_support)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use oneiron::llm::decision::{
    AnswerContract, DecisionCall, DecisionClass, DecisionPack, DecisionQuestion,
};
use oneiron::llm::run_admission::RunAdmission;
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::{BudgetExhaustionPolicy, BudgetGuard, EntityId, Vault, VaultConfig};
use oneiron_server::models::ModelRuntime;
use oneiron_server::test_doors::system_one_rung::{SystemOneRungForTest, system_one_rung_for_test};
use serde_json::json;

/// The stub seat's bearer, which the rung holds from bind.
const BEARER: &str = "stub-key";
/// How long the stub holds one seat call: past the test's patience and the
/// call's own time left, so a decide that waits the seat out always overruns.
const HOLD: Duration = Duration::from_secs(60);
/// The call's whole budget; its seat-call time left is three quarters of it.
const BUDGET: Duration = Duration::from_secs(24);
/// A cancelled decide returns well within this; waiting the seat out takes
/// the whole time left.
const PATIENCE: Duration = Duration::from_secs(10);

/// A stub seat: reads one request at a loopback `/v1/systemone` endpoint,
/// marks it received, then holds the call for [`HOLD`] without answering.
/// Returns the endpoint and the received flag. The holder thread is detached:
/// the process exit reaps it after the assertions ran.
fn holding_seat() -> (String, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("the stub seat binds");
    let endpoint = format!(
        "http://{}/v1/systemone",
        listener.local_addr().expect("the stub seat address")
    );
    let received = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&received);
    std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("the stub seat accepts");
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("the stub seat read timeout");
        let mut bytes = Vec::new();
        let end = loop {
            let mut chunk = [0u8; 4096];
            let n = socket.read(&mut chunk).expect("the stub seat reads");
            assert!(n > 0 && bytes.len() < 65_536);
            bytes.extend_from_slice(&chunk[..n]);
            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                break end + 4;
            }
        };
        let headers = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
        assert!(
            headers.starts_with("post /v1/systemone http/1.1"),
            "the seat posts its call: {headers}"
        );
        assert!(
            headers.contains("authorization: bearer stub-key"),
            "the seat call carries the key"
        );
        let length: usize = headers
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .expect("the seat call names its length")
            .trim()
            .parse()
            .expect("the seat call length parses");
        while bytes.len() - end < length {
            let mut chunk = [0u8; 4096];
            let n = socket
                .read(&mut chunk)
                .expect("the stub seat reads its body");
            assert!(n > 0);
            bytes.extend_from_slice(&chunk[..n]);
        }
        flag.store(true, Ordering::SeqCst);
        // Hold the call: never answer within the test's patience.
        std::thread::sleep(HOLD);
        // Best effort: the client is long gone.
        let _ = socket.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        );
    });
    (endpoint, received)
}

struct Fixture {
    rung: SystemOneRungForTest,
    received: Arc<AtomicBool>,
    _vault_dir: tempfile::TempDir,
    _runtime: tokio::runtime::Runtime,
}

/// The System One rung against a fresh stub seat.
fn fixture() -> Fixture {
    let (endpoint, received) = holding_seat();
    let vault_dir = tempfile::tempdir().expect("the fixture vault dir");
    let vault =
        Arc::new(Vault::open(vault_dir.path(), VaultConfig::default()).expect("the fixture vault"));
    let runtime = tokio::runtime::Runtime::new().expect("the test runtime");
    let rung = system_one_rung_for_test(
        endpoint,
        BEARER.to_owned(),
        Arc::new(ModelRuntime::unconfigured()),
        vault,
        runtime.handle().clone(),
    )
    .expect("the stub-bound rung");
    Fixture {
        rung,
        received,
        _vault_dir: vault_dir,
        _runtime: runtime,
    }
}

/// The caller's run, on its own meter, as a caller meters its pack.
fn caller_run() -> RunAdmission {
    ModelRuntime::unconfigured().funded_run(
        "pack-cancel-test",
        BudgetGuard::with_reserve_units(
            "pack-cancel-test",
            1_000_000,
            1_000,
            BudgetExhaustionPolicy::Suspend,
        ),
        None,
    )
}

fn question() -> DecisionQuestion {
    DecisionQuestion {
        id: EntityId::now(),
        version: 1,
        text: "Caller-owned question with criteria".to_owned(),
        class: DecisionClass::Judgment,
        contract: AnswerContract::Noul,
        accept_type: false,
    }
}

/// Cancels `deadline` once the seat call is pending: when the stub has the
/// request, plus a beat so the decide is inside its seat wait.
fn cancel_when_pending(
    deadline: &RetrievalDeadline,
    received: &Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    let cancel = deadline.work_cancel();
    let received = Arc::clone(received);
    std::thread::spawn(move || {
        let start = Instant::now();
        while !received.load(Ordering::SeqCst) {
            assert!(
                start.elapsed() < Duration::from_secs(15),
                "the seat call never reached the stub"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(300));
        cancel.cancel();
    })
}

/// A caller-run pack decide cancelled mid-seat-call returns at once with the
/// cancel answer instead of waiting the seat call out.
#[test]
fn caller_run_pack_cancel_returns_at_once() {
    let fixture = fixture();
    let run = caller_run();
    let deadline = RetrievalDeadline::after(BUDGET);
    let question = question();
    let questions = [&question];
    let state = json!({"unit": {"value": "example"}});
    let evidence: Vec<EntityId> = Vec::new();
    let pack = DecisionPack {
        questions: &questions,
        evidence: &evidence,
        images: &[],
        audio: &[],
        state: &state,
        deadline: &deadline,
        run: Some(&run),
        labels: None,
    };
    let canceller = cancel_when_pending(&deadline, &fixture.received);
    let started = Instant::now();
    let outcome = fixture.rung.decide_pack(&pack);
    let elapsed = started.elapsed();
    canceller.join().expect("the canceller fired");
    assert!(
        elapsed < PATIENCE,
        "a pack decide cancelled mid-seat-call returns at once, took {elapsed:?}"
    );
    let Err(error) = outcome else {
        panic!("a pack decide cancelled mid-seat-call answers instead of refusing");
    };
    let message = error.to_string();
    assert!(
        message.contains("the seat call was cancelled"),
        "a cancelled pack decide answers the cancel, got: {message}"
    );
}

/// A caller-run single decide cancelled mid-seat-call answers the same
/// cancel: the pack's answer above is the single's answer.
#[test]
fn caller_run_single_cancel_matches_pack() {
    let fixture = fixture();
    let run = caller_run();
    let deadline = RetrievalDeadline::after(BUDGET);
    let question = question();
    let state = json!({"unit": {"value": "example"}});
    let evidence: Vec<EntityId> = Vec::new();
    let call = DecisionCall {
        question: &question,
        evidence: &evidence,
        images: &[],
        audio: &[],
        state: &state,
        deadline: &deadline,
        run: Some(&run),
        labels: None,
    };
    let canceller = cancel_when_pending(&deadline, &fixture.received);
    let started = Instant::now();
    let outcome = fixture.rung.decide(&call);
    let elapsed = started.elapsed();
    canceller.join().expect("the canceller fired");
    assert!(
        elapsed < PATIENCE,
        "a single decide cancelled mid-seat-call returns at once, took {elapsed:?}"
    );
    let Err(error) = outcome else {
        panic!("a single decide cancelled mid-seat-call answers instead of refusing");
    };
    let message = error.to_string();
    assert!(
        message.contains("the seat call was cancelled"),
        "a cancelled single decide answers the cancel, got: {message}"
    );
}
