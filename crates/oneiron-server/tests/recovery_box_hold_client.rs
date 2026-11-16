#![cfg(all(unix, oneiron_test_support))]
//! The recovery box's kit-only hold caller (Fable pass 27 R7; Engine RULING
//! WAYBACK-BOX-HOLD-RELAY = A, 16 Nov 01:02): one `recovery_box_kit_only`
//! line with the vault's name, its spawn token and the choice goes to the
//! supervisor socket, and the call is `Ok` only when the supervisor answers
//! `{"held":true}`. Every other answer fails the call, so the recovery preset
//! switch that asks for the hold is refused: a refusal, a ledger ack from a
//! supervisor built before the op, an answer outside the contract, a closed
//! connection, no answer within the bound, and no supervisor at all.
//!
//! The same caller reports the vault's recovery wait and carries an owner
//! device's cancel of the box's pending release
//! (WAYBACK-WAIT-BINDS-HONEST-CLIENT-ONLY = B, lead 17 Nov 00:1x): each sends
//! its exact line, and only an answer inside its contract is `Ok`. The cancel
//! names the owner and device key that cancelled, and the release it voids
//! when the device saw one (WAYBACK-COOWNER-CANCEL-OTHER-OWNERS-RECOVERY = B).

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron_server::test_doors::recovery_box_hold::hold_client;

const VAULT: &str = "vault-7";
const BOUND: Duration = Duration::from_secs(5);
/// The owner device key the cancels in these tests name.
const DEVICE_KEY: [u8; 32] = [0xcd; 32];

/// The owner the cancels in these tests name.
fn person() -> EntityId {
    EntityId::from_hex(&"12".repeat(16)).expect("a person id")
}

fn token() -> String {
    "c3".repeat(32)
}

/// What the test's supervisor does with the one line it reads.
enum Answer {
    Line(&'static str),
    Close,
    Silence(Duration),
}

/// A supervisor on a fresh socket that reads one line, then answers as told;
/// the line it read comes back from the handle.
fn supervisor(answer: Answer) -> (tempfile::TempDir, PathBuf, JoinHandle<String>) {
    let dir = tempfile::tempdir().expect("temp dir");
    let socket = dir.path().join("hypnos.sock");
    let listener = UnixListener::bind(&socket).expect("bind the supervisor socket");
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept the vault");
        let mut reader = BufReader::new(stream.try_clone().expect("clone the stream"));
        let mut line = String::new();
        reader.read_line(&mut line).expect("read the request");
        // the clone holds the connection open too: a close must drop both
        drop(reader);
        let mut stream = stream;
        match answer {
            // a caller that gave up may be gone: its answer is then lost
            Answer::Line(text) => {
                stream.write_all(text.as_bytes()).ok();
                stream.write_all(b"\n").ok();
            }
            Answer::Close => drop(stream),
            Answer::Silence(hold) => std::thread::sleep(hold),
        }
        line
    });
    (dir, socket, handle)
}

fn expected_line(kit_only: bool) -> String {
    format!(
        "{{\"op\":\"recovery_box_kit_only\",\"vault\":\"{VAULT}\",\"token\":\"{}\",\"kit_only\":{kit_only}}}\n",
        token()
    )
}

#[test]
fn recovery_box_hold_held_answer_is_ok_and_the_line_is_exact() {
    for kit_only in [true, false] {
        let (_dir, socket, supervisor) = supervisor(Answer::Line(r#"{"held":true}"#));
        let client = hold_client(&socket, VAULT, &token(), BOUND);
        client.hold_kit_only(kit_only).expect("a held answer is Ok");
        assert_eq!(
            supervisor.join().expect("supervisor"),
            expected_line(kit_only)
        );
    }
}

#[test]
fn recovery_box_hold_refusal_fails_with_its_code() {
    let (_dir, socket, supervisor) =
        supervisor(Answer::Line(r#"{"held":false,"error":"stale_generation"}"#));
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let error = client
        .hold_kit_only(true)
        .expect_err("a refusal fails the hold")
        .to_string();
    assert!(error.contains("stale_generation"), "{error}");
    assert!(
        !error.contains(&token()),
        "the token never reaches an error"
    );
    supervisor.join().expect("supervisor");
}

#[test]
fn recovery_box_hold_ledger_ack_from_an_older_supervisor_fails() {
    // what hypsock answers a line it reads as a ledger page and cannot decode
    let (_dir, socket, supervisor) = supervisor(Answer::Line(
        r#"{"ok":false,"error":"missing field `page`","report":null,"offset":null,"committed":false}"#,
    ));
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    client
        .hold_kit_only(true)
        .expect_err("a ledger ack is not a held answer");
    supervisor.join().expect("supervisor");
}

#[test]
fn recovery_box_hold_answers_outside_the_contract_fail() {
    for answer in [
        r#"{"held":true,"error":"refused"}"#,
        r#"{"held":false}"#,
        r#"{"held":false,"error":"Not A Code"}"#,
        r#"{"held":true,"box":false}"#,
        "held",
    ] {
        let (_dir, socket, supervisor) = supervisor(Answer::Line(answer));
        let client = hold_client(&socket, VAULT, &token(), BOUND);
        assert!(client.hold_kit_only(true).is_err(), "{answer}");
        supervisor.join().expect("supervisor");
    }
}

#[test]
fn recovery_box_hold_closed_connection_fails() {
    let (_dir, socket, supervisor) = supervisor(Answer::Close);
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    client
        .hold_kit_only(false)
        .expect_err("no answer is not a held answer");
    supervisor.join().expect("supervisor");
}

#[test]
fn recovery_box_hold_no_answer_within_the_bound_fails() {
    let (_dir, socket, supervisor) = supervisor(Answer::Silence(Duration::from_secs(6)));
    let client = hold_client(&socket, VAULT, &token(), Duration::from_millis(300));
    let started = Instant::now();
    let error = client
        .hold_kit_only(true)
        .expect_err("silence is not a held answer")
        .to_string();
    let waited = started.elapsed();
    // it waited for the answer, and gave up at its bound, long before the
    // supervisor's close at 6 s would have ended the call
    assert!(waited >= Duration::from_millis(250), "{waited:?}");
    assert!(waited < Duration::from_secs(5), "{waited:?}");
    assert!(error.contains("no answer"), "{error}");
    supervisor.join().expect("supervisor");
}

#[test]
fn recovery_box_hold_without_a_supervisor_fails() {
    let dir = tempfile::tempdir().expect("temp dir");
    let client = hold_client(&dir.path().join("hypnos.sock"), VAULT, &token(), BOUND);
    client
        .hold_kit_only(true)
        .expect_err("no supervisor is not a held answer");
}

#[test]
fn recovery_box_hold_malformed_token_is_never_sent() {
    let (_dir, socket, supervisor) = supervisor(Answer::Line(r#"{"held":true}"#));
    let client = hold_client(&socket, VAULT, "not-a-token", BOUND);
    client
        .hold_kit_only(true)
        .expect_err("a request the supervisor would refuse is not sent");
    // the call never connected: a connection of the test's own releases the
    // supervisor, which read nothing
    drop(UnixStream::connect(&socket).expect("connect to release the supervisor"));
    assert_eq!(supervisor.join().expect("supervisor"), "");
}

fn expected_wait_line(wait_secs: u64) -> String {
    format!(
        "{{\"op\":\"recovery_box_wait\",\"vault\":\"{VAULT}\",\"token\":\"{}\",\"wait_secs\":{wait_secs}}}\n",
        token()
    )
}

fn expected_cancel_line(release_receipt: Option<u64>) -> String {
    let receipt = release_receipt.map_or_else(String::new, |n| format!(",\"release_receipt\":{n}"));
    format!(
        "{{\"op\":\"recovery_box_cancel\",\"vault\":\"{VAULT}\",\"token\":\"{}\",\"cancelled_by\":{{\"person\":\"{}\",\"device_key\":\"{}\"}}{receipt}}}\n",
        token(),
        "12".repeat(16),
        "cd".repeat(32)
    )
}

#[test]
fn recovery_wait_report_sends_whole_seconds_and_is_ok_when_held() {
    for (wait, secs) in [
        (Duration::ZERO, 0),
        (Duration::from_secs(24 * 3_600), 86_400),
        (Duration::from_millis(3_600_900), 3_600),
        (Duration::from_secs(30 * 24 * 3_600), 2_592_000),
    ] {
        let (_dir, socket, supervisor) = supervisor(Answer::Line(r#"{"held":true}"#));
        let client = hold_client(&socket, VAULT, &token(), BOUND);
        client
            .report_recovery_wait(wait)
            .expect("a held answer is Ok");
        assert_eq!(
            supervisor.join().expect("supervisor"),
            expected_wait_line(secs)
        );
    }
}

#[test]
fn recovery_wait_report_over_thirty_days_is_never_sent() {
    let (_dir, socket, supervisor) = supervisor(Answer::Line(r#"{"held":true}"#));
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let error = client
        .report_recovery_wait(Duration::from_secs(30 * 24 * 3_600 + 1))
        .expect_err("a wait over 30 days is refused")
        .to_string();
    assert!(error.contains("over 30 days"), "{error}");
    drop(UnixStream::connect(&socket).expect("connect to release the supervisor"));
    assert_eq!(supervisor.join().expect("supervisor"), "");
}

#[test]
fn recovery_wait_report_fails_on_every_other_answer() {
    for answer in [
        r#"{"held":false,"error":"stale_generation"}"#,
        r#"{"held":true,"cancelled":true}"#,
        r#"{"held":false}"#,
        r#"{"ok":false,"error":"missing field `page`","report":null,"offset":null,"committed":false}"#,
    ] {
        let (_dir, socket, supervisor) = supervisor(Answer::Line(answer));
        let client = hold_client(&socket, VAULT, &token(), BOUND);
        let error = client
            .report_recovery_wait(Duration::from_secs(60))
            .expect_err(answer)
            .to_string();
        assert!(error.contains("recovery wait report"), "{error}");
        assert!(
            !error.contains(&token()),
            "the token never reaches an error"
        );
        supervisor.join().expect("supervisor");
    }
}

#[test]
fn cancel_sends_its_line_and_says_whether_a_release_was_voided() {
    for (answer, voided, release_receipt) in [
        (r#"{"held":true,"cancelled":true}"#, true, None),
        (r#"{"held":true,"cancelled":false}"#, false, None),
        (r#"{"held":true,"cancelled":true}"#, true, Some(41)),
        (r#"{"held":true,"cancelled":false}"#, false, Some(41)),
    ] {
        let (_dir, socket, supervisor) = supervisor(Answer::Line(answer));
        let client = hold_client(&socket, VAULT, &token(), BOUND);
        assert_eq!(
            client
                .cancel_pending_box_release(person(), &DEVICE_KEY, release_receipt)
                .expect("a held answer is Ok"),
            voided,
            "{answer}"
        );
        assert_eq!(
            supervisor.join().expect("supervisor"),
            expected_cancel_line(release_receipt),
            "the line names the owner, the device key and the release it voids"
        );
    }
}

#[test]
fn cancel_fails_on_every_other_answer() {
    for answer in [
        r#"{"held":true}"#,
        r#"{"held":false,"error":"wrong_node"}"#,
        r#"{"held":false,"cancelled":false,"error":"refused"}"#,
        r#"{"held":true,"cancelled":true,"error":"refused"}"#,
        "cancelled",
    ] {
        let (_dir, socket, supervisor) = supervisor(Answer::Line(answer));
        let client = hold_client(&socket, VAULT, &token(), BOUND);
        let error = client
            .cancel_pending_box_release(person(), &DEVICE_KEY, None)
            .expect_err(answer)
            .to_string();
        assert!(error.contains("cancel of a pending release"), "{error}");
        supervisor.join().expect("supervisor");
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let client = hold_client(&dir.path().join("hypnos.sock"), VAULT, &token(), BOUND);
    client
        .cancel_pending_box_release(person(), &DEVICE_KEY, None)
        .expect_err("no supervisor is no cancel");
}

#[test]
fn recovery_wait_report_and_cancel_refusals_carry_their_code_and_never_the_token() {
    let (_dir, socket, supervisor) =
        supervisor(Answer::Line(r#"{"held":false,"error":"stale_generation"}"#));
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let error = client
        .report_recovery_wait(Duration::from_secs(60))
        .expect_err("a refusal fails the report")
        .to_string();
    assert!(
        error.contains("was refused by the supervisor (stale_generation)"),
        "{error}"
    );
    assert!(
        !error.contains(&token()),
        "the token never reaches an error"
    );
    supervisor.join().expect("supervisor");

    let (_dir, socket, supervisor) =
        supervisor(Answer::Line(r#"{"held":false,"error":"wrong_node"}"#));
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    let error = client
        .cancel_pending_box_release(person(), &DEVICE_KEY, None)
        .expect_err("a refusal fails the cancel")
        .to_string();
    assert!(
        error.contains("was refused by the supervisor (wrong_node)"),
        "{error}"
    );
    assert!(
        !error.contains(&token()),
        "the token never reaches an error"
    );
    supervisor.join().expect("supervisor");

    // what hypsock answers a line it reads as a ledger page: not a cancel answer
    let (_dir, socket, supervisor) = supervisor(Answer::Line(
        r#"{"ok":false,"error":"missing field `page`","report":null,"offset":null,"committed":false}"#,
    ));
    let client = hold_client(&socket, VAULT, &token(), BOUND);
    client
        .cancel_pending_box_release(person(), &DEVICE_KEY, None)
        .expect_err("a ledger ack is not a cancel answer");
    supervisor.join().expect("supervisor");
}

#[test]
fn recovery_wait_report_and_cancel_with_a_malformed_token_are_never_sent() {
    for cancel in [false, true] {
        let (_dir, socket, supervisor) = supervisor(Answer::Line(r#"{"held":true}"#));
        let client = hold_client(&socket, VAULT, "not-a-token", BOUND);
        if cancel {
            client
                .cancel_pending_box_release(person(), &DEVICE_KEY, None)
                .expect_err("a request the supervisor would refuse is not sent");
        } else {
            client
                .report_recovery_wait(Duration::from_secs(60))
                .expect_err("a request the supervisor would refuse is not sent");
        }
        drop(UnixStream::connect(&socket).expect("connect to release the supervisor"));
        assert_eq!(
            supervisor.join().expect("supervisor"),
            "",
            "cancel={cancel}"
        );
    }
}
