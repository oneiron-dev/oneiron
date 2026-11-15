#![cfg(all(unix, oneiron_test_support))]
//! The recovery box's kit-only hold caller (Fable pass 27 R7; Engine RULING
//! WAYBACK-BOX-HOLD-RELAY = A, 16 Nov 01:02): one `recovery_box_kit_only`
//! line with the vault's name, its spawn token and the choice goes to the
//! supervisor socket, and the call is `Ok` only when the supervisor answers
//! `{"held":true}`. Every other answer fails the call, so the recovery preset
//! switch that asks for the hold is refused: a refusal, a ledger ack from a
//! supervisor built before the op, an answer outside the contract, a closed
//! connection, no answer within the bound, and no supervisor at all.

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use oneiron_server::test_doors::recovery_box_hold::hold_client;

const VAULT: &str = "vault-7";
const BOUND: Duration = Duration::from_secs(5);

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
            Answer::Line(text) => {
                stream.write_all(text.as_bytes()).expect("answer");
                stream.write_all(b"\n").expect("answer's end");
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
    let (_dir, socket, supervisor) = supervisor(Answer::Silence(Duration::from_secs(3)));
    let client = hold_client(&socket, VAULT, &token(), Duration::from_millis(300));
    let started = Instant::now();
    let error = client
        .hold_kit_only(true)
        .expect_err("silence is not a held answer")
        .to_string();
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the bound holds"
    );
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
    let (_dir, socket, _supervisor) = supervisor(Answer::Line(r#"{"held":true}"#));
    let client = hold_client(&socket, VAULT, "not-a-token", BOUND);
    client
        .hold_kit_only(true)
        .expect_err("a request the supervisor would refuse is not sent");
}
