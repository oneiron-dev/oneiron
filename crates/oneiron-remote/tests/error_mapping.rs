//! ONE-1441 error-contract tests (blueprint §Test/Shared #5–#6, §Typed error
//! contract).
//!
//! The property under test is that EVERY failure a caller can provoke arrives
//! as the same `{code, message, suggestions}` triple, with a non-empty
//! suggestion list and without any foreign response body laundered into it.

use oneiron::memory::{
    Effort, MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL,
    MEMORY_CODE_LEASE_REQUIRED, RecallScope,
};
use oneiron_remote::{OneironClient, OpenOptions};

/// Every URL shape the transport contract refuses, refused at `connect`.
#[test]
fn connect_normalizes_the_origin_once() {
    let rejected = [
        ("", "empty"),
        ("127.0.0.1:8080", "missing scheme"),
        ("ftp://example.invalid/", "unsupported scheme"),
        ("http://user:pass@example.invalid/", "userinfo"),
        ("http://example.invalid/?a=b", "query string"),
        ("http://example.invalid/#frag", "fragment"),
    ];
    for (url, why) in rejected {
        let error = OneironClient::connect(url, "v2.scope=core:read.deadbeef")
            .expect_err(&format!("{why} must be refused: {url:?}"));
        assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST, "{why}");
        assert!(!error.suggestions.is_empty(), "{why}");
    }
}

/// A missing credential is refused before any request is built.
#[test]
fn connect_requires_a_slip() {
    let error =
        OneironClient::connect("http://127.0.0.1:9/", "   ").expect_err("an empty slip is refused");
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN);
    assert!(!error.suggestions.is_empty());
}

/// A well-formed origin is accepted with or without a trailing slash, and
/// `connect` makes no request while accepting it.
#[test]
fn connect_validates_configuration_only() {
    for url in [
        "http://127.0.0.1:9",
        "http://127.0.0.1:9/",
        "https://example.invalid/base",
    ] {
        let client = OneironClient::connect(url, "v2.scope=core:read.deadbeef")
            .unwrap_or_else(|error| panic!("{url:?} should be accepted: {error:?}"));
        assert!(client.is_remote());
        assert!(client.base_url().is_some_and(|base| base.ends_with('/')));
    }
}

/// §Test/Shared #6 — a dead endpoint becomes a typed transport error that
/// carries no foreign body.
///
/// Port 9 (discard) refuses or blackholes rather than answering HTTP, so this
/// exercises the connect-failure arm without standing a server up.
#[test]
fn transport_failures_are_typed_and_inert() {
    let client = OneironClient::connect("http://127.0.0.1:9/", "v2.scope=core:read.deadbeef")
        .expect("connect");
    let error = client
        .receipts(10)
        .expect_err("a dead endpoint cannot answer");

    assert_eq!(error.code, MEMORY_CODE_INTERNAL);
    assert!(!error.suggestions.is_empty());
    assert!(
        !error.message.contains('<'),
        "a foreign body must never reach the message: {:?}",
        error.message
    );
}

/// §HEAD-CONTRACT — `deep` recall returns the ENGINE's `LEASE_REQUIRED`.
///
/// The binding neither mints nor simulates a lease, so the code the caller
/// sees is the engine's own string and not a local approximation of it.
#[test]
fn deep_recall_returns_lease_required() {
    let dir = tempfile::tempdir().expect("temp dir");
    let client = OneironClient::open(Some(&dir.path().join("vault")), &OpenOptions::default())
        .expect("open");

    let error = client
        .recall(
            "window seat",
            Effort::High,
            &RecallScope::default(),
            10,
            None,
        )
        .expect_err("deep recall is lease-gated");

    assert_eq!(error.code, MEMORY_CODE_LEASE_REQUIRED);
    assert!(!error.suggestions.is_empty());
}

/// A valid JSON success body is still an INTERNAL fault when it is not this verb's DTO.
#[test]
fn a_2xx_body_that_is_not_the_verb_output_is_internal() {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback peer");
    let address = listener.local_addr().unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let peer = std::thread::spawn(move || {
        'connections: loop {
            let (mut stream, _) = listener.accept().expect("witness request");
            let mut reader = BufReader::new(&mut stream);
            let mut content_length = 0;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).expect("request headers") == 0 {
                    if !matches!(
                        done_rx.try_recv(),
                        Err(std::sync::mpsc::TryRecvError::Empty)
                    ) {
                        return false;
                    }
                    continue 'connections;
                }
                if line == "\r\n" {
                    break;
                }
                if let Some((key, value)) = line.split_once(':')
                    && key.eq_ignore_ascii_case("content-length")
                {
                    content_length = value.trim().parse::<usize>().unwrap();
                }
            }
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).expect("request body");
            let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
            if request["conversation_ref"] != "conversation" {
                return false;
            }
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}").unwrap();
            return true;
        }
    });
    // A cleanup connection can close before sending a request; the peer must
    // accept the following real request rather than waiting forever at EOF.
    drop(TcpStream::connect(address).expect("cleanup connection"));
    let client = OneironClient::connect(&format!("http://{address}"), "fixture").unwrap();
    let result = client.witness(&oneiron::memory::WitnessTurn {
        conversation_ref: "conversation".into(),
        turn_ref: None,
        messages: vec![],
        occurred_at: 1,
    });
    // Release the peer even if the client failed before making the request.
    let _ = done_tx.send(());
    drop(TcpStream::connect(address));
    assert!(peer.join().expect("peer"), "request must reach the peer");
    let error = result.expect_err("a success response is not a witness receipt");
    assert_eq!(error.code, MEMORY_CODE_INTERNAL);
    assert!(error.message.contains("witness"), "{error:?}");
    assert!(error.message.contains("200"), "{error:?}");
    assert!(error.message.contains("missing field"), "{error:?}");
    assert!(!error.suggestions.is_empty());
}

/// Embedded failures cross byte-for-byte: the engine's own triple, unedited.
#[test]
fn embedded_errors_keep_the_engine_payload() {
    let dir = tempfile::tempdir().expect("temp dir");
    let client = OneironClient::open(Some(&dir.path().join("vault")), &OpenOptions::default())
        .expect("open");

    let error = client
        .as_actor("not-an-actor-key")
        .expect_err("a malformed actor key is refused by core");

    assert!(!error.code.is_empty());
    assert!(!error.message.is_empty());
    assert!(
        !error.suggestions.is_empty(),
        "the contract says suggestions is never empty"
    );
}

#[test]
fn connect_refuses_a_malformed_credential_without_echoing_it() {
    let seed = "5a".repeat(32);
    let error = OneironClient::connect("http://127.0.0.1:9/", &format!("v2.cred.zz.{seed}"))
        .expect_err("a malformed credential is refused");
    assert!(
        error.code == MEMORY_CODE_BAD_REQUEST
            && !error.message.contains(&seed)
            && !error.suggestions.iter().any(|line| line.contains(&seed))
    );
}

#[test]
fn pair_refuses_a_malformed_link_without_echoing_it() {
    let code = "K7M2Q9X";
    let link = format!("http://127.0.0.1:9/pair#{code}.{}", "ab".repeat(16));
    let error = OneironClient::pair(&link).expect_err("a malformed link is refused");
    assert!(
        error.code == MEMORY_CODE_BAD_REQUEST
            && !error.message.contains(code)
            && !error.suggestions.iter().any(|line| line.contains(code))
    );
}

/// Native Node/Python methods use `agent_verb`, not the typed Rust method.
/// A 200 response must still decode as this verb's declared output DTO.
#[test]
fn dynamic_binding_verbs_refuse_malformed_success_bodies() {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    for (verb, input) in [
        (
            "cancel",
            serde_json::json!({"task_ref": "11111111111111111111111111111111"}),
        ),
        ("rooms.list", serde_json::json!({})),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback peer");
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("facade request");
            let mut reader = BufReader::new(&mut stream);
            let mut content_length = 0;
            loop {
                let mut line = String::new();
                assert_ne!(reader.read_line(&mut line).expect("request header"), 0);
                if line == "\r\n" {
                    break;
                }
                if let Some((key, value)) = line.split_once(':')
                    && key.eq_ignore_ascii_case("content-length")
                {
                    content_length = value.trim().parse::<usize>().unwrap();
                }
            }
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).expect("request body");
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}").expect("response");
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        });
        let client = OneironClient::connect(&format!("http://{address}"), "fixture").unwrap();
        let response = client.agent_verb(verb, input.clone());
        assert_eq!(
            peer.join().expect("peer"),
            input,
            "{verb} reached the HTTP peer"
        );
        let error = response.expect_err("a malformed 200 body is not a verb result");
        assert_eq!(error.code, MEMORY_CODE_INTERNAL, "{verb}");
        assert!(
            error.message.contains("200") && error.message.contains(verb),
            "{error:?}"
        );
    }
}
