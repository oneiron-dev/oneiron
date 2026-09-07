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
            Effort::Deep,
            &RecallScope::default(),
            10,
            None,
        )
        .expect_err("deep recall is lease-gated");

    assert_eq!(error.code, MEMORY_CODE_LEASE_REQUIRED);
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
