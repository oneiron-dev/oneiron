//! End-to-end AIA integration tests for `pkix-chain` + `pkix-aia-http`.
//!
//! Drives `Verifier::verify_one` through the real
//! [`pkix_aia_http::HttpFetcher`] sync transport against an in-process
//! [`mockito::Server`]. Exercises the full wire: cert AIA extension →
//! URI extraction → `HttpFetcher::fetch` → HTTP request to mockito →
//! HTTP response body → DER parse → pool append → `pkix_path_builder`
//! reassembly → `pkix_path::validate_path` on the built chain.
//!
//! Mockito's `Server::url()` returns a random `http://127.0.0.1:<port>`
//! URL per server, but the leaf fixture's baked-in AIA URI is the
//! constant `http://example.test/intermediate.der` (mockito's port is
//! not known at fixture-gen time, and re-signing certs at test time
//! would require committing the intermediate's private key). To bridge
//! the gap, tests use a small [`RedirectingHttpFetcher`] that wraps
//! `HttpFetcher` and rewrites known URIs at fetch time. The wrapper is
//! test-only infrastructure; production callers point their certs'
//! AIA URIs at real CA endpoints and use `HttpFetcher` directly.
//!
//! Companion coverage:
//! - `pkix-aia-http/tests/integration.rs` tests `HttpFetcher::fetch`
//!   in isolation (no `pkix-chain` integration).
//! - `pkix-chain/tests/aia_chain_build.rs` tests `Verifier::verify_one`
//!   AIA wiring with a fully in-process `MockAiaFetcher` (no HTTP).
//!
//! This file is the join point: real HTTP + real `verify_chain`.

use std::collections::HashMap;

use pkix_aia::{AiaError, AiaFetcher};
use pkix_aia_http::HttpFetcher;
use pkix_chain::{verify_chain, DefaultVerifier, NoAiaFetcher, NoRevocation};
use pkix_path::{TrustAnchor, ValidationPolicy};
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

const ROOT_DER: &[u8] = include_bytes!("fixtures/root.der");
const INTERMEDIATE_DER: &[u8] = include_bytes!("fixtures/intermediate.der");
const LEAF_VIA_INTERMEDIATE_DER: &[u8] = include_bytes!("fixtures/leaf-via-intermediate.der");

/// The constant AIA URI baked into `leaf-via-intermediate.der` by
/// `tests/fixtures/gen.py`. Tests redirect this URI to whichever
/// random port mockito has bound at runtime.
const FIXTURE_AIA_URI: &str = "http://example.test/intermediate.der";

const NOW_UNIX: u64 = 1_577_836_800; // 2020-01-01 UTC, inside fixture validity.

fn load(der: &[u8]) -> Certificate {
    Certificate::from_der(der).expect("parse cert")
}

/// Adapter that rewrites known URIs before delegating to an inner
/// [`HttpFetcher`]. The redirect map is consulted on every `fetch`; URIs
/// without a mapping are passed through verbatim so `HttpFetcher`'s
/// scheme validation and error mapping still fire on unmatched inputs.
struct RedirectingHttpFetcher<'a> {
    inner: &'a HttpFetcher,
    redirects: HashMap<String, String>,
}

impl<'a> RedirectingHttpFetcher<'a> {
    fn new(inner: &'a HttpFetcher, redirects: HashMap<String, String>) -> Self {
        Self { inner, redirects }
    }
}

impl AiaFetcher for RedirectingHttpFetcher<'_> {
    fn fetch(&self, uri: &str) -> Result<Vec<u8>, AiaError> {
        let target = self.redirects.get(uri).map_or(uri, String::as_str);
        self.inner.fetch(target)
    }
}

/// Positive case: HttpFetcher reaches a mockito server that returns the
/// intermediate DER with status 200; the chain reassembles via
/// `build_first_valid_path` and validates against the root anchor.
#[test]
fn aia_e2e_positive_chain_validates_after_http_fetch() {
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/intermediate.der")
        .with_status(200)
        .with_header("content-type", "application/pkix-cert")
        .with_body(INTERMEDIATE_DER)
        .create();

    let http = HttpFetcher::new();
    let fetcher = RedirectingHttpFetcher::new(
        &http,
        HashMap::from([(
            FIXTURE_AIA_URI.to_owned(),
            format!("{}/intermediate.der", server.url()),
        )]),
    );

    let chain = [load(LEAF_VIA_INTERMEDIATE_DER)];
    let anchors = [TrustAnchor::from_cert(load(ROOT_DER))];
    let policy = ValidationPolicy::new(NOW_UNIX);

    let validated = verify_chain(
        &chain,
        &anchors,
        &policy,
        &DefaultVerifier,
        &NoRevocation,
        &fetcher,
    )
    .expect("verify_chain should validate after fetching the intermediate");

    assert_eq!(validated.anchor_index, 0);
    assert_eq!(
        validated.depth, 1,
        "one fetched intermediate sits between leaf and anchor"
    );
    mock.assert();
}

/// Negative case: mockito returns 404 for the AIA URI. The verifier
/// must surface `Error::Aia(AiaError::HttpStatus(404))` from the
/// underlying `HttpFetcher`.
#[test]
fn aia_e2e_negative_404_surfaces_http_status() {
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/intermediate.der")
        .with_status(404)
        .create();

    let http = HttpFetcher::new();
    let fetcher = RedirectingHttpFetcher::new(
        &http,
        HashMap::from([(
            FIXTURE_AIA_URI.to_owned(),
            format!("{}/intermediate.der", server.url()),
        )]),
    );

    let chain = [load(LEAF_VIA_INTERMEDIATE_DER)];
    let anchors = [TrustAnchor::from_cert(load(ROOT_DER))];
    let policy = ValidationPolicy::new(NOW_UNIX);

    let err = verify_chain(
        &chain,
        &anchors,
        &policy,
        &DefaultVerifier,
        &NoRevocation,
        &fetcher,
    )
    .expect_err("404 on the AIA URI must surface");

    assert!(
        matches!(err, pkix_chain::Error::Aia(AiaError::HttpStatus(404))),
        "expected Aia(HttpStatus(404)), got: {err:?}"
    );
    mock.assert();
}

/// Negative case: the AIA URI is rewritten to an `ldap://` scheme.
/// `HttpFetcher::fetch` synchronously rejects non-HTTP(S) schemes with
/// `AiaError::UriUnsupported` before any network I/O. No mockito server
/// needed for this assertion — but we still build one so the test
/// fails loudly if `HttpFetcher` regresses into attempting a fetch.
#[test]
fn aia_e2e_negative_unsupported_scheme_surfaces_uri_unsupported() {
    let server = mockito::Server::new();
    // No mock registered — any HTTP request would 501 / hang. The
    // fetcher must not reach this server.

    let http = HttpFetcher::new();
    let fetcher = RedirectingHttpFetcher::new(
        &http,
        HashMap::from([(
            FIXTURE_AIA_URI.to_owned(),
            "ldap://ldap.example.com/cn=ca,dc=example,dc=com?caCertificate".to_owned(),
        )]),
    );

    let chain = [load(LEAF_VIA_INTERMEDIATE_DER)];
    let anchors = [TrustAnchor::from_cert(load(ROOT_DER))];
    let policy = ValidationPolicy::new(NOW_UNIX);

    let err = verify_chain(
        &chain,
        &anchors,
        &policy,
        &DefaultVerifier,
        &NoRevocation,
        &fetcher,
    )
    .expect_err("ldap:// rewrite must surface");

    match err {
        pkix_chain::Error::Aia(AiaError::UriUnsupported(uri)) => {
            assert!(
                uri.starts_with("ldap://"),
                "UriUnsupported should carry the rejected URI, got: {uri:?}"
            );
        }
        other => panic!("expected Aia(UriUnsupported(_)), got: {other:?}"),
    }
    // server's existence is only to ensure HttpFetcher does not silently
    // pick up an environment-default URL — keep it alive past the
    // verify_chain call.
    drop(server);
}

/// Sanity: `NoAiaFetcher` short-circuits with `FetchingDisabled`
/// regardless of what mockito would have served, demonstrating that the
/// fast path of "caller-supplied complete chain or nothing" is intact
/// even when an HTTP fetcher would theoretically be available. This
/// duplicates the equivalent test in `tests/aia_chain_build.rs` but
/// exercises the e2e fixture set rather than the mock fetcher, so a
/// regression in the e2e fixture provenance also surfaces here.
#[test]
fn aia_e2e_no_aia_fetcher_short_circuits() {
    let chain = [load(LEAF_VIA_INTERMEDIATE_DER)];
    let anchors = [TrustAnchor::from_cert(load(ROOT_DER))];
    let policy = ValidationPolicy::new(NOW_UNIX);

    let err = verify_chain(
        &chain,
        &anchors,
        &policy,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect_err("NoAiaFetcher must fail on incomplete chain");

    assert!(
        matches!(err, pkix_chain::Error::Aia(AiaError::FetchingDisabled)),
        "expected Aia(FetchingDisabled), got: {err:?}"
    );
}
