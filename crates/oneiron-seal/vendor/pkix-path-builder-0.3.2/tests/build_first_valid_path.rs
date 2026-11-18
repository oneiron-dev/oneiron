//! Integration tests for [`pkix_path_builder::build_first_valid_path`].
//!
//! Covers the three return paths of the helper:
//!
//! 1. **Positive: first DFS candidate fails, a later candidate validates.**
//!    Uses the BetterTLS `tc60` fixture (cross-signed depth-6 pool with one
//!    intermediate signed under `ecdsa-with-SHA1`, which
//!    [`pkix_path::DefaultVerifier`] does not dispatch). [`build_path`]
//!    returns a chain whose intermediate at index 3 is the SHA-1 cert and
//!    [`pkix_path::validate_path`] rejects it; `build_first_valid_path`
//!    iterates past that candidate to a SHA-256-only chain that validates.
//!
//! 2. **NoValidPath: every candidate is rejected.** PKITS §4.1.1 chain
//!    paired with a custom [`pkix_path::SignatureVerifier`] that
//!    unconditionally rejects every signature. The helper must surface
//!    [`pkix_path_builder::Error::NoValidPath`] with `tried >= 1`.
//!
//! 3. **NoPathFound passthrough: empty pool.** No candidates are ever
//!    yielded. The helper must surface [`pkix_path_builder::Error::NoPathFound`]
//!    just like [`build_path`].
//!
//! Filed under PKIX-lwr9.4.2 ("pkix-path-builder: add build_first_valid_path
//! helper").

use std::path::PathBuf;

use der::Decode as _;
use pkix_path::{DefaultVerifier, TrustAnchor, ValidationPolicy};
use pkix_path_builder::{
    build_first_valid_path, build_path, build_path_candidates, CertPool, Error,
};
use x509_cert::Certificate;

/// PKITS validity window midpoint (2020-01-26 00:00:00 UTC).
const PKITS_NOW: u64 = 1_580_000_000;

/// BetterTLS tc60 fixture's pinned validation_time (2026-01-19T17:25:55Z).
const TC60_NOW: u64 = 1_768_843_555;

fn pkits_cert(name: &str) -> Certificate {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../pkix-path/tests/pkits/certs")
        .join(format!("{name}.crt"));
    let der_bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("fixture not found at {}: {}", path.display(), e));
    Certificate::from_der(&der_bytes).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

fn load_pem_chain(name: &str) -> Vec<Certificate> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/bettertls/tc60")
        .join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    Certificate::load_pem_chain(&bytes).unwrap_or_else(|e| panic!("parse PEM at {name}: {e}"))
}

/// A [`pkix_path::SignatureVerifier`] that rejects every signature
/// regardless of input.
///
/// Used by the `NoValidPath` test to force every candidate chain into
/// validation failure. Independent of the algorithms in the actual chain
/// — works for RSA, ECDSA, future algorithms alike.
struct AlwaysRejectVerifier;

impl pkix_path::SignatureVerifier for AlwaysRejectVerifier {
    fn verify_signature(
        &self,
        _algorithm: spki::AlgorithmIdentifierRef<'_>,
        _issuer_spki: spki::SubjectPublicKeyInfoRef<'_>,
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), signature::Error> {
        Err(signature::Error::new())
    }
}

/// Positive: tc60. [`build_path`] alone yields a SHA-1 intermediate that
/// `validate_path` rejects; `build_first_valid_path` iterates past it and
/// returns a SHA-256-only chain that validates.
#[test]
fn tc60_build_first_valid_path_succeeds_where_build_path_fails() {
    let mut peer_certs = load_pem_chain("peer.pem");
    assert_eq!(peer_certs.len(), 1, "tc60 peer.pem should hold one cert");
    let peer = peer_certs.remove(0);

    let intermediates = load_pem_chain("intermediates.pem");
    assert_eq!(
        intermediates.len(),
        6,
        "tc60 should ship 6 intermediates per testcase.json"
    );
    let anchors_certs = load_pem_chain("anchors.pem");
    let anchors: Vec<TrustAnchor> = anchors_certs.iter().map(TrustAnchor::from).collect();

    let pool: CertPool = intermediates.into_iter().collect();

    let policy = ValidationPolicy::new(TC60_NOW);
    let verifier = DefaultVerifier;

    // (1) Confirm the baseline: build_path picks a candidate that
    //     validate_path rejects (this matches bettertls.rs's baseline-pkix-path.json
    //     entry `"tc60": {"phase":"validation_failed","reason":"SignatureInvalid { index: 3 }"}`).
    let bp_chain = build_path(&peer, &pool, &anchors).expect("tc60: build_path yields a chain");
    let bp_validation = pkix_path::validate_path(&bp_chain, &anchors, &policy, &verifier);
    assert!(
        bp_validation.is_err(),
        "tc60 invariant: build_path's first DFS candidate should fail validate_path \
         (if this assertion fires, the underlying DFS ordering changed and tc60 \
         is no longer the right fixture for this test)"
    );

    // (2) The point of the test: build_first_valid_path iterates past the
    //     rejected candidate and finds a chain that validates.
    let valid_chain = build_first_valid_path(&peer, &pool, &anchors, &policy, &verifier)
        .expect("tc60: build_first_valid_path should find a valid chain in the cross-signed pool");

    // The returned chain must validate end-to-end.
    pkix_path::validate_path(&valid_chain, &anchors, &policy, &verifier)
        .expect("tc60: build_first_valid_path returned a chain that does not validate");

    // The returned chain must differ from build_path's first yield (else
    // we would not have demonstrated the iteration).
    assert_ne!(
        valid_chain, bp_chain,
        "tc60: build_first_valid_path returned the same chain as build_path; \
         either build_path now picks a valid candidate first or both paths agree \
         — either way this test is no longer demonstrating the iteration"
    );
}

/// NoValidPath: every yielded candidate is rejected by the verifier.
///
/// Uses PKITS §4.1.1 (one valid 2-cert chain through `GoodCACert` to
/// `TrustAnchorRootCertificate`) and the `AlwaysRejectVerifier`. The
/// pool yields exactly one candidate; the verifier rejects it; the
/// helper must surface `NoValidPath { tried: 1, .. }`.
#[test]
fn pkits_no_valid_path_when_verifier_rejects_everything() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let intermediate = pkits_cert("GoodCACert");
    let anchor_cert = pkits_cert("TrustAnchorRootCertificate");
    let anchor = TrustAnchor::from(&anchor_cert);

    let mut pool = CertPool::new();
    pool.add(intermediate);

    let policy = ValidationPolicy::new(PKITS_NOW);
    let verifier = AlwaysRejectVerifier;

    // Sanity check: the underlying iterator does yield candidates. If this
    // ever stops being true the test is testing the wrong thing.
    let candidates_yielded: usize =
        build_path_candidates(&ee, &pool, std::slice::from_ref(&anchor))
            .filter_map(Result::ok)
            .count();
    assert!(
        candidates_yielded >= 1,
        "PKITS §4.1.1 pool should yield at least one topological candidate"
    );

    let err = build_first_valid_path(
        &ee,
        &pool,
        std::slice::from_ref(&anchor),
        &policy,
        &verifier,
    )
    .expect_err("AlwaysRejectVerifier must cause NoValidPath, not Ok");

    match err {
        Error::NoValidPath { tried, last_error, .. } => {
            assert!(
                tried >= 1,
                "NoValidPath.tried must be >= 1 (got {tried}); zero-yield exhaustion \
                 should surface as NoPathFound instead"
            );
            assert!(
                !last_error.is_empty(),
                "NoValidPath.last_error should carry the pkix_path::Error Display rendering"
            );
        }
        other => panic!("expected NoValidPath, got {other:?}"),
    }
}

/// NoPathFound passthrough: empty pool yields zero candidates.
///
/// Mirrors [`build_path`]'s contract: zero-yield exhaustion surfaces as
/// `NoPathFound`, not as `NoValidPath { tried: 0 }`.
#[test]
fn empty_pool_returns_no_path_found() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let anchor_cert = pkits_cert("TrustAnchorRootCertificate");
    let anchor = TrustAnchor::from(&anchor_cert);

    let pool = CertPool::new();
    let policy = ValidationPolicy::new(PKITS_NOW);
    let verifier = DefaultVerifier;

    let err = build_first_valid_path(
        &ee,
        &pool,
        std::slice::from_ref(&anchor),
        &policy,
        &verifier,
    )
    .expect_err("empty pool must error");

    assert!(
        matches!(err, Error::NoPathFound),
        "empty pool should surface NoPathFound, got {err:?}"
    );
}
