//! Integration tests for `pkix_chain::verify_code_signer`.
//!
//! Fixtures: see `tests/fixtures/README.md`.
//!
//! Oracle: pyca/cryptography produced the DER fixtures; the Rust verifier
//! under test never participates in fixture creation.

use pkix_chain::{
    verify_code_signer, DefaultVerifier, Error, NoAiaFetcher, NoRevocation, TrustAnchor,
};
use pkix_profiles::{BasicCodeSigningProfile, Rfc5280Profile};
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

const NOW: u64 = 1_780_272_000;
const BEFORE: u64 = 0;

fn load_fixture(name: &str) -> Certificate {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    Certificate::from_der(&der).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

// ---------------------------------------------------------------------------
// Positive path
// ---------------------------------------------------------------------------

/// Happy path: leaf with id-kp-codeSigning EKU + valid chain.
#[test]
fn verify_code_signer_ok() {
    let leaf = load_fixture("leaf-codesigning.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];

    let vp = verify_code_signer(
        &chain,
        &anchors,
        &BasicCodeSigningProfile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect("code-signing leaf + valid chain must succeed");
    assert_eq!(vp.anchor_index, 0);
    assert_eq!(vp.depth, 0);
}

// ---------------------------------------------------------------------------
// EKU enforcement
// ---------------------------------------------------------------------------

/// Negative: leaf without id-kp-codeSigning EKU (carries serverAuth instead)
/// must fail at path validation when the policy requires codeSigning.
#[test]
fn verify_code_signer_wrong_eku_returns_path_error() {
    let leaf = load_fixture("leaf-san-www-example.der"); // serverAuth, not codeSigning
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];

    let err = verify_code_signer(
        &chain,
        &anchors,
        &BasicCodeSigningProfile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect_err("serverAuth leaf must fail BasicCodeSigningProfile EKU check");
    assert!(
        matches!(err, Error::Path(_)),
        "expected Error::Path(_), got: {err:?}"
    );
}

/// Sanity: with Rfc5280Profile (no EKU constraint), any conforming leaf
/// validates regardless of its EKU. Confirms the profile generic actually
/// drives the EKU check rather than something hardcoded in the wrapper.
#[test]
fn verify_code_signer_with_rfc5280_profile_skips_eku_check() {
    let leaf = load_fixture("leaf-san-www-example.der"); // serverAuth EKU
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];

    let vp = verify_code_signer(
        &chain,
        &anchors,
        &Rfc5280Profile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect("Rfc5280Profile imposes no EKU constraint");
    assert_eq!(vp.anchor_index, 0);
}

// ---------------------------------------------------------------------------
// Standard chain failures still propagate
// ---------------------------------------------------------------------------

#[test]
fn verify_code_signer_expired_chain_returns_path_error() {
    let leaf = load_fixture("leaf-codesigning.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];

    let err = verify_code_signer(
        &chain,
        &anchors,
        &BasicCodeSigningProfile,
        BEFORE,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect_err("before notBefore must fail at path validation");
    assert!(
        matches!(err, Error::Path(_)),
        "expected Error::Path(_), got: {err:?}"
    );
}
