//! Integration tests for `pkix_chain::verify_time_stamper`.
//!
//! Fixtures: see `tests/fixtures/README.md`.
//!
//! Oracle: pyca/cryptography produced the DER fixtures; the Rust verifier
//! under test never participates in fixture creation.
//!
//! RFC 3161 §2.3 mandates that a TSA certificate's ExtendedKeyUsage
//! extension be marked critical and contain only `id-kp-timeStamping`.
//! `verify_time_stamper` enforces this post-validation.

use pkix_chain::{
    verify_time_stamper, DefaultVerifier, Error, NoAiaFetcher, NoRevocation, TrustAnchor,
};
use pkix_profiles::BasicTimeStampingProfile;
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

#[test]
fn verify_time_stamper_ok() {
    let leaf = load_fixture("leaf-timestamping.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];

    let vp = verify_time_stamper(
        &chain,
        &anchors,
        &BasicTimeStampingProfile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect("RFC 3161-compliant TSA cert + valid chain must succeed");
    assert_eq!(vp.anchor_index, 0);
    assert_eq!(vp.depth, 0);
}

// ---------------------------------------------------------------------------
// RFC 3161 §2.3 criticality enforcement
// ---------------------------------------------------------------------------

#[test]
fn verify_time_stamper_non_critical_eku_returns_profile_violation() {
    let leaf = load_fixture("leaf-timestamping-not-critical.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];

    let err = verify_time_stamper(
        &chain,
        &anchors,
        &BasicTimeStampingProfile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect_err("non-critical EKU must fail RFC 3161 §2.3 check");
    match err {
        Error::ProfileViolation { reason } => {
            assert!(
                reason.contains("critical"),
                "reason should mention critical, got: {reason:?}"
            );
        }
        other => panic!("expected Error::ProfileViolation, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// RFC 3161 §2.3 sole-EKU enforcement
// ---------------------------------------------------------------------------

#[test]
fn verify_time_stamper_extra_eku_returns_profile_violation() {
    let leaf = load_fixture("leaf-timestamping-not-sole.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];

    let err = verify_time_stamper(
        &chain,
        &anchors,
        &BasicTimeStampingProfile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect_err("timeStamping+codeSigning EKU must fail RFC 3161 §2.3 sole check");
    match err {
        Error::ProfileViolation { reason } => {
            assert!(
                reason.contains("only id-kp-timeStamping"),
                "reason should mention sole-EKU rule, got: {reason:?}"
            );
        }
        other => panic!("expected Error::ProfileViolation, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// RFC 3161 §2.1 #10 KeyUsage shape enforcement (PKIX-7cac)
// ---------------------------------------------------------------------------

#[test]
fn verify_time_stamper_bad_ku_returns_profile_violation() {
    // Fixture has critical+sole id-kp-timeStamping EKU but its KeyUsage
    // contains digitalSignature + keyEncipherment. RFC 3161 §2.1 #10
    // forbids reuse of the TSA key for non-signing purposes; OpenSSL's
    // `-purpose timestampsign` enforces this as a hard reject. The
    // wrapper must reject with Error::ProfileViolation citing the KU rule.
    let leaf = load_fixture("leaf-timestamping-bad-ku.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];

    let err = verify_time_stamper(
        &chain,
        &anchors,
        &BasicTimeStampingProfile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect_err("KU=digitalSignature+keyEncipherment must fail RFC 3161 §2.1 #10 / KU-shape check");
    match err {
        Error::ProfileViolation { reason } => {
            assert!(
                reason.contains("KeyUsage"),
                "reason should mention KeyUsage, got: {reason:?}"
            );
            assert!(
                reason.contains("digitalSignature") || reason.contains("nonRepudiation"),
                "reason should mention the permitted bits, got: {reason:?}"
            );
        }
        other => panic!("expected Error::ProfileViolation, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Path validation runs before wrapper-side profile check
// ---------------------------------------------------------------------------

#[test]
fn verify_time_stamper_path_validation_runs_before_profile_check() {
    let leaf = load_fixture("leaf-timestamping.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];

    let err = verify_time_stamper(
        &chain,
        &anchors,
        &BasicTimeStampingProfile,
        BEFORE,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect_err("before notBefore must fail at path validation, not profile");
    assert!(
        matches!(err, Error::Path(_)),
        "expected Error::Path(_), got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Wrong EKU value caught by profile (presence) check, not the wrapper
// ---------------------------------------------------------------------------

#[test]
fn verify_time_stamper_wrong_eku_returns_path_error() {
    // codeSigning leaf is missing the timeStamping EKU entirely.
    let leaf = load_fixture("leaf-codesigning.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];

    let err = verify_time_stamper(
        &chain,
        &anchors,
        &BasicTimeStampingProfile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect_err("non-timeStamping leaf must fail profile EKU requirement");
    // Caught by verify_chain's profile.required_leaf_eku check, returns
    // Error::Path(pkix_path::Error::MissingEku).
    assert!(
        matches!(err, Error::Path(_)),
        "expected Error::Path(_), got: {err:?}"
    );
}
