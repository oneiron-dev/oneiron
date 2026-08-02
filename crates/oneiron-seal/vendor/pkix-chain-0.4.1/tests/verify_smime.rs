//! Integration tests for `pkix_chain::verify_smime_signer` and
//! `pkix_chain::verify_smime_recipient`.
//!
//! Fixtures: see `tests/fixtures/README.md`.
//!
//! Oracle: pyca/cryptography produced the DER fixtures; the Rust verifier
//! under test never participates in fixture creation.

use pkix_chain::{
    verify_smime_recipient, verify_smime_signer, DefaultVerifier, Error, IdentityError,
    MailboxName, NoAiaFetcher, NoRevocation, TrustAnchor,
};
use pkix_profiles::Rfc5280Profile;
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

/// A timestamp inside every fixture's validity window (2026-06-01 UTC).
const NOW: u64 = 1_780_272_000;

/// A timestamp before every fixture's validity window (1970-01-01 UTC).
const BEFORE: u64 = 0;

fn load_fixture(name: &str) -> Certificate {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    Certificate::from_der(&der).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

// ---------------------------------------------------------------------------
// verify_smime_signer: positive path
// ---------------------------------------------------------------------------

#[test]
fn verify_smime_signer_ok() {
    let leaf = load_fixture("leaf-san-alice-example.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];
    let mailbox = MailboxName::parse("alice@example.com").unwrap();

    let vp = verify_smime_signer(
        &chain,
        &anchors,
        &mailbox,
        &Rfc5280Profile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect("matching mailbox + valid chain must succeed");
    assert_eq!(vp.anchor_index, 0);
    assert_eq!(vp.depth, 0);
}

/// Domain comparison is case-insensitive (matches the SAN-side normalization).
#[test]
fn verify_smime_signer_domain_case_insensitive() {
    let leaf = load_fixture("leaf-san-alice-example.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];
    let mailbox = MailboxName::parse("alice@Example.COM").unwrap();

    assert!(
        verify_smime_signer(
            &chain,
            &anchors,
            &mailbox,
            &Rfc5280Profile,
            NOW,
            &DefaultVerifier,
            &NoRevocation,
            &NoAiaFetcher,
        )
        .is_ok(),
        "mixed-case domain must match"
    );
}

// ---------------------------------------------------------------------------
// verify_smime_signer: identity binding failures
// ---------------------------------------------------------------------------

#[test]
fn verify_smime_signer_mailbox_mismatch_returns_identity_error() {
    let leaf = load_fixture("leaf-san-alice-example.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];
    let mailbox = MailboxName::parse("bob@example.com").unwrap();

    let err = verify_smime_signer(
        &chain,
        &anchors,
        &mailbox,
        &Rfc5280Profile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect_err("mismatched mailbox must fail");
    assert!(
        matches!(err, Error::Identity(IdentityError::NoMatchingSan)),
        "expected Error::Identity(NoMatchingSan), got: {err:?}"
    );
}

#[test]
fn verify_smime_signer_missing_san_returns_identity_error() {
    let leaf = load_fixture("leaf-no-san.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];
    let mailbox = MailboxName::parse("alice@example.com").unwrap();

    let err = verify_smime_signer(
        &chain,
        &anchors,
        &mailbox,
        &Rfc5280Profile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect_err("leaf without SAN must fail identity check");
    assert!(
        matches!(err, Error::Identity(IdentityError::MissingSan)),
        "expected Error::Identity(MissingSan), got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// verify_smime_signer: order-of-checks invariant
// ---------------------------------------------------------------------------

#[test]
fn verify_smime_signer_path_validation_runs_before_identity() {
    let leaf = load_fixture("leaf-san-alice-example.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];
    let mailbox = MailboxName::parse("alice@example.com").unwrap();

    let err = verify_smime_signer(
        &chain,
        &anchors,
        &mailbox,
        &Rfc5280Profile,
        BEFORE,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect_err("before notBefore must fail at path validation, not identity");
    assert!(
        matches!(err, Error::Path(_)),
        "expected Error::Path(_), got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// verify_smime_recipient: identical mechanics, distinct API
// ---------------------------------------------------------------------------

/// The two wrappers have byte-identical bodies; the distinct name is the
/// API-ergonomic distinction. Both must accept the same fixture+mailbox.
#[test]
fn verify_smime_recipient_ok() {
    let leaf = load_fixture("leaf-san-alice-example.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];
    let mailbox = MailboxName::parse("alice@example.com").unwrap();

    let vp = verify_smime_recipient(
        &chain,
        &anchors,
        &mailbox,
        &Rfc5280Profile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect("matching mailbox + valid chain must succeed for recipient too");
    assert_eq!(vp.anchor_index, 0);
}

#[test]
fn verify_smime_recipient_mailbox_mismatch_returns_identity_error() {
    let leaf = load_fixture("leaf-san-alice-example.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];
    let mailbox = MailboxName::parse("eve@example.com").unwrap();

    let err = verify_smime_recipient(
        &chain,
        &anchors,
        &mailbox,
        &Rfc5280Profile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect_err("mismatched mailbox must fail for recipient too");
    assert!(
        matches!(err, Error::Identity(IdentityError::NoMatchingSan)),
        "expected Error::Identity(NoMatchingSan), got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// BasicSmimeProfile wiring smoke test
// ---------------------------------------------------------------------------

/// Exercise the profile generic with `BasicSmimeProfile`. The profile sets
/// `required_leaf_eku = [id-kp-emailProtection]` and `require_rfc822_san`,
/// both of which the fixture satisfies.
#[test]
fn verify_smime_signer_with_basic_smime_profile() {
    use pkix_profiles::BasicSmimeProfile;

    let leaf = load_fixture("leaf-san-alice-example.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];
    let mailbox = MailboxName::parse("alice@example.com").unwrap();

    let vp = verify_smime_signer(
        &chain,
        &anchors,
        &mailbox,
        &BasicSmimeProfile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect("BasicSmimeProfile + emailProtection-EKU leaf + rfc822 SAN must succeed");
    assert_eq!(vp.anchor_index, 0);
}
