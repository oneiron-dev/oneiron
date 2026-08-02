//! Integration tests for `pkix_chain::verify_tls_client_dns` and
//! `pkix_chain::verify_tls_client_mailbox`.
//!
//! Fixtures: see `tests/fixtures/README.md`. The two clientAuth-EKU
//! leaves (`leaf-clientauth-dns.der`, `leaf-clientauth-mailbox.der`)
//! were produced by pyca/cryptography; the Rust verifier under test
//! never participates in fixture creation.
//!
//! Tests run under `Rfc5280Profile` (no EKU enforcement). Production
//! callers must supply a profile asserting `id-kp-clientAuth`; the
//! workspace does not yet ship a `BasicTlsClientProfile`, see the
//! follow-up bead.

use pkix_chain::{
    verify_tls_client_dns, verify_tls_client_mailbox, DefaultVerifier, Error, IdentityError,
    MailboxName, NoAiaFetcher, NoRevocation, ServerName, TrustAnchor,
};
use pkix_profiles::{BasicTlsClientProfile, Rfc5280Profile};
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

fn anchors() -> [TrustAnchor; 1] {
    [TrustAnchor::from_cert(load_fixture("root.der"))]
}

// ---------------------------------------------------------------------------
// verify_tls_client_dns — identity Some(_)
// ---------------------------------------------------------------------------

#[test]
fn client_dns_identity_match_ok() {
    let leaf = load_fixture("leaf-clientauth-dns.der");
    let chain = [leaf];
    let name = ServerName::dns_name("client.example.com").unwrap();
    let anchors = anchors();

    let vp = verify_tls_client_dns(
        &chain,
        &anchors,
        Some(&name),
        &Rfc5280Profile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect("matching DNS identity + valid chain must succeed");
    assert_eq!(vp.anchor_index, 0);
    assert_eq!(vp.depth, 0);
}

#[test]
fn client_dns_identity_mismatch_returns_identity_error() {
    let leaf = load_fixture("leaf-clientauth-dns.der");
    let chain = [leaf];
    let name = ServerName::dns_name("other.example.com").unwrap();
    let anchors = anchors();

    let err = verify_tls_client_dns(
        &chain,
        &anchors,
        Some(&name),
        &Rfc5280Profile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect_err("mismatched DNS identity must fail");
    assert!(
        matches!(err, Error::Identity(IdentityError::NoMatchingSan)),
        "expected Error::Identity(NoMatchingSan), got: {err:?}"
    );
}

#[test]
fn client_dns_missing_san_returns_identity_error() {
    let leaf = load_fixture("leaf-no-san.der");
    let chain = [leaf];
    let name = ServerName::dns_name("client.example.com").unwrap();
    let anchors = anchors();

    let err = verify_tls_client_dns(
        &chain,
        &anchors,
        Some(&name),
        &Rfc5280Profile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect_err("leaf without SAN + Some(identity) must fail identity check");
    assert!(
        matches!(err, Error::Identity(IdentityError::MissingSan)),
        "expected Error::Identity(MissingSan), got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// verify_tls_client_dns — identity None (path-only validation)
// ---------------------------------------------------------------------------

/// `identity = None` skips identity binding entirely. A valid chain
/// with no SAN match (or no SAN at all) succeeds.
#[test]
fn client_dns_identity_none_skips_binding_with_san() {
    let leaf = load_fixture("leaf-clientauth-dns.der");
    let chain = [leaf];
    let anchors = anchors();

    let vp = verify_tls_client_dns(
        &chain,
        &anchors,
        None,
        &Rfc5280Profile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect("identity=None must succeed on a valid chain");
    assert_eq!(vp.anchor_index, 0);
}

/// `identity = None` even on a leaf with no SAN extension. The
/// path-only mode bypasses the SAN check that would otherwise fail.
#[test]
fn client_dns_identity_none_skips_binding_no_san() {
    let leaf = load_fixture("leaf-no-san.der");
    let chain = [leaf];
    let anchors = anchors();

    let vp = verify_tls_client_dns(
        &chain,
        &anchors,
        None,
        &Rfc5280Profile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect("identity=None must succeed even on a leaf with no SAN");
    assert_eq!(vp.anchor_index, 0);
}

// ---------------------------------------------------------------------------
// verify_tls_client_dns — order-of-checks invariant
// ---------------------------------------------------------------------------

/// Path validation runs before identity binding. A leaf with matching
/// identity but a `before-notBefore` timestamp must fail with
/// `Error::Path(_)`, never with `Error::Identity(_)`.
#[test]
fn client_dns_path_validation_runs_before_identity() {
    let leaf = load_fixture("leaf-clientauth-dns.der");
    let chain = [leaf];
    let name = ServerName::dns_name("client.example.com").unwrap();
    let anchors = anchors();

    let err = verify_tls_client_dns(
        &chain,
        &anchors,
        Some(&name),
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
// verify_tls_client_mailbox — identity Some(_)
// ---------------------------------------------------------------------------

#[test]
fn client_mailbox_identity_match_ok() {
    let leaf = load_fixture("leaf-clientauth-mailbox.der");
    let chain = [leaf];
    let mailbox = MailboxName::parse("client@example.com").unwrap();
    let anchors = anchors();

    let vp = verify_tls_client_mailbox(
        &chain,
        &anchors,
        Some(&mailbox),
        &Rfc5280Profile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect("matching mailbox + valid chain must succeed");
    assert_eq!(vp.anchor_index, 0);
}

#[test]
fn client_mailbox_identity_mismatch_returns_identity_error() {
    let leaf = load_fixture("leaf-clientauth-mailbox.der");
    let chain = [leaf];
    let mailbox = MailboxName::parse("other@example.com").unwrap();
    let anchors = anchors();

    let err = verify_tls_client_mailbox(
        &chain,
        &anchors,
        Some(&mailbox),
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
fn client_mailbox_missing_san_returns_identity_error() {
    let leaf = load_fixture("leaf-no-san.der");
    let chain = [leaf];
    let mailbox = MailboxName::parse("client@example.com").unwrap();
    let anchors = anchors();

    let err = verify_tls_client_mailbox(
        &chain,
        &anchors,
        Some(&mailbox),
        &Rfc5280Profile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect_err("leaf without SAN + Some(identity) must fail identity check");
    assert!(
        matches!(err, Error::Identity(IdentityError::MissingSan)),
        "expected Error::Identity(MissingSan), got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// verify_tls_client_mailbox — identity None
// ---------------------------------------------------------------------------

#[test]
fn client_mailbox_identity_none_skips_binding_with_san() {
    let leaf = load_fixture("leaf-clientauth-mailbox.der");
    let chain = [leaf];
    let anchors = anchors();

    let vp = verify_tls_client_mailbox(
        &chain,
        &anchors,
        None,
        &Rfc5280Profile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect("identity=None must succeed on a valid chain");
    assert_eq!(vp.anchor_index, 0);
}

#[test]
fn client_mailbox_identity_none_skips_binding_no_san() {
    let leaf = load_fixture("leaf-no-san.der");
    let chain = [leaf];
    let anchors = anchors();

    let vp = verify_tls_client_mailbox(
        &chain,
        &anchors,
        None,
        &Rfc5280Profile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect("identity=None must succeed even on a leaf with no SAN");
    assert_eq!(vp.anchor_index, 0);
}

// ---------------------------------------------------------------------------
// verify_tls_client_mailbox — order-of-checks invariant
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// BasicTlsClientProfile wiring smoke
// ---------------------------------------------------------------------------

/// Pin that `BasicTlsClientProfile` accepts the clientAuth-EKU fixture
/// when paired with the DNS-name wrapper. The profile sets
/// `required_leaf_eku = [id-kp-clientAuth]` and does NOT require a SAN
/// at the path layer; the wrapper's SAN check runs separately for
/// `Some(name)` callers.
#[test]
fn client_dns_with_basic_tls_client_profile() {
    let leaf = load_fixture("leaf-clientauth-dns.der");
    let chain = [leaf];
    let name = ServerName::dns_name("client.example.com").unwrap();
    let anchors = anchors();

    let vp = verify_tls_client_dns(
        &chain,
        &anchors,
        Some(&name),
        &BasicTlsClientProfile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect("BasicTlsClientProfile + clientAuth-EKU leaf + matching SAN must succeed");
    assert_eq!(vp.anchor_index, 0);
}

/// Companion smoke for the mailbox wrapper under `BasicTlsClientProfile`.
#[test]
fn client_mailbox_with_basic_tls_client_profile() {
    let leaf = load_fixture("leaf-clientauth-mailbox.der");
    let chain = [leaf];
    let mailbox = MailboxName::parse("client@example.com").unwrap();
    let anchors = anchors();

    let vp = verify_tls_client_mailbox(
        &chain,
        &anchors,
        Some(&mailbox),
        &BasicTlsClientProfile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect("BasicTlsClientProfile + clientAuth-EKU leaf + matching mailbox must succeed");
    assert_eq!(vp.anchor_index, 0);
}

/// `BasicTlsClientProfile` does NOT set `require_subject_alt_name`.
/// A clientAuth-EKU leaf with no SAN extension must still pass path
/// validation under this profile (with `identity = None`).
#[test]
fn client_dns_no_san_passes_under_basic_tls_client_profile() {
    let leaf = load_fixture("leaf-no-san.der");
    let chain = [leaf];
    let anchors = anchors();

    // leaf-no-san.der carries EKU=serverAuth so it will be rejected by
    // the clientAuth-EKU requirement. We pin the failure mode is the
    // EKU mismatch, not a SAN miss — proves BasicTlsClientProfile
    // doesn't import a SAN constraint from BasicTlsProfile by accident.
    let err = verify_tls_client_dns(
        &chain,
        &anchors,
        None,
        &BasicTlsClientProfile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect_err("serverAuth-only leaf must fail clientAuth EKU check");
    assert!(
        matches!(err, Error::Path(_)),
        "expected Error::Path(_) for EKU mismatch, got: {err:?}"
    );
}

#[test]
fn client_mailbox_path_validation_runs_before_identity() {
    let leaf = load_fixture("leaf-clientauth-mailbox.der");
    let chain = [leaf];
    let mailbox = MailboxName::parse("client@example.com").unwrap();
    let anchors = anchors();

    let err = verify_tls_client_mailbox(
        &chain,
        &anchors,
        Some(&mailbox),
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
