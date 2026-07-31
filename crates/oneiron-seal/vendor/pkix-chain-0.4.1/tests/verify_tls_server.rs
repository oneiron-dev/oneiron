//! Integration tests for `pkix_chain::verify_tls_server`.
//!
//! Fixtures: see `tests/fixtures/README.md`.
//!
//! Oracle: pyca/cryptography produced the DER fixtures; the Rust verifier
//! under test never participates in fixture creation. The PKITS leaf used
//! by the `MissingSan` negative path is a NIST-published cert with no
//! SAN extension — independent of both pyca and pkix-chain.

use pkix_chain::{
    verify_tls_server, DefaultVerifier, Error, IdentityError, NoAiaFetcher, NoRevocation,
    ServerName, TrustAnchor,
};
use pkix_profiles::Rfc5280Profile;
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

/// A timestamp inside every fixture's validity window (2026-06-01 UTC).
/// Both pkix-chain fixtures and PKITS certs are valid at this time.
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
// Positive path
// ---------------------------------------------------------------------------

/// Happy path: valid chain + leaf SAN matches target hostname.
#[test]
fn verify_tls_server_ok() {
    let leaf = load_fixture("leaf-san-www-example.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];
    let name = ServerName::dns_name("www.example.com").unwrap();

    let vp = verify_tls_server(
        &chain,
        &anchors,
        &name,
        &Rfc5280Profile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect("matching SAN + valid chain must succeed");
    assert_eq!(vp.anchor_index, 0);
    assert_eq!(vp.depth, 0, "leaf directly issued by trust anchor");
}

/// Case-insensitive SAN match: caller passes mixed-case hostname.
///
/// `ServerName::dns_name` lower-cases its input; the SAN entry is
/// `www.example.com` which compares case-insensitively. Both directions
/// of normalization must hold.
#[test]
fn verify_tls_server_case_insensitive_target() {
    let leaf = load_fixture("leaf-san-www-example.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];
    let name = ServerName::dns_name("WWW.Example.COM").unwrap();

    assert!(
        verify_tls_server(
            &chain,
            &anchors,
            &name,
            &Rfc5280Profile,
            NOW,
            &DefaultVerifier,
            &NoRevocation,
            &NoAiaFetcher,
        )
        .is_ok(),
        "mixed-case target must match lowercase SAN"
    );
}

// ---------------------------------------------------------------------------
// Identity binding negative paths
// ---------------------------------------------------------------------------

/// Path validation succeeds, but the leaf's SAN does not contain the target.
/// Must return `Error::Identity(NoMatchingSan)`.
#[test]
fn verify_tls_server_hostname_mismatch_returns_identity_error() {
    let leaf = load_fixture("leaf-san-www-example.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];
    let name = ServerName::dns_name("api.example.com").unwrap();

    let err = verify_tls_server(
        &chain,
        &anchors,
        &name,
        &Rfc5280Profile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect_err("mismatched hostname must fail");
    assert!(
        matches!(err, Error::Identity(IdentityError::NoMatchingSan)),
        "expected Error::Identity(NoMatchingSan), got: {err:?}"
    );
}

/// Path validation succeeds, but the leaf has no SAN extension at all.
/// Must return `Error::Identity(MissingSan)`.
#[test]
fn verify_tls_server_missing_san_returns_identity_error() {
    let leaf = load_fixture("leaf-no-san.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];
    let name = ServerName::dns_name("www.example.com").unwrap();

    let err = verify_tls_server(
        &chain,
        &anchors,
        &name,
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
// Order-of-checks invariant
// ---------------------------------------------------------------------------

/// Path validation must run before identity binding.
///
/// We feed a chain whose leaf SAN matches the target but whose `now_unix`
/// is before every cert's notBefore. The result must be `Error::Path(_)`
/// (validity error) — NOT `Error::Identity(_)`. If identity were checked
/// first, a malicious-but-otherwise-untrusted leaf could leak SAN-match
/// information via the error type.
#[test]
fn verify_tls_server_path_validation_runs_before_identity() {
    let leaf = load_fixture("leaf-san-www-example.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];
    let name = ServerName::dns_name("www.example.com").unwrap();

    let err = verify_tls_server(
        &chain,
        &anchors,
        &name,
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
// Profile generic parameter wiring
// ---------------------------------------------------------------------------

/// Passing `BasicTlsProfile` exercises the profile generic with the policy
/// the workspace expects production callers to use. `BasicTlsProfile` sets
/// `required_leaf_eku = [id-kp-serverAuth]` and `require_subject_alt_name`,
/// so the fixture's serverAuth EKU + DNS SAN must both pass.
#[test]
fn verify_tls_server_with_basic_tls_profile() {
    use pkix_profiles::BasicTlsProfile;

    let leaf = load_fixture("leaf-san-www-example.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];
    let name = ServerName::dns_name("www.example.com").unwrap();

    let vp = verify_tls_server(
        &chain,
        &anchors,
        &name,
        &BasicTlsProfile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect("BasicTlsProfile + serverAuth-EKU leaf + matching SAN must succeed");
    assert_eq!(vp.anchor_index, 0);
}
