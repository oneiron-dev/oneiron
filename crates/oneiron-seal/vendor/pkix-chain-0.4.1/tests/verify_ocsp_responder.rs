//! Integration tests for `pkix_chain::verify_ocsp_responder`.
//!
//! Fixtures: see `tests/fixtures/README.md`.
//!
//! Oracle: pyca/cryptography produced the DER fixtures; the Rust verifier
//! under test never participates in fixture creation.
//!
//! RFC 6960 §4.2.2.2 mandates that a delegated OCSP responder cert be
//! signed by the same CA whose certs it asserts status on, and carry
//! `id-kp-OCSPSigning` in extKeyUsage. RFC 6960 §4.2.2.2.1 lets the
//! responder cert carry `id-pkix-ocsp-nocheck` to opt out of revocation
//! checks on itself (otherwise an infinite OCSP loop is required).
//!
//! `verify_ocsp_responder` enforces the EKU presence via the
//! `BasicOcspResponderProfile` ValidationPolicy, the delegation DN
//! match as a wrapper-side post-validation check, and the nocheck
//! handling via a `RevocationChecker` shim that bypasses the
//! caller's checker for the responder leaf only.

use pkix_chain::{
    verify_ocsp_responder, DefaultVerifier, Error, NoAiaFetcher, NoRevocation, RevocationChecker,
    TrustAnchor,
};
use pkix_profiles::BasicOcspResponderProfile;
use pkix_revocation::Error as RevocationError;
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

const NOW: u64 = 1_780_272_000;

fn load_fixture(name: &str) -> Certificate {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    Certificate::from_der(&der).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

/// A `RevocationChecker` that reports every cert as revoked. Used to
/// drive the nocheck-bypass tests: with this checker, `chain[0]` must
/// be reported as not-revoked iff the wrapper's nocheck shim is
/// honoring `id-pkix-ocsp-nocheck`.
struct AlwaysRevoking;

impl RevocationChecker for AlwaysRevoking {
    fn check_revocation(
        &self,
        cert: &Certificate,
        _issuer: &Certificate,
    ) -> pkix_revocation::Result<()> {
        Err(RevocationError::Revoked {
            serial: cert.tbs_certificate.serial_number.clone(),
            reason_code: None,
        })
    }

    fn check_revocation_against_anchor(
        &self,
        cert: &Certificate,
        _anchor: &TrustAnchor,
    ) -> pkix_revocation::Result<()> {
        Err(RevocationError::Revoked {
            serial: cert.tbs_certificate.serial_number.clone(),
            reason_code: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Positive path
// ---------------------------------------------------------------------------

#[test]
fn verify_ocsp_responder_ok() {
    let leaf = load_fixture("leaf-ocsp-responder.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root.clone())];
    let chain = [leaf];

    let vp = verify_ocsp_responder(
        &chain,
        &anchors,
        &root,
        &BasicOcspResponderProfile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect("RFC 6960-compliant delegated responder + valid chain must succeed");
    assert_eq!(vp.anchor_index, 0);
    assert_eq!(vp.depth, 0);
}

// ---------------------------------------------------------------------------
// RFC 6960 §4.2.2.2 delegation: responder cert's issuer DN must match
// the supplied `issuer` cert's subject DN.
// ---------------------------------------------------------------------------

#[test]
fn verify_ocsp_responder_wrong_issuer_returns_ocsp_delegation() {
    let leaf = load_fixture("leaf-ocsp-responder.der");
    let root = load_fixture("root.der");
    let wrong_issuer = load_fixture("root-wrong-issuer.der");
    // The chain itself validates fine — leaf is signed by `root` and
    // anchored against `root`. Only the wrapper-level delegation DN
    // check, which compares chain[0].issuer with the SUPPLIED issuer
    // (here `wrong_issuer`, NOT `root`), must reject.
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];

    let err = verify_ocsp_responder(
        &chain,
        &anchors,
        &wrong_issuer,
        &BasicOcspResponderProfile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect_err("issuer-DN mismatch must fail RFC 6960 §4.2.2.2 delegation check");
    match err {
        Error::OcspDelegation { reason } => {
            assert!(
                reason.contains("issuer DN"),
                "reason should mention issuer DN, got: {reason:?}"
            );
        }
        other => panic!("expected Error::OcspDelegation, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// RFC 6960 §4.2.2.2 cryptographic delegation binding: the responder
// cert must be signed by the supplied `issuer`'s key. A DN-twin issuer
// (same subject DN as the real signer, different key) must NOT pass.
//
// Pre-PKIX-q9hv.3, DN equality alone was checked, so this would have
// been silently accepted as a valid delegation. With the cryptographic
// binding in place, the responder signature fails to verify under the
// twin's SPKI and the wrapper rejects with Error::OcspDelegation,
// surfacing the trust-misattribution attempt to the caller.
// ---------------------------------------------------------------------------

#[test]
fn verify_ocsp_responder_twin_dn_issuer_returns_ocsp_delegation() {
    let leaf = load_fixture("leaf-ocsp-responder.der");
    let root = load_fixture("root.der");
    // Twin root: same DN as `root` (CN=pkix-chain test root) but a
    // different P-256 key. The chain validates fine against the real
    // root as anchor; only the delegation binding under `twin` must
    // reject.
    let twin = load_fixture("root-twin-dn.der");
    let anchors = [TrustAnchor::from_cert(root)];
    let chain = [leaf];

    let err = verify_ocsp_responder(
        &chain,
        &anchors,
        &twin,
        &BasicOcspResponderProfile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect_err(
        "DN-twin issuer (same DN as real signer, different key) must fail RFC 6960 §4.2.2.2 \
         cryptographic delegation binding even though the DN-equality gate passes",
    );
    match err {
        Error::OcspDelegation { reason } => {
            // The reason must point at the signature-binding failure,
            // not the DN gate — both surface as OcspDelegation but
            // mean different things diagnostically.
            assert!(
                reason.contains("signature"),
                "reason should mention signature-binding failure, got: {reason:?}"
            );
        }
        other => panic!("expected Error::OcspDelegation, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Wrong EKU caught by profile (presence) check, NOT by the wrapper.
//
// A code-signing leaf has EKU=codeSigning but not OCSPSigning. The
// profile's required_leaf_eku enforcement runs inside verify_chain
// and surfaces as Error::Path before the wrapper's delegation check
// has a chance to run.
// ---------------------------------------------------------------------------

#[test]
fn verify_ocsp_responder_missing_eku_returns_path_error() {
    let leaf = load_fixture("leaf-codesigning.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root.clone())];
    let chain = [leaf];

    let err = verify_ocsp_responder(
        &chain,
        &anchors,
        &root,
        &BasicOcspResponderProfile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect_err("non-OCSPSigning leaf must fail profile EKU requirement");
    // Caught by verify_chain's profile.required_leaf_eku check, returns
    // Error::Path(pkix_path::Error::MissingEku).
    assert!(
        matches!(err, Error::Path(_)),
        "expected Error::Path(_), got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// RFC 6960 §4.2.2.2.1: id-pkix-ocsp-nocheck on the responder cert
// bypasses revocation checks on that cert.
// ---------------------------------------------------------------------------

#[test]
fn verify_ocsp_responder_nocheck_bypasses_revoking_oracle() {
    let leaf = load_fixture("leaf-ocsp-responder-nocheck.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root.clone())];
    let chain = [leaf];

    // AlwaysRevoking would reject any cert, including the responder
    // leaf. With nocheck present, the wrapper's shim short-circuits
    // the call for chain[0], and the rest of the chain (none here —
    // single-cert chain) gets the normal treatment. For the
    // anchor-issued last-cert path, the shim also bypasses.
    let vp = verify_ocsp_responder(
        &chain,
        &anchors,
        &root,
        &BasicOcspResponderProfile,
        NOW,
        &DefaultVerifier,
        &AlwaysRevoking,
        &NoAiaFetcher,
    )
    .expect("id-pkix-ocsp-nocheck must bypass revocation on the responder leaf");
    assert_eq!(vp.anchor_index, 0);
    assert_eq!(vp.depth, 0);
}

// ---------------------------------------------------------------------------
// Negative companion: without nocheck, the same AlwaysRevoking oracle
// must reach chain[0] and produce Error::Revocation.
// ---------------------------------------------------------------------------

#[test]
fn verify_ocsp_responder_without_nocheck_honors_revoking_oracle() {
    let leaf = load_fixture("leaf-ocsp-responder.der");
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root.clone())];
    let chain = [leaf];

    let err = verify_ocsp_responder(
        &chain,
        &anchors,
        &root,
        &BasicOcspResponderProfile,
        NOW,
        &DefaultVerifier,
        &AlwaysRevoking,
        &NoAiaFetcher,
    )
    .expect_err("without nocheck, AlwaysRevoking must surface Error::Revocation");
    match err {
        Error::Revocation(RevocationError::Revoked { .. }) => {}
        other => {
            panic!("expected Error::Revocation(Revoked {{ .. }}), got: {other:?}")
        }
    }
}
