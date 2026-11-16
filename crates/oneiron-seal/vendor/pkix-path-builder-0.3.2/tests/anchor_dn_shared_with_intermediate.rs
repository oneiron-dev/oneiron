//! A trust anchor that shares its subject DN with a pool intermediate under
//! a different key (Oneiron local test, FIX PKIX-BUILDER-ANCHOR-DN-ENDS-SEARCH;
//! not upstream's).
//!
//! The shape is a trusted list that names an issuing CA by its new key while
//! the end entity was issued under the CA's old key, whose certificate chains
//! to a listed root. Built from public NIST PKITS certificates, copied from
//! the pkix-path 0.3.2 archive into `tests/fixtures/pkits`:
//! - target: `ValidCertificatePathTest1EE`, issued by "Good CA";
//! - pool: `GoodCACert` ("Good CA", issued by the PKITS trust anchor);
//! - anchors: the PKITS trust anchor, and an anchor named "Good CA" that
//!   holds the trust anchor's key instead of Good CA's.
//!
//! The end entity's issuer DN names the second anchor, so the first candidate
//! is the end entity alone, and it fails validation (Good CA's key signed it).
//! The valid path, `[EE, GoodCACert]` to the PKITS trust anchor, goes through
//! the pool.

use std::path::PathBuf;

use der::Decode as _;
use pkix_path::{DefaultVerifier, TrustAnchor, ValidationPolicy};
use pkix_path_builder::{build_first_valid_path, build_path, CertPool};
use x509_cert::Certificate;

/// PKITS validity window midpoint (2020-01-26 00:00:00 UTC).
const PKITS_NOW: u64 = 1_580_000_000;

fn pkits_cert(name: &str) -> Certificate {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/pkits")
        .join(format!("{name}.crt"));
    let der_bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("fixture not found at {}: {}", path.display(), e));
    Certificate::from_der(&der_bytes).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

#[test]
fn an_anchor_named_like_the_issuing_intermediate_does_not_end_the_search() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let good_ca = pkits_cert("GoodCACert");
    let root = TrustAnchor::from(&pkits_cert("TrustAnchorRootCertificate"));
    // "Good CA" under the root's key: an intermediate's DN, not its key.
    let renamed = TrustAnchor::new(
        good_ca.tbs_certificate.subject.clone(),
        root.subject_public_key_info.clone(),
    );
    let anchors = vec![root, renamed];
    let pool: CertPool = core::iter::once(good_ca.clone()).collect();
    let policy = ValidationPolicy::new(PKITS_NOW);

    // The fixture has the shape: the first DFS candidate is the end entity
    // alone under the renamed anchor, and it does not validate.
    let first = build_path(&ee, &pool, &anchors).expect("build_path yields a candidate");
    assert_eq!(
        first,
        vec![ee.clone()],
        "the first candidate ends at the anchor named like Good CA"
    );
    assert!(
        pkix_path::validate_path(&first, &anchors, &policy, &DefaultVerifier).is_err(),
        "the end entity alone does not validate under the renamed anchor"
    );

    let chain = build_first_valid_path(&ee, &pool, &anchors, &policy, &DefaultVerifier)
        .expect("the path through the pool's Good CA validates");
    assert_eq!(chain, vec![ee, good_ca]);
}
