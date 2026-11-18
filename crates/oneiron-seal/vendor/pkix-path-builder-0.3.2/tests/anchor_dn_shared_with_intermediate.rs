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
//!
//! The second test bounds the search past anchor matches: a pool in which
//! every intermediate is named like one of two anchors gets at most 16 more
//! validations than the first pass, not one per frame of the DFS budget.

use std::cell::Cell;
use std::path::PathBuf;

use der::asn1::BitString;
use der::Decode as _;
use pkix_path::{DefaultVerifier, TrustAnchor, ValidationPolicy};
use pkix_path_builder::{build_first_valid_path, build_path, CertPool, Error};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
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

/// Counts its calls and rejects every signature.
struct CountingRejectVerifier {
    calls: Cell<usize>,
}

impl pkix_path::SignatureVerifier for CountingRejectVerifier {
    fn verify_signature(
        &self,
        _algorithm: spki::AlgorithmIdentifierRef<'_>,
        _issuer_spki: spki::SubjectPublicKeyInfoRef<'_>,
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), signature::Error> {
        self.calls.set(self.calls.get() + 1);
        Err(signature::Error::new())
    }
}

/// `template` with a new subject, issuer and serial, and one byte inside its RSA
/// modulus changed by `serial` (the key stays well-formed): each copy has its
/// own issuer+serial and key, so neither the builder's repeated-key guard nor
/// the validator's duplicate check stops a chain before its signature check.
fn renamed_ca(template: &Certificate, subject: &Name, issuer: &Name, serial: u8) -> Certificate {
    let mut cert = template.clone();
    let tbs = &mut cert.tbs_certificate;
    tbs.subject = subject.clone();
    tbs.issuer = issuer.clone();
    tbs.serial_number = SerialNumber::new(&[serial]).expect("serial number");
    let mut key = tbs
        .subject_public_key_info
        .subject_public_key
        .raw_bytes()
        .to_vec();
    // Byte 20 of the RSAPublicKey DER lies inside the modulus.
    key[20] ^= serial;
    tbs.subject_public_key_info.subject_public_key = BitString::from_bytes(&key).expect("key bits");
    cert
}

#[test]
fn a_pool_named_like_two_anchors_gets_at_most_sixteen_more_validations() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let good_ca = pkits_cert("GoodCACert");
    let root = TrustAnchor::from(&pkits_cert("TrustAnchorRootCertificate"));
    let a = good_ca.tbs_certificate.subject.clone();
    let b = root.subject.clone();
    // Anchor A is named like the end entity's issuer, under the root's key.
    let anchors = vec![
        TrustAnchor::new(a.clone(), root.subject_public_key_info.clone()),
        root,
    ];
    // Five CAs named A issued by B and five named B issued by A: every frame of
    // the search past the first anchor match matches an anchor again, so
    // without a cap the second pass validates one chain per budget unit.
    let pool: CertPool = (1..=10u8)
        .map(|n| {
            if n <= 5 {
                renamed_ca(&good_ca, &a, &b, n)
            } else {
                renamed_ca(&good_ca, &b, &a, n)
            }
        })
        .collect();
    let policy = ValidationPolicy::new(PKITS_NOW);
    let verifier = CountingRejectVerifier {
        calls: Cell::new(0),
    };

    let result = build_first_valid_path(&ee, &pool, &anchors, &policy, &verifier);
    assert!(
        matches!(result, Err(Error::NoValidPath { tried: 1, .. })),
        "the first pass's NoValidPath (one candidate, the end entity alone), got {result:?}"
    );
    let calls = verifier.calls.get();
    assert!(
        calls > 1,
        "the second pass checks chains past the first anchor match (calls: {calls})"
    );
    assert!(
        calls <= 1 + 16,
        "one check in the first pass and at most 16 in the second (calls: {calls})"
    );
}
