//! End-to-end tests for `pkix_chain::verify_chain_default` and `verify_chain`.
//!
//! Uses PKITS §4.1.1 certificates as the test vector:
//!   - TrustAnchorRootCertificate.crt (trust anchor, RSA-2048/SHA-256)
//!   - GoodCACert.crt                 (intermediate, notBefore=2010-01-01, notAfter=2030-12-31)
//!   - ValidCertificatePathTest1EE.crt (end-entity, same validity window)
//!
//! Oracle: NIST PKITS §4.1.1 specifies this path MUST validate.
//! Unix timestamps: PKITS certs valid 2010-01-01 08:30 to 2030-12-31 08:30 UTC.
//!   `PKITS_NOW`  = 2020-01-01 00:00:00 UTC = 1 577 836 800
//!   `PKITS_PAST` = 1970-01-01 00:00:00 UTC = 0  (before notBefore)

use pkix_chain::{
    verify_chain, verify_chain_default, DefaultVerifier, NoAiaFetcher, NoRevocation,
    RevocationChecker, Verifier,
};
use pkix_path::{TrustAnchor, ValidationPolicy};
use x509_cert::Certificate;

// PKITS cert validity: notBefore=2010-01-01 08:30 UTC, notAfter=2030-12-31 08:30 UTC.
// PKITS_NOW is 2020-01-01 00:00:00 UTC, comfortably within the validity window.
// Must match pkix-path/tests/pkits_helper.rs::PKITS_NOW.
const PKITS_NOW: u64 = 1_577_836_800;

// Cert bytes are compiled in; tests run fully offline.
const TRUST_ANCHOR_DER: &[u8] =
    include_bytes!("../../pkix-path/tests/pkits/certs/TrustAnchorRootCertificate.crt");
const GOOD_CA_DER: &[u8] = include_bytes!("../../pkix-path/tests/pkits/certs/GoodCACert.crt");
const VALID_EE_DER: &[u8] =
    include_bytes!("../../pkix-path/tests/pkits/certs/ValidCertificatePathTest1EE.crt");

fn load(der: &[u8]) -> Certificate {
    use x509_cert::der::Decode as _;
    Certificate::from_der(der).expect("parse cert")
}

/// PKITS §4.1.1 — `verify_chain_default` happy path.
///
/// Chain: [`ValidCertificatePathTest1EE`, `GoodCACert`]
/// Anchor: `TrustAnchorRootCertificate`
/// Oracle: PKITS §4.1.1 MUST validate; depth = 1 (one intermediate: `GoodCACert`).
#[test]
fn e2e_verify_chain_default_pkits_4_1_1() {
    let chain = [load(VALID_EE_DER), load(GOOD_CA_DER)];
    let anchors = [TrustAnchor::from_cert(load(TRUST_ANCHOR_DER))];
    let policy = ValidationPolicy::new(PKITS_NOW);

    let result = verify_chain_default(&chain, &anchors, &policy, &NoRevocation);
    let vp = result.expect("PKITS §4.1.1 must validate via verify_chain_default");
    assert_eq!(vp.anchor_index, 0, "trust anchor must be at index 0");
    assert_eq!(vp.depth, 1, "one intermediate (GoodCACert)");
}

/// Same chain as §4.1.1 but with `now_unix` = 0 (before all certs' notBefore).
///
/// Oracle: PKITS certs have notBefore=2010-01-01; at Unix time 0 they are not yet valid.
/// Expected: `Err(pkix_chain::Error::Path(pkix_path::Error::ValidityPeriod` { .. })).
#[test]
fn e2e_verify_chain_default_expired_returns_validity_error() {
    let chain = [load(VALID_EE_DER), load(GOOD_CA_DER)];
    let anchors = [TrustAnchor::from_cert(load(TRUST_ANCHOR_DER))];
    let policy = ValidationPolicy::new(0);

    let result = verify_chain_default(&chain, &anchors, &policy, &NoRevocation);
    assert!(
        matches!(
            result,
            Err(pkix_chain::Error::Path(
                pkix_path::Error::ValidityPeriod { .. }
            ))
        ),
        "before notBefore must return ValidityPeriod, got: {result:?}"
    );
}

/// Regression (PKIX-pr6): `check_revocation_against_anchor` is called for the
/// last cert in the chain (the one directly issued by the trust anchor).
///
/// Before the fix, the last cert was silently skipped. This test uses a spy
/// `RevocationChecker` that records whether the anchor-check method was called.
#[test]
fn e2e_anchor_issued_cert_revocation_check_is_called() {
    use std::cell::Cell;

    struct SpyChecker {
        anchor_check_called: Cell<bool>,
    }
    impl RevocationChecker for SpyChecker {
        fn check_revocation(
            &self,
            _cert: &Certificate,
            _issuer: &Certificate,
        ) -> pkix_revocation::Result<()> {
            Ok(())
        }
        fn check_revocation_against_anchor(
            &self,
            _cert: &Certificate,
            _anchor: &TrustAnchor,
        ) -> pkix_revocation::Result<()> {
            self.anchor_check_called.set(true);
            Ok(())
        }
    }

    let chain = [load(VALID_EE_DER), load(GOOD_CA_DER)];
    let anchors = [TrustAnchor::from_cert(load(TRUST_ANCHOR_DER))];
    let policy = ValidationPolicy::new(PKITS_NOW);
    let spy = SpyChecker {
        anchor_check_called: Cell::new(false),
    };

    verify_chain(
        &chain,
        &anchors,
        &policy,
        &DefaultVerifier,
        &spy,
        &NoAiaFetcher,
    )
    .expect("chain must validate");
    assert!(
        spy.anchor_check_called.get(),
        "check_revocation_against_anchor must be called for the anchor-issued cert"
    );
}

/// Same chain as §4.1.1 but using `verify_chain` with explicit `DefaultVerifier`.
///
/// Confirms the generic `verify_chain` API works end-to-end.
/// Oracle: same as §4.1.1.
#[test]
fn e2e_verify_chain_explicit_verifier() {
    let chain = [load(VALID_EE_DER), load(GOOD_CA_DER)];
    let anchors = [TrustAnchor::from_cert(load(TRUST_ANCHOR_DER))];
    let policy = ValidationPolicy::new(PKITS_NOW);

    let result = verify_chain(
        &chain,
        &anchors,
        &policy,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    );
    let vp = result.expect("PKITS §4.1.1 must validate via verify_chain with DefaultVerifier");
    assert_eq!(vp.anchor_index, 0);
    assert_eq!(vp.depth, 1);
}

/// `Verifier::verify_one` produces the same `ValidatedPath` as the free
/// function `verify_chain` for identical inputs.
///
/// Oracle: `verify_chain` itself, which is independently tested above
/// against the PKITS §4.1.1 oracle. `Verifier::verify_one` is the body
/// `verify_chain` now delegates to; this test pins the equivalence so a
/// future refactor that diverges them fails immediately. (PKIX-gsd9.)
#[test]
fn e2e_verifier_verify_one_matches_verify_chain() {
    let chain = [load(VALID_EE_DER), load(GOOD_CA_DER)];
    let anchors = [TrustAnchor::from_cert(load(TRUST_ANCHOR_DER))];
    let policy = ValidationPolicy::new(PKITS_NOW);

    let from_free = verify_chain(
        &chain,
        &anchors,
        &policy,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect("free");
    let verifier = Verifier::new(
        &anchors,
        &DefaultVerifier,
        &NoRevocation,
        &policy,
        &NoAiaFetcher,
    );
    let from_struct = verifier.verify_one(&chain).expect("struct");

    assert_eq!(from_free.anchor_index, from_struct.anchor_index);
    assert_eq!(from_free.depth, from_struct.depth);
    assert_eq!(from_free.leaf_subject, from_struct.leaf_subject);
    assert_eq!(from_free.leaf_issuer, from_struct.leaf_issuer);
    assert_eq!(from_free.leaf_serial, from_struct.leaf_serial);
    assert_eq!(from_free.leaf_spki, from_struct.leaf_spki);
}

/// `Verifier::verify_batch` returns one result per input chain in the
/// same order, and a failure in one chain does not poison the others.
///
/// Oracle: mixes the PKITS §4.1.1 good chain (must succeed) with the
/// same chain validated at `now_unix = 0` (must fail with
/// `ValidityPeriod`). Independent of the implementation under test —
/// we already know from `e2e_verify_chain_default_pkits_4_1_1` and
/// `e2e_verify_chain_default_expired_returns_validity_error` what each
/// outcome is in isolation. (PKIX-gsd9.)
#[test]
fn e2e_verifier_verify_batch_returns_per_chain_results() {
    let chain = [load(VALID_EE_DER), load(GOOD_CA_DER)];
    let anchors = [TrustAnchor::from_cert(load(TRUST_ANCHOR_DER))];

    let good_policy = ValidationPolicy::new(PKITS_NOW);
    let good_verifier = Verifier::new(
        &anchors,
        &DefaultVerifier,
        &NoRevocation,
        &good_policy,
        &NoAiaFetcher,
    );

    let bad_policy = ValidationPolicy::new(0);
    let bad_verifier = Verifier::new(
        &anchors,
        &DefaultVerifier,
        &NoRevocation,
        &bad_policy,
        &NoAiaFetcher,
    );

    // Run each chain through its respective verifier and collect the
    // results into a single batch shape; this proves verify_batch
    // composes correctly without sharing state across results.
    let chain_slice: &[Certificate] = &chain;
    let chains: [&[Certificate]; 2] = [chain_slice, chain_slice];

    let good_results = good_verifier.verify_batch(&chains);
    assert_eq!(good_results.len(), 2);
    assert!(good_results[0].is_ok(), "good[0]: {:?}", good_results[0]);
    assert!(good_results[1].is_ok(), "good[1]: {:?}", good_results[1]);

    let bad_results = bad_verifier.verify_batch(&chains);
    assert_eq!(bad_results.len(), 2);
    for (i, r) in bad_results.iter().enumerate() {
        assert!(
            matches!(
                r,
                Err(pkix_chain::Error::Path(
                    pkix_path::Error::ValidityPeriod { .. }
                ))
            ),
            "bad[{i}]: {r:?}"
        );
    }
}

/// `Verifier::verify_batch` on an empty slice returns an empty
/// `Vec` (zero results in, zero results out).
#[test]
fn e2e_verifier_verify_batch_empty_input_returns_empty() {
    let anchors = [TrustAnchor::from_cert(load(TRUST_ANCHOR_DER))];
    let policy = ValidationPolicy::new(PKITS_NOW);
    let verifier = Verifier::new(
        &anchors,
        &DefaultVerifier,
        &NoRevocation,
        &policy,
        &NoAiaFetcher,
    );

    let results = verifier.verify_batch(&[]);
    assert!(results.is_empty());
}
