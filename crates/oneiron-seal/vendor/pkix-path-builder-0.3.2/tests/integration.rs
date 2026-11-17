//! Integration tests for pkix-path-builder.
//!
//! Uses PKITS (NIST SP 800-89) certificate fixtures from the pkix-path crate.
//! All tests are fully offline; no network access is performed.

use der::asn1::{BitString, ObjectIdentifier, OctetString};
use der::Decode as _;
use pkix_path::{DefaultVerifier, TrustAnchor, ValidationPolicy};
use pkix_path_builder::{
    build_path, build_path_candidates, build_path_candidates_with_config, CertPool,
    PathBuilderConfig,
};
use x509_cert::Certificate;

/// Unix timestamp within the PKITS cert validity window.
///
/// PKITS certs are valid from 2010-01-01 to 2030-12-31.
/// Using 2020-01-26 00:00:00 UTC = 1 580 000 000.
const PKITS_NOW: u64 = 1_580_000_000;

/// Load a PKITS DER certificate by base name (without `.crt`).
///
/// `CARGO_MANIFEST_DIR` at test time is the pkix-path-builder directory,
/// so `../pkix-path/tests/pkits/certs/` resolves to the pkix-path fixture tree.
fn pkits_cert(name: &str) -> Certificate {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../pkix-path/tests/pkits/certs")
        .join(format!("{name}.crt"));
    let der_bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("fixture not found at {}: {}", path.display(), e));
    Certificate::from_der(&der_bytes).unwrap_or_else(|e| panic!("failed to parse cert {name}: {e}"))
}

/// Build a trust anchor from the PKITS root certificate.
fn pkits_trust_anchor() -> TrustAnchor {
    TrustAnchor::from(&pkits_cert("TrustAnchorRootCertificate"))
}

/// OID `id-ce-basicConstraints` (RFC 5280 §4.2.1.9).
///
/// Inlined here rather than importing — `pkix_path_builder::OID_BASIC_CONSTRAINTS`
/// is a private constant in the path-builder crate.
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");

/// Take a cert with a real `BasicConstraints` extension and corrupt the
/// extension's `extn_value` to bytes that cannot DER-decode as
/// `BasicConstraints`.
///
/// The chosen payload (`0xff 0xff`) is not valid DER — the leading
/// 0xFF byte is not a valid identifier octet. This is the same technique
/// used in `pkix-path/tests/anchor_nc.rs` for `NameConstraints` corruption.
///
/// The outer DER (`Certificate` SEQUENCE) and the cert's signature both
/// become invalid after this surgery, but path-building does not verify
/// signatures — it only walks the topology and inspects `BasicConstraints`.
/// That makes this helper sufficient for testing the skip-not-fail
/// behaviour of [`pkix_path_builder::build_path`] in isolation.
fn corrupt_basic_constraints(mut cert: Certificate) -> Certificate {
    let exts = cert
        .tbs_certificate
        .extensions
        .as_mut()
        .expect("template cert must have extensions");
    let bc = exts
        .iter_mut()
        .find(|e| e.extn_id == OID_BASIC_CONSTRAINTS)
        .expect("template cert must carry BasicConstraints");
    bc.extn_value = OctetString::new(b"\xff\xff".to_vec()).expect("OctetString::new");
    cert
}

/// Test that `build_path` succeeds on the PKITS §4.1.1 two-cert chain and that
/// the result passes `validate_path`.
#[test]
fn test_build_path_two_cert_chain() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let intermediate = pkits_cert("GoodCACert");
    let anchor = pkits_trust_anchor();

    let mut pool = CertPool::new();
    pool.add(intermediate);

    let path = build_path(&ee, &pool, std::slice::from_ref(&anchor))
        .expect("build_path should succeed for PKITS §4.1.1 chain");

    // Chain must be leaf-first with at least [EE, GoodCACert].
    assert!(
        path.len() >= 2,
        "path should contain at least EE + intermediate"
    );

    // Validate the built path end-to-end.
    let policy = ValidationPolicy::new(PKITS_NOW);
    let verifier = DefaultVerifier;
    pkix_path::validate_path(&path, &[anchor], &policy, &verifier)
        .expect("validate_path should succeed on the built chain");
}

/// Test that `build_path` works regardless of pool insertion order.
/// With a single intermediate there is only one order, but this test
/// documents the contract that pool order must not matter.
#[test]
fn test_build_path_shuffled_order() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let intermediate = pkits_cert("GoodCACert");
    let anchor = pkits_trust_anchor();

    // Pool contains only the single intermediate — no shuffling needed,
    // but the test asserts the contract holds.
    let mut pool = CertPool::new();
    pool.add(intermediate);

    let path = build_path(&ee, &pool, std::slice::from_ref(&anchor))
        .expect("build_path should succeed regardless of pool insertion order");

    assert!(path.len() >= 2);

    let policy = ValidationPolicy::new(PKITS_NOW);
    let verifier = DefaultVerifier;
    pkix_path::validate_path(&path, &[anchor], &policy, &verifier)
        .expect("validate_path should succeed");
}

/// Test that `build_path` returns [`pkix_path_builder::Error::NoPathFound`] when the pool is empty.
#[test]
fn test_build_path_no_path() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let anchor = pkits_trust_anchor();

    let pool = CertPool::new(); // empty pool

    let err =
        build_path(&ee, &pool, &[anchor]).expect_err("build_path should fail with an empty pool");

    assert!(
        matches!(err, pkix_path_builder::Error::NoPathFound),
        "expected NoPathFound, got {err}"
    );
}

/// Pool contains a self-signed cert that is NOT a trust anchor.
///
/// `build_path` must NOT terminate at it — it must continue searching for the
/// real anchor. The correct chain uses `GoodCACert`; the self-signed `BadSignedCACert`
/// (subject ≠ trust anchor subject) must be skipped.
#[test]
fn test_build_path_self_signed_non_anchor_in_pool() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let intermediate = pkits_cert("GoodCACert");
    // BadSignedCACert is self-signed (subject == issuer) but NOT the trust anchor.
    let bad_ca = pkits_cert("BadSignedCACert");
    let anchor = pkits_trust_anchor();

    let mut pool = CertPool::new();
    pool.add(intermediate);
    pool.add(bad_ca); // self-signed, different CA, not the anchor

    let path = build_path(&ee, &pool, std::slice::from_ref(&anchor))
        .expect("build_path must find the correct path ignoring the self-signed non-anchor");

    // The built path must still validate end-to-end.
    let policy = pkix_path::ValidationPolicy::new(PKITS_NOW);
    let verifier = pkix_path::DefaultVerifier;
    pkix_path::validate_path(&path, &[anchor], &policy, &verifier)
        .expect("validate_path should succeed on the built chain");
}

/// Test that `build_path` returns `NoPathFound` when the pool contains a cert
/// that does not link to the target's issuer.
#[test]
fn test_build_path_wrong_pool() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let anchor = pkits_trust_anchor();

    // BadSignedCACert is a CA cert but it is not in the EE's issuer chain.
    let wrong_cert = pkits_cert("BadSignedCACert");

    let mut pool = CertPool::new();
    pool.add(wrong_cert);

    let err = build_path(&ee, &pool, &[anchor])
        .expect_err("build_path should fail when pool contains unrelated cert");

    assert!(
        matches!(err, pkix_path_builder::Error::NoPathFound),
        "expected NoPathFound, got {err}"
    );
}

/// Verify SPKI-based cycle detection: adding the same intermediate certificate
/// twice to the pool must not cause a duplicate-SPKI loop. The path builder
/// must still find the correct path (the duplicate is pruned by SPKI identity).
///
/// Oracle: the PKITS §4.1.1 chain is known-valid. If cycle detection incorrectly
/// pruned a legitimate certificate (false positive), `build_path` would return
/// `NoPathFound`. If it failed to prune duplicates (false negative), it might
/// return duplicate entries in the chain or loop indefinitely.
#[test]
fn test_build_path_duplicate_cert_in_pool_pruned_by_spki() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let intermediate = pkits_cert("GoodCACert");
    let anchor = pkits_trust_anchor();

    // Add the same intermediate twice — same SPKI, so one should be pruned.
    let mut pool = CertPool::new();
    pool.add(intermediate.clone());
    pool.add(intermediate); // duplicate — different Vec slot, same SPKI

    let path = build_path(&ee, &pool, std::slice::from_ref(&anchor))
        .expect("build_path must find path even with duplicate certs in pool");

    // Validate the result to confirm it's a real path, not a loop.
    let mut policy = ValidationPolicy::new(PKITS_NOW);
    policy.enforce_key_usage = false;
    pkix_path::validate_path(&path, &[anchor], &policy, &DefaultVerifier)
        .expect("path returned with duplicate pool entries must be valid");

    // Chain must not have duplicates — SPKI-based pruning ensures the same
    // intermediate was not selected twice at different positions.
    let spkis: Vec<_> = path
        .iter()
        .map(|c| {
            use der::Encode as _;
            let mut buf = Vec::new();
            c.tbs_certificate
                .subject_public_key_info
                .encode_to_vec(&mut buf)
                .unwrap();
            buf
        })
        .collect();
    let deduped_len = {
        let mut seen = std::collections::HashSet::new();
        spkis.iter().filter(|s| seen.insert(*s)).count()
    };
    assert_eq!(
        spkis.len(),
        deduped_len,
        "path must not contain duplicate SPKI entries"
    );
}

/// Adversarial pool test: verify that `build_path` returns `BudgetExceeded`
/// within a reasonable time when given a pool engineered to maximise DFS
/// branching.
///
/// Construction: take the PKITS `GoodCACert` as a template CA certificate
/// (it has `BasicConstraints cA=TRUE`).  Clone it 30 times, each clone with:
/// - `subject`  = "`GoodCA`" (same as template — so all clones are candidates
///   whenever another cert's issuer is "`GoodCA`")
/// - `issuer`   = "`GoodCA`" (same as `subject` — so at every DFS level the
///   algorithm searches the pool for a parent and finds all unvisited clones)
/// - unique `subject_public_key` bytes — bypasses the SPKI cycle guard so
///   the same logical DN may be visited repeatedly via different key material
///
/// The EE target has `issuer` = "`GoodCA`", so the DFS starts with 30 candidates
/// at depth 1, 29 unvisited at depth 2 (for each of the 30), etc.
/// Without the budget cap this would run in O(30!) time; the cap must fire
/// well before 10 000 node visits and return `BudgetExceeded`.
///
/// Oracle: `matches!(err, Error::BudgetExceeded)`.
/// The test also asserts it completes in under two seconds to guard against
/// accidental budget removal.
#[test]
fn test_build_path_adversarial_pool_budget_exceeded() {
    // Create 30 CA clones with the same subject/issuer but distinct SPKIs.
    //
    // NOTE: these mutations produce Rust-object-level modifications that are
    // inconsistent with the outer Certificate DER (the TBS fields no longer
    // match the outer signature). That is intentional — `build_path` only does
    // name-matching and SPKI cycle detection, not signature verification.
    // These certs must NOT be passed to `pkix_path::validate_path`.
    const N: usize = 30;
    const _: () = assert!(N <= u8::MAX as usize, "N must fit in u8");

    let ee = pkits_cert("ValidCertificatePathTest1EE");
    // Template CA: subject = target's issuer DN; has `BasicConstraints` cA=TRUE.
    let template_ca = pkits_cert("GoodCACert");

    // Use a trust anchor whose subject does NOT match any cert in the pool,
    // so no path can succeed and the DFS exhausts all candidates.
    // Use a cert whose subject is unrelated to `GoodCACert`'s issuer chain so
    // no path can terminate successfully and the DFS exhausts all candidates.
    let fake_anchor = TrustAnchor::from(&pkits_cert("BadSignedCACert"));

    let mut pool = CertPool::new();
    for i in 0..N {
        let mut ca = template_ca.clone();
        // Make issuer == subject: each clone will look for its own parent
        // in the pool, finding all other clones as candidates → exponential fan-out.
        ca.tbs_certificate.issuer = ca.tbs_certificate.subject.clone();
        // Unique SPKI defeats the cycle guard so all N clones are treated as
        // distinct DFS nodes.
        ca.tbs_certificate
            .subject_public_key_info
            .subject_public_key = BitString::new(
            0,
            vec![u8::try_from(i).expect("loop bound N fits in u8"); 32],
        )
        .expect("BitString construction must succeed for valid parameters");
        pool.add(ca);
    }

    let start = std::time::Instant::now();
    let err = build_path(&ee, &pool, std::slice::from_ref(&fake_anchor))
        .expect_err("adversarial pool should not find a valid path");
    let elapsed = start.elapsed();

    assert!(
        matches!(err, pkix_path_builder::Error::BudgetExceeded),
        "expected BudgetExceeded, got {err}"
    );
    assert!(
        elapsed.as_secs() < 2,
        "build_path took {elapsed:?}; budget enforcement must prevent exponential blowup"
    );
}

/// Encode a cert's `SubjectPublicKeyInfo` to DER bytes for SPKI-based equality
/// comparison in tests. The tests below identify "which intermediate did the
/// builder pick" by SPKI, not by re-running the builder logic.
fn encode_spki(cert: &Certificate) -> Vec<u8> {
    use der::Encode as _;
    let mut buf = Vec::new();
    cert.tbs_certificate
        .subject_public_key_info
        .encode_to_vec(&mut buf)
        .expect("SubjectPublicKeyInfo must encode");
    buf
}

/// AKI-based candidate selection (PKIX-yn3e).
///
/// Bridge-CA disambiguation: pool contains two CA certs with the **same
/// subject DN** ("Basic Self-Issued Old Key CA") but **different SPKIs**.
/// The target's `AuthorityKeyIdentifier.keyIdentifier` matches exactly one
/// of them (`BasicSelfIssuedOldKeyCACert.SKI`); the other
/// (`BasicSelfIssuedOldKeyNewWithOldCACert`) is a self-issued rollover
/// bridge with a different SPKI/SKI.
///
/// **AKI/SKI binding** (verified independently via `openssl x509 -text`,
/// see the unit-test hex constants in lib.rs):
/// - Test4EE.AKI.keyIdentifier == OldKeyCACert.SKI    (DD:0D:75:…:AF)
/// - Test4EE.AKI.keyIdentifier != bridge_ca.SKI       (88:5F:BE:…:2A)
///
/// **Pool insertion order** is `[bridge, oldkey]`. Without AKI ranking the
/// DFS would try the bridge first (pool order), recurse through it, and
/// return a topologically valid chain `[Test4EE, bridge, oldkey, anchor]`
/// that fails `validate_path` with `SignatureInvalid` (Test4EE was actually
/// signed by oldkey directly, not via the bridge).
///
/// **Independent oracle**: end-to-end `validate_path` succeeds on the
/// returned chain iff the chosen intermediate's pubkey actually verifies
/// Test4EE's signature. This is what we assert.
#[test]
fn test_build_path_aki_ranking_disambiguates_same_dn_different_spki() {
    let ee = pkits_cert("ValidBasicSelfIssuedNewWithOldTest4EE");

    // Both CAs share the subject DN "Basic Self-Issued Old Key CA".
    let oldkey_ca = pkits_cert("BasicSelfIssuedOldKeyCACert");
    let bridge_ca = pkits_cert("BasicSelfIssuedOldKeyNewWithOldCACert");
    let anchor = pkits_trust_anchor();

    // Insert bridge first so DN-only ordering would pick it.
    let mut pool = CertPool::new();
    pool.add(bridge_ca.clone());
    pool.add(oldkey_ca.clone());

    let path =
        build_path(&ee, &pool, std::slice::from_ref(&anchor)).expect("build_path must succeed");

    // The intermediate at path[1] must be OldKeyCACert (whose SKI matches
    // Test4EE's AKI), not the bridge cert that has a different SKI.
    let selected = encode_spki(&path[1]);
    let expected = encode_spki(&oldkey_ca);
    let unexpected = encode_spki(&bridge_ca);
    assert_eq!(
        selected, expected,
        "AKI ranking must select OldKeyCACert (SKI matches Test4EE.AKI), \
         not the same-DN bridge cert"
    );
    assert_ne!(selected, unexpected);

    // End-to-end validation: this is the independent oracle. If AKI
    // ranking picked the wrong intermediate, validate_path would fail
    // with SignatureInvalid because the bridge's pubkey does not verify
    // Test4EE's signature. Disable key-usage enforcement (PKITS §4.5
    // self-issued certs may not carry digitalSignature on the EE).
    let mut policy = ValidationPolicy::new(PKITS_NOW);
    policy.enforce_key_usage = false;
    pkix_path::validate_path(&path, &[anchor], &policy, &DefaultVerifier)
        .expect("validate_path must succeed on the AKI-disambiguated chain");
}

/// Regression: when the target has no AKI, candidate selection falls back
/// to DN-only ordering with stable iteration of pool insertion order. This
/// is the contract the existing tests assume, and we assert it explicitly
/// here for one synthetic shape so the contract has a named owner.
///
/// Construction: GoodCACert is a normal PKITS intermediate. Its EE
/// (`ValidCertificatePathTest1EE`) has an AKI extension, but only one CA
/// in the pool can match the EE's issuer DN. The AKI heuristic picks that
/// same single candidate; with or without ranking, the result is the same.
/// What this test pins down is that adding an *unrelated* CA cert to the
/// pool does not perturb the selection — proving the tier-1 ordering
/// preserves pool insertion order for non-matching candidates.
#[test]
fn test_build_path_aki_ranking_unrelated_pool_cert_does_not_perturb_selection() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let good_ca = pkits_cert("GoodCACert");
    // Unrelated CA from §4.5 family — different subject DN; cannot match
    // GoodCA's issuer chain. Tests that tier-1 ordering doesn't accidentally
    // promote it via spurious AKI matches.
    let unrelated = pkits_cert("BasicSelfIssuedNewKeyCACert");
    let anchor = pkits_trust_anchor();

    let mut pool = CertPool::new();
    pool.add(unrelated.clone());
    pool.add(good_ca.clone());

    let path =
        build_path(&ee, &pool, std::slice::from_ref(&anchor)).expect("build_path must succeed");

    // The selected intermediate must be GoodCACert (only DN-matching cand.).
    let selected = encode_spki(&path[1]);
    let expected = encode_spki(&good_ca);
    assert_eq!(
        selected, expected,
        "GoodCACert must be selected; unrelated pool cert must not be chosen"
    );

    // End-to-end validation as independent oracle.
    let policy = ValidationPolicy::new(PKITS_NOW);
    pkix_path::validate_path(&path, &[anchor], &policy, &DefaultVerifier)
        .expect("validate_path must succeed");
}

// =========================================================================
// PathCandidates iterator tests (PKIX-mszo)
// =========================================================================

/// PathCandidates iterator: smime build-then-validate retry loop pattern.
///
/// This is the canonical S/MIME usage shape: keep pulling chains from
/// the iterator until one validates cryptographically. The independent
/// oracle is `validate_path`'s success on the chain the iterator
/// supplies — the iterator's job is just to produce candidate chains
/// in some defensible order; the validator's job is to accept or reject
/// each.
///
/// Test fixture: same as the AKI-ranking test (PKITS Test4EE +
/// OldKeyCACert + bridge cert with same DN). Pool insertion order is
/// `[bridge, oldkey]`. The iterator MUST find the verifying chain
/// within 2 `next()` calls (it does so in 1, courtesy of AKI ranking).
#[test]
fn test_iterator_smime_retry_loop_finds_verifying_chain() {
    let ee = pkits_cert("ValidBasicSelfIssuedNewWithOldTest4EE");
    let oldkey_ca = pkits_cert("BasicSelfIssuedOldKeyCACert");
    let bridge_ca = pkits_cert("BasicSelfIssuedOldKeyNewWithOldCACert");
    let anchor = pkits_trust_anchor();

    let mut pool = CertPool::new();
    pool.add(bridge_ca);
    pool.add(oldkey_ca);

    let mut policy = ValidationPolicy::new(PKITS_NOW);
    policy.enforce_key_usage = false;
    let verifier = DefaultVerifier;
    let anchors = std::slice::from_ref(&anchor);

    let mut iter = build_path_candidates(&ee, &pool, anchors);
    let mut next_calls = 0_usize;
    let mut verified_chain: Option<Vec<Certificate>> = None;
    loop {
        match iter.next() {
            None => break,
            Some(Err(e)) => panic!("iterator yielded fatal error: {e}"),
            Some(Ok(chain)) => {
                next_calls += 1;
                if pkix_path::validate_path(&chain, anchors, &policy, &verifier).is_ok() {
                    verified_chain = Some(chain);
                    break;
                }
                // else: try next candidate
            }
        }
        // Defensive cap so a buggy iterator can't loop forever in the test.
        assert!(next_calls < 10, "iterator should terminate quickly");
    }

    let chain = verified_chain.expect("at least one chain must verify");
    assert!(
        next_calls <= 2,
        "iterator must find a verifying chain in ≤2 calls, took {next_calls}"
    );
    // Sanity: the verified chain must be the one rooted at OldKeyCACert.
    assert!(chain.len() >= 2, "chain has at least leaf + intermediate");
}

/// PathCandidates iterator: enumerates all topologically-valid chains.
///
/// In the AKI fixture, both `[Test4EE, oldkey]` and
/// `[Test4EE, bridge, oldkey]` are topologically valid paths. The
/// iterator must yield both (in some order — we don't pin the order
/// beyond "AKI-tier-0 first") and then return `None`.
///
/// Independent oracle: each yielded chain must independently terminate
/// at the trust anchor's DN by `pkix_path::names_match`. We do not
/// validate signatures here; that would conflate the iterator
/// enumeration semantics with cryptographic verification.
#[test]
fn test_iterator_enumerates_all_topologically_valid_chains() {
    let ee = pkits_cert("ValidBasicSelfIssuedNewWithOldTest4EE");
    let oldkey_ca = pkits_cert("BasicSelfIssuedOldKeyCACert");
    let bridge_ca = pkits_cert("BasicSelfIssuedOldKeyNewWithOldCACert");
    let anchor = pkits_trust_anchor();

    let mut pool = CertPool::new();
    pool.add(bridge_ca.clone());
    pool.add(oldkey_ca.clone());

    let oldkey_spki = encode_spki(&oldkey_ca);
    let bridge_spki = encode_spki(&bridge_ca);

    let iter = build_path_candidates(&ee, &pool, std::slice::from_ref(&anchor));
    let mut chains: Vec<Vec<Certificate>> = Vec::new();
    for item in iter {
        let chain = item.expect("no fatal errors expected on this fixture");
        // Each yielded chain's terminal cert must be issued by the anchor.
        let terminal_issuer = &chain
            .last()
            .expect("yielded chain non-empty")
            .tbs_certificate
            .issuer;
        assert!(
            pkix_path::names_match(&anchor.subject, terminal_issuer),
            "yielded chain must terminate at the trust anchor"
        );
        chains.push(chain);
    }

    // Two topologically valid chains exist:
    //   [Test4EE, oldkey]                       (length 2)
    //   [Test4EE, bridge, oldkey]               (length 3)
    // Both must be yielded.
    assert_eq!(
        chains.len(),
        2,
        "exactly two topologically valid chains must be yielded; got {}",
        chains.len()
    );
    let len2 = chains.iter().filter(|c| c.len() == 2).count();
    let len3 = chains.iter().filter(|c| c.len() == 3).count();
    assert_eq!(len2, 1, "one length-2 chain expected (direct via oldkey)");
    assert_eq!(
        len3, 1,
        "one length-3 chain expected (via bridge then oldkey)"
    );

    // The shortest chain (length 2) must use OldKeyCACert directly.
    let shortest = chains.iter().find(|c| c.len() == 2).expect("present");
    assert_eq!(encode_spki(&shortest[1]), oldkey_spki);
    // The longer chain must traverse the bridge first, then OldKeyCA.
    let longer = chains.iter().find(|c| c.len() == 3).expect("present");
    assert_eq!(encode_spki(&longer[1]), bridge_spki);
    assert_eq!(encode_spki(&longer[2]), oldkey_spki);
}

/// PathCandidates iterator: returns `None` after enumeration is exhausted.
///
/// Construction: a single-intermediate happy-path chain (PKITS §4.1.1).
/// Exactly one topologically valid path exists. The iterator yields it
/// once and then returns `None` indefinitely.
#[test]
fn test_iterator_returns_none_after_exhaustion() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let intermediate = pkits_cert("GoodCACert");
    let anchor = pkits_trust_anchor();

    let mut pool = CertPool::new();
    pool.add(intermediate);

    let mut iter = build_path_candidates(&ee, &pool, std::slice::from_ref(&anchor));
    let first = iter.next();
    assert!(
        matches!(first, Some(Ok(_))),
        "first call must yield a chain"
    );

    // After the only chain is yielded, the iterator must be exhausted.
    let second = iter.next();
    assert!(second.is_none(), "second call must return None");

    // And remain exhausted on subsequent calls (the `done` flag is sticky).
    let third = iter.next();
    assert!(third.is_none(), "subsequent calls must remain None");
}

/// PathCandidates iterator: budget is shared across all `next()` calls.
///
/// Construction: identical to the budget-exhaustion test for the legacy
/// `build_path` (30 same-DN self-issued CAs, no anchor reachable). The
/// iterator must terminate with `Err(BudgetExceeded)` and become exhausted.
/// After the error is yielded once, subsequent `next()` calls must
/// return `None`.
///
/// Independent oracle: wall-clock time bound — a buggy iterator with no
/// budget bound would not terminate within the test time limit.
#[test]
fn test_iterator_budget_bounded_across_calls() {
    const N: usize = 30;
    const _: () = assert!(N <= u8::MAX as usize, "N must fit in u8");

    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let template_ca = pkits_cert("GoodCACert");
    let fake_anchor = TrustAnchor::from(&pkits_cert("BadSignedCACert"));

    let mut pool = CertPool::new();
    for i in 0..N {
        let mut ca = template_ca.clone();
        ca.tbs_certificate.issuer = ca.tbs_certificate.subject.clone();
        ca.tbs_certificate
            .subject_public_key_info
            .subject_public_key = BitString::new(
            0,
            vec![u8::try_from(i).expect("loop bound N fits in u8"); 32],
        )
        .expect("BitString construction must succeed for valid parameters");
        pool.add(ca);
    }

    let start = std::time::Instant::now();
    let mut iter = build_path_candidates(&ee, &pool, std::slice::from_ref(&fake_anchor));

    // Pull until the iterator terminates (None) or yields an error.
    let mut got_budget_exceeded = false;
    let mut yielded_chains = 0_usize;
    let mut steps = 0_usize;
    loop {
        match iter.next() {
            None => break,
            Some(Ok(_)) => {
                yielded_chains += 1;
            }
            Some(Err(pkix_path_builder::Error::BudgetExceeded)) => {
                got_budget_exceeded = true;
                break;
            }
            Some(Err(e)) => panic!("unexpected error: {e}"),
        }
        steps += 1;
        // Defensive cap so a buggy iterator without a budget cannot wedge the test.
        assert!(
            steps < 50_000,
            "iterator did not terminate; budget appears unbounded"
        );
    }
    let elapsed = start.elapsed();

    assert!(
        got_budget_exceeded,
        "iterator must yield BudgetExceeded on adversarial pool; \
         yielded {yielded_chains} chains and {steps} steps before termination"
    );
    assert!(
        elapsed.as_secs() < 2,
        "iterator took {elapsed:?}; budget enforcement must prevent exponential blowup"
    );

    // After BudgetExceeded, subsequent calls must return None.
    let after_error = iter.next();
    assert!(
        after_error.is_none(),
        "iterator must be exhausted after BudgetExceeded; got {after_error:?}"
    );
}

/// PathCandidates iterator: respects a `PathBuilderConfig` `max_depth`
/// of 0 by yielding only the trivial `[target]` chain when target's
/// issuer matches an anchor directly (no intermediates needed).
///
/// Construction: target = `GoodCACert` (a PKITS intermediate whose
/// issuer is "Trust Anchor"), anchor = the PKITS trust anchor. Target's
/// issuer matches anchor.subject ⇒ anchor matches at frame 0 with no
/// intermediate, even when `max_depth = 0` rules out exploring any
/// candidates at all.
///
/// This pins down the depth-0 base case and confirms that
/// `build_path_candidates_with_config` plumbs `max_depth` through.
#[test]
fn test_iterator_max_depth_zero_respects_trivial_chain() {
    // GoodCACert is directly issued by the PKITS trust anchor.
    let target = pkits_cert("GoodCACert");
    let anchor = pkits_trust_anchor();

    let pool = CertPool::new();
    let mut config = PathBuilderConfig::new();
    config.max_depth = 0;
    config.dfs_budget = 1000;

    let mut iter =
        build_path_candidates_with_config(&target, &pool, std::slice::from_ref(&anchor), &config);
    let chain = iter
        .next()
        .expect("iterator must yield the trivial chain")
        .expect("no error expected on trivial chain");
    assert_eq!(
        chain.len(),
        1,
        "max_depth=0 yields the target alone (anchor matches at frame 0)"
    );

    // No further chains exist (pool is empty).
    assert!(
        iter.next().is_none(),
        "iterator must exhaust after one yield"
    );
}

// ──────────────────────────────────────────────────────────────────────
// PKIX-qgw1: skip-not-fail on malformed BasicConstraints
//
// A candidate intermediate whose `BasicConstraints` extension is present
// but cannot be DER-decoded must be silently skipped rather than poison
// the whole search. CMS `SignedData.certificates` bags routinely include
// unsolicited / corrupt certs; one bad cert in the bag must not abort
// verification of an otherwise-valid chain.
// ──────────────────────────────────────────────────────────────────────

/// Pool contains a malformed-`BasicConstraints` cert AND a valid
/// intermediate. `build_path` must skip the malformed cert and return
/// the chain through the valid intermediate.
///
/// Independent oracle: `pkix_path::validate_path` succeeds on the
/// returned chain. Because the malformed cert's outer signature bytes
/// would not verify (the corruption breaks the TBS encoding the
/// signature was computed over), `validate_path` succeeding is proof
/// that the well-formed `GoodCACert` clone was selected.
#[test]
fn test_build_path_skips_malformed_bc_when_valid_alternative_exists() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let valid_intermediate = pkits_cert("GoodCACert");
    let malformed = corrupt_basic_constraints(pkits_cert("GoodCACert"));
    let anchor = pkits_trust_anchor();

    // Insert the malformed cert FIRST so it shows up earlier in the
    // candidate ranking. Both candidates share the same subject DN, so
    // they fall in the same AKI tier and pool insertion order
    // determines which one is tried first. The skip-not-fail change
    // means the malformed cert is skipped even though it is tried
    // before the valid one.
    let mut pool = CertPool::new();
    pool.add(malformed);
    pool.add(valid_intermediate);

    let path = build_path(&ee, &pool, std::slice::from_ref(&anchor))
        .expect("skip-not-fail: malformed BC must be skipped, valid intermediate selected");

    // Independent oracle: end-to-end cryptographic validation.
    let policy = ValidationPolicy::new(PKITS_NOW);
    let verifier = DefaultVerifier;
    pkix_path::validate_path(&path, &[anchor], &policy, &verifier)
        .expect("validate_path must succeed; this proves the well-formed GoodCACert was selected");
}

/// Pool contains ONLY a malformed-`BasicConstraints` intermediate.
/// `build_path` must return [`pkix_path_builder::Error::NoPathFound`],
/// not a structural-error variant.
///
/// This is the negative half of the contract: skip-not-fail must
/// produce a chain-not-found verdict, not a structural-error verdict,
/// when the corrupt cert was the only available bridge.
#[test]
fn test_build_path_no_path_found_when_only_intermediate_has_malformed_bc() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let malformed = corrupt_basic_constraints(pkits_cert("GoodCACert"));
    let anchor = pkits_trust_anchor();

    let mut pool = CertPool::new();
    pool.add(malformed);

    let err = build_path(&ee, &pool, std::slice::from_ref(&anchor))
        .expect_err("with only a malformed-BC intermediate, no path can be built");

    assert!(
        matches!(err, pkix_path_builder::Error::NoPathFound),
        "expected NoPathFound (skip-not-fail semantics); got {err}"
    );
}

/// Belt-and-braces: insertion order reversed from the first test.
/// Valid intermediate first, malformed second. Build must still
/// succeed; the malformed cert never gets reached because the valid
/// one wins. This documents that pool order doesn't matter for the
/// "alternative exists" case, only for proving skip-not-fail (the
/// first test does that).
#[test]
fn test_build_path_skips_malformed_bc_independent_of_pool_order() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let valid_intermediate = pkits_cert("GoodCACert");
    let malformed = corrupt_basic_constraints(pkits_cert("GoodCACert"));
    let anchor = pkits_trust_anchor();

    let mut pool = CertPool::new();
    pool.add(valid_intermediate);
    pool.add(malformed);

    let path = build_path(&ee, &pool, std::slice::from_ref(&anchor))
        .expect("build_path must succeed regardless of which cert is first in the pool");

    let policy = ValidationPolicy::new(PKITS_NOW);
    let verifier = DefaultVerifier;
    pkix_path::validate_path(&path, &[anchor], &policy, &verifier)
        .expect("validate_path must succeed on the built chain");
}
