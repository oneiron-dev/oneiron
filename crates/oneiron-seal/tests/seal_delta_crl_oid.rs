//! Seal-path rows for the CRL complete-scope OID gate
//! (FIX-LIST [SEAL-DELTA-CRL-OID]): a delta CRL (carrying
//! deltaCRLIndicator, 2.5.29.27) is not complete revocation evidence, while
//! a complete base CRL that merely advertises freshestCRL (2.5.29.46) is.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::Arc;

use oneiron_seal::{
    FetchPolicy, NativeSealEngine, PadesProfile, PdfSealEngine, ProfileDegradeReason, SealConfig,
    SealRequest, SealWarning, TsaEndpoint,
};

use support::{
    FixedClock, FixtureBackend, FixtureFetcher, TEST_TIME_MS, TestIdentity, ca_with_kus,
    leaf_identity_with_crl_dp, p256_identity,
};

fn fixture_pdf(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/pdf-input/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(path).unwrap()
}

fn config_for(anchors: Vec<Vec<u8>>, with_tsa: bool) -> SealConfig {
    SealConfig {
        trust_anchors_der: anchors,
        timestamp_authorities: if with_tsa {
            vec![TsaEndpoint {
                url: url::Url::parse("https://tsa.example.test/").unwrap(),
                expected_policy_oid: None,
            }]
        } else {
            Vec::new()
        },
        fetch_policy: FetchPolicy::default(),
        resource_limits: support::grant_all_limits(),
    }
}

fn request(target: PadesProfile) -> SealRequest {
    SealRequest {
        operation_id: "test-op-0001".to_string(),
        target_profile: target,
    }
}

fn engine_with(
    id: TestIdentity,
    fetcher: Arc<dyn oneiron_seal::SealFetcher>,
    config: SealConfig,
) -> (NativeSealEngine, Arc<FixtureBackend>) {
    let backend = Arc::new(FixtureBackend::new(id));
    let engine = NativeSealEngine::new(
        config,
        backend.clone(),
        fetcher,
        Arc::new(FixedClock(TEST_TIME_MS)),
    )
    .unwrap();
    (engine, backend)
}

/// One CRL `Extension` SEQUENCE (RFC 5280 5.2): OID, optional critical
/// flag, and the DER of the extension value in an OCTET STRING.
fn crl_extension(oid_content: &[u8], critical: bool, value_der: &[u8]) -> Vec<u8> {
    let mut body = support::oid_tlv(oid_content);
    if critical {
        body.extend_from_slice(&support::tlv(0x01, &[0xff]));
    }
    body.extend_from_slice(&support::tlv(0x04, value_der));
    support::tlv(0x30, &body)
}

/// deltaCRLIndicator value (RFC 5280 5.2.4): the number of the base CRL
/// this delta applies to. Critical, as issued in practice.
fn delta_indicator_ext(base_crl_number: u8) -> Vec<u8> {
    crl_extension(
        &[0x55, 0x1d, 0x1b],
        true,
        &support::tlv(0x02, &[base_crl_number]),
    )
}

/// freshestCRL value (RFC 5280 5.2.7): where to fetch a newer (delta) CRL.
/// Non-critical: a base CRL carrying it is still complete evidence.
fn freshest_crl_ext(delta_url: &str) -> Vec<u8> {
    // One DistributionPoint naming the delta location by fullName URI.
    let name = support::tlv(0x86, delta_url.as_bytes());
    let full_name = support::tlv(0xA0, &name);
    let dp_name = support::tlv(0xA0, &full_name);
    let dp = support::tlv(0x30, &dp_name);
    crl_extension(&[0x55, 0x1d, 0x2e], false, &support::tlv(0x30, &dp))
}

/// A v2 CRL signed by `ca` (P-256) carrying caller-chosen CRL extensions:
/// the same TBS bytes as `support::signed_crl_der` plus a trailing
/// `[0] EXPLICIT Extensions` (RFC 5280 5.1). `this_update`/`next_update`
/// are GeneralizedTime strings ("YYYYMMDDHHMMSSZ").
fn signed_crl_der_with_extensions(
    ca: &support::TestCa,
    this_update: &str,
    next_update: &str,
    extensions: &[Vec<u8>],
) -> Vec<u8> {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    // For the self-signed fixture CA the issuer Name TLV is the subject.
    let (issuer_name, _serial) = support::issuer_and_serial(&ca.cert_der);
    let alg = support::alg_id(support::OID_ECDSA_SHA256, false);
    let mut tbs_body = support::tlv(0x02, &[1]); // version v2
    tbs_body.extend_from_slice(&alg);
    tbs_body.extend_from_slice(&issuer_name);
    tbs_body.extend_from_slice(&support::tlv(0x18, this_update.as_bytes()));
    tbs_body.extend_from_slice(&support::tlv(0x18, next_update.as_bytes()));
    let mut ext_seq: Vec<u8> = Vec::new();
    for ext in extensions {
        ext_seq.extend_from_slice(ext);
    }
    tbs_body.extend_from_slice(&support::tlv(0xA0, &support::tlv(0x30, &ext_seq)));
    let tbs = support::tlv(0x30, &tbs_body);
    let digest = support::sha256(&tbs);
    let sig: p256::ecdsa::Signature = ca.signing_key.sign_prehash(&digest).unwrap();
    let mut bit_string = vec![0u8]; // no unused bits
    bit_string.extend_from_slice(sig.to_der().as_bytes());
    let mut body = tbs;
    body.extend_from_slice(&alg);
    body.extend_from_slice(&support::tlv(0x03, &bit_string));
    support::tlv(0x30, &body)
}

#[tokio::test]
async fn seal_degrades_to_b_t_when_dp_crl_carries_delta_indicator() {
    // The leaf's CRL DP serves a well-formed, fresh, correctly-signed CRL
    // that carries deltaCRLIndicator (2.5.29.27): changes since a base CRL,
    // not complete revocation evidence (a revoked cert absent from the
    // delta would read as not revoked). The gather must refuse it, so the
    // seal degrades to B-T with a structured warning instead of embedding
    // it.
    let root = ca_with_kus(
        "root-delta-scope",
        vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ],
    );
    let leaf = leaf_identity_with_crl_dp(&root, "signer-leaf", "https://crl.example.test/root.crl");
    let tsa = p256_identity(true);
    let delta = delta_indicator_ext(7);
    let crl = signed_crl_der_with_extensions(&root, "20260730070000Z", "20260730090000Z", &[delta]);
    let anchors = vec![root.cert_der.clone(), tsa.cert_der.clone()];
    let mut fetcher = FixtureFetcher::with_tsa(tsa);
    fetcher.responses.insert(
        "https://crl.example.test/root.crl".to_string(),
        oneiron_seal::FetchResponse {
            body: support::shared_bytes(&crl),
            content_type: None,
        },
    );
    let (engine, _b) = engine_with(leaf, Arc::new(fetcher), config_for(anchors, true));
    let out = engine
        .seal_pdf(
            &fixture_pdf("classic_1page.pdf"),
            &request(PadesProfile::BaselineLt),
        )
        .await
        .unwrap();
    assert_eq!(out.achieved_profile, PadesProfile::BaselineT);
    assert!(
        out.warnings.iter().any(|w| matches!(
            w,
            SealWarning::ProfileDegraded {
                requested,
                achieved,
                reason,
            } if *requested == PadesProfile::BaselineLt
                && *achieved == PadesProfile::BaselineT
                && *reason == ProfileDegradeReason::ValidationMaterialUnavailable
        )),
        "expected a B-LT -> B-T ValidationMaterialUnavailable degradation: {:?}",
        out.warnings
    );
    assert!(out.self_verify_report.passes_self_verify());
    let report = engine.verify_sealed_pdf(&out.bytes).unwrap();
    assert!(report.valid());
    assert_eq!(report.achieved_profile(), Some(PadesProfile::BaselineT));
}

#[tokio::test]
async fn seal_achieves_b_lt_when_base_crl_advertises_freshest_crl() {
    // Control: a complete base CRL that merely advertises where its delta
    // lives (freshestCRL, 2.5.29.46) is complete evidence and must gather,
    // reaching B-LT with no warnings.
    let root = ca_with_kus(
        "root-freshest-scope",
        vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ],
    );
    let leaf = leaf_identity_with_crl_dp(&root, "signer-leaf", "https://crl.example.test/root.crl");
    let tsa = p256_identity(true);
    let freshest = freshest_crl_ext("https://crl.example.test/root-delta.crl");
    let crl =
        signed_crl_der_with_extensions(&root, "20260730070000Z", "20260730090000Z", &[freshest]);
    let anchors = vec![root.cert_der.clone(), tsa.cert_der.clone()];
    let mut fetcher = FixtureFetcher::with_tsa(tsa);
    fetcher.responses.insert(
        "https://crl.example.test/root.crl".to_string(),
        oneiron_seal::FetchResponse {
            body: support::shared_bytes(&crl),
            content_type: None,
        },
    );
    let (engine, _b) = engine_with(leaf, Arc::new(fetcher), config_for(anchors, true));
    let out = engine
        .seal_pdf(
            &fixture_pdf("classic_1page.pdf"),
            &request(PadesProfile::BaselineLt),
        )
        .await
        .unwrap();
    assert_eq!(out.achieved_profile, PadesProfile::BaselineLt);
    assert!(out.warnings.is_empty());
    let report = engine.verify_sealed_pdf(&out.bytes).unwrap();
    assert!(report.valid());
    assert_eq!(report.achieved_profile(), Some(PadesProfile::BaselineLt));
}
