//! Seal-path vectors: B-B/B-T/B-LT/B-LTA assembly, degradation warnings,
//! evidence digests, and backend seam rules (§7, §10).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::Arc;

use oneiron_seal::{
    FetchPolicy, NativeSealEngine, OfflineFetcher, PadesProfile, PdfSealEngine, ProfileDegradeReason,
    SealConfig, SealError, SealRequest, SealResourceLimits, SealWarning, TsaEndpoint,
};

use support::{
    p256_identity, rsa_identity, FixtureBackend, FixtureFetcher, FixedClock, TestIdentity,
    TEST_TIME_MS,
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
        resource_limits: SealResourceLimits::default(),
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

#[tokio::test]
async fn seal_baseline_b_both_suites_and_fixtures() {
    for (mk, name) in [(p256_identity as fn(bool) -> TestIdentity, "p256"), (rsa_identity, "rsa")] {
        for pdf in ["classic_1page.pdf", "stream_1page.pdf", "acroform.pdf", "multipage.pdf"] {
            let id = mk(false);
            let anchor = id.cert_der.clone();
            let (engine, _backend) = engine_with(
                id,
                Arc::new(OfflineFetcher),
                config_for(vec![anchor], false),
            );
            let input = fixture_pdf(pdf);
            let out = engine
                .seal_pdf(&input, &request(PadesProfile::BaselineB))
                .await
                .unwrap_or_else(|e| panic!("seal failed for {name}/{pdf}: {e}"));
            assert_eq!(out.achieved_profile, PadesProfile::BaselineB);
            assert!(out.warnings.is_empty());
            assert!(out.self_verify_report.passes_self_verify());
            assert_eq!(out.evidence_sha256, support::sha256(&out.bytes));
            // Every pre-existing input byte is preserved (§7.1 rule 8).
            assert!(out.bytes.starts_with(&input));
            assert!(out.bytes.ends_with(b"%%EOF"));
            // Independent verify entry point agrees.
            let report = engine.verify_sealed_pdf(&out.bytes).unwrap();
            assert!(report.valid);
            assert_eq!(report.achieved_profile, Some(PadesProfile::BaselineB));
            assert_eq!(report.evidence_sha256, out.evidence_sha256);
        }
    }
}

#[tokio::test]
async fn seal_baseline_t_with_fixture_tsa() {
    let signer = p256_identity(false);
    let tsa = p256_identity(true);
    let anchors = vec![signer.cert_der.clone(), tsa.cert_der.clone()];
    let fetcher = Arc::new(FixtureFetcher::with_tsa(tsa));
    let (engine, _b) = engine_with(signer, fetcher, config_for(anchors, true));
    let input = fixture_pdf("classic_1page.pdf");
    let out = engine
        .seal_pdf(&input, &request(PadesProfile::BaselineT))
        .await
        .unwrap();
    assert_eq!(out.achieved_profile, PadesProfile::BaselineT);
    assert!(out.warnings.is_empty());
    let report = engine.verify_sealed_pdf(&out.bytes).unwrap();
    assert!(report.valid);
    assert_eq!(report.achieved_profile, Some(PadesProfile::BaselineT));
}

#[tokio::test]
async fn seal_baseline_lt_and_lta_full_assembly() {
    let signer = rsa_identity(false);
    let tsa = p256_identity(true);
    let anchors = vec![signer.cert_der.clone(), tsa.cert_der.clone()];
    let fetcher = Arc::new(FixtureFetcher::with_tsa(tsa));
    let (engine, _b) = engine_with(signer, fetcher, config_for(anchors, true));
    let input = fixture_pdf("classic_1page.pdf");
    let out = engine
        .seal_pdf(&input, &request(PadesProfile::BaselineLt))
        .await
        .unwrap();
    assert_eq!(out.achieved_profile, PadesProfile::BaselineLt);
    assert!(out.warnings.is_empty());

    // B-LTA on a fresh seal run reaches the archival profile.
    let signer2 = rsa_identity(false);
    let tsa2 = p256_identity(true);
    let anchors2 = vec![signer2.cert_der.clone(), tsa2.cert_der.clone()];
    let fetcher2 = Arc::new(FixtureFetcher::with_tsa(tsa2));
    let (engine2, _b2) = engine_with(signer2, fetcher2, config_for(anchors2, true));
    let out2 = engine2
        .seal_pdf(&fixture_pdf("classic_1page.pdf"), &request(PadesProfile::BaselineLta))
        .await
        .unwrap();
    assert_eq!(out2.achieved_profile, PadesProfile::BaselineLta);
    let report2 = engine2.verify_sealed_pdf(&out2.bytes).unwrap();
    assert!(report2.valid);
    assert_eq!(report2.achieved_profile, Some(PadesProfile::BaselineLta));
}

#[tokio::test]
async fn degradation_ladder_offline_fetcher() {
    let signer = p256_identity(false);
    let anchor = signer.cert_der.clone();
    let (engine, _b) = engine_with(
        signer,
        Arc::new(OfflineFetcher),
        config_for(vec![anchor], true),
    );
    let input = fixture_pdf("classic_1page.pdf");
    let out = engine
        .seal_pdf(&input, &request(PadesProfile::BaselineLta))
        .await
        .unwrap();
    assert_eq!(out.achieved_profile, PadesProfile::BaselineB);
    let reasons: Vec<_> = out
        .warnings
        .iter()
        .map(|w| match w {
            SealWarning::ProfileDegraded {
                requested,
                achieved,
                reason,
            } => {
                assert_eq!(*requested, PadesProfile::BaselineLta);
                assert_eq!(*achieved, PadesProfile::BaselineB);
                *reason
            }
        })
        .collect();
    assert!(reasons.contains(&ProfileDegradeReason::TimestampUnavailable));
    assert!(reasons.contains(&ProfileDegradeReason::ValidationMaterialUnavailable));
    assert!(reasons.contains(&ProfileDegradeReason::DocumentTimestampUnavailable));
    assert!(out.self_verify_report.passes_self_verify());
}

#[tokio::test]
async fn target_b_t_offline_degrades_to_b_with_timestamp_warning_only() {
    let signer = p256_identity(false);
    let anchor = signer.cert_der.clone();
    let (engine, _b) = engine_with(
        signer,
        Arc::new(OfflineFetcher),
        config_for(vec![anchor], true),
    );
    let out = engine
        .seal_pdf(&fixture_pdf("classic_1page.pdf"), &request(PadesProfile::BaselineT))
        .await
        .unwrap();
    assert_eq!(out.achieved_profile, PadesProfile::BaselineB);
    assert_eq!(out.warnings.len(), 1);
}

#[tokio::test]
async fn backend_operation_ids_stable_per_operation() {
    let signer = p256_identity(false);
    let anchor = signer.cert_der.clone();
    let (engine, backend) = engine_with(
        signer,
        Arc::new(OfflineFetcher),
        config_for(vec![anchor], false),
    );
    let input = fixture_pdf("classic_1page.pdf");
    engine
        .seal_pdf(&input, &request(PadesProfile::BaselineB))
        .await
        .unwrap();
    let first: Vec<String> = backend
        .requests
        .lock()
        .unwrap()
        .iter()
        .map(|r| r.operation_id.clone())
        .collect();
    engine
        .seal_pdf(&input, &request(PadesProfile::BaselineB))
        .await
        .unwrap();
    let second: Vec<String> = backend
        .requests
        .lock()
        .unwrap()
        .iter()
        .map(|r| r.operation_id.clone())
        .skip(first.len())
        .collect();
    assert_eq!(first, second, "same operation must derive stable sub-ids");
    assert!(first[0].starts_with("test-op-0001:"));
}

#[tokio::test]
async fn p1363_backend_output_is_rejected() {
    let signer = p256_identity(false);
    let anchor = signer.cert_der.clone();
    let (engine, backend) = engine_with(
        signer,
        Arc::new(OfflineFetcher),
        config_for(vec![anchor], false),
    );
    backend.raw_p1363.store(true, std::sync::atomic::Ordering::SeqCst);
    let err = engine
        .seal_pdf(&fixture_pdf("classic_1page.pdf"), &request(PadesProfile::BaselineB))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        SealError::Fatal {
            code: oneiron_seal::FatalCode::InvalidSigningIdentity,
            ..
        }
    ));
}

#[tokio::test]
async fn invalid_operation_id_is_fatal_configuration() {
    let signer = p256_identity(false);
    let anchor = signer.cert_der.clone();
    let (engine, _b) = engine_with(
        signer,
        Arc::new(OfflineFetcher),
        config_for(vec![anchor], false),
    );
    let bad = SealRequest {
        operation_id: String::new(),
        target_profile: PadesProfile::BaselineB,
    };
    let err = engine
        .seal_pdf(&fixture_pdf("classic_1page.pdf"), &bad)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        SealError::Fatal {
            code: oneiron_seal::FatalCode::InvalidConfiguration,
            ..
        }
    ));
    assert!(!err.is_retryable());
}
