//! Seal-path vectors: B-B/B-T/B-LT/B-LTA assembly, degradation warnings,
//! evidence digests, and backend seam rules (§7, §10).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::{Arc, Mutex};

use oneiron_seal::{
    FetchPolicy, NativeSealEngine, OfflineFetcher, PadesProfile, PdfSealEngine,
    ProfileDegradeReason, SealConfig, SealError, SealRequest, SealResourceLimits, SealWarning,
    TsaEndpoint,
};

use support::{
    FixedClock, FixtureBackend, FixtureFetcher, TEST_TIME_MS, TestIdentity, p256_identity,
    rsa_identity,
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
async fn seal_output_exceeding_verify_cap_is_refused_at_seal_time() {
    // Self-consistency (bot-fix leg 5): verify_document rejects
    // len > max_input_bytes, so the sealer must REFUSE to emit a document
    // past that cap instead of producing a self-rejecting artifact.
    let id = p256_identity(false);
    let anchor = id.cert_der.clone();
    let input = fixture_pdf("classic_1page.pdf");
    let mut config = config_for(vec![anchor], false);
    // Admits the input but not the signature-revision growth.
    config.resource_limits.max_input_bytes = input.len() + 1024;
    let (engine, _backend) = engine_with(id, Arc::new(OfflineFetcher), config);
    let err = engine
        .seal_pdf(&input, &request(PadesProfile::BaselineB))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            SealError::Fatal {
                stage: oneiron_seal::SealStage::PdfIncrementalUpdate,
                code: oneiron_seal::FatalCode::PdfInvariantFailed,
            }
        ),
        "over-cap seal must be refused at seal time: {err:?}"
    );
}

#[tokio::test]
async fn seal_baseline_b_both_suites_and_fixtures() {
    for (mk, name) in [
        (p256_identity as fn(bool) -> TestIdentity, "p256"),
        (rsa_identity, "rsa"),
    ] {
        for pdf in [
            "classic_1page.pdf",
            "stream_1page.pdf",
            // P1-1 pin: a page with a real content stream carries /Contents
            // without /ByteRange — mandatory self-verification must not
            // false-reject it as a partial signature shape.
            "content_1page.pdf",
            "acroform.pdf",
            "multipage.pdf",
        ] {
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

/// Two functional TSAs: the first endpoint mints tokens dated past the
/// documented clock skew, the second mints valid ones.
struct TwoTsaFetcher {
    skewed_tsa: TestIdentity,
    good_tsa: TestIdentity,
    skewed_url: String,
    good_url: String,
    calls: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl oneiron_seal::SealFetcher for TwoTsaFetcher {
    async fn fetch(
        &self,
        request: oneiron_seal::FetchRequest,
    ) -> Result<oneiron_seal::FetchResponse, oneiron_seal::FetchError> {
        self.calls.lock().unwrap().push(request.url.to_string());
        if request.purpose != oneiron_seal::FetchPurpose::Timestamp {
            return Err(oneiron_seal::FetchError::Unavailable);
        }
        let body = if request.url.as_str() == self.skewed_url {
            support::tsa_response_at(
                &self.skewed_tsa,
                &request.request_body,
                TEST_TIME_MS + 600_000,
            )
        } else if request.url.as_str() == self.good_url {
            support::tsa_response(&self.good_tsa, &request.request_body)
        } else {
            None
        };
        body.map(|body| oneiron_seal::FetchResponse {
            body,
            content_type: Some("application/timestamp-reply".to_string()),
        })
        .ok_or(oneiron_seal::FetchError::Unavailable)
    }
}

#[tokio::test]
async fn seal_fails_over_past_over_skew_tsa_token() {
    // The first TSA returns a token dated past the documented skew: the
    // seal-side validation must skip it (the verify path would reject it),
    // so the seal succeeds through the second TSA instead of producing an
    // artifact its own mandatory self-verify refuses.
    let signer = p256_identity(false);
    let skewed_tsa = p256_identity(true);
    let good_tsa = p256_identity(true);
    let anchors = vec![
        signer.cert_der.clone(),
        skewed_tsa.cert_der.clone(),
        good_tsa.cert_der.clone(),
    ];
    let fetcher = Arc::new(TwoTsaFetcher {
        skewed_tsa,
        good_tsa,
        skewed_url: "https://tsa-skewed.example.test/".to_string(),
        good_url: "https://tsa-good.example.test/".to_string(),
        calls: Mutex::new(Vec::new()),
    });
    let mut config = config_for(anchors, false);
    config.timestamp_authorities = vec![
        TsaEndpoint {
            url: url::Url::parse("https://tsa-skewed.example.test/").unwrap(),
            expected_policy_oid: None,
        },
        TsaEndpoint {
            url: url::Url::parse("https://tsa-good.example.test/").unwrap(),
            expected_policy_oid: None,
        },
    ];
    let (engine, _b) = engine_with(signer, fetcher.clone(), config);
    let out = engine
        .seal_pdf(
            &fixture_pdf("classic_1page.pdf"),
            &request(PadesProfile::BaselineT),
        )
        .await
        .unwrap();
    assert_eq!(out.achieved_profile, PadesProfile::BaselineT);
    assert!(
        out.warnings.is_empty(),
        "failover to a valid TSA is not a degradation"
    );
    assert!(out.self_verify_report.passes_self_verify());
    let calls = fetcher.calls.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![
            "https://tsa-skewed.example.test/".to_string(),
            "https://tsa-good.example.test/".to_string()
        ],
        "the over-skew token must be skipped and the next TSA tried"
    );
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
        .seal_pdf(
            &fixture_pdf("classic_1page.pdf"),
            &request(PadesProfile::BaselineLta),
        )
        .await
        .unwrap();
    assert_eq!(out2.achieved_profile, PadesProfile::BaselineLta);
    let report2 = engine2.verify_sealed_pdf(&out2.bytes).unwrap();
    assert!(report2.valid);
    assert_eq!(report2.achieved_profile, Some(PadesProfile::BaselineLta));
}

#[tokio::test]
async fn seal_degrades_to_b_t_when_available_crl_issuer_lacks_crl_sign() {
    // The leaf's CRL DP serves a well-formed, fresh, correctly-signed CRL —
    // but the issuer certificate's KeyUsage omits cRLSign. The gather must
    // refuse it (the verify path would), so the seal degrades to B-T with a
    // structured warning instead of embedding material the mandatory
    // self-verify would reject as a whole-seal VerifyFailed.
    let root = support::ca_with_kus(
        "root-no-crlsign",
        vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyCertSign,
        ],
    );
    let leaf = support::leaf_identity_with_crl_dp(
        &root,
        "signer-leaf",
        "https://crl.example.test/root.crl",
    );
    let tsa = p256_identity(true);
    let crl = support::signed_crl_der(&root, "20260730070000Z", "20260730090000Z");
    let anchors = vec![root.cert_der.clone(), tsa.cert_der.clone()];
    let mut fetcher = FixtureFetcher::with_tsa(tsa);
    fetcher.responses.insert(
        "https://crl.example.test/root.crl".to_string(),
        oneiron_seal::FetchResponse {
            body: crl,
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
        "expected a B-LT → B-T ValidationMaterialUnavailable degradation: {:?}",
        out.warnings
    );
    assert!(out.self_verify_report.passes_self_verify());
    let report = engine.verify_sealed_pdf(&out.bytes).unwrap();
    assert!(report.valid);
    assert_eq!(report.achieved_profile, Some(PadesProfile::BaselineT));
}

#[tokio::test]
async fn seal_achieves_b_lt_when_crl_issuer_asserts_crl_sign() {
    // Control: the same chain and CRL shape with an issuer KeyUsage that
    // asserts cRLSign gathers and reaches B-LT — the gate rejects
    // unauthorized USE, not CRL evidence in general.
    let root = support::ca_with_kus(
        "root-crlsign",
        vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ],
    );
    let leaf = support::leaf_identity_with_crl_dp(
        &root,
        "signer-leaf",
        "https://crl.example.test/root.crl",
    );
    let tsa = p256_identity(true);
    let crl = support::signed_crl_der(&root, "20260730070000Z", "20260730090000Z");
    let anchors = vec![root.cert_der.clone(), tsa.cert_der.clone()];
    let mut fetcher = FixtureFetcher::with_tsa(tsa);
    fetcher.responses.insert(
        "https://crl.example.test/root.crl".to_string(),
        oneiron_seal::FetchResponse {
            body: crl,
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
    assert!(report.valid);
    assert_eq!(report.achieved_profile, Some(PadesProfile::BaselineLt));
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
        .seal_pdf(
            &fixture_pdf("classic_1page.pdf"),
            &request(PadesProfile::BaselineT),
        )
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
    backend
        .raw_p1363
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let err = engine
        .seal_pdf(
            &fixture_pdf("classic_1page.pdf"),
            &request(PadesProfile::BaselineB),
        )
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
