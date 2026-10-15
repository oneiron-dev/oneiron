//! Verify-path vectors: mutation matrix, prepared-input rejection codes,
//! and structural failure classification (§7.1, §7.7, §10).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron_seal::{
    FetchPolicy, InputInvalidCode, NativeSealEngine, OfflineFetcher, PadesProfile, PdfSealEngine,
    SealConfig, SealError, SealRequest, SealResourceLimits, VerifyCheckKind, VerifyCheckStatus,
    VerifyFindingCode, VerifyReport,
};

use crate::support::{FixedClock, FixtureBackend, TEST_TIME_MS, TestIdentity, p256_identity};

fn fixture_pdf(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/pdf-input/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(path).unwrap()
}

fn sealed_b_input(input: &[u8]) -> (NativeSealEngine, Vec<u8>) {
    let id: TestIdentity = p256_identity(false);
    let anchor = id.cert_der.clone();
    let engine = NativeSealEngine::new(
        SealConfig {
            trust_anchors_der: vec![anchor],
            timestamp_authorities: Vec::new(),
            fetch_policy: FetchPolicy::default(),
            resource_limits: SealResourceLimits::default(),
        },
        Arc::new(FixtureBackend::new(id)),
        Arc::new(OfflineFetcher),
        Arc::new(FixedClock(TEST_TIME_MS)),
    )
    .unwrap();
    let out = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(engine.seal_pdf(
            input,
            &SealRequest {
                operation_id: "verify-vector".to_string(),
                target_profile: PadesProfile::BaselineB,
            },
        ))
        .unwrap();
    (engine, out.bytes)
}

fn sealed_b() -> (NativeSealEngine, Vec<u8>) {
    sealed_b_input(&fixture_pdf("classic_1page.pdf"))
}

fn finding(report: &VerifyReport, kind: VerifyCheckKind) -> Option<VerifyFindingCode> {
    report
        .checks()
        .find(|c| c.kind == kind && c.status == VerifyCheckStatus::Fail)
        .and_then(|c| c.finding)
}

#[test]
fn prepared_input_rejection_matrix() {
    let (engine, _) = sealed_b();
    let cases: &[(&str, InputInvalidCode)] = &[
        ("neg_signed.pdf", InputInvalidCode::ExistingSignature),
        ("neg_docts.pdf", InputInvalidCode::ExistingSignature),
        ("neg_sigpair.pdf", InputInvalidCode::ExistingSignature),
        ("neg_openaction.pdf", InputInvalidCode::ActiveContentPresent),
        ("neg_aa.pdf", InputInvalidCode::ActiveContentPresent),
        ("neg_js.pdf", InputInvalidCode::ActiveContentPresent),
        (
            "neg_js_indirect.pdf",
            InputInvalidCode::ActiveContentPresent,
        ),
        (
            "neg_js_deep_indirect.pdf",
            InputInvalidCode::ActiveContentPresent,
        ),
        ("neg_launch.pdf", InputInvalidCode::ActiveContentPresent),
        ("neg_names_js.pdf", InputInvalidCode::ActiveContentPresent),
        ("neg_embedded.pdf", InputInvalidCode::EmbeddedFilePresent),
        ("neg_nopages.pdf", InputInvalidCode::MissingPage),
        ("neg_malformed.pdf", InputInvalidCode::MalformedXref),
        ("neg_hybrid.pdf", InputInvalidCode::UnsupportedHybridXref),
    ];
    for (file, expected) in cases {
        let input = fixture_pdf(file);
        let err = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(engine.seal_pdf(
                &input,
                &SealRequest {
                    operation_id: "neg".to_string(),
                    target_profile: PadesProfile::BaselineB,
                },
            ))
            .unwrap_err();
        match err {
            SealError::InputInvalid { code } => {
                assert_eq!(code, *expected, "wrong code for {file}");
            }
            other => panic!("{file}: expected InputInvalid({expected:?}), got {other}"),
        }
    }
    // Empty / non-PDF / oversize short-circuit before parsing.
    for (input, expected) in [
        (Vec::new(), InputInvalidCode::Empty),
        (b"not a pdf at all".to_vec(), InputInvalidCode::NotPdf),
    ] {
        let err = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(engine.seal_pdf(
                &input,
                &SealRequest {
                    operation_id: "neg".to_string(),
                    target_profile: PadesProfile::BaselineB,
                },
            ))
            .unwrap_err();
        assert!(matches!(
            err,
            SealError::InputInvalid { code } if code == expected
        ));
    }
}

#[test]
fn one_byte_mutation_in_signed_span_fails_digest() {
    let (engine, bytes) = sealed_b();
    // Byte 40 lives inside the original content, covered by span 1.
    let mut mutated = bytes;
    mutated[40] ^= 0x01;
    let report = engine.verify_sealed_pdf(&mutated).unwrap();
    assert!(!report.valid());
    assert_eq!(
        finding(&report, VerifyCheckKind::ContentDigest),
        Some(VerifyFindingCode::DigestMismatch)
    );
    assert_eq!(report.achieved_profile(), None);
}

#[test]
fn mutation_inside_cms_signed_attributes_fails() {
    let (engine, bytes) = sealed_b();
    // Locate the message-digest attribute OID inside the hex-encoded CMS and
    // flip one hex digit pair (a byte inside the signed-attribute region).
    let needle = b"2A864886F70D010904";
    let hay: Vec<u8> = bytes.iter().map(u8::to_ascii_uppercase).collect();
    let pos = hay
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("message-digest OID present");
    let mut mutated = bytes;
    // Flip a byte a little past the OID: inside the attribute value.
    let at = pos + needle.len() + 24;
    mutated[at] = if mutated[at] == b'0' { b'1' } else { b'0' };
    let report = engine.verify_sealed_pdf(&mutated).unwrap();
    assert!(!report.valid());
    let f = [
        finding(&report, VerifyCheckKind::ContentDigest),
        finding(&report, VerifyCheckKind::SignedAttributes),
        finding(&report, VerifyCheckKind::SignatureValue),
        finding(&report, VerifyCheckKind::CmsEnvelope),
        finding(&report, VerifyCheckKind::SigningCertificateBinding),
    ];
    assert!(
        f.iter().flatten().any(|c| matches!(
            c,
            VerifyFindingCode::DigestMismatch
                | VerifyFindingCode::InvalidSignedAttributes
                | VerifyFindingCode::SignatureMismatch
                | VerifyFindingCode::InvalidCms
                | VerifyFindingCode::CertificateBindingMismatch
        )),
        "expected a CMS-class failure, got {f:?}"
    );
}

#[test]
fn trailing_bytes_after_final_eof_fail() {
    let (engine, bytes) = sealed_b();
    let mut mutated = bytes;
    mutated.extend_from_slice(b"\njunk-after-eof");
    let report = engine.verify_sealed_pdf(&mutated).unwrap();
    assert!(!report.valid());
    assert_eq!(
        finding(&report, VerifyCheckKind::PdfRevision),
        Some(VerifyFindingCode::InvalidPdfRevision)
    );
}

#[test]
fn unsigned_document_is_not_valid() {
    let (engine, _) = sealed_b();
    let report = engine
        .verify_sealed_pdf(&fixture_pdf("classic_1page.pdf"))
        .unwrap();
    assert!(!report.valid());
    assert_eq!(report.achieved_profile(), None);
}

#[test]
fn v2_report_keeps_per_signature_evidence_and_derived_verdict() {
    let (engine, bytes) = sealed_b();
    let report = engine.verify_sealed_pdf(&bytes).unwrap();
    assert_eq!(report.verdict(), oneiron_seal::VerifyVerdict::Passed);
    assert_eq!(report.signatures.len(), 1);
    let sig = &report.signatures[0];
    assert_eq!(sig.kind, oneiron_seal::SignatureKind::Signature);
    assert_eq!(sig.coverage, oneiron_seal::Coverage::EntireFile);
    assert_eq!(sig.trust, VerifyCheckStatus::Pass);
    assert_eq!(sig.byte_range.values[0], 0);
    assert_eq!(sig.byte_range.covers_to, Some(bytes.len() as u64));
    assert!(sig.digest.is_some());
    assert_eq!(
        report.modifications,
        oneiron_seal::Modifications::Clean(oneiron_seal::ModificationLevel::None)
    );
    assert_eq!(report.revisions.len(), 2);
    assert!(
        report.anomalies.is_empty(),
        "ordinary signing is not anomalous"
    );
    assert_eq!(
        report.revisions[1].signed_by.as_deref(),
        Some(sig.id.as_str())
    );
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["verdict"], "passed", "wire verdict is derived");
    assert!(json["reasons"].as_array().unwrap().is_empty());
}

#[test]
fn marker_in_stream_is_accepted_by_input_gate_and_self_verify() {
    let mut doc = lopdf::Document::load_mem(&fixture_pdf("classic_1page.pdf")).unwrap();
    doc.add_object(lopdf::Stream::new(
        lopdf::Dictionary::new(),
        b"startxref\n0\n%%EOF\n".to_vec(),
    ));
    let mut input = Vec::new();
    doc.save_to(&mut input).unwrap();
    let (engine, signed) = sealed_b_input(&input);
    assert_eq!(
        engine.verify_sealed_pdf(&signed).unwrap().verdict(),
        oneiron_seal::VerifyVerdict::Passed
    );
}

// Bounded property/fuzz legs (test budget: 24 cases each, no dependency
// re-testing): arbitrary bytes must yield a structured result, never a
// panic or unbounded allocation.
mod prop {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(24))]

        #[test]
        fn arbitrary_bytes_never_panic_verify(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let (engine, _) = sealed_b();
            let _ = engine.verify_sealed_pdf(&bytes);
        }

        #[test]
        fn pdf_prefixed_prefixes_never_panic_verify(
            tail in proptest::collection::vec(any::<u8>(), 0..2048)
        ) {
            let (engine, _) = sealed_b();
            let mut bytes = b"%PDF-1.4\n".to_vec();
            bytes.extend_from_slice(&tail);
            let _ = engine.verify_sealed_pdf(&bytes);
        }
    }
}
