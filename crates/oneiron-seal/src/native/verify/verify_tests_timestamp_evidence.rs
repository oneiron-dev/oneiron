//! Public native-verifier regressions for both RFC 3161 timestamp forms.
#![allow(clippy::unwrap_used)]

use super::super::super::{cms, pdf};
use super::super::verify_revocation::TS_GEN_TIME_MAX_SKEW_SECS;
use super::super::verify_tests_fixtures_dss_a::tests::{AT_UNIX, TestCa, sign_p256, test_ca};
use super::super::verify_tests_lta_probes::tests::base_input;
use super::super::verify_tests_time_lta_a::tests::{
    append_doc_ts_revision, append_sig_revision, mint_token, tsa_ca, verify_engine,
};
use crate::api::{
    PdfSealEngine, SealResourceLimits, SignatureAlgorithm, SignatureKind, VerifyCheckKind,
    VerifyCheckStatus, VerifyFindingCode, VerifyVerdict,
};

/// Mint a fully valid detached signer envelope with caller-controlled unsigned
/// Attributes. This keeps a malformed Attribute inside a parseable envelope.
fn signed_with_unsigned(ca: &TestCa, attrs: impl FnOnce(&[u8]) -> Vec<Vec<u8>>) -> Vec<u8> {
    let input = base_input();
    let state = pdf::reparse_revision(&input, &SealResourceLimits::default()).unwrap();
    let mut draft = pdf::append_revision(
        &input,
        &state,
        &pdf::RevisionKind::Signature {
            field_name: pdf::field_name_for("ts-attribute-regression"),
            date_str: pdf::pdf_date(AT_UNIX * 1000),
        },
        64 * 1024,
    )
    .unwrap();
    let digest = pdf::hash_byte_range(&draft.bytes, draft.byte_range.unwrap()).unwrap();
    let (issuer, serial) = cms::issuer_and_serial(&ca.cert_der).unwrap();
    let (wire, signing) = cms::assemble_signed_attrs(vec![
        cms::attr_content_type_data(),
        cms::attr_message_digest(&digest),
        cms::attr_signing_cert_v2(&ca.cert_der, &issuer, &serial),
    ]);
    let signature = sign_p256(&ca.key, &signing);
    let material = cms::SignerMaterial {
        algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        signer_cert_der: &ca.cert_der,
        issuer_name_der: &issuer,
        serial_der: &serial,
        chain_ders: &[],
    };
    let der = cms::build_signed_data(&material, &wire, &signature, &attrs(&signature));
    pdf::patch_contents(&mut draft, &der).unwrap();
    draft.bytes
}

fn pair(
    report: &crate::api::VerifyReport,
    kind: SignatureKind,
    crypto: VerifyCheckKind,
    trust: VerifyCheckKind,
) -> (
    VerifyCheckStatus,
    VerifyCheckStatus,
    Option<VerifyFindingCode>,
) {
    let sig = report.signatures.iter().find(|s| s.kind == kind).unwrap();
    let crypto_checks: Vec<_> = sig.checks.iter().filter(|c| c.kind == crypto).collect();
    let trust_checks: Vec<_> = sig.checks.iter().filter(|c| c.kind == trust).collect();
    assert_eq!(crypto_checks.len(), 1, "one crypto check per timestamp");
    assert_eq!(trust_checks.len(), 1, "one trust check per timestamp");
    (
        crypto_checks[0].status,
        trust_checks[0].status,
        trust_checks[0].finding,
    )
}

#[test]
fn public_signature_timestamp_attribute_outcomes_are_total_under_both_anchor_sets() {
    type Case = (
        &'static str,
        Vec<u8>,
        VerifyCheckStatus,
        VerifyCheckStatus,
        Option<VerifyFindingCode>,
    );
    let signer = test_ca("ts-attribute-signer");
    let tsa = tsa_ca();
    let cases: [Case; 5] = [
        (
            "absent",
            signed_with_unsigned(&signer, |_| vec![]),
            VerifyCheckStatus::NotApplicable,
            VerifyCheckStatus::NotApplicable,
            None,
        ),
        (
            "malformed-attribute",
            signed_with_unsigned(&signer, |_| vec![cms::tlv(0x30, &cms::tlv(0x02, &[0]))]),
            VerifyCheckStatus::Fail,
            VerifyCheckStatus::NotRun,
            Some(VerifyFindingCode::TrustCheckNotRun),
        ),
        (
            "invalid-token",
            signed_with_unsigned(&signer, |_| vec![cms::attr_ts_token(&[1, 2, 3])]),
            VerifyCheckStatus::Fail,
            VerifyCheckStatus::NotRun,
            Some(VerifyFindingCode::TrustCheckNotRun),
        ),
        (
            "duplicate",
            signed_with_unsigned(&signer, |sig| {
                let token = mint_token(&tsa, &cms::sha256(sig), AT_UNIX);
                let second = mint_token(&tsa, &cms::sha256(sig), AT_UNIX + 1);
                vec![cms::attr_ts_token(&token), cms::attr_ts_token(&second)]
            }),
            VerifyCheckStatus::Fail,
            VerifyCheckStatus::NotRun,
            Some(VerifyFindingCode::TrustCheckNotRun),
        ),
        (
            "skew",
            signed_with_unsigned(&signer, |sig| {
                vec![cms::attr_ts_token(&mint_token(
                    &tsa,
                    &cms::sha256(sig),
                    AT_UNIX + TS_GEN_TIME_MAX_SKEW_SECS + 1,
                ))]
            }),
            VerifyCheckStatus::Fail,
            VerifyCheckStatus::NotRun,
            Some(VerifyFindingCode::TrustCheckNotRun),
        ),
    ];
    for (label, bytes, crypto, trust, reason) in cases {
        for roots in [
            vec![signer.cert_der.clone(), tsa.cert_der.clone()],
            vec![signer.cert_der.clone()],
            vec![],
        ] {
            let report = verify_engine(roots, AT_UNIX)
                .verify_sealed_pdf(&bytes)
                .unwrap();
            assert_eq!(
                pair(
                    &report,
                    SignatureKind::Signature,
                    VerifyCheckKind::SignatureTimestamp,
                    VerifyCheckKind::TimestampCertificatePath
                ),
                (crypto, trust, reason),
                "{label}"
            );
            if crypto == VerifyCheckStatus::Fail {
                assert_eq!(report.verdict(), VerifyVerdict::Failed, "{label}");
            }
        }
    }
}

#[test]
fn public_timestamp_time_is_trusted_only_with_tsa_authority() {
    let signer = test_ca("ts-time-signer");
    let tsa = tsa_ca();
    let signed = append_sig_revision(&base_input(), &signer, "ts-time", Some(&tsa), AT_UNIX);
    let document = append_doc_ts_revision(&signed, &tsa, AT_UNIX);
    let signer_der = signer.cert_der;
    let tsa_der = tsa.cert_der;
    for (roots, trust, finding) in [
        (
            vec![signer_der.clone(), tsa_der],
            VerifyCheckStatus::Pass,
            None,
        ),
        (
            vec![signer_der],
            VerifyCheckStatus::NotRun,
            Some(VerifyFindingCode::TrustRootUnavailable),
        ),
    ] {
        let report = verify_engine(roots, AT_UNIX)
            .verify_sealed_pdf(&document)
            .unwrap();
        for (kind, crypto, tsa_check) in [
            (
                SignatureKind::Signature,
                VerifyCheckKind::SignatureTimestamp,
                VerifyCheckKind::TimestampCertificatePath,
            ),
            (
                SignatureKind::DocumentTimestamp,
                VerifyCheckKind::DocumentTimestamp,
                VerifyCheckKind::TimestampCertificatePath,
            ),
        ] {
            assert_eq!(
                pair(&report, kind, crypto, tsa_check),
                (VerifyCheckStatus::Pass, trust, finding)
            );
        }
    }
}

#[test]
fn public_document_timestamps_absent_malformed_skew_and_multiple_revisions() {
    let signer = test_ca("doc-ts-signer");
    let tsa = tsa_ca();
    let signed = append_sig_revision(&base_input(), &signer, "doc-ts-sign", None, AT_UNIX);
    let complete_roots = vec![signer.cert_der.clone(), tsa.cert_der.clone()];
    let report = verify_engine(complete_roots.clone(), AT_UNIX)
        .verify_sealed_pdf(&signed)
        .unwrap();
    assert!(
        report
            .signatures
            .iter()
            .all(|s| s.kind != SignatureKind::DocumentTimestamp)
    );
    assert!(
        !report
            .checks()
            .any(|c| c.kind == VerifyCheckKind::DocumentTimestamp)
    );

    let valid = append_doc_ts_revision(&signed, &tsa, AT_UNIX);
    let mut malformed = valid.clone();
    let at = malformed
        .windows(b"/Contents <".len())
        .rposition(|w| w == b"/Contents <")
        .unwrap()
        + b"/Contents <".len();
    malformed[at] = b'F';
    let skew = append_doc_ts_revision(&signed, &tsa, AT_UNIX + TS_GEN_TIME_MAX_SKEW_SECS + 1);
    for (label, bytes) in [("malformed", malformed), ("skew", skew)] {
        for roots in [complete_roots.clone(), vec![signer.cert_der.clone()]] {
            let report = verify_engine(roots, AT_UNIX)
                .verify_sealed_pdf(&bytes)
                .unwrap();
            assert_eq!(
                pair(
                    &report,
                    SignatureKind::DocumentTimestamp,
                    VerifyCheckKind::DocumentTimestamp,
                    VerifyCheckKind::TimestampCertificatePath
                ),
                (
                    VerifyCheckStatus::Fail,
                    VerifyCheckStatus::NotRun,
                    Some(VerifyFindingCode::TrustCheckNotRun)
                ),
                "{label}"
            );
            assert_eq!(report.verdict(), VerifyVerdict::Failed, "{label}");
        }
    }

    // Separate DocTimeStamp revisions are legal, not duplicate unsigned CMS
    // Attributes. Each must project its own complete pair of checks.
    let multiple = append_doc_ts_revision(&valid, &tsa, AT_UNIX);
    for roots in [complete_roots, vec![signer.cert_der]] {
        let report = verify_engine(roots, AT_UNIX)
            .verify_sealed_pdf(&multiple)
            .unwrap();
        let docs: Vec<_> = report
            .signatures
            .iter()
            .filter(|s| s.kind == SignatureKind::DocumentTimestamp)
            .collect();
        assert_eq!(docs.len(), 2);
        for doc in docs {
            assert_eq!(
                doc.checks
                    .iter()
                    .filter(|c| c.kind == VerifyCheckKind::DocumentTimestamp)
                    .count(),
                1
            );
            assert_eq!(
                doc.checks
                    .iter()
                    .filter(|c| c.kind == VerifyCheckKind::TimestampCertificatePath)
                    .count(),
                1
            );
        }
    }
}
