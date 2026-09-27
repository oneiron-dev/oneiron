//! Regression probes for per-signature report and revision admission.
#![cfg(test)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "fixture setup fails loudly on invalid input"
)]

use super::super::{cms, pdf};
use super::verify_tests_fixtures_dss_a::tests::*;
use super::verify_tests_lta_probes::tests::base_input;
use super::verify_tests_time_lta_a::tests::*;
use crate::api::*;

fn signed_with_eol(
    bytes: &[u8],
    ca: &TestCa,
    op: &str,
    tsa: Option<&TestCa>,
    gen_time: u64,
) -> Vec<u8> {
    let state = pdf::reparse_revision(bytes, &SealResourceLimits::default()).unwrap();
    let kind = pdf::RevisionKind::Signature {
        field_name: pdf::field_name_for(op),
        date_str: pdf::pdf_date(AT_UNIX * 1000),
    };
    let mut draft = pdf::append_revision(bytes, &state, &kind, 64 * 1024).unwrap();
    let mut br = draft.byte_range.unwrap();
    draft.bytes.push(b'\n');
    br[3] += 1;
    draft.byte_range = Some(br);
    let marker = b"/ByteRange [0 ";
    let offset = draft
        .bytes
        .windows(marker.len())
        .rposition(|w| w == marker)
        .unwrap()
        + marker.len();
    for i in 0..3 {
        let s = format!("{:020}", br[i + 1]);
        draft.bytes[offset + i * 21..offset + i * 21 + 20].copy_from_slice(s.as_bytes());
    }
    let digest = pdf::hash_byte_range(&draft.bytes, br).unwrap();
    let (issuer, serial) = cms::issuer_and_serial(&ca.cert_der).unwrap();
    let attrs = vec![
        cms::attr_content_type_data(),
        cms::attr_message_digest(&digest),
        cms::attr_signing_cert_v2(&ca.cert_der, &issuer, &serial),
    ];
    let (wire, signing) = cms::assemble_signed_attrs(attrs);
    let sig = sign_p256(&ca.key, &signing);
    let unsigned: Vec<Vec<u8>> = tsa
        .map(|t| mint_token(t, &cms::sha256(&sig), gen_time))
        .into_iter()
        .map(|t| cms::attr_ts_token(&t))
        .collect();
    let material = cms::SignerMaterial {
        algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        signer_cert_der: &ca.cert_der,
        issuer_name_der: &issuer,
        serial_der: &serial,
        chain_ders: &[],
    };
    let cms_der = cms::build_signed_data(&material, &wire, &sig, &unsigned);
    pdf::patch_contents(&mut draft, &cms_der).unwrap();
    draft.bytes
}

fn append_unknown(bytes: &[u8]) -> Vec<u8> {
    let state = pdf::reparse_revision(bytes, &SealResourceLimits::default()).unwrap();
    let mut out = bytes.to_vec();
    out.push(b'\n');
    let n = state.max_obj + 1;
    let at = out.len();
    out.extend_from_slice(format!("{n} 0 obj\n<< /Unknown (changed) >>\nendobj\n").as_bytes());
    let xref = out.len();
    out.extend_from_slice(format!("xref\n{n} 1\n{at:010} 00000 n\r\ntrailer\n<< /Size {} /Root {} {} R /Prev {} >>\nstartxref\n{xref}\n%%EOF", n+1, state.root.0, state.root.1, state.prev_startxref).as_bytes());
    out
}
#[test]
fn review_signed_eol_must_not_skip_modification_gate() {
    let signer = test_ca("review-eol");
    let signed = signed_with_eol(&base_input(), &signer, "eol", None, AT_UNIX);
    let engine = verify_engine(vec![signer.cert_der], AT_UNIX);
    let before = engine.verify_sealed_pdf(&signed).unwrap();
    assert_eq!(before.verdict(), VerifyVerdict::Passed, "valid fixture");
    let report = engine.verify_sealed_pdf(&append_unknown(&signed)).unwrap();
    assert_eq!(report.signatures[0].integrity, VerifyVerdict::Passed);
    assert_eq!(report.modifications, Modifications::Suspicious);
}
#[test]
fn review_missing_tsa_root_must_be_indeterminate() {
    let signer = test_ca("review-tsa");
    let tsa = tsa_ca();
    let signed = append_sig_revision(&base_input(), &signer, "tsa", Some(&tsa), AT_UNIX);
    let trusted = verify_engine(vec![signer.cert_der.clone(), tsa.cert_der], AT_UNIX);
    assert_eq!(
        trusted.verify_sealed_pdf(&signed).unwrap().verdict(),
        VerifyVerdict::Passed
    );
    let engine = verify_engine(vec![signer.cert_der], AT_UNIX);
    let report = engine.verify_sealed_pdf(&signed).unwrap();
    assert_eq!(report.verdict(), VerifyVerdict::Indeterminate);
}
#[test]
fn review_trusted_doc_timestamp_has_trust_check() {
    let signer = test_ca("review-dts");
    let tsa = tsa_ca();
    let signed = append_sig_revision(&base_input(), &signer, "dts", None, AT_UNIX);
    let signed = append_doc_ts_revision(&signed, &tsa, AT_UNIX);
    let engine = verify_engine(vec![signer.cert_der, tsa.cert_der], AT_UNIX);
    let report = engine.verify_sealed_pdf(&signed).unwrap();
    assert_eq!(report.signatures[1].trust, VerifyCheckStatus::Pass);
}

#[test]
fn review_doc_timestamp_missing_tsa_root_is_unknown() {
    let signer = test_ca("review-dts-untrusted");
    let tsa = tsa_ca();
    let signed = append_sig_revision(&base_input(), &signer, "dts-untrusted", None, AT_UNIX);
    let stamped = append_doc_ts_revision(&signed, &tsa, AT_UNIX);
    let engine = verify_engine(vec![signer.cert_der], AT_UNIX);
    let report = engine.verify_sealed_pdf(&stamped).unwrap();
    assert_eq!(report.signatures[1].integrity, VerifyVerdict::Passed);
    assert_eq!(report.signatures[1].trust, VerifyCheckStatus::NotRun);
    assert_eq!(report.verdict(), VerifyVerdict::Indeterminate);
    assert_ne!(
        report.signatures[0].profile,
        Some(PadesProfile::BaselineLta)
    );
}

#[test]
fn review_existing_dts_cannot_archive_a_later_signature() {
    let signer = test_ca("review-profile");
    let tsa = tsa_ca();
    let b1 = append_sig_revision(&base_input(), &signer, "first", Some(&tsa), AT_UNIX);
    let b2 = append_dss_revision(
        &b1,
        vec![signer.cert_der.clone(), tsa.cert_der.clone()],
        vec![],
    );
    let b3 = append_doc_ts_revision(&b2, &tsa, AT_UNIX);
    let b4 = append_sig_revision(&b3, &signer, "second", Some(&tsa), AT_UNIX);
    let engine = verify_engine(vec![signer.cert_der, tsa.cert_der], AT_UNIX);
    let report = engine.verify_sealed_pdf(&b4).unwrap();
    assert_eq!(
        report.signatures[0].profile,
        Some(PadesProfile::BaselineLta)
    );
    assert_ne!(
        report.signatures[2].profile,
        Some(PadesProfile::BaselineLta)
    );
}
#[test]
fn review_known_bad_key_usage_is_failure_not_unknown() {
    let root = test_ca("review-root");
    let signer = ocsp_delegate_with_kus(
        &root,
        "bad-ku",
        (2020, 1, 1),
        (2030, 1, 1),
        vec![rcgen::KeyUsagePurpose::KeyEncipherment],
    );
    let b = append_sig_revision(&base_input(), &signer, "bad-ku", None, AT_UNIX);
    let engine = verify_engine(vec![root.cert_der], AT_UNIX);
    let report = engine.verify_sealed_pdf(&b).unwrap();
    assert_eq!(report.signatures[0].integrity, VerifyVerdict::Passed);
    assert_eq!(report.signatures[0].trust, VerifyCheckStatus::Fail);
}

#[test]
fn review_stream_marker_is_not_a_revision() {
    let mut doc = lopdf::Document::load_mem(&base_input()).unwrap();
    doc.add_object(lopdf::Stream::new(
        lopdf::Dictionary::new(),
        b"startxref\n0\n%%EOF\n".to_vec(),
    ));
    let mut input = Vec::new();
    doc.save_to(&mut input).unwrap();
    pdf::validate_prepared(&input, &SealResourceLimits::default()).unwrap();
    let signer = test_ca("review-marker");
    let signed = append_sig_revision(&input, &signer, "marker", None, AT_UNIX);
    let engine = verify_engine(vec![signer.cert_der], AT_UNIX);
    let report = engine.verify_sealed_pdf(&signed).unwrap();
    assert_eq!(report.verdict(), VerifyVerdict::Passed);
}
#[test]
fn review_unknown_timestamp_key_is_not_lta() {
    let signer = test_ca("review-key");
    let tsa = tsa_ca();
    let signed = append_sig_revision(&base_input(), &signer, "key", None, AT_UNIX);
    let state = pdf::reparse_revision(&signed, &SealResourceLimits::default()).unwrap();
    let mut draft = pdf::append_revision(
        &signed,
        &state,
        &pdf::RevisionKind::DocumentTimestamp,
        64 * 1024,
    )
    .unwrap();
    let br = draft.byte_range.unwrap();
    let marker = b"/ByteRange [0 ";
    let start = draft
        .bytes
        .windows(marker.len())
        .rposition(|w| w == marker)
        .unwrap();
    let end = draft.bytes[start..]
        .windows(9)
        .position(|w| w == b"/Contents")
        .unwrap()
        + start;
    let mut replacement = format!(
        "/ByteRange [0 {} {} {}] /Unknown (new) ",
        br[1], br[2], br[3]
    )
    .into_bytes();
    assert!(replacement.len() < end - start);
    replacement.resize(end - start, b' ');
    draft.bytes[start..end].copy_from_slice(&replacement);
    let token = mint_token(
        &tsa,
        &pdf::hash_byte_range(&draft.bytes, br).unwrap(),
        AT_UNIX,
    );
    pdf::patch_contents(&mut draft, &token).unwrap();
    let engine = verify_engine(vec![signer.cert_der, tsa.cert_der], AT_UNIX);
    let report = engine.verify_sealed_pdf(&draft.bytes).unwrap();
    assert_eq!(report.signatures[1].integrity, VerifyVerdict::Passed);
    assert_eq!(report.modifications, Modifications::Suspicious);
}
#[test]
fn review_unknown_evidence_key_is_not_lta() {
    let signer = test_ca("review-evidence");
    let signed = append_sig_revision(&base_input(), &signer, "ev", None, AT_UNIX);
    let state = pdf::reparse_revision(&signed, &SealResourceLimits::default()).unwrap();
    let material = super::super::profile::DssMaterial {
        certs_der: vec![signer.cert_der.clone()],
        ocsps_der: vec![],
        crls_der: vec![],
    };
    let (mut objects, dss_obj) =
        super::super::profile::build_dss_objects(&material, state.max_obj + 1).unwrap();
    let stream = objects
        .iter_mut()
        .find(|(_, b)| b.windows(6).any(|w| w == b"stream"))
        .unwrap();
    let at = stream.1.windows(2).position(|w| w == b"<<").unwrap() + 2;
    stream.1.splice(at..at, b" /Unknown (new) ".iter().copied());
    let draft = pdf::append_revision(
        &signed,
        &state,
        &pdf::RevisionKind::Dss {
            material_objects: objects,
            dss_obj,
        },
        0,
    )
    .unwrap();
    let engine = verify_engine(vec![signer.cert_der], AT_UNIX);
    let report = engine.verify_sealed_pdf(&draft.bytes).unwrap();
    assert_eq!(report.modifications, Modifications::Suspicious);
}

#[test]
fn review_compressed_snapshot_uses_configured_limit() {
    let mut doc = lopdf::Document::load_mem(&base_input()).unwrap();
    doc.add_object(lopdf::Object::string_literal(vec![b'A'; 100_000]));
    let mut input = Vec::new();
    doc.save_modern(&mut input).unwrap();
    assert!(input.len() < 100_000);
    pdf::validate_prepared(&input, &SealResourceLimits::default()).unwrap();
    let signer = test_ca("review-compression");
    let signed = append_sig_revision(&input, &signer, "compressed", None, AT_UNIX);
    let engine = verify_engine(vec![signer.cert_der], AT_UNIX);
    let report = engine.verify_sealed_pdf(&signed).unwrap();
    assert_eq!(report.verdict(), VerifyVerdict::Passed);
}

#[test]
fn review_compressed_xref_uses_configured_limit() {
    let input = std::fs::read(format!(
        "{}/tests/fixtures/pdf-input/review_compressed_xref.pdf",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    pdf::validate_prepared(&input, &SealResourceLimits::default()).unwrap();
    let signer = test_ca("review-xref");
    let signed = append_sig_revision(&input, &signer, "compressed-xref", None, AT_UNIX);
    let engine = verify_engine(vec![signer.cert_der], AT_UNIX);
    let report = engine.verify_sealed_pdf(&signed).unwrap();
    assert_eq!(report.verdict(), VerifyVerdict::Passed);
}

#[test]
fn review_r2_four_eol_bytes_remain_valid() {
    let signer = test_ca("review-eol-four");
    let signed = append_sig_revision(&base_input(), &signer, "eol-four", None, AT_UNIX);
    let engine = verify_engine(vec![signer.cert_der], AT_UNIX);
    assert_eq!(
        engine.verify_sealed_pdf(&signed).unwrap().verdict(),
        VerifyVerdict::Passed
    );
    let mut failures = Vec::new();
    for suffix in [b"\n".as_slice(), b"\r", b"\r\n", b"\n\n", b"\r\n\r\n"] {
        let mut input = signed.clone();
        input.extend_from_slice(suffix);
        let report = engine.verify_sealed_pdf(&input).unwrap();
        if report.verdict() != VerifyVerdict::Passed {
            failures.push(suffix.to_vec());
        }
    }
    assert!(
        failures.is_empty(),
        "lawful EOL suffixes rejected: {failures:?}"
    );
}

#[test]
fn review_r2_fake_xref_object_is_not_lta() {
    let signer = test_ca("review-fake-xref");
    let signed = append_sig_revision(&base_input(), &signer, "fake-xref", None, AT_UNIX);
    let state = pdf::reparse_revision(&signed, &SealResourceLimits::default()).unwrap();
    let material = super::super::profile::DssMaterial {
        certs_der: vec![signer.cert_der.clone()],
        ocsps_der: vec![],
        crls_der: vec![],
    };
    let (mut objects, dss_obj) =
        super::super::profile::build_dss_objects(&material, state.max_obj + 1).unwrap();
    objects.push((
        dss_obj + 1,
        b"<< /Type /XRef /Unknown (changed) >>".to_vec(),
    ));
    let out = pdf::append_revision(
        &signed,
        &state,
        &pdf::RevisionKind::Dss {
            material_objects: objects,
            dss_obj,
        },
        0,
    )
    .unwrap();
    let engine = verify_engine(vec![signer.cert_der], AT_UNIX);
    let report = engine.verify_sealed_pdf(&out.bytes).unwrap();
    assert_eq!(report.modifications, Modifications::Suspicious);
}

#[test]
fn review_r2_known_expired_leaf_is_failure() {
    let root = test_ca("review-expiry-root");
    let signer = ocsp_delegate_with_kus(
        &root,
        "expired-leaf",
        (2010, 1, 1),
        (2020, 1, 1),
        vec![rcgen::KeyUsagePurpose::DigitalSignature],
    );
    let signed = append_sig_revision(&base_input(), &signer, "expiry", None, AT_UNIX);
    let engine = verify_engine(vec![root.cert_der], AT_UNIX);
    let report = engine.verify_sealed_pdf(&signed).unwrap();
    assert_eq!(report.signatures[0].trust, VerifyCheckStatus::Fail);
}

#[test]
fn review_r2_document_timestamp_supplies_baseline_t() {
    let signer = test_ca("review-docts-t");
    let tsa = tsa_ca();
    let signed = append_sig_revision(&base_input(), &signer, "docts-t", None, AT_UNIX);
    let stamped = append_doc_ts_revision(&signed, &tsa, AT_UNIX);
    let engine = verify_engine(vec![signer.cert_der, tsa.cert_der], AT_UNIX);
    let report = engine.verify_sealed_pdf(&stamped).unwrap();
    assert_eq!(report.verdict(), VerifyVerdict::Passed);
    assert_eq!(report.signatures[0].profile, Some(PadesProfile::BaselineT));
}

#[test]
fn review_r3_trailer_info_change_is_not_lta_table() {
    review_r3_trailer_info_change(false);
}

#[test]
fn review_r3_trailer_info_change_is_not_lta_stream() {
    review_r3_trailer_info_change(true);
}

fn review_r3_trailer_info_change(stream: bool) {
    let mut doc = lopdf::Document::load_mem(&base_input()).unwrap();
    let mut old_dict = lopdf::Dictionary::new();
    old_dict.set("Title", lopdf::Object::string_literal("SIGNED TITLE"));
    let old_info = doc.add_object(old_dict);
    let mut new_dict = lopdf::Dictionary::new();
    new_dict.set("Title", lopdf::Object::string_literal("REPLACED TITLE"));
    let new_info = doc.add_object(new_dict);
    doc.trailer.set("Info", lopdf::Object::Reference(old_info));
    let mut input = Vec::new();
    if stream {
        doc.save_modern(&mut input).unwrap();
    } else {
        doc.save_to(&mut input).unwrap();
    }
    let signer = test_ca("r3-info");
    let signed = append_sig_revision(&input, &signer, "info", None, AT_UNIX);
    let engine = verify_engine(vec![signer.cert_der.clone()], AT_UNIX);
    assert_eq!(
        engine.verify_sealed_pdf(&signed).unwrap().verdict(),
        VerifyVerdict::Passed
    );
    let mut state = pdf::reparse_revision(&signed, &SealResourceLimits::default()).unwrap();
    assert_eq!(state.info, Some(old_info));
    let normal = append_dss_revision(&signed, vec![signer.cert_der.clone()], vec![]);
    let normal_report = engine.verify_sealed_pdf(&normal).unwrap();
    assert_eq!(normal_report.verdict(), VerifyVerdict::Passed);
    assert_eq!(
        normal_report.modifications,
        Modifications::Clean(ModificationLevel::LtaUpdates)
    );
    state.info = Some(new_info);
    let material = super::super::profile::DssMaterial {
        certs_der: vec![signer.cert_der],
        ocsps_der: vec![],
        crls_der: vec![],
    };
    let (objects, dss_obj) =
        super::super::profile::build_dss_objects(&material, state.max_obj + 1).unwrap();
    let draft = pdf::append_revision(
        &signed,
        &state,
        &pdf::RevisionKind::Dss {
            material_objects: objects,
            dss_obj,
        },
        0,
    )
    .unwrap();
    let after = lopdf::Document::load_mem(&draft.bytes).unwrap();
    let info = after
        .get_object(after.trailer.get(b"Info").unwrap().as_reference().unwrap())
        .unwrap()
        .as_dict()
        .unwrap();
    assert_eq!(
        info.get(b"Title").unwrap().as_str().unwrap(),
        b"REPLACED TITLE"
    );
    let report = engine.verify_sealed_pdf(&draft.bytes).unwrap();
    assert_eq!(report.modifications, Modifications::Suspicious);
}

#[test]
fn review_r3_document_timestamp_supplies_applicable_time() {
    let root = test_ca("r3-time-root");
    let signer = ocsp_delegate_with_kus(
        &root,
        "r3-time-leaf",
        (2020, 1, 1),
        (2027, 1, 1),
        vec![rcgen::KeyUsagePurpose::DigitalSignature],
    );
    let tsa = tsa_ca();
    let engine = verify_engine(
        vec![root.cert_der.clone(), tsa.cert_der.clone()],
        1_830_297_600,
    ); // 2028-01-01
    // Positive control: identical leaf and TSA at the same trusted instant,
    // using the alternate timestamp form accepted by the B-T law.
    let sig_ts = append_sig_revision(&base_input(), &signer, "r3-sig-ts", Some(&tsa), AT_UNIX);
    let sig_report = engine.verify_sealed_pdf(&sig_ts).unwrap();
    assert_eq!(sig_report.verdict(), VerifyVerdict::Passed);
    assert_eq!(
        sig_report.signatures[0].profile,
        Some(PadesProfile::BaselineT)
    );
    let signed = append_sig_revision(&base_input(), &signer, "r3-doc-ts", None, AT_UNIX);
    let stamped = append_doc_ts_revision(&signed, &tsa, AT_UNIX);
    let at_signing = verify_engine(vec![root.cert_der, tsa.cert_der], AT_UNIX);
    assert_eq!(
        at_signing.verify_sealed_pdf(&stamped).unwrap().verdict(),
        VerifyVerdict::Passed
    );
    let report = engine.verify_sealed_pdf(&stamped).unwrap();
    assert_eq!(report.verdict(), VerifyVerdict::Passed);
    assert_eq!(report.signatures[0].profile, Some(PadesProfile::BaselineT));
}
