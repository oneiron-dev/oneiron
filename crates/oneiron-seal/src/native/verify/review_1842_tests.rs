//! SGN-05 public verifier regressions retained across the ONE-1941 report merge.
#![cfg(test)]
#![allow(
    clippy::unwrap_used,
    reason = "bounded fixture construction in verifier regressions"
)]
use super::super::pdf;
use super::verify_tests_fixtures_dss_a::tests::*;
use super::verify_tests_lta_probes::tests::base_input;
use super::verify_tests_time_lta_a::tests::*;
use crate::api::*;

fn insert_unindexed_catalog_before_xref(bytes: &[u8], separator: u8) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let xref = out
        .windows(b"\nxref\n".len())
        .rposition(|w| w == b"\nxref\n")
        .unwrap()
        + 1;
    assert_eq!(out[xref - 1], b'\n');
    let extra = format!(
        "{}1 0 obj << /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        char::from(separator)
    );
    out.splice(xref - 1..xref, extra.bytes());
    let new_xref = xref - 1 + extra.len();
    let marker = b"startxref\n";
    let at = out
        .windows(marker.len())
        .rposition(|w| w == marker)
        .unwrap()
        + marker.len();
    let end = at + out[at..].iter().position(|b| *b == b'\n').unwrap();
    out.splice(at..end, new_xref.to_string().bytes());
    out
}

#[test]
fn structural_facts_share_one_inventory_across_pdf_separators() {
    let signer = test_ca("all-separators-signer");
    let engine = verify_engine(vec![signer.cert_der.clone()], VERIFY_SECS);
    for separator in [
        b" ".as_slice(),
        b"\r",
        b"\n",
        b"\r\n",
        b"\t",
        b"\x0c",
        b"\0",
        b"%inline comment\n",
        b"%inline comment\r",
        b"%inline comment\r\n",
    ] {
        let mut input = base_input();
        let xref = input
            .windows(b"xref\n".len())
            .position(|w| w == b"xref\n")
            .unwrap();
        let extra = [
            b"1".as_slice(),
            separator,
            b"0",
            separator,
            b"obj << /Type /Catalog /Pages 2 0 R >> endobj\n",
        ]
        .concat();
        input.splice(xref..xref, extra.iter().copied());
        let marker = b"startxref\n186\n";
        let at = input
            .windows(marker.len())
            .position(|w| w == marker)
            .unwrap();
        input.splice(
            at..at + marker.len(),
            format!("startxref\n{}\n", xref + extra.len()).bytes(),
        );
        let signed = append_sig_revision(&input, &signer, "separator", None, AT_UNIX);
        let report = engine.verify_sealed_pdf(&signed).unwrap();
        assert!(
            report.anomalies.contains(&Anomaly::DuplicateObjectNumber),
            "separator {separator:?}: {report:?}"
        );
        assert_eq!(report.verdict(), VerifyVerdict::Passed);
    }
}

#[test]
fn public_verifier_refuses_comment_delimited_definition_in_dss_renewal() {
    let signer = test_ca("comment-definition-signer");
    let tsa = tsa_ca();
    let engine = verify_engine(
        vec![signer.cert_der.clone(), tsa.cert_der.clone()],
        VERIFY_SECS,
    );
    let signed = append_sig_revision(&base_input(), &signer, "comment-dss", Some(&tsa), AT_UNIX);
    let crl = build_crl(
        &signer,
        AT_UNIX - 60,
        Some(VERIFY_SECS + 3600),
        None,
        vec![],
    );
    let dss = append_dss_revision(&signed, vec![signer.cert_der, tsa.cert_der], vec![crl]);
    assert_eq!(
        engine.verify_sealed_pdf(&dss).unwrap().verdict(),
        VerifyVerdict::Passed
    );
    for header in [
        b"1 0 obj%legal comment\n".as_slice(),
        b"1 %legal comment\n0 obj ",
        b"1 0 obj%legal comment\r\n",
        b"1 %legal comment\r0 obj ",
    ] {
        let mut altered = dss.clone();
        let xref = altered
            .windows(b"\nxref\n".len())
            .rposition(|w| w == b"\nxref\n")
            .unwrap()
            + 1;
        let extra = [
            b"\n".as_slice(),
            header,
            b" << /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        ]
        .concat();
        altered.splice(xref - 1..xref, extra.iter().copied());
        let at = altered
            .windows(b"startxref\n".len())
            .rposition(|w| w == b"startxref\n")
            .unwrap()
            + b"startxref\n".len();
        let end = at + altered[at..].iter().position(|b| *b == b'\n').unwrap();
        altered.splice(at..end, (xref - 1 + extra.len()).to_string().bytes());
        let report = engine.verify_sealed_pdf(&altered).unwrap();
        assert_eq!(
            report.modifications,
            Modifications::Suspicious,
            "{header:?}: {report:?}"
        );
        assert!(report.anomalies.contains(&Anomaly::DuplicateObjectNumber));
        assert_eq!(report.verdict(), VerifyVerdict::Failed);
    }
}

#[test]
fn public_verifier_catches_same_line_catalog_definitions_and_dss_bypass() {
    let signer = test_ca("same-line-signer");
    let tsa = tsa_ca();
    let engine = verify_engine(
        vec![signer.cert_der.clone(), tsa.cert_der.clone()],
        VERIFY_SECS,
    );
    for separator in [b' ', b'\r'] {
        let input = insert_unindexed_catalog_before_xref(&base_input(), separator);
        let pre_signed = append_sig_revision(&input, &signer, "original-extra", None, AT_UNIX);
        let original = engine.verify_sealed_pdf(&pre_signed).unwrap();
        assert!(original.anomalies.contains(&Anomaly::DuplicateObjectNumber));
        assert_eq!(original.verdict(), VerifyVerdict::Passed);
    }
    let signed = append_sig_revision(&base_input(), &signer, "dss-extra", Some(&tsa), AT_UNIX);
    let crl = build_crl(
        &signer,
        AT_UNIX - 60,
        Some(VERIFY_SECS + 3600),
        None,
        vec![],
    );
    let dss = append_dss_revision(&signed, vec![signer.cert_der, tsa.cert_der], vec![crl]);
    assert_eq!(
        engine.verify_sealed_pdf(&dss).unwrap().verdict(),
        VerifyVerdict::Passed
    );
    let new_line = insert_unindexed_catalog_before_xref(&dss, b'\n');
    let rejected = engine.verify_sealed_pdf(&new_line).unwrap();
    assert_eq!(rejected.modifications, Modifications::Suspicious);
    assert!(rejected.anomalies.contains(&Anomaly::DuplicateObjectNumber));
    for separator in [b' ', b'\r'] {
        let altered = insert_unindexed_catalog_before_xref(&dss, separator);
        let report = engine.verify_sealed_pdf(&altered).unwrap();
        assert_eq!(
            report.modifications,
            Modifications::Suspicious,
            "separator {separator:?}: {report:?}"
        );
        assert_eq!(report.verdict(), VerifyVerdict::Failed);
        assert!(report.anomalies.contains(&Anomaly::DuplicateObjectNumber));
    }
}

#[test]
fn public_verifier_reports_crlf_and_inline_duplicate_definitions() {
    let signer = test_ca("duplicate-spelling-signer");
    let engine = verify_engine(vec![signer.cert_der.clone()], VERIFY_SECS);
    for (suffix, duplicate) in [
        (
            "crlf",
            b"1 0 obj\r\n<< /Type /Catalog /Pages 2 0 R >>\r\nendobj\r\n".as_slice(),
        ),
        (
            "inline",
            b"1 0 obj << /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        ),
    ] {
        let mut input = base_input();
        let xref = input
            .windows(b"xref\n".len())
            .position(|w| w == b"xref\n")
            .unwrap();
        input.splice(xref..xref, duplicate.iter().copied());
        let at = input
            .windows(b"startxref\n186\n".len())
            .position(|w| w == b"startxref\n186\n")
            .unwrap();
        input.splice(
            at..at + b"startxref\n186\n".len(),
            format!("startxref\n{}\n", xref + duplicate.len()).bytes(),
        );
        let signed = append_sig_revision(&input, &signer, suffix, None, AT_UNIX);
        let first = engine.verify_sealed_pdf(&signed).unwrap();
        assert!(
            first.anomalies.contains(&Anomaly::DuplicateObjectNumber),
            "before signing: {suffix}"
        );
        assert_eq!(first.verdict(), VerifyVerdict::Passed);
        let state = pdf::reparse_revision(&signed, &SealResourceLimits::default()).unwrap();
        let id = state.max_obj + 1;
        let mut later = signed;
        let extra = if suffix == "crlf" {
            format!("\n{id} 0 obj\r\n<< /Probe /Orphan >>\r\nendobj\r\n")
        } else {
            format!("\n{id} 0 obj << /Probe /Orphan >>\nendobj\n")
        };
        later.extend_from_slice(extra.as_bytes());
        let active = later.len();
        later.extend_from_slice(format!("{id} 0 obj\n<< /Probe /Active >>\nendobj\n").as_bytes());
        let xref_offset = later.len();
        later.extend_from_slice(format!("xref\n{id} 1\n{active:010} 00000 n\r\ntrailer\n<< /Size {} /Prev {} /Root {} {} R >>\nstartxref\n{xref_offset}\n%%EOF",
                id + 1, state.prev_startxref, state.root.0, state.root.1).as_bytes());
        let second = engine.verify_sealed_pdf(&later).unwrap();
        assert!(
            second.anomalies.contains(&Anomaly::DuplicateObjectNumber),
            "after signing: {suffix}"
        );
        assert_eq!(second.modifications, Modifications::Suspicious);
    }
}

#[test]
fn public_verifier_reports_duplicate_object_numbers_before_and_after_signing() {
    let signer = test_ca("duplicate-signer");
    let engine = verify_engine(vec![signer.cert_der.clone()], VERIFY_SECS);
    let mut input = base_input();
    let xref = input
        .windows(b"xref\n".len())
        .position(|w| w == b"xref\n")
        .unwrap();
    let duplicate = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";
    input.splice(xref..xref, duplicate.iter().copied());
    let old_offset = b"startxref\n186\n";
    let at = input
        .windows(old_offset.len())
        .position(|w| w == old_offset)
        .unwrap();
    input.splice(
        at..at + old_offset.len(),
        format!("startxref\n{}\n", xref + duplicate.len()).bytes(),
    );
    let signed = append_sig_revision(&input, &signer, "duplicate-before", None, AT_UNIX);
    let first = engine.verify_sealed_pdf(&signed).unwrap();
    assert!(first.anomalies.contains(&Anomaly::DuplicateObjectNumber));
    assert_eq!(
        first.verdict(),
        VerifyVerdict::Passed,
        "an anomaly indicator must not independently change the verdict"
    );
    // An unindexed earlier definition of a new object in an appended
    // revision must be visible even though the merged object map keeps
    // only the definition named by xref.
    let state = pdf::reparse_revision(&signed, &SealResourceLimits::default()).unwrap();
    let id = state.max_obj + 1;
    let mut later = signed;
    later.extend_from_slice(format!("\n{id} 0 obj\n<< /Probe /Orphan >>\nendobj\n").as_bytes());
    let active = later.len();
    later.extend_from_slice(format!("{id} 0 obj\n<< /Probe /Active >>\nendobj\n").as_bytes());
    let xref_offset = later.len();
    later.extend_from_slice(format!("xref\n{id} 1\n{active:010} 00000 n\r\ntrailer\n<< /Size {} /Prev {} /Root {} {} R >>\nstartxref\n{xref_offset}\n%%EOF",
            id + 1, state.prev_startxref, state.root.0, state.root.1).as_bytes());
    let second = engine.verify_sealed_pdf(&later).unwrap();
    assert!(second.anomalies.contains(&Anomaly::DuplicateObjectNumber));
    assert_eq!(second.modifications, Modifications::Suspicious);
}

#[test]
fn public_verifier_refuses_dss_trailer_id_and_info_changes() {
    let signer = test_ca("trailer-signer");
    let tsa = tsa_ca();
    let mut input = base_input();
    let marker = b"/Root 1 0 R >>";
    let i = input
        .windows(marker.len())
        .rposition(|w| w == marker)
        .unwrap()
        + b"/Root 1 0 R ".len();
    input.splice(
        i..i,
        b"/ID [<0011223344556677> <0011223344556677>] "
            .iter()
            .copied(),
    );
    let signed = append_sig_revision(&input, &signer, "trailer", Some(&tsa), AT_UNIX);
    let crl = build_crl(
        &signer,
        AT_UNIX - 60,
        Some(VERIFY_SECS + 3600),
        None,
        vec![],
    );
    let dss = append_dss_revision(
        &signed,
        vec![signer.cert_der.clone(), tsa.cert_der.clone()],
        vec![crl],
    );
    let engine = verify_engine(vec![signer.cert_der, tsa.cert_der], VERIFY_SECS);
    assert_eq!(
        engine.verify_sealed_pdf(&dss).unwrap().modifications,
        Modifications::Clean(crate::api::ModificationLevel::LtaUpdates)
    );
    let mut changed_id = dss.clone();
    let last_trailer = changed_id
        .windows(b"trailer\n".len())
        .rposition(|w| w == b"trailer\n")
        .unwrap();
    let relative_id = changed_id[last_trailer..]
        .windows(b"<0011223344556677>".len())
        .position(|w| w == b"<0011223344556677>")
        .unwrap();
    changed_id[last_trailer + relative_id + 1] = b'1';
    let mut changed_info = dss;
    let last_end = changed_info
        .windows(b">>\nstartxref\n".len())
        .rposition(|w| w == b">>\nstartxref\n")
        .unwrap();
    changed_info.splice(last_end..last_end, b" /Info 1 0 R".iter().copied());
    for altered in [changed_id, changed_info] {
        let report = engine.verify_sealed_pdf(&altered).unwrap();
        assert_eq!(report.modifications, Modifications::Suspicious);
        assert_eq!(report.verdict(), VerifyVerdict::Failed);
        assert_eq!(report.signatures[0].integrity, VerifyVerdict::Passed);
    }
}

#[test]
fn public_verifier_uses_four_byte_eol_tolerance_consistently() {
    let signer = test_ca("eol-signer");
    let signed = append_sig_revision(&base_input(), &signer, "eol", None, AT_UNIX);
    let engine = verify_engine(vec![signer.cert_der], VERIFY_SECS);
    for tail in [b"".as_slice(), b"\n", b"\r\n", b"\n\r\n", b"\r\n\r\n"] {
        let mut bytes = signed.clone();
        bytes.extend_from_slice(tail);
        let report = engine.verify_sealed_pdf(&bytes).unwrap();
        assert_eq!(
            report.verdict(),
            VerifyVerdict::Passed,
            "tail {tail:?}: {report:?}"
        );
        assert_eq!(report.signatures[0].coverage, Coverage::EntireFile);
        assert_eq!(
            report.modifications,
            Modifications::Clean(crate::api::ModificationLevel::None)
        );
    }
    for tail in [b"\n\r\n\r\n".as_slice(), b"\nx"] {
        let mut bytes = signed.clone();
        bytes.extend_from_slice(tail);
        let report = engine.verify_sealed_pdf(&bytes).unwrap();
        assert_eq!(report.verdict(), VerifyVerdict::Failed);
    }
}

#[test]
fn revision_classifier_allows_writer_lta_but_denies_unlisted_post_sign_object() {
    let signer = test_ca("classifier-signer");
    let tsa = tsa_ca();
    let input = std::fs::read(format!(
        "{}/tests/fixtures/pdf-input/classic_1page.pdf",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let signed = append_sig_revision(&input, &signer, "classifier", Some(&tsa), AT_UNIX);
    let crl = build_crl(&signer, AT_UNIX - 60, Some(AT_UNIX + 3600), None, vec![]);
    let dss = append_dss_revision(
        &signed,
        vec![signer.cert_der.clone(), tsa.cert_der.clone()],
        vec![crl],
    );
    let renewed = append_doc_ts_revision(&dss, &tsa, AT_UNIX);
    let engine = verify_engine(vec![signer.cert_der, tsa.cert_der], VERIFY_SECS);
    let clean = engine.verify_sealed_pdf(&renewed).unwrap();
    assert_eq!(
        clean.modifications,
        Modifications::Clean(crate::api::ModificationLevel::LtaUpdates)
    );
    assert_eq!(clean.verdict(), VerifyVerdict::Passed);
    assert_eq!(clean.signatures[0].profile, Some(PadesProfile::BaselineLta));
    let state = pdf::reparse_revision(&renewed, &SealResourceLimits::default()).unwrap();
    let (tampered, _) = emit_revision(
        &renewed,
        &state,
        &[(state.max_obj + 1, b"<< /Type /Unknown >>".to_vec())],
        None,
    );
    let report = engine.verify_sealed_pdf(&tampered).unwrap();
    assert_eq!(report.modifications, Modifications::Suspicious);
    assert_eq!(report.verdict(), VerifyVerdict::Failed);
    assert!(report.checks().any(
            |c| c.kind == VerifyCheckKind::Modification && c.status == VerifyCheckStatus::Fail
        ));
    assert!(
        report.signatures[0].digest.is_some(),
        "old signed bytes remain checkable"
    );
}
