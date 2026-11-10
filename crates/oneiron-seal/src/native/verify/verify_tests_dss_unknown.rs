//! Verifier tests: which authenticated OCSP `unknown` statuses count (Engine
//! call SEAL-OCSP-UNKNOWN-GLOBAL-VETO, 10 Nov 06:05). An `unknown` counts
//! only when it names a covered non-anchor certificate, one in a signer or
//! TSA chain; material unrelated to the chain never changes a genuine result.

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use der::{Decode, Encode};
    use lopdf::Document;

    use super::super::verify_chain_gates::classify_missing_material_root;
    use super::super::verify_dss_core::verify_dss;
    use super::super::verify_sig_pipeline::Checks;
    use super::super::verify_tests_fixtures_dss_a::tests::*;
    use super::super::*;
    use crate::api::{VerifyCheckKind, VerifyCheckStatus, VerifyFindingCode};
    use crate::memory::testing::process_operation_limits;

    const THIS_UPDATE: u64 = AT_UNIX - 3600;
    const NEXT_UPDATE: Option<u64> = Some(AT_UNIX + 3600);

    /// The DSS material check of `doc` under `anchors`, for the `covered`
    /// chain certificates.
    fn material_check(doc: &Document, anchors: &[&TestCa], covered: &[&[u8]]) -> Checks<'static> {
        let limits = process_operation_limits();
        let memory = limits.memory.ledger().unwrap();
        let anchors: Vec<EmbeddedCert> = anchors
            .iter()
            .map(|ca| EmbeddedCert::from_der(&ca.cert_der).unwrap())
            .collect();
        let covered = covered_of(covered);
        let mut checks = Checks::new(limits);
        verify_dss(
            doc,
            &anchors,
            &covered,
            AT_UNIX,
            &memory,
            &mut checks,
            limits,
        )
        .unwrap();
        checks
    }

    /// An authenticated OCSP `unknown` from `ca` for the certificate `der`
    /// that `ca` issued.
    fn unknown_for(ca: &TestCa, der: &[u8]) -> Vec<u8> {
        let cert = x509_cert::Certificate::from_der(der).unwrap();
        build_ocsp(
            ca,
            cert.tbs_certificate.serial_number,
            AT_UNIX - 60,
            NEXT_UPDATE,
            x509_ocsp::CertStatus::unknown(),
        )
    }

    /// A second DER of the certificate `der` that `ca` issued: the same
    /// signed content (TBSCertificate) under another valid signature by
    /// `ca`. (An ECDSA (r, n-s) twin is another, needing no key.)
    fn second_encoding(ca: &TestCa, der: &[u8]) -> Vec<u8> {
        let mut cert = x509_cert::Certificate::from_der(der).unwrap();
        let tbs = cert.tbs_certificate.to_der().unwrap();
        cert.signature = der::asn1::BitString::from_bytes(&sign_p256(&ca.key, &tbs)).unwrap();
        let second = cert.to_der().unwrap();
        assert_ne!(second, der);
        second
    }

    #[test]
    fn dss_ocsp_unknown_for_unrelated_certificate_keeps_genuine_coverage() {
        // The leaf's anchor covers it with a genuine CRL. /Certs also holds
        // an unrelated certificate under another anchor, with that anchor's
        // genuine OCSP `unknown` for it. The unrelated certificate is in no
        // signer or TSA chain, so its `unknown` says nothing about the chain:
        // the material passes, as it does without that response.
        let anchor = test_ca("issuer-a");
        let leaf_der = leaf_under(&anchor, "leaf");
        let other = test_ca("issuer-b");
        let unrelated_der = leaf_under(&other, "unrelated");
        let crl = build_crl(&anchor, THIS_UPDATE, NEXT_UPDATE, None, vec![]);
        let unknown = unknown_for(&other, &unrelated_der);
        let doc = dss_doc(
            &[leaf_der.clone(), unrelated_der.clone()],
            &[crl],
            &[unknown],
        );
        let checks = material_check(&doc, &[&anchor, &other], &[&leaf_der]);
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
    }

    #[test]
    fn dss_ocsp_unknown_for_covered_certificate_stays_unresolved() {
        // Control: the anchor's genuine CRL covers the leaf, and the anchor's
        // authenticated OCSP response says `unknown` for the leaf itself. An
        // `unknown` about a chain certificate still counts, beside other
        // coverage too: NotRun with RevocationStatusUnknown.
        let anchor = test_ca("issuer-a");
        let leaf_der = leaf_under(&anchor, "leaf");
        let crl = build_crl(&anchor, THIS_UPDATE, NEXT_UPDATE, None, vec![]);
        let unknown = unknown_for(&anchor, &leaf_der);
        let doc = dss_doc(std::slice::from_ref(&leaf_der), &[crl], &[unknown]);
        let checks = material_check(&doc, &[&anchor], &[&leaf_der]);
        assert_material_unresolved(&checks, VerifyFindingCode::RevocationStatusUnknown);
    }

    #[test]
    fn dss_ocsp_unknown_counts_for_its_covered_certificate_whichever_certificate_it_binds_first() {
        // Hostile input, one row per shape. A CertID names a certificate by
        // issuer and serial number and binds to the first certificate in
        // /Certs that matches it. In each row another certificate that
        // matches comes before the leaf; the anchor's genuine CRL covers the
        // leaf, and the anchor's authenticated `unknown` still names the
        // leaf: NotRun with RevocationStatusUnknown, as in the control above.
        let anchor = test_ca("issuer-a");
        let leaf_der = leaf_with_serial(&anchor, "leaf", 7);
        // Row 1: a second encoding of the leaf (same TBSCertificate, another
        // valid signature).
        let second_encoding_der = second_encoding(&anchor, &leaf_der);
        // Row 2: a second certificate the anchor gave the same serial number
        // (RFC 5280 forbids it, but both verify).
        let same_serial_der = leaf_with_serial(&anchor, "other", 7);
        for (row, first_der) in [
            ("second encoding of the leaf", second_encoding_der),
            ("second certificate with the leaf's serial", same_serial_der),
        ] {
            let crl = build_crl(&anchor, THIS_UPDATE, NEXT_UPDATE, None, vec![]);
            let unknown = unknown_for(&anchor, &leaf_der);
            let doc = dss_doc(&[first_der, leaf_der.clone()], &[crl], &[unknown]);
            let checks = material_check(&doc, &[&anchor], &[&leaf_der]);
            assert_eq!(
                dss_finding(&checks),
                (
                    VerifyCheckStatus::NotRun,
                    Some(VerifyFindingCode::RevocationStatusUnknown)
                ),
                "{row}"
            );
        }
    }

    #[test]
    fn dss_shadow_is_possible_tampering_after_the_missing_root_probe() {
        // Hostile input, one row per shape. A shadow CRL beside the anchor's
        // genuine CRL, and the anchor's authenticated `unknown` for the leaf.
        // A certificate path is left unresolved, so the missing-root probe
        // re-reads the material at the provisional time with every covered
        // certificate as a provisional root, which exempts the leaf from its
        // `unknown` and from the shadow scan. Whatever the probe finds, the
        // shadow stays visible: NotRun with
        // ValidationMaterialPossibleTampering (lead ruling F).
        let anchor = test_ca("issuer");
        let leaf_der = leaf_under(&anchor, "leaf");
        let leaf = x509_cert::Certificate::from_der(&leaf_der).unwrap();
        let shadow = test_ca("issuer");
        let later = Some(AT_UNIX + 10_800);
        // Row 1: read at the provisional time itself; the shadow is found at
        // once. Row 2: read two hours later, when the anchor's genuine CRL is
        // stale, so the material fails early, before the shadow scan; the
        // probe's re-read at the provisional time, under the real anchors,
        // finds the shadow. (A shadow's own stale CRL is about nothing in the
        // chains and never fails early: Engine call Q-C = A.)
        for (row, verified_at, genuine_next) in [
            ("genuine CRL fresh", AT_UNIX, later),
            (
                "genuine CRL stale at the verification time",
                AT_UNIX + 7200,
                NEXT_UPDATE,
            ),
        ] {
            let genuine = build_crl(&anchor, THIS_UPDATE, genuine_next, None, vec![]);
            let forged = build_crl(&shadow, THIS_UPDATE, NEXT_UPDATE, None, vec![]);
            let unknown = build_ocsp_full(
                &anchor,
                leaf.tbs_certificate.serial_number.clone(),
                AT_UNIX - 60,
                later,
                x509_ocsp::CertStatus::unknown(),
                AT_UNIX - 60,
                &anchor,
                true,
            );
            let doc = dss_doc(
                &[
                    leaf_der.clone(),
                    shadow.cert_der.clone(),
                    anchor.cert_der.clone(),
                ],
                &[genuine, forged],
                &[unknown],
            );
            let limits = process_operation_limits();
            let memory = limits.memory.ledger().unwrap();
            let anchors = vec![EmbeddedCert::from_der(&anchor.cert_der).unwrap()];
            let covered = covered_of(&[&leaf_der]);
            let mut checks = Checks::new(limits);
            verify_dss(
                &doc,
                &anchors,
                &covered,
                verified_at,
                &memory,
                &mut checks,
                limits,
            )
            .unwrap();
            checks
                .not_run(VerifyCheckKind::TimestampCertificatePath)
                .unwrap();
            classify_missing_material_root(
                &doc,
                &anchors,
                &covered,
                AT_UNIX,
                &memory,
                limits,
                &mut checks,
            )
            .unwrap();
            assert_eq!(
                dss_finding(&checks),
                (
                    VerifyCheckStatus::NotRun,
                    Some(VerifyFindingCode::ValidationMaterialPossibleTampering)
                ),
                "{row}"
            );
        }
    }
    #[test]
    fn missing_root_probe_keeps_a_genuine_failure_and_an_unknown() {
        // Hostile input, one row per shape (Sol, report-unknown-4 section 3).
        // A certificate path is left unresolved and the material failed at
        // the verification time, so the missing-root probe re-reads it at the
        // provisional time. A genuine failure that persists there, or an
        // authenticated `unknown` found there, is what the check reports,
        // never a missing trust root: treating every covered certificate as a
        // root would exempt them from the very checks that found it.
        let anchor = test_ca("issuer-a");
        let leaf_der = leaf_under(&anchor, "leaf");
        let leaf = x509_cert::Certificate::from_der(&leaf_der).unwrap();
        // Row 1: the anchor's genuine CRL about the leaf is stale at both
        // times. A TSA chain whose root is no anchor is covered, and its
        // root's authenticated `unknown` names the TSA certificate. The
        // anchor itself is not in /Certs.
        let tsa_root = test_ca("tsa-root");
        let tsa_der = leaf_under(&tsa_root, "tsa");
        let stale = build_crl(&anchor, AT_UNIX - 7200, Some(AT_UNIX - 60), None, vec![]);
        let tsa_unknown = unknown_for(&tsa_root, &tsa_der);
        let failing = dss_doc(
            &[leaf_der.clone(), tsa_der.clone(), tsa_root.cert_der.clone()],
            &[stale],
            &[tsa_unknown],
        );
        // Row 2: the anchor's genuine CRL is fresh at the provisional time
        // and stale two hours later; its authenticated `unknown` for the
        // leaf is fresh at both.
        let fresh_then_stale = build_crl(&anchor, THIS_UPDATE, NEXT_UPDATE, None, vec![]);
        let leaf_unknown = build_ocsp_full(
            &anchor,
            leaf.tbs_certificate.serial_number.clone(),
            AT_UNIX - 60,
            Some(AT_UNIX + 10_800),
            x509_ocsp::CertStatus::unknown(),
            AT_UNIX - 60,
            &anchor,
            false,
        );
        let unknown_then = dss_doc(
            std::slice::from_ref(&leaf_der),
            &[fresh_then_stale],
            &[leaf_unknown],
        );
        // Row 3: the anchor's genuine CRL is fresh at both times and lists
        // the leaf; the TSA chain's root is still no anchor. The revocation
        // persists at the provisional time (review round 1 of #6944, P1a).
        let revoking = dss_doc(
            &[leaf_der.clone(), tsa_der.clone(), tsa_root.cert_der.clone()],
            &[build_crl(
                &anchor,
                THIS_UPDATE,
                NEXT_UPDATE,
                None,
                vec![leaf.tbs_certificate.serial_number.clone()],
            )],
            &[],
        );
        let rows = [
            (
                "genuine CRL about the leaf stale at both times",
                failing,
                vec![leaf_der.clone(), tsa_der.clone(), tsa_root.cert_der.clone()],
                AT_UNIX,
                (
                    VerifyCheckStatus::Fail,
                    Some(VerifyFindingCode::ValidationMaterialInvalid),
                ),
            ),
            (
                "unknown for the leaf at the provisional time",
                unknown_then,
                vec![leaf_der.clone()],
                AT_UNIX + 7200,
                (
                    VerifyCheckStatus::NotRun,
                    Some(VerifyFindingCode::RevocationStatusUnknown),
                ),
            ),
            (
                "fresh anchor CRL revokes the leaf while the TSA root is missing",
                revoking,
                vec![leaf_der.clone(), tsa_der.clone(), tsa_root.cert_der.clone()],
                AT_UNIX,
                (
                    VerifyCheckStatus::Fail,
                    Some(VerifyFindingCode::ValidationMaterialInvalid),
                ),
            ),
        ];
        let mut wrong = Vec::new();
        for (row, doc, covered_ders, verified_at, expected) in rows {
            let limits = process_operation_limits();
            let memory = limits.memory.ledger().unwrap();
            let anchors = vec![EmbeddedCert::from_der(&anchor.cert_der).unwrap()];
            let covered_refs: Vec<&[u8]> = covered_ders.iter().map(Vec::as_slice).collect();
            let covered = covered_of(&covered_refs);
            let mut checks = Checks::new(limits);
            verify_dss(
                &doc,
                &anchors,
                &covered,
                verified_at,
                &memory,
                &mut checks,
                limits,
            )
            .unwrap();
            let first = dss_finding(&checks);
            checks
                .not_run(VerifyCheckKind::TimestampCertificatePath)
                .unwrap();
            classify_missing_material_root(
                &doc,
                &anchors,
                &covered,
                AT_UNIX,
                &memory,
                limits,
                &mut checks,
            )
            .unwrap();
            let found = dss_finding(&checks);
            if first.0 != VerifyCheckStatus::Fail || found != expected {
                wrong.push(format!("{row}: first {first:?}, then {found:?}"));
            }
        }
        assert!(wrong.is_empty(), "rows not as ruled: {wrong:#?}");
    }
}
