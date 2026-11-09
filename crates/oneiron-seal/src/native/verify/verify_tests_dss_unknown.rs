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
    use crate::api::{VerifyCheckKind, VerifyFindingCode};
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
    fn dss_ocsp_unknown_for_covered_certificate_counts_through_a_second_encoding() {
        // /Certs carries a second encoding of the leaf (same TBSCertificate,
        // another valid signature) before the leaf itself. The response's
        // CertID binds to the first certificate that matches it, the second
        // encoding, but the `unknown` still names the leaf: NotRun with
        // RevocationStatusUnknown, as in the control above.
        let anchor = test_ca("issuer-a");
        let leaf_der = leaf_under(&anchor, "leaf");
        let second_der = second_encoding(&anchor, &leaf_der);
        let crl = build_crl(&anchor, THIS_UPDATE, NEXT_UPDATE, None, vec![]);
        let unknown = unknown_for(&anchor, &leaf_der);
        let doc = dss_doc(&[second_der, leaf_der.clone()], &[crl], &[unknown]);
        let checks = material_check(&doc, &[&anchor], &[&leaf_der]);
        assert_material_unresolved(&checks, VerifyFindingCode::RevocationStatusUnknown);
    }

    #[test]
    fn dss_shadow_failure_survives_the_missing_root_probe() {
        // A shadow CRL beside the anchor's genuine CRL, and the anchor's
        // authenticated `unknown` for the leaf: Invalid under the real
        // anchors. With a certificate path left unresolved, the missing-root
        // probe re-runs the material with every covered certificate as a
        // provisional anchor, which exempts the leaf from its `unknown` and
        // from the shadow scan. A forged-material failure is never a
        // missing-root symptom, so it stays Fail / ValidationMaterialInvalid.
        let anchor = test_ca("issuer");
        let leaf_der = leaf_under(&anchor, "leaf");
        let leaf = x509_cert::Certificate::from_der(&leaf_der).unwrap();
        let shadow = test_ca("issuer");
        let genuine = build_crl(&anchor, THIS_UPDATE, NEXT_UPDATE, None, vec![]);
        let forged = build_crl(&shadow, THIS_UPDATE, NEXT_UPDATE, None, vec![]);
        let unknown = build_ocsp_full(
            &anchor,
            leaf.tbs_certificate.serial_number,
            AT_UNIX - 60,
            NEXT_UPDATE,
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
            AT_UNIX,
            &memory,
            &mut checks,
            limits,
        )
        .unwrap();
        assert_material_fails(&checks);
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
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_ocsp_unknown_counts_for_a_covered_certificate_sharing_its_serial() {
        // The anchor issued two certificates with one serial number (RFC 5280
        // forbids it, but both verify): an unrelated one first in /Certs,
        // then the leaf. An `unknown` for that issuer and serial binds to the
        // first, and still names the leaf, whose issuer and serial it
        // carries: NotRun with RevocationStatusUnknown.
        let anchor = test_ca("issuer-a");
        let other_der = leaf_with_serial(&anchor, "other", 7);
        let leaf_der = leaf_with_serial(&anchor, "leaf", 7);
        let crl = build_crl(&anchor, THIS_UPDATE, NEXT_UPDATE, None, vec![]);
        let unknown = unknown_for(&anchor, &leaf_der);
        let doc = dss_doc(&[other_der, leaf_der.clone()], &[crl], &[unknown]);
        let checks = material_check(&doc, &[&anchor], &[&leaf_der]);
        assert_material_unresolved(&checks, VerifyFindingCode::RevocationStatusUnknown);
    }

    #[test]
    fn dss_shadow_behind_a_stale_crl_survives_the_missing_root_probe() {
        // At the verification time the shadow's CRL is stale, so the
        // material fails early, before the shadow scan. The missing-root
        // probe re-reads it at the earlier provisional time, when that CRL is
        // fresh, with every covered certificate as a provisional root, which
        // exempts the leaf from its `unknown` and from the shadow scan. Under
        // the real anchors at that time the shadow is found, so the failure
        // stays Fail / ValidationMaterialInvalid.
        let verified_at = AT_UNIX + 7200;
        let later = Some(AT_UNIX + 10_800);
        let anchor = test_ca("issuer");
        let leaf_der = leaf_under(&anchor, "leaf");
        let leaf = x509_cert::Certificate::from_der(&leaf_der).unwrap();
        let shadow = test_ca("issuer");
        let genuine = build_crl(&anchor, THIS_UPDATE, later, None, vec![]);
        let stale_forged = build_crl(&shadow, THIS_UPDATE, NEXT_UPDATE, None, vec![]);
        let unknown = build_ocsp_full(
            &anchor,
            leaf.tbs_certificate.serial_number,
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
            &[genuine, stale_forged],
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
        assert_material_fails(&checks);
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
        assert_material_fails(&checks);
    }
}
