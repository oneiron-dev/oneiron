//! Verifier tests: which authenticated OCSP `unknown` statuses count (Engine
//! call SEAL-OCSP-UNKNOWN-GLOBAL-VETO, 10 Nov 06:05). An `unknown` counts
//! only when it names a covered non-anchor certificate, one in a signer or
//! TSA chain; material unrelated to the chain never changes a genuine result.

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use der::Decode;
    use lopdf::Document;

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
}
