//! Verifier tests: same-subject shadow CRL signers (lead rulings
//! SEAL-SHADOW-ETSI, 10 Nov 05:38, and F, 06:50). A shadow is a CRL signer
//! that carries a covered certificate's issuer subject, did not sign it, and
//! holds a key no trust anchor vouches for. Wherever the result would
//! otherwise be unresolved, it reports NotRun with the sub-indication
//! ValidationMaterialPossibleTampering; legitimate same-subject keys are
//! never shadows.

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use der::Decode;
    use lopdf::Document;

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

    /// The certificate `old`'s key issues for `new`'s subject and key: a key
    /// rollover's link certificate.
    fn link_certificate(old: &TestCa, new: &TestCa) -> Vec<u8> {
        let issuer = rcgen::Issuer::from_params(&old.rcgen_params, &old.rcgen_key);
        new.rcgen_params
            .signed_by(&new.rcgen_key, &issuer)
            .unwrap()
            .der()
            .to_vec()
    }

    #[test]
    fn dss_crl_shadow_beside_covered_target_is_possible_tampering() {
        // Hostile input, one row per shape. In each, the anchor's genuine CRL
        // covers the leaf, and an attacker's self-signed certificate with the
        // anchor's subject signs a second CRL. Where the result would
        // otherwise be unresolved, the shadow reports possible tampering
        // instead: NotRun with ValidationMaterialPossibleTampering (lead
        // rulings SEAL-SHADOW-ETSI Q3 and F).
        let anchor = test_ca("issuer");
        let leaf_der = leaf_under(&anchor, "leaf");
        let leaf = x509_cert::Certificate::from_der(&leaf_der).unwrap();
        let shadow = test_ca("issuer");
        let genuine = || build_crl(&anchor, THIS_UPDATE, NEXT_UPDATE, None, vec![]);
        let forged = || build_crl(&shadow, THIS_UPDATE, NEXT_UPDATE, None, vec![]);
        // Row 1: a second leaf, under another anchor, has no coverage, so the
        // result would be ValidationMaterialUnavailable.
        let other = test_ca("other-ca");
        let second_der = leaf_under(&other, "second-leaf");
        let incomplete = dss_doc(
            &[
                leaf_der.clone(),
                second_der.clone(),
                shadow.cert_der.clone(),
            ],
            &[genuine(), forged()],
            &[],
        );
        // Row 2: the anchor's authenticated OCSP response says `unknown` for
        // the leaf, so the result would be RevocationStatusUnknown. The
        // response carries its responder certificate, so its by-name
        // responder ID resolves to the anchor, not to the shadow in /Certs.
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
        let unknown_leaf = dss_doc(
            &[leaf_der.clone(), shadow.cert_der.clone()],
            &[genuine(), forged()],
            &[unknown],
        );
        let rows: [(&str, &Document, &[&TestCa], &[&[u8]]); 2] = [
            (
                "coverage incomplete",
                &incomplete,
                &[&anchor, &other],
                &[leaf_der.as_slice(), second_der.as_slice()],
            ),
            (
                "authenticated unknown for the leaf",
                &unknown_leaf,
                &[&anchor],
                &[leaf_der.as_slice()],
            ),
        ];
        for (row, doc, anchors, covered) in rows {
            let checks = material_check(doc, anchors, covered);
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
    fn dss_crl_shadow_beside_complete_genuine_coverage_passes() {
        // Control: the anchor's genuine CRL covers every covered certificate
        // and nothing is unknown, so the shadow's CRL is disregarded, as EN
        // 319 102-1 disregards unauthorized revocation data.
        let anchor = test_ca("issuer");
        let leaf_der = leaf_under(&anchor, "leaf");
        let shadow = test_ca("issuer");
        let genuine = build_crl(&anchor, THIS_UPDATE, NEXT_UPDATE, None, vec![]);
        let forged = build_crl(&shadow, THIS_UPDATE, NEXT_UPDATE, None, vec![]);
        let doc = dss_doc(
            &[leaf_der.clone(), shadow.cert_der.clone()],
            &[genuine, forged],
            &[],
        );
        let checks = material_check(&doc, &[&anchor], &[&leaf_der]);
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
    }

    #[test]
    fn dss_crl_from_separate_crl_signing_key_is_unavailable() {
        // The CA signs certificates with one key and CRLs with another,
        // which it certified under its own subject (RFC 5280 §5.1.1.3). The
        // verifier does not take that CRL as the leaf's coverage, but the
        // anchor vouches for the key: missing material, not forged.
        let anchor = test_ca("issuer");
        let leaf_der = leaf_under(&anchor, "leaf");
        let crl_signer = child_ca(&anchor, "issuer");
        let crl = build_crl(&crl_signer, THIS_UPDATE, NEXT_UPDATE, None, vec![]);
        let doc = dss_doc(
            &[leaf_der.clone(), crl_signer.cert_der.clone()],
            &[crl],
            &[],
        );
        let checks = material_check(&doc, &[&anchor], &[&leaf_der]);
        assert_material_unresolved(&checks, VerifyFindingCode::ValidationMaterialUnavailable);
    }

    #[test]
    fn dss_crl_after_key_rollover_with_link_certificate_is_unavailable() {
        // The CA rolled over to a new key (RFC 5280 §5.2.1). /Certs holds
        // its new self-signed certificate first, then the link certificate
        // the old key issued for the new key; the only CRL is signed with
        // the new key. The old key signed the leaf, so the leaf has no
        // coverage, but the anchor vouches for the new key through the link
        // certificate: missing material, not forged.
        let old = test_ca("issuer");
        let leaf_der = leaf_under(&old, "leaf");
        let new = test_ca("issuer");
        let link_der = link_certificate(&old, &new);
        let crl = build_crl(&new, THIS_UPDATE, NEXT_UPDATE, None, vec![]);
        let doc = dss_doc(
            &[leaf_der.clone(), new.cert_der.clone(), link_der],
            &[crl],
            &[],
        );
        let checks = material_check(&doc, &[&old], &[&leaf_der]);
        assert_material_unresolved(&checks, VerifyFindingCode::ValidationMaterialUnavailable);
    }

    #[test]
    fn dss_crl_from_same_subject_anchored_ca_is_unavailable() {
        // Two trusted CAs share a subject (RFC 5280 §8). The DSS carries the
        // first CA's genuine CRL, and the second CA issued the leaf, which
        // has no coverage: missing material, not forged.
        let first = test_ca("issuer");
        let second = test_ca("issuer");
        let leaf_der = leaf_under(&second, "leaf");
        let crl = build_crl(&first, THIS_UPDATE, NEXT_UPDATE, None, vec![]);
        let doc = dss_doc(std::slice::from_ref(&leaf_der), &[crl], &[]);
        let checks = material_check(&doc, &[&first, &second], &[&leaf_der]);
        assert_material_unresolved(&checks, VerifyFindingCode::ValidationMaterialUnavailable);
    }
}
