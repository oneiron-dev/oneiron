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
        let anchor_ders: Vec<&[u8]> = anchors.iter().map(|ca| ca.cert_der.as_slice()).collect();
        material_check_ders(doc, &anchor_ders, covered)
    }

    /// [`material_check`] with the anchors given as certificate DERs.
    fn material_check_ders(
        doc: &Document,
        anchors: &[&[u8]],
        covered: &[&[u8]],
    ) -> Checks<'static> {
        let limits = process_operation_limits();
        let memory = limits.memory.ledger().unwrap();
        let anchors: Vec<EmbeddedCert> = anchors
            .iter()
            .map(|der| EmbeddedCert::from_der(der).unwrap())
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
    fn dss_crl_from_separate_crl_signing_key_covers_the_leaf() {
        // The CA signs certificates with one key and CRLs with another,
        // which it certified under its own subject with cRLSign (RFC 5280
        // §5.1.1.3). That key has revocation authority over the leaf, so
        // its fresh complete CRL is the leaf's coverage (review round 1 of
        // #6944, P1c).
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
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
    }

    #[test]
    fn dss_crl_after_key_rollover_with_link_certificate_covers_the_leaf() {
        // The CA rolled over to a new key (RFC 5280 §5.2.1). /Certs holds
        // its new self-signed certificate first, then the link certificate
        // the old key issued for the new key with cRLSign; the only CRL is
        // signed with the new key. The old key signed the leaf, and the
        // link certificate gives the new key revocation authority over it,
        // so the new key's fresh complete CRL is the leaf's coverage (review
        // round 1 of #6944, P1c).
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
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
    }

    #[test]
    fn dss_crl_under_another_name_from_a_certified_key_gives_no_coverage() {
        // The leaf's issuer certified a CRL-signing key under another
        // subject. That key's CRL carries the other name, so the verifier
        // never judged it for the leaf (its freshness here has lapsed): it
        // is no coverage, whatever authority the key holds. Indirect CRLs
        // are out of scope (review round 1 of #6944, P1c).
        let anchor = test_ca("issuer");
        let leaf_der = leaf_under(&anchor, "leaf");
        let crl_signer = child_ca(&anchor, "crl-signer");
        let crl = build_crl(
            &crl_signer,
            AT_UNIX - 7200,
            Some(AT_UNIX - 3600),
            None,
            vec![],
        );
        let doc = dss_doc(
            &[leaf_der.clone(), crl_signer.cert_der.clone()],
            &[crl],
            &[],
        );
        let checks = material_check(&doc, &[&anchor], &[&leaf_der]);
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

    #[test]
    fn dss_crl_gains_no_authority_from_a_replacement_certificate_key_usage() {
        // The leaf's issuer certified a same-subject key for digital
        // signatures only. /Certs holds first a self-signed certificate for
        // that key that adds cRLSign, then the issuer's certificate for it;
        // the key's CRL lists the leaf. cRLSign must come from the
        // certificate the issuer gave the key (RFC 5280 §6.3.3(f)), not from
        // the key holder's own copy, so the key has no revocation authority
        // and its CRL claims nothing about the leaf. The issuer still vouches
        // for the key, so it is no shadow: missing material, not forged
        // (review round 1 of #6944, P1b).
        let issuer = test_ca("issuer");
        let leaf_der = leaf_under(&issuer, "leaf");
        let leaf = x509_cert::Certificate::from_der(&leaf_der).unwrap();
        let key_holder = ca_with_kus("issuer", vec![rcgen::KeyUsagePurpose::DigitalSignature]);
        let issuer_rc = rcgen::Issuer::from_params(&issuer.rcgen_params, &issuer.rcgen_key);
        let certified_der = key_holder
            .rcgen_params
            .signed_by(&key_holder.rcgen_key, &issuer_rc)
            .unwrap()
            .der()
            .to_vec();
        let mut replacement_params = key_holder.rcgen_params.clone();
        replacement_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::CrlSign);
        let replacement_der = replacement_params
            .self_signed(&key_holder.rcgen_key)
            .unwrap()
            .der()
            .to_vec();
        let crl = build_crl(
            &key_holder,
            THIS_UPDATE,
            NEXT_UPDATE,
            None,
            vec![leaf.tbs_certificate.serial_number],
        );
        let doc = dss_doc(
            &[replacement_der, certified_der, leaf_der.clone()],
            &[crl],
            &[],
        );
        let checks = material_check(&doc, &[&issuer], &[&leaf_der]);
        assert_material_unresolved(&checks, VerifyFindingCode::ValidationMaterialUnavailable);
    }

    #[test]
    fn dss_crl_counts_only_from_a_key_with_authority_over_the_leaf() {
        // A same-subject CRL key the leaf's own issuer certified is that
        // issuer's revocation authority (RFC 5280 §5.1.1.3, §5.2.1): its CRL is
        // about the leaf's chain, and its listing of the leaf is a revocation
        // that fails. A same-subject CA another trust anchor vouches for is no
        // shadow (ruling Q2) but has no authority over the leaf (RFC 5280 §8,
        // §6.3.3(f)): its CRL claims nothing about it (Engine call Q-C = A),
        // whether it lists the leaf's serial or is stale, and beside the
        // issuer's genuine CRL the material passes (Sol, report-shadow-f3
        // section 2).
        let serial_of = |der: &[u8]| {
            x509_cert::Certificate::from_der(der)
                .unwrap()
                .tbs_certificate
                .serial_number
        };
        let failed = (
            VerifyCheckStatus::Fail,
            Some(VerifyFindingCode::ValidationMaterialInvalid),
        );
        let missing = (
            VerifyCheckStatus::NotRun,
            Some(VerifyFindingCode::ValidationMaterialUnavailable),
        );
        let passed = (VerifyCheckStatus::Pass, None);
        let anchor = test_ca("issuer");
        let anchor_leaf = leaf_under(&anchor, "leaf");
        let crl_signer = child_ca(&anchor, "issuer");
        let old = test_ca("issuer");
        let old_leaf = leaf_under(&old, "leaf");
        let new = test_ca("issuer");
        let link_der = link_certificate(&old, &new);
        let first = test_ca("issuer");
        let second = test_ca("issuer");
        let second_leaf = leaf_under(&second, "leaf");
        // The issuer's link certificate for its new key is a configured
        // trust anchor, and /Certs holds the new key's own self-signed
        // certificate, which is the one that verifies the CRL (Sol,
        // report-shadow-f4 section 1.2).
        let issuer = test_ca("issuer");
        let issuer_leaf = leaf_under(&issuer, "leaf");
        let next = test_ca("issuer");
        let anchored_link = link_certificate(&issuer, &next);
        let rows: Vec<(&str, Document, Vec<&[u8]>, &[u8], _)> = vec![
            (
                "the issuer's separate CRL-signing key lists the leaf",
                dss_doc(
                    &[anchor_leaf.clone(), crl_signer.cert_der.clone()],
                    &[build_crl(
                        &crl_signer,
                        THIS_UPDATE,
                        NEXT_UPDATE,
                        None,
                        vec![serial_of(&anchor_leaf)],
                    )],
                    &[],
                ),
                vec![anchor.cert_der.as_slice()],
                anchor_leaf.as_slice(),
                failed,
            ),
            (
                "the issuer's rolled-over key, with its link certificate, lists the leaf",
                dss_doc(
                    &[old_leaf.clone(), new.cert_der.clone(), link_der],
                    &[build_crl(
                        &new,
                        THIS_UPDATE,
                        NEXT_UPDATE,
                        None,
                        vec![serial_of(&old_leaf)],
                    )],
                    &[],
                ),
                vec![old.cert_der.as_slice()],
                old_leaf.as_slice(),
                failed,
            ),
            (
                "another anchored CA with the same subject lists the leaf's serial",
                dss_doc(
                    std::slice::from_ref(&second_leaf),
                    &[build_crl(
                        &first,
                        THIS_UPDATE,
                        NEXT_UPDATE,
                        None,
                        vec![serial_of(&second_leaf)],
                    )],
                    &[],
                ),
                vec![first.cert_der.as_slice(), second.cert_der.as_slice()],
                second_leaf.as_slice(),
                missing,
            ),
            (
                "another anchored CA's stale CRL beside the issuer's genuine CRL",
                dss_doc(
                    std::slice::from_ref(&second_leaf),
                    &[
                        build_crl(&first, AT_UNIX - 7200, Some(AT_UNIX - 60), None, vec![]),
                        build_crl(&second, THIS_UPDATE, NEXT_UPDATE, None, vec![]),
                    ],
                    &[],
                ),
                vec![first.cert_der.as_slice(), second.cert_der.as_slice()],
                second_leaf.as_slice(),
                passed,
            ),
            (
                "the issuer's anchored link certificate certifies the key that lists the leaf",
                dss_doc(
                    &[issuer_leaf.clone(), next.cert_der.clone()],
                    &[build_crl(
                        &next,
                        THIS_UPDATE,
                        NEXT_UPDATE,
                        None,
                        vec![serial_of(&issuer_leaf)],
                    )],
                    &[],
                ),
                vec![issuer.cert_der.as_slice(), anchored_link.as_slice()],
                issuer_leaf.as_slice(),
                failed,
            ),
        ];
        let mut wrong = Vec::new();
        for (row, doc, anchors, leaf, expected) in rows {
            let checks = material_check_ders(&doc, &anchors, &[leaf]);
            let found = dss_finding(&checks);
            if found != expected {
                wrong.push(format!("{row}: {found:?}"));
            }
        }
        assert!(wrong.is_empty(), "rows not as ruled: {wrong:#?}");
    }
}
