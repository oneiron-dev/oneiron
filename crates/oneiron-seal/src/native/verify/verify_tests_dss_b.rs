//! Verifier tests B: remaining DSS coverage and binding tests, KU gates, OCSP delegate and TSP token tests.

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used)]
    use der::{Decode, Encode};
    use lopdf::{Document, Object};

    use super::super::super::{cms, tsp};
    use super::super::verify_chain_gates::{enforce_signer_leaf_key_usage, key_usage_permits};
    use super::super::verify_dss_core::verify_dss;
    use super::super::verify_sig_pipeline::Checks;
    use super::super::verify_tests_fixtures_dss_a::tests::*;
    use super::super::verify_tests_time_lta_a::tests::*;
    use super::super::*;
    use crate::api::{VerifyCheckKind, VerifyCheckStatus};

    #[test]
    fn dss_cert_only_fails_revocation_coverage() {
        // A /Certs-only DSS (chain DERs present, /CRLs and /OCSPs absent)
        // carries zero revocation material and must not inflate B-LT.
        let ca = test_ca("dss-ca");
        let leaf_der = leaf_under(&ca, "leaf");
        let doc = dss_doc(&[ca.cert_der.clone(), leaf_der.clone()], &[], &[]);
        let covered = covered_of(&[&ca.cert_der, &leaf_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_irrelevant_issuer_evidence_fails_coverage() {
        // Authentic-but-irrelevant evidence: an attacker-embedded
        // self-signed "issuer" with its own fresh CRL/OCSP says nothing
        // about the covered chain.
        let real_ca = test_ca("real-ca");
        let leaf_der = leaf_under(&real_ca, "signer");
        let evil = test_ca("evil-ca");
        let evil_crl = build_crl(&evil, AT_UNIX - 3600, Some(AT_UNIX + 3600), None, vec![]);
        let evil_ocsp = build_ocsp(
            &evil,
            evil.cert.tbs_certificate.serial_number.clone(),
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
        );
        let doc = dss_doc(
            &[real_ca.cert_der.clone(), leaf_der.clone(), evil.cert_der],
            &[evil_crl],
            &[evil_ocsp],
        );
        let covered = covered_of(&[&real_ca.cert_der, &leaf_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_crl_covers_chain_passes() {
        // One CRL issued by the CA covers both the CA (self-issued) and the
        // leaf it issued.
        let ca = test_ca("dss-ca");
        let leaf_der = leaf_under(&ca, "leaf");
        let crl = build_crl(&ca, AT_UNIX - 3600, Some(AT_UNIX + 3600), None, vec![]);
        let doc = dss_doc(&[ca.cert_der.clone(), leaf_der.clone()], &[crl], &[]);
        let covered = covered_of(&[&ca.cert_der, &leaf_der]);
        let checks = dss_check(&doc, &covered);
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
    }

    #[test]
    fn dss_ocsp_covers_chain_passes() {
        // OCSP responses bound to each covered cert with `good` status.
        let ca = test_ca("dss-ca");
        let leaf_der = leaf_under(&ca, "leaf");
        let leaf = x509_cert::Certificate::from_der(&leaf_der).unwrap();
        let ocsp_ca = build_ocsp(
            &ca,
            ca.cert.tbs_certificate.serial_number.clone(),
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
        );
        let ocsp_leaf = build_ocsp(
            &ca,
            leaf.tbs_certificate.serial_number,
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
        );
        let doc = dss_doc(
            &[ca.cert_der.clone(), leaf_der.clone()],
            &[],
            &[ocsp_ca, ocsp_leaf],
        );
        let covered = covered_of(&[&ca.cert_der, &leaf_der]);
        let checks = dss_check(&doc, &covered);
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
    }

    #[test]
    fn dss_mixed_crl_ocsp_coverage_passes() {
        // Three-tier chain where each evidence kind proves its own path:
        // the root and the intermediate it issued ride the root's CRL (the
        // CRL cannot cover the leaf — the leaf's ACTUAL issuer is the
        // intermediate, not the CRL signer), and the leaf rides an OCSP
        // response bound to it via the intermediate. Dropping either entry
        // must fail coverage.
        let root = test_ca("root");
        let inter = child_ca(&root, "intermediate");
        let leaf_der = leaf_under(&inter, "leaf");
        let leaf = x509_cert::Certificate::from_der(&leaf_der).unwrap();
        let crl = build_crl(&root, AT_UNIX - 3600, Some(AT_UNIX + 3600), None, vec![]);
        let ocsp_leaf = build_ocsp(
            &inter,
            leaf.tbs_certificate.serial_number,
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
        );
        let doc = dss_doc(
            &[
                root.cert_der.clone(),
                inter.cert_der.clone(),
                leaf_der.clone(),
            ],
            &[crl],
            &[ocsp_leaf],
        );
        let covered = covered_of(&[&root.cert_der, &inter.cert_der, &leaf_der]);
        let checks = dss_check(&doc, &covered);
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
    }

    #[test]
    fn dss_crl_same_dn_fake_issuer_rejected() {
        // Same-subject fake-issuer shadowing on the CRL path: a real
        // covered leaf issued by anchor A; /Certs orders [leaf, F] where F
        // is attacker self-signed with subject DN == A's DN. A fresh EMPTY
        // CRL signed by F (issuer = A's DN) must fail ValidationMaterial —
        // never pass, never AbsentAllowed.
        let anchor = test_ca("issuer");
        let leaf_der = leaf_under(&anchor, "leaf");
        let fake = test_ca("issuer");
        let crl = build_crl(&fake, AT_UNIX - 3600, Some(AT_UNIX + 3600), None, vec![]);
        let doc = dss_doc(&[leaf_der.clone(), fake.cert_der], &[crl], &[]);
        let anchor_cert = EmbeddedCert::from_der(&anchor.cert_der).unwrap();
        let covered = covered_of(&[&leaf_der]);
        let mut checks = Checks::new();
        verify_dss(
            &doc,
            std::slice::from_ref(&anchor_cert),
            &covered,
            AT_UNIX,
            usize::MAX,
            &mut checks,
        );
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_ocsp_same_dn_fake_issuer_rejected() {
        // Same shadowing on the OCSP path: a `good` SingleResponse for the
        // real leaf's serial whose CertID issuer name/key hashes are
        // computed against F and whose response is signed by F must fail
        // ValidationMaterial.
        let anchor = test_ca("issuer");
        let leaf_der = leaf_under(&anchor, "leaf");
        let leaf = x509_cert::Certificate::from_der(&leaf_der).unwrap();
        let fake = test_ca("issuer");
        let ocsp = build_ocsp(
            &fake,
            leaf.tbs_certificate.serial_number,
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
        );
        let doc = dss_doc(&[leaf_der.clone(), fake.cert_der], &[], &[ocsp]);
        let anchor_cert = EmbeddedCert::from_der(&anchor.cert_der).unwrap();
        let covered = covered_of(&[&leaf_der]);
        let mut checks = Checks::new();
        verify_dss(
            &doc,
            std::slice::from_ref(&anchor_cert),
            &covered,
            AT_UNIX,
            usize::MAX,
            &mut checks,
        );
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_anchor_exempt_from_coverage_passes() {
        // Anchor certificates ride anchor trust: the covered anchor needs
        // no evidence of its own; the non-anchor intermediate is covered by
        // an OCSP response bound to it.
        let anchor_ca = test_ca("anchor-ca");
        let inter_der = leaf_under(&anchor_ca, "intermediate");
        let inter = x509_cert::Certificate::from_der(&inter_der).unwrap();
        let ocsp_inter = build_ocsp(
            &anchor_ca,
            inter.tbs_certificate.serial_number,
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
        );
        let doc = dss_doc(
            &[anchor_ca.cert_der.clone(), inter_der.clone()],
            &[],
            &[ocsp_inter],
        );
        let anchor = EmbeddedCert::from_der(&anchor_ca.cert_der).unwrap();
        let covered = covered_of(&[&anchor_ca.cert_der, &inter_der]);
        let mut checks = Checks::new();
        verify_dss(
            &doc,
            std::slice::from_ref(&anchor),
            &covered,
            AT_UNIX,
            usize::MAX,
            &mut checks,
        );
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
    }

    #[test]
    fn dss_ocsp_target_binds_serial_and_issuer_together() {
        // Two covered-set leaves share a serial under DIFFERENT issuers. The
        // OCSP response (issued by ca2) must bind to leaf2 even though leaf1
        // sorts first in the embedded set: serial alone is not identity.
        let ca1 = test_ca("ca-one");
        let ca2 = test_ca("ca-two");
        let leaf1_der = leaf_with_serial(&ca1, "leaf-one", 0x5EED);
        let leaf2_der = leaf_with_serial(&ca2, "leaf-two", 0x5EED);
        let leaf2 = x509_cert::Certificate::from_der(&leaf2_der).unwrap();
        let ocsp = build_ocsp(
            &ca2,
            leaf2.tbs_certificate.serial_number,
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
        );
        let doc = dss_doc(&[leaf1_der, leaf2_der.clone(), ca2.cert_der], &[], &[ocsp]);
        let covered = covered_of(&[&leaf2_der]);
        let checks = dss_check(&doc, &covered);
        assert!(
            checks.passed(VerifyCheckKind::ValidationMaterial),
            "binding must walk past the serial-matching wrong-issuer leaf"
        );
    }

    #[test]
    fn dss_freshness_uses_archival_applicable_time() {
        // A CRL fresh at the archival (DocTimeStamp) time but expired by the
        // verification clock is valid evidence for an archived document: the
        // DocTimeStamp covers the DSS revision and attests it as of genTime.
        let ca = test_ca("dss-ca");
        let archival = AT_UNIX - 86_400;
        let crl = build_crl(&ca, archival - 3600, Some(archival + 3600), None, vec![]);
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[crl], &[]);
        let covered = covered_of(&[&ca.cert_der]);
        let mut checks = Checks::new();
        verify_dss(&doc, &[], &covered, archival, usize::MAX, &mut checks);
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
        // The same material judged at the verification clock is stale.
        let checks_now = dss_check(&doc, &covered);
        assert_material_fails(&checks_now);
    }

    #[test]
    fn dss_direct_dict_root_classifies_invalid() {
        // lopdf catalog() errs on a spec-invalid direct-dictionary trailer
        // /Root; a /DSS hidden inside it must classify Invalid, never
        // Absent.
        let mut doc = Document::with_version("1.4");
        let mut dss = lopdf::Dictionary::new();
        dss.set("Type", Object::Name(b"DSS".to_vec()));
        let mut catalog = lopdf::Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        catalog.set("DSS", Object::Dictionary(dss));
        doc.trailer.set("Root", Object::Dictionary(catalog));
        let checks = dss_check(&doc, &[]);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_no_trailer_root_stays_absent() {
        // A genuinely DSS-free document (no trailer /Root at all) keeps the
        // AbsentAllowed classification.
        let doc = Document::with_version("1.4");
        let checks = dss_check(&doc, &[]);
        assert_eq!(
            dss_finding(&checks),
            (VerifyCheckStatus::AbsentAllowed, None)
        );
    }

    // --- botfix3a gates: signer-leaf KU, CRL scope, OCSP delegate/producedAt,

    // --- tsp content-type, covered-on-valid-only ------------------------------

    pub(crate) fn anchors_of(ca: &TestCa) -> Vec<pkix_chain::TrustAnchor> {
        vec![pkix_chain::TrustAnchor::from_cert(ca.cert.clone())]
    }

    #[test]
    fn signer_leaf_key_encipherment_only_fails_certificate_path() {
        let ca = test_ca("ku-ca");
        let leaf = leaf_with_ku(
            &ca,
            "ku-leaf",
            vec![rcgen::KeyUsagePurpose::KeyEncipherment],
        );
        assert!(
            validate_chain(&[leaf], &anchors_of(&ca), AT_UNIX).is_err(),
            "a keyEncipherment-only leaf must not pass as a signing identity"
        );
    }

    #[test]
    fn signer_leaf_digital_signature_or_absent_ku_passes() {
        let ca = test_ca("ku-ca");
        let ds = leaf_with_ku(
            &ca,
            "ds-leaf",
            vec![rcgen::KeyUsagePurpose::DigitalSignature],
        );
        assert!(validate_chain(&[ds], &anchors_of(&ca), AT_UNIX).is_ok());
        let cc = leaf_with_ku(
            &ca,
            "cc-leaf",
            vec![rcgen::KeyUsagePurpose::ContentCommitment],
        );
        assert!(validate_chain(&[cc], &anchors_of(&ca), AT_UNIX).is_ok());
        // No KeyUsage extension at all: RFC 5280-unconstrained, permitted.
        let bare = leaf_with_ku(&ca, "bare-leaf", Vec::new());
        assert!(validate_chain(&[bare], &anchors_of(&ca), AT_UNIX).is_ok());
    }

    fn crl_ext(oid: &str, value_der: Vec<u8>) -> x509_cert::ext::Extension {
        x509_cert::ext::Extension {
            extn_id: der::asn1::ObjectIdentifier::new_unwrap(oid),
            critical: false,
            extn_value: der::asn1::OctetString::new(value_der).unwrap(),
        }
    }

    #[test]
    fn dss_delta_crl_is_not_revocation_evidence() {
        // deltaCRLIndicator (2.5.29.46): changes since a base, fail-closed.
        let ca = test_ca("dss-ca");
        let delta_ext = crl_ext(
            "2.5.29.46",
            der::asn1::Int::new(&[1]).unwrap().to_der().unwrap(),
        );
        let crl = build_crl_ext(
            &ca,
            AT_UNIX - 3600,
            Some(AT_UNIX + 3600),
            None,
            vec![],
            vec![delta_ext],
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[crl], &[]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_idp_scoped_crl_is_not_revocation_evidence() {
        // IssuingDistributionPoint (2.5.29.28): subset coverage, fail-closed.
        let ca = test_ca("dss-ca");
        let idp_ext = crl_ext("2.5.29.28", vec![0x30, 0x00]);
        let crl = build_crl_ext(
            &ca,
            AT_UNIX - 3600,
            Some(AT_UNIX + 3600),
            None,
            vec![],
            vec![idp_ext],
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[crl], &[]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_ocsp_future_produced_at_fails() {
        // producedAt one day beyond the applicable time: not plausible
        // evidence (skew tolerance is 300s).
        let ca = test_ca("dss-ca");
        let ocsp = build_ocsp_full(
            &ca,
            ca.cert.tbs_certificate.serial_number.clone(),
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
            AT_UNIX + 86_400,
            &ca,
            false,
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[], &[ocsp]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
        // The same response produced AT the applicable time passes.
        let ok = build_ocsp_full(
            &ca,
            ca.cert.tbs_certificate.serial_number.clone(),
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
            AT_UNIX,
            &ca,
            false,
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[], &[ok]);
        let checks = dss_check(&doc, &covered_of(&[&ca.cert_der]));
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
    }

    #[test]
    fn dss_ocsp_expired_delegate_response_fails() {
        // Delegate cert expired before the applicable time: its `good`
        // response authorizes nothing.
        let ca = test_ca("dss-ca");
        let delegate = ocsp_delegate(&ca, "ocsp-delegate", (2020, 1, 1), (2021, 1, 1));
        let ocsp = build_ocsp_full(
            &ca,
            ca.cert.tbs_certificate.serial_number.clone(),
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
            AT_UNIX - 60,
            &delegate,
            true,
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[], &[ocsp]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_ocsp_time_valid_delegate_passes() {
        let ca = test_ca("dss-ca");
        let delegate = ocsp_delegate(&ca, "ocsp-delegate", (2020, 1, 1), (2030, 1, 1));
        let ocsp = build_ocsp_full(
            &ca,
            ca.cert.tbs_certificate.serial_number.clone(),
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
            AT_UNIX - 60,
            &delegate,
            true,
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[], &[ocsp]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
    }

    #[test]
    fn dss_ocsp_delegate_crl_sign_only_ku_fails() {
        // botfix7 P2-1: a PRESENT delegate KeyUsage omitting
        // digitalSignature (here: cRLSign-only) is unauthorized even with
        // the OCSPSigning EKU — symmetric with the signer-leaf / CRL-issuer
        // gates. The time-valid delegate with digitalSignature (the control
        // above) still passes.
        let ca = test_ca("dss-ca");
        let delegate = ocsp_delegate_with_kus(
            &ca,
            "ocsp-delegate-nosig",
            (2020, 1, 1),
            (2030, 1, 1),
            vec![rcgen::KeyUsagePurpose::CrlSign],
        );
        let ocsp = build_ocsp_full(
            &ca,
            ca.cert.tbs_certificate.serial_number.clone(),
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
            AT_UNIX - 60,
            &delegate,
            true,
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[], &[ocsp]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_ocsp_delegate_malformed_ku_fails_closed() {
        // botfix8 F2: a delegate whose KeyUsage is PRESENT but whose DER
        // does not decode must be REFUSED, not authorized. The botfix-7
        // shape used `.is_ok_and(|ku| !ku.digital_signature())` inside a
        // negated `any`, so a parse failure collapsed to "no violation
        // found" and the delegate passed. Everything else here is honest —
        // OCSPSigning EKU, time-valid, issued by the CA — so ONLY the
        // unreadable usage restriction can produce the refusal.
        use x509_cert::ext::pkix::KeyUsage;
        let ca = test_ca("dss-ca");
        let delegate = ocsp_delegate_broken_ku(&ca, "ocsp-delegate-broken-ku");
        assert!(
            !key_usage_permits(&delegate.cert, KeyUsage::digital_signature),
            "fixture must present an undecodable KeyUsage"
        );
        let ocsp = build_ocsp_full(
            &ca,
            ca.cert.tbs_certificate.serial_number.clone(),
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
            AT_UNIX - 60,
            &delegate,
            true,
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[], &[ocsp]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn key_usage_turnstile_is_fail_closed_on_every_gate() {
        // The shared turnstile all three KU gates ride: absent extension
        // passes (RFC 5280 §4.2.1.3), present-and-readable defers to the
        // predicate, present-but-undecodable REFUSES. Pinned here so the
        // signer-leaf and CRL-issuer gates cannot silently drift open.
        let ca = test_ca("ku-turnstile-ca");
        let broken = ocsp_delegate_broken_ku(&ca, "broken-ku");
        assert!(
            !key_usage_permits(&broken.cert, |_| true),
            "undecodable KeyUsage must refuse even a permit-everything predicate"
        );
        assert!(
            enforce_signer_leaf_key_usage(&broken.cert).is_err(),
            "signer-leaf gate must reject an undecodable KeyUsage"
        );
        assert!(
            !issuer_permits_crl_sign(&broken.cert),
            "CRL-issuer gate must reject an undecodable KeyUsage"
        );
        // Absent KeyUsage: unconstrained key, so the turnstile passes
        // WITHOUT consulting the predicate (here: a predicate that would
        // refuse everything it saw).
        let no_ku = ocsp_delegate_with_kus(&ca, "no-ku", (2020, 1, 1), (2030, 1, 1), vec![]);
        assert!(
            no_ku
                .cert
                .tbs_certificate
                .extensions
                .as_ref()
                .is_none_or(|exts| {
                    use const_oid::AssociatedOid;
                    !exts
                        .iter()
                        .any(|e| e.extn_id == x509_cert::ext::pkix::KeyUsage::OID)
                }),
            "fixture must omit KeyUsage entirely"
        );
        assert!(
            key_usage_permits(&no_ku.cert, |_| false),
            "absent KeyUsage passes without consulting the predicate"
        );
    }

    #[test]
    fn tsp_token_without_content_type_attr_is_rejected() {
        // RFC 3161 §2.4.2: signedAttrs must carry content-type id-ct-TSTInfo.
        let tsa = tsa_ca();
        let imprint = [9u8; 32];
        let anchors = anchors_of(&tsa);
        let missing = mint_token_shaped(&tsa, &imprint, AT_UNIX, false);
        assert!(
            tsp::validate_token_for_verify(&missing, &imprint, &anchors).is_err(),
            "a token without the content-type attribute must fail"
        );
        let complete = mint_token_shaped(&tsa, &imprint, AT_UNIX, true);
        assert!(tsp::validate_token_for_verify(&complete, &imprint, &anchors).is_ok());
    }

    #[test]
    fn tsp_v2_token_is_rejected_on_verify_path() {
        // TSTInfo version is enforced on BOTH tsp paths: a v2 token must be
        // rejected by validate_token_for_verify, not only at seal time.
        let tsa = tsa_ca();
        let imprint = [9u8; 32];
        let anchors = anchors_of(&tsa);
        let mut token = mint_token(&tsa, &imprint, AT_UNIX);
        // The TSTInfo body opens `INTEGER 1` (version) immediately followed
        // by the policy OID tag — a byte pattern unique to the eContent.
        let marker = [0x02, 0x01, 0x01, 0x06];
        let pos = token
            .windows(marker.len())
            .position(|w| w == marker)
            .expect("TSTInfo version marker present");
        token[pos + 2] = 0x02; // version := v2
        assert!(
            tsp::validate_token_for_verify(&token, &imprint, &anchors).is_err(),
            "a non-v1 TSTInfo must fail the verify path"
        );
    }

    #[test]
    fn tsp_digest_algs_surface_checked_on_both_paths() {
        // The SignedData digestAlgorithms SET is policy surface: an extra
        // weak entry must fail the verify path AND the response path, not
        // just the CAdES envelope gate.
        let tsa = tsa_ca();
        let imprint = [9u8; 32];
        let nonce = [7u8; 16];
        let anchors = anchors_of(&tsa);
        let wrap_granted = |token: &[u8]| {
            let mut body = cms::tlv(0x30, &cms::tlv(0x02, &[0]));
            body.extend_from_slice(token);
            cms::tlv(0x30, &body)
        };
        let weak = mint_token_custom(&tsa, &imprint, AT_UNIX, true, Some(nonce), true);
        assert!(
            tsp::validate_token_for_verify(&weak, &imprint, &anchors).is_err(),
            "extra weak digest alg must fail the verify path"
        );
        assert!(
            tsp::validate_response(
                &wrap_granted(&weak),
                &imprint,
                &nonce,
                None,
                &anchors,
                AT_UNIX * 1000,
            )
            .is_err(),
            "extra weak digest alg must fail the response path"
        );
        let clean = mint_token_custom(&tsa, &imprint, AT_UNIX, true, Some(nonce), false);
        assert!(tsp::validate_token_for_verify(&clean, &imprint, &anchors).is_ok());
        assert!(
            tsp::validate_response(
                &wrap_granted(&clean),
                &imprint,
                &nonce,
                None,
                &anchors,
                AT_UNIX * 1000,
            )
            .is_ok()
        );
    }
}
