//! Verifier tests: how presented DSS material that is not usable reports
//! (lead ruling F, SEAL-SHADOW-ETSI, 10 Nov 06:50; Engine reading 07:02 and
//! call Q-A = C, 07:07). Anyone holding a signed PDF can append a DSS
//! without breaking its signatures, so such material never turns the verdict
//! into failed:
//! - forged or unverifiable material is discarded and, where the result
//!   would otherwise be unresolved, reports NotRun with the visible
//!   sub-indication ValidationMaterialPossibleTampering;
//! - material that claims nothing about the signer's certificates is
//!   missing coverage, NotRun with ValidationMaterialUnavailable; so is a
//!   genuine negative claim (stale, scoped, revoked, produced later) about
//!   anything outside the covered chains (Engine call Q-C = A, 07:23);
//! - a broken DSS never takes away the B-B or B-T profile the signature
//!   earned (Engine call Q-D = A, 07:23).
//!
//! Genuine stale, revoked or out-of-scope material about the covered chains
//! still fails; its tests are in verify_tests_fixtures_dss_a.rs and
//! verify_tests_dss_b.rs.

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use der::Decode;
    use lopdf::{Dictionary, Document, Object, Stream};

    use super::super::verify_tests_fixtures_dss_a::tests::*;
    use super::super::verify_tests_lta_probes::tests::base_input;
    use super::super::verify_tests_time_lta_a::tests::{
        VERIFY_SECS, append_dss_revision, append_sig_revision, tsa_ca, verify_engine,
    };
    use crate::api::{PadesProfile, VerifyCheckKind, VerifyCheckStatus, VerifyFindingCode};

    const THIS_UPDATE: u64 = AT_UNIX - 3600;
    const NEXT_UPDATE: Option<u64> = Some(AT_UNIX + 3600);

    /// A document whose catalog /DSS is what `build` makes on it (so the
    /// DSS can reference streams `build` adds).
    fn doc_with_dss(build: impl FnOnce(&mut Document) -> Object) -> Document {
        let mut doc = Document::with_version("1.4");
        let dss = build(&mut doc);
        let dss_id = doc.add_object(dss);
        let mut catalog = Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        catalog.set("DSS", Object::Reference(dss_id));
        let catalog_id = doc.add_object(Object::Dictionary(catalog));
        doc.trailer.set("Root", Object::Reference(catalog_id));
        doc
    }

    /// An array of references to one stream per item, added to `doc`.
    fn stream_array(doc: &mut Document, items: &[Vec<u8>]) -> Object {
        Object::Array(
            items
                .iter()
                .map(|item| {
                    let stream = Stream::new(Dictionary::new(), item.clone());
                    Object::Reference(doc.add_object(Object::Stream(stream)))
                })
                .collect(),
        )
    }

    /// A DSS dictionary with `entries`.
    fn dss_dict(entries: Vec<(&str, Object)>) -> Object {
        let mut dss = Dictionary::new();
        dss.set("Type", Object::Name(b"DSS".to_vec()));
        for (key, value) in entries {
            dss.set(key, value);
        }
        Object::Dictionary(dss)
    }

    #[test]
    fn dss_unusable_presented_material_never_fails_the_verdict() {
        // Hostile input, one row per shape. Each row's covered certificate
        // has no anchor, and the row's material is the only evidence about
        // it, so the result would otherwise be unresolved.
        let ca = test_ca("dss-ca");
        let other = test_ca("dss-other");
        let unrelated = test_ca("unrelated-ca");
        // A leaf its CA issued, and an attacker's self-signed certificate
        // with the CA's subject (a shadow).
        let leaf_ca = test_ca("issuer");
        let leaf_der = leaf_under(&leaf_ca, "leaf");
        let leaf = x509_cert::Certificate::from_der(&leaf_der).unwrap();
        let shadow = test_ca("issuer");
        let no_crl_sign = ca_with_kus("no-crlsign", vec![rcgen::KeyUsagePurpose::DigitalSignature]);
        let delegate = ocsp_delegate_with_kus(
            &ca,
            "ocsp-delegate-nosig",
            (2020, 1, 1),
            (2030, 1, 1),
            vec![rcgen::KeyUsagePurpose::CrlSign],
        );
        let good = |responder: &TestCa, embed: bool| {
            build_ocsp_full(
                &ca,
                ca.cert.tbs_certificate.serial_number.clone(),
                AT_UNIX - 60,
                NEXT_UPDATE,
                x509_ocsp::CertStatus::good(),
                AT_UNIX - 60,
                responder,
                embed,
            )
        };
        let mut bad_signature_ocsp = good(&ca, false);
        *bad_signature_ocsp.last_mut().unwrap() ^= 0x01;
        let unbound_ocsp = build_ocsp(
            &ca,
            x509_cert::serial_number::SerialNumber::new(&[0x7f, 0x7f, 0x01]).unwrap(),
            AT_UNIX - 60,
            NEXT_UPDATE,
            x509_ocsp::CertStatus::good(),
        );
        // OCSPResponse { responseStatus tryLater }: no response bytes.
        let unsuccessful_ocsp = vec![0x30, 0x03, 0x0a, 0x01, 0x03];
        // Genuine negative claims about nothing in the covered chains
        // (Engine call Q-C = A): an unrelated CA's stale CRL, an attacker
        // certificate revoking itself in its own CRL, and an attacker CA's
        // responder saying no about an extra certificate it issued.
        let stale_crl =
            |signer: &TestCa| build_crl(signer, AT_UNIX - 7200, Some(AT_UNIX - 60), None, vec![]);
        let attacker = test_ca("attacker");
        let self_revoking_crl = build_crl(
            &attacker,
            THIS_UPDATE,
            NEXT_UPDATE,
            None,
            vec![attacker.cert.tbs_certificate.serial_number.clone()],
        );
        let attacker_ca = test_ca("attacker-ca");
        let extra_der = leaf_under(&attacker_ca, "extra");
        let extra = x509_cert::Certificate::from_der(&extra_der).unwrap();
        let attacker_certs = vec![
            ca.cert_der.clone(),
            attacker_ca.cert_der.clone(),
            extra_der.clone(),
        ];
        let about_extra = |this: u64, next: Option<u64>, status, produced_at| {
            build_ocsp_full(
                &attacker_ca,
                extra.tbs_certificate.serial_number.clone(),
                this,
                next,
                status,
                produced_at,
                &attacker_ca,
                false,
            )
        };
        let revoked_status = || {
            x509_ocsp::CertStatus::revoked(x509_ocsp::RevokedInfo {
                revocation_time: x509_ocsp::OcspGeneralizedTime(gt(AT_UNIX - 120)),
                revocation_reason: None,
            })
        };
        let certs = vec![ca.cert_der.clone()];
        let tampering = VerifyFindingCode::ValidationMaterialPossibleTampering;
        let missing = VerifyFindingCode::ValidationMaterialUnavailable;
        let rows: Vec<(&str, Document, Vec<u8>, VerifyFindingCode)> = vec![
            (
                "CRL whose signature no claimed issuer's key verifies",
                dss_doc(
                    &certs,
                    &[build_crl(
                        &ca,
                        THIS_UPDATE,
                        NEXT_UPDATE,
                        Some(&other.key),
                        vec![],
                    )],
                    &[],
                ),
                ca.cert_der.clone(),
                tampering,
            ),
            (
                "CRL signed by an issuer whose key usage lacks cRLSign",
                dss_doc(
                    std::slice::from_ref(&no_crl_sign.cert_der),
                    &[build_crl(
                        &no_crl_sign,
                        THIS_UPDATE,
                        NEXT_UPDATE,
                        None,
                        vec![],
                    )],
                    &[],
                ),
                no_crl_sign.cert_der.clone(),
                tampering,
            ),
            (
                "CRL entry that does not parse",
                dss_doc(&certs, &[b"not a CRL".to_vec()], &[]),
                ca.cert_der.clone(),
                tampering,
            ),
            (
                "OCSP response whose signature does not verify",
                dss_doc(&certs, &[], &[bad_signature_ocsp]),
                ca.cert_der.clone(),
                tampering,
            ),
            (
                "OCSP response signed by a responder nobody presents",
                dss_doc(&certs, &[], &[good(&other, false)]),
                ca.cert_der.clone(),
                tampering,
            ),
            (
                "OCSP CertID bound to no validation-set certificate",
                dss_doc(&certs, &[], &[unbound_ocsp]),
                ca.cert_der.clone(),
                tampering,
            ),
            (
                "OCSP delegate whose key usage lacks digitalSignature",
                dss_doc(&certs, &[], &[good(&delegate, true)]),
                ca.cert_der.clone(),
                tampering,
            ),
            (
                "unsuccessful OCSP response",
                dss_doc(&certs, &[], &[unsuccessful_ocsp]),
                ca.cert_der.clone(),
                tampering,
            ),
            (
                "shadow CRL listing the covered leaf's serial as revoked",
                dss_doc(
                    &[leaf_der.clone(), shadow.cert_der.clone()],
                    &[build_crl(
                        &shadow,
                        THIS_UPDATE,
                        NEXT_UPDATE,
                        None,
                        vec![leaf.tbs_certificate.serial_number.clone()],
                    )],
                    &[],
                ),
                leaf_der.clone(),
                tampering,
            ),
            (
                "shadow's stale CRL",
                dss_doc(
                    &[leaf_der.clone(), shadow.cert_der.clone()],
                    &[stale_crl(&shadow)],
                    &[],
                ),
                leaf_der.clone(),
                tampering,
            ),
            (
                "/Certs entry that does not parse",
                dss_doc(
                    &[ca.cert_der.clone(), b"not a certificate".to_vec()],
                    &[],
                    &[],
                ),
                ca.cert_der.clone(),
                tampering,
            ),
            (
                "/CRLs that is not an array",
                doc_with_dss(|doc| {
                    let certs = stream_array(doc, &certs);
                    dss_dict(vec![("Certs", certs), ("CRLs", Object::Integer(1))])
                }),
                ca.cert_der.clone(),
                tampering,
            ),
            (
                "/DSS that is not a dictionary",
                doc_with_dss(|_| Object::Integer(1)),
                ca.cert_der.clone(),
                tampering,
            ),
            (
                "DSS with no arrays",
                doc_with_dss(|_| dss_dict(vec![])),
                ca.cert_der.clone(),
                missing,
            ),
            (
                "DSS whose only array is present but empty",
                doc_with_dss(|_| dss_dict(vec![("CRLs", Object::Array(vec![]))])),
                ca.cert_der.clone(),
                missing,
            ),
            (
                "unrelated CA's stale CRL",
                dss_doc(
                    &[ca.cert_der.clone(), unrelated.cert_der.clone()],
                    &[stale_crl(&unrelated)],
                    &[],
                ),
                ca.cert_der.clone(),
                missing,
            ),
            (
                "attacker certificate revoking itself in its own CRL",
                dss_doc(
                    &[ca.cert_der.clone(), attacker.cert_der.clone()],
                    &[self_revoking_crl],
                    &[],
                ),
                ca.cert_der.clone(),
                missing,
            ),
            (
                "attacker CA's revoked status for an extra certificate it issued",
                dss_doc(
                    &attacker_certs,
                    &[],
                    &[about_extra(
                        AT_UNIX - 60,
                        NEXT_UPDATE,
                        revoked_status(),
                        AT_UNIX - 60,
                    )],
                ),
                ca.cert_der.clone(),
                missing,
            ),
            (
                "attacker CA's stale status for an extra certificate it issued",
                dss_doc(
                    &attacker_certs,
                    &[],
                    &[about_extra(
                        AT_UNIX - 7200,
                        Some(AT_UNIX - 60),
                        x509_ocsp::CertStatus::good(),
                        AT_UNIX - 7200,
                    )],
                ),
                ca.cert_der.clone(),
                missing,
            ),
            (
                "attacker CA's response about an extra certificate, produced later",
                dss_doc(
                    &attacker_certs,
                    &[],
                    &[about_extra(
                        AT_UNIX - 60,
                        NEXT_UPDATE,
                        x509_ocsp::CertStatus::good(),
                        AT_UNIX + 86_400,
                    )],
                ),
                ca.cert_der.clone(),
                missing,
            ),
            (
                "covered certificate missing from /Certs and the anchors",
                dss_doc(
                    std::slice::from_ref(&unrelated.cert_der),
                    &[build_crl(
                        &unrelated,
                        THIS_UPDATE,
                        NEXT_UPDATE,
                        None,
                        vec![],
                    )],
                    &[],
                ),
                ca.cert_der.clone(),
                missing,
            ),
        ];
        // Every row is judged before the test fails, so a run names each
        // row that differs.
        let mut wrong = Vec::new();
        for (row, doc, covered, finding) in rows {
            let checks = dss_check(&doc, &covered_of(&[&covered]));
            let found = dss_finding(&checks);
            if found != (VerifyCheckStatus::NotRun, Some(finding)) {
                wrong.push(format!("{row}: {found:?}"));
            }
        }
        assert!(wrong.is_empty(), "rows not as ruled: {wrong:#?}");
    }

    #[test]
    fn dss_unverifiable_material_beside_complete_genuine_coverage_passes() {
        // Control: the CA's genuine CRL covers the covered certificate and
        // nothing is unknown, so an unverifiable CRL beside it (signed by a
        // key the CA does not hold) is discarded, and the material passes,
        // as EN 319 102-1 uses only the applicable revocation data.
        let ca = test_ca("dss-ca");
        let other = test_ca("dss-other");
        let genuine = build_crl(&ca, THIS_UPDATE, NEXT_UPDATE, None, vec![]);
        let forged = build_crl(&ca, THIS_UPDATE, NEXT_UPDATE, Some(&other.key), vec![]);
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[forged, genuine], &[]);
        let checks = dss_check(&doc, &covered_of(&[&ca.cert_der]));
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
    }
    #[test]
    fn broken_dss_appended_to_a_baseline_t_document_keeps_baseline_t() {
        // Engine call Q-D = A (10 Nov 07:23): anyone holding the signed PDF
        // can append a DSS, so a broken one leaves validation material
        // NotRun (possible tampering) and denies LT and LTA, but never takes
        // away the B-T profile the signature and its timestamp earned.
        let root = test_ca("bt-root");
        let signer = child_ca(&root, "bt-signer");
        let tsa = tsa_ca();
        let signed = append_sig_revision(&base_input(), &signer, "bt", Some(&tsa), AT_UNIX);
        let anchors = vec![root.cert_der.clone(), tsa.cert_der.clone()];
        let before = verify_engine(anchors.clone(), VERIFY_SECS)
            .verify_sealed_pdf(&signed)
            .unwrap();
        assert_eq!(before.signatures[0].profile, Some(PadesProfile::BaselineT));
        let attacked = append_dss_revision(
            &signed,
            vec![signer.cert_der.clone()],
            vec![b"not a CRL".to_vec()],
        );
        let report = verify_engine(anchors, VERIFY_SECS)
            .verify_sealed_pdf(&attacked)
            .unwrap();
        let material = report
            .checks()
            .find(|c| c.kind == VerifyCheckKind::ValidationMaterial)
            .unwrap();
        assert_eq!(
            (material.status, material.finding),
            (
                VerifyCheckStatus::NotRun,
                Some(VerifyFindingCode::ValidationMaterialPossibleTampering)
            )
        );
        assert_eq!(report.signatures[0].profile, Some(PadesProfile::BaselineT));
    }
}
