//! Verifier tests A: rcgen fixtures, CRL/OCSP builders, DSS harness and first DSS revocation tests.

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used)]
    use const_oid::AssociatedOid;
    use der::{Decode, Encode};
    use lopdf::{Document, Object, Stream};

    use super::super::super::cms;
    use super::super::verify_dss_core::verify_dss;
    use super::super::verify_sig_pipeline::Checks;
    use super::super::*;
    use crate::api::{VerifyCheckKind, VerifyCheckStatus, VerifyFindingCode};

    /// 2026-07-30T08:00:00Z — the applicable verification time.
    pub(crate) const AT_UNIX: u64 = 1_785_398_400;

    pub(crate) struct TestCa {
        pub(crate) cert_der: Vec<u8>,
        pub(crate) cert: x509_cert::Certificate,
        pub(crate) key: p256::ecdsa::SigningKey,
        pub(crate) rcgen_params: rcgen::CertificateParams,
        pub(crate) rcgen_key: rcgen::KeyPair,
    }

    pub(crate) fn test_ca(cn: &str) -> TestCa {
        ca_with_kus(
            cn,
            vec![
                rcgen::KeyUsagePurpose::DigitalSignature,
                rcgen::KeyUsagePurpose::CrlSign,
            ],
        )
    }

    /// A self-signed CA-shaped identity with caller-chosen KeyUsage purposes.
    pub(crate) fn ca_with_kus(cn: &str, kus: Vec<rcgen::KeyUsagePurpose>) -> TestCa {
        use p256::pkcs8::DecodePrivateKey;
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn.to_string());
        params.key_usages = kus;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let key = p256::ecdsa::SigningKey::from_pkcs8_der(&key_pair.serialize_der()).unwrap();
        let cert = x509_cert::Certificate::from_der(&cert_der).unwrap();
        TestCa {
            cert_der,
            cert,
            key,
            rcgen_params: params,
            rcgen_key: key_pair,
        }
    }

    /// A leaf certificate issued by `ca` (fresh key pair, DER only).
    pub(crate) fn leaf_under(ca: &TestCa, cn: &str) -> Vec<u8> {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn.to_string());
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let issuer = rcgen::Issuer::from_params(&ca.rcgen_params, &ca.rcgen_key);
        params.signed_by(&key_pair, &issuer).unwrap().der().to_vec()
    }

    /// A leaf under `ca` with a caller-chosen serial number.
    pub(crate) fn leaf_with_serial(ca: &TestCa, cn: &str, serial: u64) -> Vec<u8> {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn.to_string());
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.serial_number = Some(rcgen::SerialNumber::from(serial));
        let issuer = rcgen::Issuer::from_params(&ca.rcgen_params, &ca.rcgen_key);
        params.signed_by(&key_pair, &issuer).unwrap().der().to_vec()
    }

    /// A leaf under `ca` with caller-chosen KeyUsage purposes (empty = no
    /// KeyUsage extension).
    pub(crate) fn leaf_with_ku(ca: &TestCa, cn: &str, kus: Vec<rcgen::KeyUsagePurpose>) -> Vec<u8> {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn.to_string());
        params.key_usages = kus;
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        let issuer = rcgen::Issuer::from_params(&ca.rcgen_params, &ca.rcgen_key);
        params.signed_by(&key_pair, &issuer).unwrap().der().to_vec()
    }

    /// An OCSP delegate certificate issued by `issuer`: digitalSignature KU,
    /// id-kp-OCSPSigning EKU, caller-chosen validity window.
    pub(crate) fn ocsp_delegate(
        issuer: &TestCa,
        cn: &str,
        not_before: (i32, u8, u8),
        not_after: (i32, u8, u8),
    ) -> TestCa {
        ocsp_delegate_with_kus(
            issuer,
            cn,
            not_before,
            not_after,
            vec![rcgen::KeyUsagePurpose::DigitalSignature],
        )
    }

    /// `ocsp_delegate` with caller-chosen KeyUsage purposes.
    pub(crate) fn ocsp_delegate_with_kus(
        issuer: &TestCa,
        cn: &str,
        not_before: (i32, u8, u8),
        not_after: (i32, u8, u8),
        kus: Vec<rcgen::KeyUsagePurpose>,
    ) -> TestCa {
        use p256::pkcs8::DecodePrivateKey;
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn.to_string());
        params.key_usages = kus;
        params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        let eku = cms::tlv(
            0x30,
            &cms::oid_tlv(&der::asn1::ObjectIdentifier::new_unwrap(
                "1.3.6.1.5.5.7.3.9",
            )),
        );
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[2, 5, 29, 37],
                eku,
            ));
        let issuer_rc = rcgen::Issuer::from_params(&issuer.rcgen_params, &issuer.rcgen_key);
        let cert = params.signed_by(&key_pair, &issuer_rc).unwrap();
        let cert_der = cert.der().to_vec();
        let key = p256::ecdsa::SigningKey::from_pkcs8_der(&key_pair.serialize_der()).unwrap();
        let cert = x509_cert::Certificate::from_der(&cert_der).unwrap();
        TestCa {
            cert_der,
            cert,
            key,
            rcgen_params: params,
            rcgen_key: key_pair,
        }
    }

    /// An OCSP delegate whose KeyUsage extension is PRESENT but carries DER
    /// that does not decode as a KeyUsage BIT STRING. Everything else about
    /// the delegate is honest: OCSPSigning EKU, time-valid, issued by
    /// `issuer`. rcgen's `key_usages` always emits well-formed DER, so the
    /// extension is injected raw.
    pub(crate) fn ocsp_delegate_broken_ku(issuer: &TestCa, cn: &str) -> TestCa {
        use p256::pkcs8::DecodePrivateKey;
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn.to_string());
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 1, 1);
        let eku = cms::tlv(
            0x30,
            &cms::oid_tlv(&der::asn1::ObjectIdentifier::new_unwrap(
                "1.3.6.1.5.5.7.3.9",
            )),
        );
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[2, 5, 29, 37],
                eku,
            ));
        // KeyUsage (2.5.29.15) whose value is an OCTET STRING, not the
        // BIT STRING the type requires: present, unreadable.
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[2, 5, 29, 15],
                cms::tlv(0x04, &[0x07, 0x80]),
            ));
        let issuer_rc = rcgen::Issuer::from_params(&issuer.rcgen_params, &issuer.rcgen_key);
        let cert = params.signed_by(&key_pair, &issuer_rc).unwrap();
        let cert_der = cert.der().to_vec();
        let key = p256::ecdsa::SigningKey::from_pkcs8_der(&key_pair.serialize_der()).unwrap();
        let cert = x509_cert::Certificate::from_der(&cert_der).unwrap();
        TestCa {
            cert_der,
            cert,
            key,
            rcgen_params: params,
            rcgen_key: key_pair,
        }
    }

    /// An intermediate CA issued by `parent` (fresh key pair).
    pub(crate) fn child_ca(parent: &TestCa, cn: &str) -> TestCa {
        use p256::pkcs8::DecodePrivateKey;
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn.to_string());
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let issuer = rcgen::Issuer::from_params(&parent.rcgen_params, &parent.rcgen_key);
        let cert = params.signed_by(&key_pair, &issuer).unwrap();
        let cert_der = cert.der().to_vec();
        let key = p256::ecdsa::SigningKey::from_pkcs8_der(&key_pair.serialize_der()).unwrap();
        let cert = x509_cert::Certificate::from_der(&cert_der).unwrap();
        TestCa {
            cert_der,
            cert,
            key,
            rcgen_params: params,
            rcgen_key: key_pair,
        }
    }

    pub(crate) fn sign_p256(key: &p256::ecdsa::SigningKey, data: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use sha2::Digest;
        let digest = sha2::Sha256::digest(data);
        let sig: p256::ecdsa::Signature = key.sign_prehash(&digest).unwrap();
        sig.to_der().as_bytes().to_vec()
    }

    fn ecdsa_alg() -> spki::AlgorithmIdentifierOwned {
        spki::AlgorithmIdentifierOwned {
            oid: cms::OID_ECDSA_SHA256,
            parameters: None,
        }
    }

    pub(crate) fn gt(secs: u64) -> der::asn1::GeneralizedTime {
        der::asn1::GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(secs))
            .unwrap()
    }

    fn x509_time(secs: u64) -> x509_cert::time::Time {
        x509_cert::time::Time::GeneralTime(gt(secs))
    }

    pub(crate) fn build_crl(
        ca: &TestCa,
        this: u64,
        next: Option<u64>,
        sign_with: Option<&p256::ecdsa::SigningKey>,
        revoked: Vec<x509_cert::serial_number::SerialNumber>,
    ) -> Vec<u8> {
        build_crl_ext(ca, this, next, sign_with, revoked, Vec::new())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_crl_ext(
        ca: &TestCa,
        this: u64,
        next: Option<u64>,
        sign_with: Option<&p256::ecdsa::SigningKey>,
        revoked: Vec<x509_cert::serial_number::SerialNumber>,
        crl_extensions: Vec<x509_cert::ext::Extension>,
    ) -> Vec<u8> {
        let alg = ecdsa_alg();
        let revoked_certificates = if revoked.is_empty() {
            None
        } else {
            Some(
                revoked
                    .into_iter()
                    .map(|serial_number| x509_cert::crl::RevokedCert {
                        serial_number,
                        revocation_date: x509_time(this),
                        crl_entry_extensions: None,
                    })
                    .collect(),
            )
        };
        let tbs = x509_cert::crl::TbsCertList {
            version: x509_cert::Version::V2,
            signature: alg.clone(),
            issuer: ca.cert.tbs_certificate.subject.clone(),
            this_update: x509_time(this),
            next_update: next.map(x509_time),
            revoked_certificates,
            crl_extensions: if crl_extensions.is_empty() {
                None
            } else {
                Some(crl_extensions)
            },
        };
        let tbs_der = tbs.to_der().unwrap();
        let sig = sign_p256(sign_with.unwrap_or(&ca.key), &tbs_der);
        x509_cert::crl::CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: alg,
            signature: der::asn1::BitString::from_bytes(&sig).unwrap(),
        }
        .to_der()
        .unwrap()
    }

    pub(crate) fn build_ocsp(
        ca: &TestCa,
        serial: x509_cert::serial_number::SerialNumber,
        this: u64,
        next: Option<u64>,
        status: x509_ocsp::CertStatus,
    ) -> Vec<u8> {
        build_ocsp_full(ca, serial, this, next, status, this, ca, false)
    }

    /// Full OCSP fixture: CertID hashes against `id_ca` (the target's
    /// issuer), response signed by `responder` with responderID =
    /// responder's subject, `produced_at` as given, and the responder
    /// certificate embedded when `embed_responder` (the delegate shape).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_ocsp_full(
        id_ca: &TestCa,
        serial: x509_cert::serial_number::SerialNumber,
        this: u64,
        next: Option<u64>,
        status: x509_ocsp::CertStatus,
        produced_at: u64,
        responder: &TestCa,
        embed_responder: bool,
    ) -> Vec<u8> {
        use sha1::Digest;
        let subject_der = id_ca.cert.tbs_certificate.subject.to_der().unwrap();
        let key_bytes = id_ca
            .cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        let cert_id = x509_ocsp::CertId {
            hash_algorithm: spki::AlgorithmIdentifierOwned {
                oid: der::asn1::ObjectIdentifier::new_unwrap("1.3.14.3.2.26"),
                parameters: Some(der::asn1::Null.into()),
            },
            issuer_name_hash: der::asn1::OctetString::new(
                sha1::Sha1::digest(&subject_der).to_vec(),
            )
            .unwrap(),
            issuer_key_hash: der::asn1::OctetString::new(sha1::Sha1::digest(key_bytes).to_vec())
                .unwrap(),
            serial_number: serial,
        };
        let single = x509_ocsp::SingleResponse {
            cert_id,
            cert_status: status,
            this_update: x509_ocsp::OcspGeneralizedTime(gt(this)),
            next_update: next.map(|n| x509_ocsp::OcspGeneralizedTime(gt(n))),
            single_extensions: None,
        };
        let data = x509_ocsp::ResponseData {
            version: Default::default(),
            responder_id: x509_ocsp::ResponderId::ByName(
                responder.cert.tbs_certificate.subject.clone(),
            ),
            produced_at: x509_ocsp::OcspGeneralizedTime(gt(produced_at)),
            responses: vec![single],
            response_extensions: None,
        };
        let tbs_der = data.to_der().unwrap();
        let sig = sign_p256(&responder.key, &tbs_der);
        let basic = x509_ocsp::BasicOcspResponse {
            tbs_response_data: data,
            signature_algorithm: ecdsa_alg(),
            signature: der::asn1::BitString::from_bytes(&sig).unwrap(),
            certs: if embed_responder {
                Some(vec![responder.cert.clone()])
            } else {
                None
            },
        };
        let basic_der = basic.to_der().unwrap();
        x509_ocsp::OcspResponse {
            response_status: x509_ocsp::OcspResponseStatus::Successful,
            response_bytes: Some(x509_ocsp::ResponseBytes {
                response_type: x509_ocsp::BasicOcspResponse::OID,
                response: der::asn1::OctetString::new(basic_der).unwrap(),
            }),
        }
        .to_der()
        .unwrap()
    }

    /// In-memory document carrying a catalog `/DSS` with the given global
    /// arrays (empty arrays are omitted).
    pub(crate) fn dss_doc(certs: &[Vec<u8>], crls: &[Vec<u8>], ocsps: &[Vec<u8>]) -> Document {
        let mut doc = Document::with_version("1.4");
        let mut dss = lopdf::Dictionary::new();
        dss.set("Type", Object::Name(b"DSS".to_vec()));
        for (key, items) in [("Certs", certs), ("CRLs", crls), ("OCSPs", ocsps)] {
            if items.is_empty() {
                continue;
            }
            let refs: Vec<Object> = items
                .iter()
                .map(|d| {
                    let s = Stream::new(lopdf::Dictionary::new(), d.clone());
                    Object::Reference(doc.add_object(Object::Stream(s)))
                })
                .collect();
            dss.set(key, Object::Array(refs));
        }
        let dss_id = doc.add_object(Object::Dictionary(dss));
        let mut catalog = lopdf::Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        catalog.set("DSS", Object::Reference(dss_id));
        let cat_id = doc.add_object(Object::Dictionary(catalog));
        doc.trailer.set("Root", Object::Reference(cat_id));
        doc
    }

    pub(crate) fn dss_check(doc: &Document, covered: &[EmbeddedCert]) -> Checks {
        let mut checks = Checks::new();
        verify_dss(doc, &[], covered, AT_UNIX, usize::MAX, &mut checks);
        checks
    }

    pub(crate) fn covered_of(ders: &[&[u8]]) -> Vec<EmbeddedCert> {
        ders.iter()
            .map(|d| EmbeddedCert::from_der(d).unwrap())
            .collect()
    }

    pub(crate) fn dss_finding(checks: &Checks) -> (VerifyCheckStatus, Option<VerifyFindingCode>) {
        let c = checks
            .list
            .iter()
            .find(|c| c.kind == VerifyCheckKind::ValidationMaterial)
            .unwrap();
        (c.status, c.finding)
    }

    pub(crate) fn assert_material_fails(checks: &Checks) {
        assert_eq!(
            dss_finding(checks),
            (
                VerifyCheckStatus::Fail,
                Some(VerifyFindingCode::ValidationMaterialInvalid)
            )
        );
    }

    #[test]
    fn dss_valid_crl_and_ocsp_pass() {
        let ca = test_ca("dss-ca");
        let crl = build_crl(&ca, AT_UNIX - 3600, Some(AT_UNIX + 3600), None, vec![]);
        let ocsp = build_ocsp(
            &ca,
            ca.cert.tbs_certificate.serial_number.clone(),
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[crl], &[ocsp]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
    }

    #[test]
    fn dss_empty_dss_is_evidence_free_and_fails() {
        // /DSS present with /Certs, /CRLs, /OCSPs all absent must not
        // inflate a B-T document into B-LT.
        let doc = dss_doc(&[], &[], &[]);
        let checks = dss_check(&doc, &[]);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_unrelated_certs_fail_binding() {
        // Authenticated material about unrelated self-signed /Certs must not
        // authenticate the document's covered signer chain.
        let dss_ca = test_ca("dss-ca");
        let signer = test_ca("signer-ca");
        let crl = build_crl(&dss_ca, AT_UNIX - 3600, Some(AT_UNIX + 3600), None, vec![]);
        let doc = dss_doc(std::slice::from_ref(&dss_ca.cert_der), &[crl], &[]);
        let covered = covered_of(&[&signer.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_anchor_only_binding_passes() {
        // A covered certificate that is a trust anchor satisfies the binding
        // without appearing in /Certs.
        let ca = test_ca("dss-ca");
        let crl = build_crl(&ca, AT_UNIX - 3600, Some(AT_UNIX + 3600), None, vec![]);
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[crl], &[]);
        let anchor = EmbeddedCert::from_der(&ca.cert_der).unwrap();
        let covered = covered_of(&[&ca.cert_der]);
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
    fn dss_crl_bad_signature_fails_validation_material() {
        let ca = test_ca("dss-ca");
        let other = test_ca("dss-other");
        let crl = build_crl(
            &ca,
            AT_UNIX - 3600,
            Some(AT_UNIX + 3600),
            Some(&other.key),
            vec![],
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[crl], &[]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_crl_stale_next_update_fails_never_absent() {
        let ca = test_ca("dss-ca");
        let crl = build_crl(&ca, AT_UNIX - 7200, Some(AT_UNIX - 60), None, vec![]);
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[crl], &[]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_crl_listing_in_scope_serial_fails() {
        // A covered leaf revoked by its CA's CRL: the evidence asserts a
        // revocation and can never support validity.
        let ca = test_ca("dss-ca");
        let leaf_der = leaf_under(&ca, "leaf");
        let leaf = x509_cert::Certificate::from_der(&leaf_der).unwrap();
        let crl = build_crl(
            &ca,
            AT_UNIX - 3600,
            Some(AT_UNIX + 3600),
            None,
            vec![leaf.tbs_certificate.serial_number],
        );
        let doc = dss_doc(&[ca.cert_der.clone(), leaf_der.clone()], &[crl], &[]);
        let covered = covered_of(&[&ca.cert_der, &leaf_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_crl_listing_out_of_scope_serial_passes() {
        // A revoked serial that matches no validation-set certificate does
        // not invalidate the evidence.
        let ca = test_ca("dss-ca");
        let stranger = x509_cert::serial_number::SerialNumber::new(&[0x11, 0x22, 0x33]).unwrap();
        let crl = build_crl(
            &ca,
            AT_UNIX - 3600,
            Some(AT_UNIX + 3600),
            None,
            vec![stranger],
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[crl], &[]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
    }

    #[test]
    fn dss_ocsp_unbound_serial_fails() {
        let ca = test_ca("dss-ca");
        let serial = x509_cert::serial_number::SerialNumber::new(&[0x7f, 0x7f, 0x01]).unwrap();
        let ocsp = build_ocsp(
            &ca,
            serial,
            AT_UNIX - 60,
            None,
            x509_ocsp::CertStatus::good(),
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[], &[ocsp]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_ocsp_stale_next_update_fails() {
        let ca = test_ca("dss-ca");
        let ocsp = build_ocsp(
            &ca,
            ca.cert.tbs_certificate.serial_number.clone(),
            AT_UNIX - 7200,
            Some(AT_UNIX - 60),
            x509_ocsp::CertStatus::good(),
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[], &[ocsp]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_ocsp_revoked_status_fails() {
        let ca = test_ca("dss-ca");
        let ocsp = build_ocsp(
            &ca,
            ca.cert.tbs_certificate.serial_number.clone(),
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::revoked(x509_ocsp::RevokedInfo {
                revocation_time: x509_ocsp::OcspGeneralizedTime(gt(AT_UNIX - 120)),
                revocation_reason: None,
            }),
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[], &[ocsp]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_ocsp_unknown_status_fails_closed() {
        // The blueprint leaves `unknown` unpinned (§7.5/§7.7): fail closed.
        let ca = test_ca("dss-ca");
        let ocsp = build_ocsp(
            &ca,
            ca.cert.tbs_certificate.serial_number.clone(),
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::unknown(),
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[], &[ocsp]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }
}
