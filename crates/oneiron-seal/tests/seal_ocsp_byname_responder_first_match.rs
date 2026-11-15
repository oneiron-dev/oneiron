#![cfg(all(feature = "native", oneiron_test_support))]
#![allow(clippy::unwrap_used)]
//! [SEAL-OCSP-BYNAME-RESPONDER-FIRST-MATCH] (FIX-LIST line 22803): a ByName
//! OCSP responder used to be the first DSS/anchor certificate whose NAME
//! matched, so a same-subject shadow filed ahead of the genuine responder
//! failed a genuine response with Unverifiable, and reordering /Certs
//! changed the verdict. Each name match is now tried in turn; the responder
//! is the first match that is authorized and whose key verifies the
//! response.
//!
//! The door `oneiron_seal::test_doors::ocsp_entry_good_targets` runs the DSS
//! OCSP entry validator over caller bytes and reports the DER of every
//! target it covers good, or why the entry was rejected.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-seal --all-features --test seal_ocsp_byname_responder_first_match`.

use const_oid::AssociatedOid;
use der::{Decode, Encode};
use oneiron_seal::test_doors::ocsp_entry_good_targets;

/// 2026-07-30T08:00:00Z — the applicable verification time.
const AT_UNIX: u64 = 1_785_398_400;

struct TestCa {
    cert_der: Vec<u8>,
    cert: x509_cert::Certificate,
    key: p256::ecdsa::SigningKey,
    rcgen_params: rcgen::CertificateParams,
    rcgen_key: rcgen::KeyPair,
}

fn test_ca(cn: &str) -> TestCa {
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
fn leaf_under(ca: &TestCa, cn: &str) -> Vec<u8> {
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

fn serial_of(der: &[u8]) -> x509_cert::serial_number::SerialNumber {
    x509_cert::Certificate::from_der(der)
        .unwrap()
        .tbs_certificate
        .serial_number
        .clone()
}

fn sign_p256(key: &p256::ecdsa::SigningKey, data: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use sha2::Digest;
    let digest = sha2::Sha256::digest(data);
    let sig: p256::ecdsa::Signature = key.sign_prehash(&digest).unwrap();
    sig.to_der().as_bytes().to_vec()
}

fn ecdsa_alg() -> spki::AlgorithmIdentifierOwned {
    spki::AlgorithmIdentifierOwned {
        oid: der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
        parameters: None,
    }
}

fn gt(secs: u64) -> der::asn1::GeneralizedTime {
    der::asn1::GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(secs)).unwrap()
}

/// A BasicOCSPResponse whose responderID is `responder`'s subject, with one
/// SingleResponse naming `serial` under `id_ca`'s name/key hashes, signed by
/// `responder`'s key.
fn build_ocsp(
    id_ca: &TestCa,
    serial: x509_cert::serial_number::SerialNumber,
    this: u64,
    next: Option<u64>,
    status: x509_ocsp::CertStatus,
    produced_at: u64,
    responder: &TestCa,
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
        issuer_name_hash: der::asn1::OctetString::new(sha1::Sha1::digest(&subject_der).to_vec())
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
        certs: None,
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

fn good_response_for(id_ca: &TestCa, leaf_der: &[u8], responder: &TestCa) -> Vec<u8> {
    build_ocsp(
        id_ca,
        serial_of(leaf_der),
        AT_UNIX - 60,
        Some(AT_UNIX + 3600),
        x509_ocsp::CertStatus::good(),
        AT_UNIX - 60,
        responder,
    )
}

#[test]
fn byname_shadow_ahead_of_genuine_responder_still_verifies() {
    // /Certs = [L, F, A]: F carries A's DN with another key, ahead of A.
    // The genuine A-signed good response for L must still cover L; on the
    // first-match code it fails Unverifiable under F's key.
    let ca = test_ca("ocsp-try-each-ca");
    let leaf_der = leaf_under(&ca, "ocsp-try-each-leaf");
    let shadow = test_ca("ocsp-try-each-ca");
    assert_eq!(
        shadow.cert.tbs_certificate.subject,
        ca.cert.tbs_certificate.subject,
        "the shadow carries the genuine responder's DN"
    );
    assert_ne!(
        shadow
            .cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
        ca.cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
        "the shadow holds another key"
    );
    let ocsp = good_response_for(&ca, &leaf_der, &ca);
    let outcome = ocsp_entry_good_targets(
        &ocsp,
        &[
            leaf_der.clone(),
            shadow.cert_der.clone(),
            ca.cert_der.clone(),
        ],
        &[],
        AT_UNIX,
    )
    .unwrap();
    assert_eq!(
        outcome,
        Ok(vec![leaf_der]),
        "the responder is the first name match that verifies, not the first name match"
    );
}

#[test]
fn byname_genuine_first_still_verifies() {
    // Control: the genuine responder filed first verifies, before and after
    // the fix.
    let ca = test_ca("ocsp-try-each-ca");
    let leaf_der = leaf_under(&ca, "ocsp-try-each-leaf");
    let shadow = test_ca("ocsp-try-each-ca");
    let ocsp = good_response_for(&ca, &leaf_der, &ca);
    let outcome = ocsp_entry_good_targets(
        &ocsp,
        &[
            leaf_der.clone(),
            ca.cert_der.clone(),
            shadow.cert_der.clone(),
        ],
        &[],
        AT_UNIX,
    )
    .unwrap();
    assert_eq!(outcome, Ok(vec![leaf_der]));
}
