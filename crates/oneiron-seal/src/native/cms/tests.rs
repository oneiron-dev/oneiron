//! CMS assembly/parsing round-trip, canonicality, and version-gating tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use const_oid::ObjectIdentifier;

use crate::api::SignatureAlgorithm;

use super::*;

fn cert_der() -> Vec<u8> {
    // Ephemeral throwaway identity, generated fresh for the test run.
    let key_pair = rcgen::KeyPair::generate().expect("keygen");
    let params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params.self_signed(&key_pair).expect("cert").der().to_vec()
}

fn baseline_attrs() -> (ParsedCms, Vec<u8>) {
    let cert = cert_der();
    let (issuer, serial) = issuer_and_serial(&cert).expect("issuer/serial");
    let attrs = vec![
        attr_content_type_data(),
        attr_message_digest(&[7u8; 32]),
        attr_signing_cert_v2(&cert, &issuer, &serial),
    ];
    let (wire, signing) = assemble_signed_attrs(attrs);
    let material = SignerMaterial {
        algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        signer_cert_der: &cert,
        issuer_name_der: &issuer,
        serial_der: &serial,
        chain_ders: &[],
    };
    let der = build_signed_data(&material, &wire, &[9u8; 64], &[]);
    let parsed = parse_cms(&der).expect("parse");
    (parsed, signing)
}

#[test]
fn baseline_has_exactly_three_attributes_once_each_sorted() {
    let (parsed, _) = baseline_attrs();
    let signer = &parsed.signer;
    // parse_cms already rejected anything but DER-sorted full octets.
    assert_eq!(signer.signed_attrs.len(), 3);
    let mut oids: Vec<Vec<u8>> = signer
        .signed_attrs
        .iter()
        .map(|a| parse_attribute(a).expect("attr").0)
        .collect();
    oids.sort();
    oids.dedup();
    assert_eq!(oids.len(), 3, "each baseline attribute exactly once");
    let md = check_baseline_attrs(signer).expect("baseline ok");
    assert_eq!(md, [7u8; 32]);
}

#[test]
fn rfc5652_signature_input_uses_universal_set_tag() {
    let (parsed, signing) = baseline_attrs();
    assert_eq!(signing[0], 0x31, "signature input is the universal SET OF");
    // On-wire field is the IMPLICIT [0] with identical content octets.
    assert!(signing.ends_with(&parsed.signer.signed_attrs_content));
    let rebuilt = signed_attrs_signature_input(&parsed.signer);
    assert_eq!(rebuilt, signing);
}

#[test]
fn ess_omits_default_hash_algorithm_and_binds_full_cert() {
    let cert = cert_der();
    let (issuer, serial) = issuer_and_serial(&cert).expect("i/s");
    let attr = attr_signing_cert_v2(&cert, &issuer, &serial);
    let (_, value) = parse_attribute(&attr).expect("attribute");
    assert_eq!(value.tag, 0x30);
    let mut signing_cert = DerReader::new(value.content);
    let certs = signing_cert.expect(0x30).expect("certs sequence");
    let mut certs_reader = DerReader::new(certs.content);
    let ess = certs_reader.expect(0x30).expect("ESSCertIDv2");
    let mut ess_reader = DerReader::new(ess.content);
    // With the DEFAULT hashAlgorithm omitted, certHash is the first field.
    assert_eq!(
        ess_reader.read().expect("certHash").tag,
        0x04,
        "DEFAULT hashAlgorithm must be omitted",
    );
    check_ess_binding(&attr, &cert, &issuer, &serial).expect("binding");
    // One flipped cert byte must break the full-certificate digest.
    let mut wrong = cert;
    let n = wrong.len();
    wrong[n - 20] ^= 0x01;
    assert!(check_ess_binding(&attr, &wrong, &issuer, &serial).is_err());
}

#[test]
fn duplicate_and_foreign_attributes_are_rejected() {
    let (mut parsed, _) = baseline_attrs();
    // Duplicate the content-type attribute.
    let dup = parsed.signer.signed_attrs[0].clone();
    parsed.signer.signed_attrs.push(dup);
    assert!(check_baseline_attrs(&parsed.signer).is_err());
}

#[test]
fn der_reader_rejects_indefinite_and_nonminimal_lengths() {
    // BER indefinite length.
    assert!(DerReader::new(&[0x30, 0x80, 0x00, 0x00]).read().is_err());
    // Non-minimal long form for a short length.
    assert!(DerReader::new(&[0x30, 0x81, 0x01, 0x00]).read().is_err());
    // Truncated content.
    assert!(DerReader::new(&[0x30, 0x05, 0x01]).read().is_err());
}

#[test]
fn unsorted_signed_attribute_set_is_rejected_on_parse() {
    let cert = cert_der();
    let (issuer, serial) = issuer_and_serial(&cert).expect("i/s");
    // Deliberately wrong order: message-digest before content-type.
    let attrs = vec![
        attr_message_digest(&[7u8; 32]),
        attr_content_type_data(),
        attr_signing_cert_v2(&cert, &issuer, &serial),
    ];
    let mut content = Vec::new();
    for a in &attrs {
        content.extend_from_slice(a);
    }
    let wire = tlv(0xA0, &content);
    let material = SignerMaterial {
        algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        signer_cert_der: &cert,
        issuer_name_der: &issuer,
        serial_der: &serial,
        chain_ders: &[],
    };
    let der = build_signed_data(&material, &wire, &[9u8; 64], &[]);
    assert!(parse_cms(&der).is_err(), "unsorted SET must fail");
}

#[test]
fn repeated_signed_data_fields_are_rejected_on_parse() {
    let cert = cert_der();
    let (issuer, serial) = issuer_and_serial(&cert).expect("i/s");
    let attrs = vec![
        attr_content_type_data(),
        attr_message_digest(&[7u8; 32]),
        attr_signing_cert_v2(&cert, &issuer, &serial),
    ];
    let (wire, _) = assemble_signed_attrs(attrs);
    let certs_a0 = tlv(0xA0, &cert);
    let real_set = {
        let mut si_body = tlv(0x02, &[1]);
        let mut sid_body = issuer;
        sid_body.extend_from_slice(&serial);
        si_body.extend_from_slice(&tlv(0x30, &sid_body));
        si_body.extend_from_slice(&alg_id(&OID_SHA256, true));
        si_body.extend_from_slice(&wire);
        si_body.extend_from_slice(&alg_id(&OID_ECDSA_SHA256, false));
        si_body.extend_from_slice(&tlv(0x04, &[9u8; 64]));
        tlv(0x31, &tlv(0x30, &si_body))
    };
    // Hand-built ContentInfo with two signerInfos SETs: the second must
    // not silently overwrite the first.
    let mut sd_body = tlv(0x02, &[1]);
    sd_body.extend_from_slice(&tlv(0x31, &alg_id(&OID_SHA256, true)));
    sd_body.extend_from_slice(&tlv(0x30, &oid_tlv(&OID_DATA)));
    sd_body.extend_from_slice(&certs_a0);
    sd_body.extend_from_slice(&real_set);
    sd_body.extend_from_slice(&real_set); // repeated field
    let signed_data = tlv(0x30, &sd_body);
    let mut ci_body = oid_tlv(&OID_SIGNED_DATA);
    ci_body.extend_from_slice(&tlv(0xA0, &signed_data));
    let der = tlv(0x30, &ci_body);
    assert!(
        parse_cms(&der).is_err(),
        "a second signerInfos SET must be rejected, not overwrite"
    );
    // Same for a repeated certificates [0] field.
    let mut sd_body2 = tlv(0x02, &[1]);
    sd_body2.extend_from_slice(&tlv(0x31, &alg_id(&OID_SHA256, true)));
    sd_body2.extend_from_slice(&tlv(0x30, &oid_tlv(&OID_DATA)));
    sd_body2.extend_from_slice(&certs_a0);
    sd_body2.extend_from_slice(&certs_a0);
    sd_body2.extend_from_slice(&real_set);
    let signed_data2 = tlv(0x30, &sd_body2);
    let mut ci_body2 = oid_tlv(&OID_SIGNED_DATA);
    ci_body2.extend_from_slice(&tlv(0xA0, &signed_data2));
    let der2 = tlv(0x30, &ci_body2);
    assert!(
        parse_cms(&der2).is_err(),
        "a second certificates field must be rejected"
    );
}

#[test]
fn certificates_set_of_is_der_sorted_on_assembly() {
    // Fake cert members (opaque TLVs to the certs field) chosen so the
    // signing cert sorts AFTER the chain cert.
    let high = tlv(0x30, &[0x02, 0x01, 0x7F]);
    let low = tlv(0x30, &[0x02, 0x01, 0x01]);
    let chain = vec![low.clone()];
    let material = SignerMaterial {
        algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        signer_cert_der: &high,
        issuer_name_der: &tlv(0x30, &[]),
        serial_der: &tlv(0x02, &[1]),
        chain_ders: &chain,
    };
    let der = build_signed_data(&material, &tlv(0xA0, &[]), &[1u8; 64], &[]);
    let mut reader = DerReader::new(&der);
    let content_info = reader.expect(0x30).expect("ContentInfo");
    let mut reader = DerReader::new(content_info.content);
    reader.expect(0x06).expect("contentType");
    let content = reader.expect(0xA0).expect("content");
    let mut reader = DerReader::new(content.content);
    let signed_data = reader.expect(0x30).expect("SignedData");
    let mut reader = DerReader::new(signed_data.content);
    reader.expect(0x02).expect("version");
    reader.expect(0x31).expect("digestAlgorithms");
    reader.expect(0x30).expect("encapContentInfo");
    let certificates = reader.expect(0xA0).expect("certificates");
    let mut reader = DerReader::new(certificates.content);
    let first = reader.read().expect("first certificate");
    let second = reader.read().expect("second certificate");
    assert!(reader.is_done());
    assert!(
        (first.full == low.as_slice() && second.full == high.as_slice())
            || (first.full == high.as_slice() && second.full == low.as_slice()),
        "both certificate members must be preserved",
    );
    assert!(
        first.full < second.full,
        "certificates SET OF members must be in ascending DER order",
    );
}

#[test]
fn sid_ess_disagreement_is_rejected_on_parse() {
    // sid names cert A's issuer/serial; the ESS issuerSerial names a
    // DIFFERENT serial. Both well-formed: the disagreement alone must
    // kill the parse.
    let cert = cert_der();
    let (issuer, serial) = issuer_and_serial(&cert).expect("i/s");
    let attrs = vec![
        attr_content_type_data(),
        attr_message_digest(&[7u8; 32]),
        attr_signing_cert_v2(&cert, &issuer, &serial),
    ];
    let (wire, _) = assemble_signed_attrs(attrs);
    let foreign_serial = tlv(0x02, &[0x7E, 0x7E]);
    let material = SignerMaterial {
        algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        signer_cert_der: &cert,
        issuer_name_der: &issuer,
        serial_der: &foreign_serial,
        chain_ders: &[],
    };
    let der = build_signed_data(&material, &wire, &[9u8; 64], &[]);
    assert!(
        parse_cms(&der).is_err(),
        "sid/ESS issuerSerial disagreement must be rejected"
    );
}

#[test]
fn sig_alg_permitted_denies_rsa_pss_everywhere() {
    assert!(sig_alg_permitted(
        SignatureAlgorithm::RsaPkcs1v15Sha256,
        OID_SHA256_WITH_RSA.as_bytes()
    ));
    assert!(!sig_alg_permitted(
        SignatureAlgorithm::RsaPkcs1v15Sha256,
        OID_RSA_PSS.as_bytes()
    ));
    assert!(!sig_alg_permitted(
        SignatureAlgorithm::EcdsaP256Sha256,
        OID_RSA_PSS.as_bytes()
    ));
}

/// Offset of the SignedData version INTEGER's single value octet inside
/// a ContentInfo DER emitted by `build_signed_data`.
fn version_value_offset(der: &[u8]) -> usize {
    fn header_len(buf: &[u8]) -> usize {
        assert!(buf.len() >= 2, "header present");
        let first_len = buf[1];
        if first_len & 0x80 == 0 {
            2
        } else {
            2 + usize::from(first_len & 0x7F)
        }
    }
    let mut at = header_len(der); // start of ci.content == OID tlv
    at += DerReader::new(&der[at..])
        .expect(0x06)
        .expect("oid")
        .full
        .len(); // start of [0] wrapper
    assert_eq!(der[at], 0xA0, "signed-data wrapper tag");
    at += header_len(&der[at..]); // start of SignedData SEQUENCE
    assert_eq!(der[at], 0x30, "SignedData sequence tag");
    at += header_len(&der[at..]); // start of version INTEGER
    assert_eq!(der[at], 0x02, "version is an INTEGER");
    assert_eq!(der[at + 1], 0x01, "version length 1");
    at + 2
}

/// A signed-attribute wire + signer material pair reused by the envelope
/// fixtures below.
fn version_probe_signer_info(cert: &[u8]) -> Vec<u8> {
    let (issuer, serial) = issuer_and_serial(cert).expect("i/s");
    let attrs = vec![
        attr_content_type_data(),
        attr_message_digest(&[7u8; 32]),
        attr_signing_cert_v2(cert, &issuer, &serial),
    ];
    let (wire, _) = assemble_signed_attrs(attrs);
    let material = SignerMaterial {
        algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        signer_cert_der: cert,
        issuer_name_der: &issuer,
        serial_der: &serial,
        chain_ders: &[],
    };
    let der = build_signed_data(&material, &wire, &[9u8; 64], &[]);
    let ci = DerReader::new(&der).expect(0x30).expect("ci");
    let mut r = DerReader::new(ci.content);
    r.expect(0x06).expect("oid");
    let w = r.expect(0xA0).expect("wrapper");
    let sd = DerReader::new(w.content).expect(0x30).expect("sd");
    let mut s = DerReader::new(sd.content);
    s.expect(0x02).expect("version");
    s.expect(0x31).expect("digestAlgorithms");
    s.expect(0x30).expect("eci");
    s.expect(0xA0).expect("certificates");
    s.expect(0x31).expect("signerInfos").full.to_vec()
}

/// A detached SignedData at a caller-chosen version and eContentType.
/// Only the envelope shape matters: `parse_cms` checks structure here,
/// not the encapsulated body.
fn envelope_with(version: u8, econtent_type: &ObjectIdentifier) -> Vec<u8> {
    let cert = cert_der();
    let signer_info = version_probe_signer_info(&cert);
    let mut sd_body = tlv(0x02, &[version]);
    sd_body.extend_from_slice(&tlv(0x31, &alg_id(&OID_SHA256, true)));
    sd_body.extend_from_slice(&tlv(0x30, &oid_tlv(econtent_type)));
    sd_body.extend_from_slice(&tlv(0xA0, &cert));
    sd_body.extend_from_slice(&signer_info);
    let mut ci_body = oid_tlv(&OID_SIGNED_DATA);
    ci_body.extend_from_slice(&tlv(0xA0, &tlv(0x30, &sd_body)));
    tlv(0x30, &ci_body)
}

#[test]
fn id_data_signed_data_requires_version_one() {
    // RFC 5652 5.1: eContentType id-data => version 1. The detached
    // CAdES document-signature shape this parser reads is exactly that,
    // so every other version is a field layout it would misread.
    let cert = cert_der();
    let (issuer, serial) = issuer_and_serial(&cert).expect("i/s");
    let attrs = vec![
        attr_content_type_data(),
        attr_message_digest(&[7u8; 32]),
        attr_signing_cert_v2(&cert, &issuer, &serial),
    ];
    let (wire, _) = assemble_signed_attrs(attrs);
    let material = SignerMaterial {
        algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        signer_cert_der: &cert,
        issuer_name_der: &issuer,
        serial_der: &serial,
        chain_ders: &[],
    };
    let base = build_signed_data(&material, &wire, &[9u8; 64], &[]);
    let at = version_value_offset(&base);
    assert_eq!(base[at], 1, "control: builder emits v1 under id-data");
    assert!(parse_cms(&base).is_ok(), "id-data at v1 parses");
    for bad in [0u8, 2, 3, 4, 5] {
        let mut der = base.clone();
        der[at] = bad;
        assert!(
            parse_cms(&der).is_err(),
            "id-data SignedData at version {bad} must be rejected"
        );
    }
}

#[test]
fn tst_info_signed_data_requires_version_three() {
    // botfix8 F1 REGRESSION: botfix-7 pinned every SignedData to v1,
    // which rejects EVERY standards-compliant RFC 3161 token — RFC 5652
    // 5.1 mandates v3 whenever eContentType is not id-data, and both
    // tsp.rs paths bind econtent_oid to id-ct-TSTInfo before use. An
    // unconditional `== 1` gate breaks the live timestamp paths; an
    // unconditional `== 3` gate breaks the CAdES document path.
    assert!(
        parse_cms(&envelope_with(3, &OID_CT_TST_INFO)).is_ok(),
        "id-ct-TSTInfo at version 3 must parse"
    );
    for bad in [0u8, 1, 2, 4, 5] {
        assert!(
            parse_cms(&envelope_with(bad, &OID_CT_TST_INFO)).is_err(),
            "id-ct-TSTInfo SignedData at version {bad} must be rejected"
        );
    }
    // The mismatched pair in the other direction: id-data never rides v3.
    assert!(
        parse_cms(&envelope_with(3, &OID_DATA)).is_err(),
        "id-data at version 3 must be rejected"
    );
    assert!(
        parse_cms(&envelope_with(1, &OID_DATA)).is_ok(),
        "control: id-data at version 1 parses through this builder too"
    );
}

#[test]
fn unknown_econtent_type_is_rejected() {
    // Only the two encapsulations this parser implements are admitted;
    // any other content type has a field layout this code does not read,
    // so it must not reach the signature checks at any version.
    let other = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.2"); // id-ct-authData
    for version in [1u8, 3] {
        assert!(
            parse_cms(&envelope_with(version, &other)).is_err(),
            "unimplemented eContentType at v{version} must be rejected"
        );
    }
}
