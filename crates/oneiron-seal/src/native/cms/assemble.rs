//! Signed-attribute builders and detached SignedData assembly.

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};

use crate::api::{Sha256Digest, SignatureAlgorithm};
use crate::error::SealError;

use super::cms_err;
use super::der::{alg_id, oid_tlv, sha256, tlv};
use super::oids::{
    OID_ATTR_CONTENT_TYPE, OID_ATTR_MESSAGE_DIGEST, OID_ATTR_SIGNING_CERT_V2, OID_ATTR_TS_TOKEN,
    OID_DATA, OID_ECDSA_SHA256, OID_SHA256, OID_SHA256_WITH_RSA, OID_SIGNED_DATA,
};

// ---------------------------------------------------------------------------
// Signed-attribute assembly (§7.3)
// ---------------------------------------------------------------------------

fn attribute(oid: &ObjectIdentifier, value_der: &[u8]) -> Vec<u8> {
    let mut body = oid_tlv(oid);
    body.extend_from_slice(&tlv(0x31, value_der)); // SET OF (single value)
    tlv(0x30, &body)
}

pub(crate) fn attr_content_type_data() -> Vec<u8> {
    attribute(&OID_ATTR_CONTENT_TYPE, &oid_tlv(&OID_DATA))
}

pub(crate) fn attr_message_digest(digest: &Sha256Digest) -> Vec<u8> {
    attribute(&OID_ATTR_MESSAGE_DIGEST, &tlv(0x04, digest))
}

/// `signingCertificateV2` with SHA-256 over the complete signer certificate
/// DER, the DEFAULT hashAlgorithm field omitted, and issuerSerial present.
pub(crate) fn attr_signing_cert_v2(
    signer_cert_der: &[u8],
    issuer_name_der: &[u8],
    serial_der: &[u8],
) -> Vec<u8> {
    let cert_hash = tlv(0x04, &sha256(signer_cert_der));
    // IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber INTEGER }
    // GeneralNames single entry: directoryName [4] EXPLICIT Name.
    let gn = tlv(0xA4, issuer_name_der);
    let mut is_body = tlv(0x30, &gn);
    is_body.extend_from_slice(serial_der);
    let issuer_serial = tlv(0x30, &is_body);
    let mut ess_body = cert_hash;
    ess_body.extend_from_slice(&issuer_serial);
    let ess_cert_id = tlv(0x30, &ess_body);
    let certs_seq = tlv(0x30, &ess_cert_id); // SEQUENCE OF ESSCertIDv2
    let signing_cert = tlv(0x30, &certs_seq);
    attribute(&OID_ATTR_SIGNING_CERT_V2, &signing_cert)
}

fn canonical_attribute_content(mut attrs: Vec<Vec<u8>>) -> Vec<u8> {
    attrs.sort();
    attrs.dedup();
    attrs.concat()
}

/// Canonical signed-attribute pair: on-wire IMPLICIT `[0]` content and the
/// RFC 5652 §5.4 universal-`SET OF` signature input. Both share the same
/// canonically sorted content octets; only the tag differs.
pub(crate) fn assemble_signed_attrs(attrs: Vec<Vec<u8>>) -> (Vec<u8>, Vec<u8>) {
    let content = canonical_attribute_content(attrs);
    let wire = tlv(0xA0, &content);
    let signing = tlv(0x31, &content);
    (wire, signing)
}

/// Unsigned `signatureTimeStampToken` attribute wrapping a token ContentInfo.
pub(crate) fn attr_ts_token(token_content_info_der: &[u8]) -> Vec<u8> {
    attribute(&OID_ATTR_TS_TOKEN, token_content_info_der)
}

pub(crate) fn assemble_unsigned_attrs(attrs: Vec<Vec<u8>>) -> Vec<u8> {
    tlv(0xA1, &canonical_attribute_content(attrs))
}

// ---------------------------------------------------------------------------
// SignedData assembly
// ---------------------------------------------------------------------------

pub(crate) struct SignerMaterial<'a> {
    pub algorithm: SignatureAlgorithm,
    pub signer_cert_der: &'a [u8],
    pub issuer_name_der: &'a [u8],
    pub serial_der: &'a [u8],
    pub chain_ders: &'a [Vec<u8>],
}

fn signature_alg_id(alg: SignatureAlgorithm) -> Vec<u8> {
    match alg {
        SignatureAlgorithm::RsaPkcs1v15Sha256 => alg_id(&OID_SHA256_WITH_RSA, true),
        SignatureAlgorithm::EcdsaP256Sha256 => alg_id(&OID_ECDSA_SHA256, false),
    }
}

/// Assemble the detached CMS `ContentInfo` (§7.3): one SignedData, one
/// SignerInfo, `eContentType` id-data, `eContent` absent, signer identifier
/// issuerAndSerialNumber.
pub(crate) fn build_signed_data(
    material: &SignerMaterial,
    signed_attrs_wire: &[u8],
    signature: &[u8],
    unsigned_attrs: &[Vec<u8>],
) -> Vec<u8> {
    let mut signer_info_body = tlv(0x02, &[1]); // version 1
    let mut sid_body = material.issuer_name_der.to_vec();
    sid_body.extend_from_slice(material.serial_der);
    signer_info_body.extend_from_slice(&tlv(0x30, &sid_body));
    signer_info_body.extend_from_slice(&alg_id(&OID_SHA256, true));
    signer_info_body.extend_from_slice(signed_attrs_wire);
    signer_info_body.extend_from_slice(&signature_alg_id(material.algorithm));
    signer_info_body.extend_from_slice(&tlv(0x04, signature));
    if !unsigned_attrs.is_empty() {
        signer_info_body.extend_from_slice(&assemble_unsigned_attrs(unsigned_attrs.to_vec()));
    }
    let signer_info = tlv(0x30, &signer_info_body);

    let mut sd_body = tlv(0x02, &[1]); // version 1
    sd_body.extend_from_slice(&tlv(0x31, &alg_id(&OID_SHA256, true))); // digestAlgorithms
    sd_body.extend_from_slice(&tlv(0x30, &oid_tlv(&OID_DATA))); // encapContentInfo
    // certificates [0] IMPLICIT is a SET OF: DER requires the members in
    // ascending lexicographic order of their full encodings.
    let mut certs_members: Vec<&[u8]> = vec![material.signer_cert_der];
    certs_members.extend(material.chain_ders.iter().map(Vec::as_slice));
    certs_members.sort_unstable();
    certs_members.dedup();
    let mut certs = Vec::new();
    for c in certs_members {
        certs.extend_from_slice(c);
    }
    sd_body.extend_from_slice(&tlv(0xA0, &certs)); // certificates [0] IMPLICIT
    sd_body.extend_from_slice(&tlv(0x31, &signer_info)); // signerInfos
    let signed_data = tlv(0x30, &sd_body);

    let mut ci_body = oid_tlv(&OID_SIGNED_DATA);
    ci_body.extend_from_slice(&tlv(0xA0, &signed_data)); // [0] EXPLICIT
    tlv(0x30, &ci_body)
}

/// Extract the issuer Name and serialNumber TLVs from a certificate DER.
pub(crate) fn issuer_and_serial(cert_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SealError> {
    let cert = x509_cert::Certificate::from_der(cert_der).map_err(|_| cms_err())?;
    let issuer = cert
        .tbs_certificate
        .issuer
        .to_der()
        .map_err(|_| cms_err())?;
    let serial = cert
        .tbs_certificate
        .serial_number
        .to_der()
        .map_err(|_| cms_err())?;
    Ok((issuer, serial))
}
