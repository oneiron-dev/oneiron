//! Attribute/ESS binding and frozen signature-suite verification gates.

use der::{Decode, Encode};

use crate::api::{Sha256Digest, SignatureAlgorithm};
use crate::error::{FatalCode, SealError, SealStage};

use super::cms_err;
use super::der::{DerReader, Tlv, sha256};
use super::oids::{
    OID_ATTR_CONTENT_TYPE, OID_ATTR_MESSAGE_DIGEST, OID_ATTR_SIGNING_CERT_V2, OID_DATA,
    OID_EC_PUBLIC_KEY, OID_ECDSA_SHA256, OID_P256, OID_RSA_ENCRYPTION, OID_RSA_PSS, OID_SHA256,
    OID_SHA256_WITH_RSA,
};
use super::parse::{ParsedSignerInfo, parse_oid};

// ---------------------------------------------------------------------------
// Attribute inspection and signature verification
// ---------------------------------------------------------------------------

/// Parse one Attribute: returns (attr OID content bytes, single value TLV).
pub(crate) fn parse_attribute(attr_der: &[u8]) -> Result<(Vec<u8>, Tlv<'_>), SealError> {
    let top = DerReader::new(attr_der).expect(0x30)?;
    let mut r = DerReader::new(top.content);
    let oid = parse_oid(r.expect(0x06)?)?;
    let set = r.expect(0x31)?;
    let mut sr = DerReader::new(set.content);
    let value = sr.read()?;
    if !sr.is_done() {
        return Err(cms_err()); // single-valued baseline attributes only
    }
    if !r.is_done() {
        return Err(cms_err());
    }
    Ok((oid, value))
}

/// Enforce the exact three-attribute PAdES baseline (§7.3). Returns the
/// `message-digest` value.
pub(crate) fn check_baseline_attrs(signer: &ParsedSignerInfo) -> Result<Sha256Digest, SealError> {
    if signer.signed_attrs.len() != 3 {
        return Err(cms_err());
    }
    let mut digest: Option<Sha256Digest> = None;
    let mut seen_ct = false;
    let mut seen_sc = false;
    for attr in &signer.signed_attrs {
        let (oid, value) = parse_attribute(attr)?;
        if oid == OID_ATTR_CONTENT_TYPE.as_bytes() {
            if seen_ct || value.tag != 0x06 || value.content != OID_DATA.as_bytes() {
                return Err(cms_err());
            }
            seen_ct = true;
        } else if oid == OID_ATTR_MESSAGE_DIGEST.as_bytes() {
            if digest.is_some() || value.tag != 0x04 || value.content.len() != 32 {
                return Err(cms_err());
            }
            let mut d = [0u8; 32];
            d.copy_from_slice(value.content);
            digest = Some(d);
        } else if oid == OID_ATTR_SIGNING_CERT_V2.as_bytes() {
            if seen_sc {
                return Err(cms_err());
            }
            seen_sc = true;
        } else {
            return Err(cms_err()); // attribute outside the allowed set
        }
    }
    if !seen_ct || !seen_sc {
        return Err(cms_err());
    }
    digest.ok_or_else(cms_err)
}

/// (cert hash content, issuer Name DER, serialNumber TLV) of one
/// ESSCertIDv2.
type EssCertIdParts = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Walk a signingCertificateV2 attribute down to its (single) ESSCertIDv2,
/// returning (cert hash content, issuer Name DER, serialNumber TLV). The
/// attribute must be the exact baseline shape: single value, one
/// ESSCertIDv2, issuerSerial with one directoryName GeneralName.
pub(super) fn ess_cert_id_v2(attr_der: &[u8]) -> Result<EssCertIdParts, SealError> {
    let (oid, value) = parse_attribute(attr_der)?;
    if oid != OID_ATTR_SIGNING_CERT_V2.as_bytes() || value.tag != 0x30 {
        return Err(cms_err());
    }
    let mut r = DerReader::new(value.content);
    let certs_seq = r.expect(0x30)?;
    if !r.is_done() {
        return Err(cms_err());
    }
    let mut cr = DerReader::new(certs_seq.content);
    let ess = cr.expect(0x30)?;
    if !cr.is_done() {
        return Err(cms_err());
    }
    let mut er = DerReader::new(ess.content);
    let hash = er.expect(0x04)?;
    let is = er.expect(0x30)?;
    if !er.is_done() {
        return Err(cms_err());
    }
    let mut ir = DerReader::new(is.content);
    let gn = ir.expect(0x30)?; // GeneralNames SEQUENCE
    let serial = ir.expect(0x02)?;
    if !ir.is_done() {
        return Err(cms_err());
    }
    let mut gr = DerReader::new(gn.content);
    let dir_name = gr.expect(0xA4)?;
    if !gr.is_done() {
        return Err(cms_err());
    }
    Ok((
        hash.content.to_vec(),
        dir_name.content.to_vec(),
        serial.full.to_vec(),
    ))
}

/// Verify the ESSCertIDv2 binding inside a signingCertificateV2 attribute:
/// SHA-256 over the complete certificate DER, DEFAULT hashAlgorithm omitted,
/// issuerSerial present and matching.
pub(crate) fn check_ess_binding(
    attr_der: &[u8],
    signer_cert_der: &[u8],
    issuer_name_der: &[u8],
    serial_der: &[u8],
) -> Result<(), SealError> {
    let (hash, issuer, serial) = ess_cert_id_v2(attr_der)?;
    if hash != sha256(signer_cert_der) || issuer != issuer_name_der || serial != serial_der {
        return Err(cms_err());
    }
    Ok(())
}

/// Map a certificate's public-key algorithm to a frozen signature suite.
/// Rejects RSA-PSS and any algorithm outside the §7.3 allowlist.
pub(crate) fn cert_signature_algorithm(cert_der: &[u8]) -> Result<SignatureAlgorithm, SealError> {
    let cert = x509_cert::Certificate::from_der(cert_der).map_err(|_| SealError::Fatal {
        stage: SealStage::CmsAssembly,
        code: FatalCode::InvalidSigningIdentity,
    })?;
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let oid = spki.algorithm.oid;
    if oid == OID_RSA_ENCRYPTION {
        return Ok(SignatureAlgorithm::RsaPkcs1v15Sha256);
    }
    if oid == OID_EC_PUBLIC_KEY {
        let params_ok = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<der::asn1::ObjectIdentifier>().ok())
            .is_some_and(|p| p == OID_P256);
        if params_ok {
            return Ok(SignatureAlgorithm::EcdsaP256Sha256);
        }
    }
    Err(SealError::Fatal {
        stage: SealStage::CmsAssembly,
        code: FatalCode::UnsupportedSignatureAlgorithm,
    })
}

/// Prehash signature verification of the universal-SET signing input against
/// the signer certificate's public key.
pub(crate) fn verify_signature_value(
    alg: SignatureAlgorithm,
    signer_cert_der: &[u8],
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), SealError> {
    let cert = x509_cert::Certificate::from_der(signer_cert_der).map_err(|_| cms_err())?;
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let digest = sha256(signing_input);
    let ok = match alg {
        SignatureAlgorithm::RsaPkcs1v15Sha256 => {
            use rsa::pkcs8::DecodePublicKey;
            let key = rsa::RsaPublicKey::from_public_key_der(
                spki.to_der().map_err(|_| cms_err())?.as_slice(),
            )
            .map_err(|_| cms_err())?;
            let scheme = rsa::Pkcs1v15Sign::new::<sha2::Sha256>();
            key.verify(scheme, &digest, signature).is_ok()
        }
        SignatureAlgorithm::EcdsaP256Sha256 => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            let key_bytes = spki.subject_public_key.raw_bytes();
            let key =
                p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes).map_err(|_| cms_err())?;
            let sig = p256::ecdsa::Signature::from_der(signature).map_err(|_| cms_err())?;
            key.verify_prehash(&digest, &sig).is_ok()
        }
    };
    if ok { Ok(()) } else { Err(cms_err()) }
}

/// Consistency between the CMS signatureAlgorithm OID and the frozen suite.
pub(crate) fn sig_alg_oid_matches(alg: SignatureAlgorithm, oid_bytes: &[u8]) -> bool {
    let expected = match alg {
        SignatureAlgorithm::RsaPkcs1v15Sha256 => OID_SHA256_WITH_RSA,
        SignatureAlgorithm::EcdsaP256Sha256 => OID_ECDSA_SHA256,
    };
    oid_bytes == expected.as_bytes()
}

/// The single signature-algorithm gate for every verify path (signature,
/// timestamp token, CRL, OCSP): the OID must match the frozen suite AND not
/// be on the denylist.
pub(crate) fn sig_alg_permitted(alg: SignatureAlgorithm, oid_bytes: &[u8]) -> bool {
    sig_alg_oid_matches(alg, oid_bytes) && !is_denied_alg_oid(oid_bytes)
}

pub(crate) fn is_denied_alg_oid(oid_bytes: &[u8]) -> bool {
    oid_bytes == OID_RSA_PSS.as_bytes()
}

pub(crate) fn is_sha256_oid(oid_bytes: &[u8]) -> bool {
    oid_bytes == OID_SHA256.as_bytes()
}
