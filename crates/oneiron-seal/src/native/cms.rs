//! CMS/CAdES SignedData assembly and parsing with exact byte control (§7.3).
//!
//! Hand-assembled DER (GATE-1 amendment A3: the `cms` crate's builder feature
//! is deliberately unused) so the PAdES signed-attribute set, the RFC 5652
//! §5.4 universal-SET signature input, and DER canonicality checks are under
//! this crate's direct control.

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use sha2::Digest;

use crate::api::{Sha256Digest, SignatureAlgorithm};
use crate::error::{FatalCode, SealError, SealStage};

pub(crate) const OID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
pub(crate) const OID_SIGNED_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
pub(crate) const OID_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
pub(crate) const OID_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
pub(crate) const OID_SHA256_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
pub(crate) const OID_RSA_PSS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
pub(crate) const OID_ECDSA_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
pub(crate) const OID_EC_PUBLIC_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
pub(crate) const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
pub(crate) const OID_ATTR_CONTENT_TYPE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
pub(crate) const OID_ATTR_MESSAGE_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
pub(crate) const OID_ATTR_SIGNING_CERT_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
pub(crate) const OID_ATTR_TS_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

fn cms_err() -> SealError {
    SealError::Fatal {
        stage: SealStage::CmsAssembly,
        code: FatalCode::CmsEncodingFailed,
    }
}

pub(crate) fn sha256(data: &[u8]) -> Sha256Digest {
    sha2::Sha256::digest(data).into()
}

// ---------------------------------------------------------------------------
// Minimal strict-DER writer/reader
// ---------------------------------------------------------------------------

pub(crate) fn len_bytes(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let be = len.to_be_bytes();
    let start = be.iter().position(|b| *b != 0).unwrap_or(be.len() - 1);
    let significant = &be[start..];
    let mut out = vec![0x80 | significant.len() as u8];
    out.extend_from_slice(significant);
    out
}

pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&len_bytes(content.len()));
    out.extend_from_slice(content);
    out
}

pub(crate) fn oid_tlv(oid: &ObjectIdentifier) -> Vec<u8> {
    tlv(0x06, oid.as_bytes())
}

fn null_tlv() -> Vec<u8> {
    vec![0x05, 0x00]
}

fn alg_id(oid: &ObjectIdentifier, with_null: bool) -> Vec<u8> {
    let mut body = oid_tlv(oid);
    if with_null {
        body.extend_from_slice(&null_tlv());
    }
    tlv(0x30, &body)
}

/// One parsed TLV: tag, content octets, and the complete TLV slice.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub full: &'a [u8],
}

pub(crate) struct DerReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn is_done(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Strict DER read: rejects indefinite and non-minimal lengths.
    pub(crate) fn read(&mut self) -> Result<Tlv<'a>, SealError> {
        let start = self.pos;
        if self.buf.len() < start + 2 {
            return Err(cms_err());
        }
        let tag = self.buf[start];
        let first_len = self.buf[start + 1];
        let (len, hdr) = if first_len & 0x80 == 0 {
            (usize::from(first_len), 2)
        } else {
            let n = usize::from(first_len & 0x7F);
            if n == 0 || n > 4 || self.buf.len() < start + 2 + n {
                return Err(cms_err());
            }
            if self.buf[start + 2] == 0 {
                return Err(cms_err()); // non-minimal long form
            }
            let mut len = 0usize;
            for i in 0..n {
                len = (len << 8) | usize::from(self.buf[start + 2 + i]);
            }
            if len < 0x80 {
                return Err(cms_err()); // should have used short form
            }
            (len, 2 + n)
        };
        let end = start
            .checked_add(hdr)
            .and_then(|p| p.checked_add(len))
            .filter(|e| *e <= self.buf.len())
            .ok_or_else(cms_err)?;
        self.pos = end;
        Ok(Tlv {
            tag,
            content: &self.buf[start + hdr..end],
            full: &self.buf[start..end],
        })
    }

    pub(crate) fn expect(&mut self, tag: u8) -> Result<Tlv<'a>, SealError> {
        let t = self.read()?;
        if t.tag != tag {
            return Err(cms_err());
        }
        Ok(t)
    }
}

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

// ---------------------------------------------------------------------------
// CMS parsing for verification
// ---------------------------------------------------------------------------

/// Parsed subset of one SignerInfo used by the verifier.
#[derive(Debug)]
pub(crate) struct ParsedSignerInfo {
    pub digest_alg_oid: Vec<u8>,
    /// Full DER of each signed attribute, in wire order.
    pub signed_attrs: Vec<Vec<u8>>,
    /// Raw content octets of the IMPLICIT `[0]` signedAttrs field.
    pub signed_attrs_content: Vec<u8>,
    pub signature_alg_oid: Vec<u8>,
    pub signature: Vec<u8>,
    pub unsigned_attrs: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub(crate) struct ParsedCms {
    pub content_oid: Vec<u8>,
    pub digest_algs: Vec<Vec<u8>>,
    pub econtent_oid: Vec<u8>,
    pub econtent: Option<Vec<u8>>,
    pub certificates: Vec<Vec<u8>>,
    pub signer: ParsedSignerInfo,
}

fn parse_oid(t: Tlv) -> Result<Vec<u8>, SealError> {
    if t.tag != 0x06 {
        return Err(cms_err());
    }
    Ok(t.content.to_vec())
}

fn parse_signer_info(tlv_bytes: &[u8]) -> Result<ParsedSignerInfo, SealError> {
    let top = DerReader::new(tlv_bytes).expect(0x30)?;
    let mut r = DerReader::new(top.content);
    let version = r.expect(0x02)?;
    if version.content != [1] {
        return Err(cms_err());
    }
    let sid = r.expect(0x30)?;
    let mut sid_r = DerReader::new(sid.content);
    sid_r.expect(0x30)?; // issuer Name
    sid_r.expect(0x02)?; // serialNumber
    let digest_alg = r.expect(0x30)?;
    let digest_oid = parse_oid(DerReader::new(digest_alg.content).expect(0x06)?)?;
    let attrs_field = r.expect(0xA0)?;
    // Canonicality: attributes must be strictly sorted by DER octets.
    let mut attrs_r = DerReader::new(attrs_field.content);
    let mut signed_attrs = Vec::new();
    while !attrs_r.is_done() {
        let a = attrs_r.expect(0x30)?;
        if signed_attrs
            .last()
            .is_some_and(|last: &Vec<u8>| last.as_slice() >= a.full)
        {
            return Err(cms_err()); // unsorted or duplicate
        }
        signed_attrs.push(a.full.to_vec());
    }
    let sig_alg = r.expect(0x30)?;
    let sig_oid = parse_oid(DerReader::new(sig_alg.content).expect(0x06)?)?;
    let signature = r.expect(0x04)?.content.to_vec();
    let mut unsigned_attrs = Vec::new();
    if !r.is_done() {
        let ua = r.expect(0xA1)?;
        let mut ua_r = DerReader::new(ua.content);
        while !ua_r.is_done() {
            unsigned_attrs.push(ua_r.expect(0x30)?.full.to_vec());
        }
    }
    if !r.is_done() {
        return Err(cms_err());
    }
    Ok(ParsedSignerInfo {
        digest_alg_oid: digest_oid,
        signed_attrs,
        signed_attrs_content: attrs_field.content.to_vec(),
        signature_alg_oid: sig_oid,
        signature,
        unsigned_attrs,
    })
}

/// Parse a detached CMS ContentInfo. Strict DER only; exactly one signer.
pub(crate) fn parse_cms(der: &[u8]) -> Result<ParsedCms, SealError> {
    let mut top = DerReader::new(der);
    let ci = top.expect(0x30)?;
    if !top.is_done() {
        return Err(cms_err()); // trailing bytes after ContentInfo
    }
    let mut r = DerReader::new(ci.content);
    let content_oid = parse_oid(r.expect(0x06)?)?;
    if content_oid != OID_SIGNED_DATA.as_bytes() {
        return Err(cms_err());
    }
    let sd_wrapper = r.expect(0xA0)?;
    let sd = DerReader::new(sd_wrapper.content).expect(0x30)?;
    if !r.is_done() {
        return Err(cms_err());
    }
    let mut s = DerReader::new(sd.content);
    s.expect(0x02)?; // version
    let digest_set = s.expect(0x31)?;
    let mut digest_algs = Vec::new();
    let mut dr = DerReader::new(digest_set.content);
    while !dr.is_done() {
        let alg = dr.expect(0x30)?;
        digest_algs.push(parse_oid(DerReader::new(alg.content).expect(0x06)?)?);
    }
    let eci = s.expect(0x30)?;
    let mut eci_r = DerReader::new(eci.content);
    let econtent_oid = parse_oid(eci_r.expect(0x06)?)?;
    let econtent = if eci_r.is_done() {
        None
    } else {
        let wrapper = eci_r.expect(0xA0)?;
        let os = DerReader::new(wrapper.content).expect(0x04)?;
        Some(os.content.to_vec())
    };
    let mut certificates = Vec::new();
    let mut seen_certificates = false;
    let mut signer_info_der = None;
    while !s.is_done() {
        let t = s.read()?;
        match t.tag {
            0xA0 => {
                if seen_certificates {
                    return Err(cms_err()); // repeated certificates field
                }
                seen_certificates = true;
                let mut cr = DerReader::new(t.content);
                while !cr.is_done() {
                    certificates.push(cr.expect(0x30)?.full.to_vec());
                }
            }
            0x31 => {
                if signer_info_der.is_some() {
                    return Err(cms_err()); // a second signerInfos SET must not overwrite
                }
                let mut sr = DerReader::new(t.content);
                let first = sr.expect(0x30)?;
                if !sr.is_done() {
                    return Err(cms_err()); // exactly one SignerInfo
                }
                signer_info_der = Some(first.full.to_vec());
            }
            _ => return Err(cms_err()), // crls/other fields not used in v1
        }
    }
    let signer_info_der = signer_info_der.ok_or_else(cms_err)?;
    Ok(ParsedCms {
        content_oid,
        digest_algs,
        econtent_oid,
        econtent,
        certificates,
        signer: parse_signer_info(&signer_info_der)?,
    })
}

/// Rebuild the RFC 5652 §5.4 signature input from parsed signed attributes:
/// the same content octets under the universal `SET OF` tag.
pub(crate) fn signed_attrs_signature_input(signer: &ParsedSignerInfo) -> Vec<u8> {
    tlv(0x31, &signer.signed_attrs_content)
}

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

/// Verify the ESSCertIDv2 binding inside a signingCertificateV2 attribute:
/// SHA-256 over the complete certificate DER, DEFAULT hashAlgorithm omitted,
/// issuerSerial present and matching.
pub(crate) fn check_ess_binding(
    attr_der: &[u8],
    signer_cert_der: &[u8],
    issuer_name_der: &[u8],
    serial_der: &[u8],
) -> Result<(), SealError> {
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
    if hash.content != sha256(signer_cert_der) {
        return Err(cms_err());
    }
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
    if !gr.is_done() || dir_name.content != issuer_name_der || serial.full != serial_der {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
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
        // The SHA-256 AlgorithmIdentifier OID must NOT appear inside: DER
        // omits DEFAULT-valued fields.
        let sha256_oid = oid_tlv(&OID_SHA256);
        assert!(
            !attr
                .windows(sha256_oid.len())
                .any(|w| w == sha256_oid.as_slice()),
            "DEFAULT hashAlgorithm must be omitted"
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
        let low_pos = der
            .windows(low.len())
            .position(|w| w == low.as_slice())
            .expect("chain cert present");
        let high_pos = der
            .windows(high.len())
            .position(|w| w == high.as_slice())
            .expect("signer cert present");
        assert!(
            low_pos < high_pos,
            "certificates SET OF members must be in ascending DER order"
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
}
