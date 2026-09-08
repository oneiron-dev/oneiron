//! Strict CMS ContentInfo/SignerInfo parsing with version gating.

use crate::error::SealError;

use super::cms_err;
use super::der::{DerReader, Tlv, tlv};
use super::oids::{OID_ATTR_SIGNING_CERT_V2, OID_CT_TST_INFO, OID_DATA, OID_SIGNED_DATA};
use super::policy::{ess_cert_id_v2, parse_attribute};

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

pub(super) fn parse_oid(t: Tlv) -> Result<Vec<u8>, SealError> {
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
    let sid_issuer = sid_r.expect(0x30)?.full.to_vec(); // issuer Name TLV
    let sid_serial = sid_r.expect(0x02)?.full.to_vec(); // serialNumber TLV
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
    // sid/ESS consistency (conformance hardening): when a
    // signingCertificateV2 attribute is present, its issuerSerial must name
    // the SAME issuer/serial as the SignerInfo sid; a disagreement is
    // rejected rather than silently decided by the ESS alone.
    for attr in &signed_attrs {
        let (oid, _) = parse_attribute(attr)?;
        if oid == OID_ATTR_SIGNING_CERT_V2.as_bytes() {
            let (_, ess_issuer, ess_serial) = ess_cert_id_v2(attr)?;
            if ess_issuer != sid_issuer || ess_serial != sid_serial {
                return Err(cms_err());
            }
        }
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
    // SignedData.version is enforced below, once eContentType is known:
    // RFC 5652 §5.1 makes the version a FUNCTION of the encapsulated
    // content type, so the two must be checked as a pair.
    let sd_version = s.expect(0x02)?;
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
    // RFC 5652 §5.1: the SignedData version is DETERMINED by eContentType —
    // version 1 iff the content type is id-data, version 3 whenever it is
    // anything else. This parser implements exactly two encapsulations, so
    // each is pinned to the one version the standard permits for it:
    //   id-data       (detached CAdES document signature) => 1
    //   id-ct-TSTInfo (RFC 3161 timestamp token)          => 3
    // Both are single-signer / issuerAndSerialNumber shapes; a mismatched
    // pair, or any other content type, is a shape this parser would read
    // under the wrong field layout — reject it rather than guess.
    let required_version: &[u8] = if econtent_oid == OID_DATA.as_bytes() {
        &[1]
    } else if econtent_oid == OID_CT_TST_INFO.as_bytes() {
        &[3]
    } else {
        return Err(cms_err());
    };
    if sd_version.content != required_version {
        return Err(cms_err());
    }
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
