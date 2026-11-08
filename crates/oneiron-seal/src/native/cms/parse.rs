//! Strict CMS ContentInfo/SignerInfo parsing with version gating.

use std::mem::size_of;

use crate::error::SealError;
use crate::memory::{Held, LedgerHold, MemoryLedger, SealMemoryRefusal};

use super::cms_err;
use super::der::{DerReader, Tlv};
use super::oids::{OID_ATTR_SIGNING_CERT_V2, OID_CT_TST_INFO, OID_DATA, OID_SIGNED_DATA};
use super::policy::{ess_cert_id_v2, parse_attribute};

/// Why a CMS envelope or timestamp token was not validated: the token itself, or memory
/// its copies and decodes were refused, which ends the operation as the
/// seal's memory error, never as an invalid token (FIX 12260).
#[derive(Debug)]
pub(crate) enum TokenError {
    /// The token fails a check; every caller treats each check alike.
    Invalid,
    Memory(SealMemoryRefusal),
}

impl From<SealError> for TokenError {
    fn from(_: SealError) -> Self {
        Self::Invalid
    }
}

impl From<SealMemoryRefusal> for TokenError {
    fn from(refusal: SealMemoryRefusal) -> Self {
        Self::Memory(refusal)
    }
}

/// Copies a retained field only after its bytes are held on the parse's ledger.
fn copy_field(
    bytes: &[u8],
    memory: &MemoryLedger,
    hold: &mut LedgerHold,
) -> Result<Vec<u8>, TokenError> {
    memory.extend_hold(hold, u64::try_from(bytes.len()).unwrap_or(u64::MAX))?;
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| SealMemoryRefusal::Floor {
            needed: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            available: 0,
        })?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

/// Holds both allocations during replacement; only the old charged slots are
/// returned once the reallocation succeeds. Allocator slack is never a credit.
fn push_field<T>(
    items: &mut Vec<T>,
    charged: &mut u64,
    value: T,
    memory: &MemoryLedger,
    hold: &mut LedgerHold,
) -> Result<(), TokenError> {
    if items.len() == items.capacity() {
        let overflow = || SealMemoryRefusal::Floor {
            needed: u64::MAX,
            available: 0,
        };
        let needed = items.len().checked_add(1).ok_or_else(overflow)?;
        let capacity = needed.max(items.capacity().saturating_mul(2));
        let bytes = capacity.checked_mul(size_of::<T>()).ok_or_else(overflow)?;
        let bytes = u64::try_from(bytes).map_err(|_| overflow())?;
        memory.extend_hold(hold, bytes)?;
        items
            .try_reserve_exact(capacity - items.len())
            .map_err(|_| SealMemoryRefusal::Floor {
                needed: bytes,
                available: 0,
            })?;
        hold.shrink(*charged);
        *charged = bytes;
    }
    items.push(value);
    Ok(())
}

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

fn parse_signer_info(
    tlv_bytes: &[u8],
    memory: &MemoryLedger,
    hold: &mut LedgerHold,
) -> Result<ParsedSignerInfo, TokenError> {
    let top = DerReader::new(tlv_bytes).expect(0x30)?;
    let mut r = DerReader::new(top.content);
    let version = r.expect(0x02)?;
    if version.content != [1] {
        return Err(cms_err().into());
    }
    let sid = r.expect(0x30)?;
    let mut sid_r = DerReader::new(sid.content);
    // Read in place, never copied (FIX 12260).
    let sid_issuer = sid_r.expect(0x30)?.full; // issuer Name TLV
    let sid_serial = sid_r.expect(0x02)?.full; // serialNumber TLV
    let digest_alg = r.expect(0x30)?;
    let digest_oid = copy_field(
        DerReader::new(digest_alg.content).expect(0x06)?.content,
        memory,
        hold,
    )?;
    let attrs_field = r.expect(0xA0)?;
    // Canonicality: attributes must be strictly sorted by DER octets.
    let mut attrs_r = DerReader::new(attrs_field.content);
    let mut signed_attrs = Vec::new();
    let mut signed_slots = 0;
    while !attrs_r.is_done() {
        let a = attrs_r.expect(0x30)?;
        if signed_attrs
            .last()
            .is_some_and(|last: &Vec<u8>| last.as_slice() >= a.full)
        {
            return Err(cms_err().into()); // unsorted or duplicate
        }
        let attr = copy_field(a.full, memory, hold)?;
        push_field(&mut signed_attrs, &mut signed_slots, attr, memory, hold)?;
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
                return Err(cms_err().into());
            }
        }
    }
    let sig_alg = r.expect(0x30)?;
    let sig_oid = copy_field(
        DerReader::new(sig_alg.content).expect(0x06)?.content,
        memory,
        hold,
    )?;
    let signature = copy_field(r.expect(0x04)?.content, memory, hold)?;
    let mut unsigned_attrs = Vec::new();
    let mut unsigned_slots = 0;
    if !r.is_done() {
        let ua = r.expect(0xA1)?;
        let mut ua_r = DerReader::new(ua.content);
        while !ua_r.is_done() {
            let attr = copy_field(ua_r.expect(0x30)?.full, memory, hold)?;
            push_field(&mut unsigned_attrs, &mut unsigned_slots, attr, memory, hold)?;
        }
    }
    if !r.is_done() {
        return Err(cms_err().into());
    }
    Ok(ParsedSignerInfo {
        digest_alg_oid: digest_oid,
        signed_attrs,
        signed_attrs_content: copy_field(attrs_field.content, memory, hold)?,
        signature_alg_oid: sig_oid,
        signature,
        unsigned_attrs,
    })
}

/// Parse a detached CMS ContentInfo. Strict DER only; exactly one signer.
pub(crate) fn parse_cms(der: &[u8], memory: &MemoryLedger) -> Result<Held<ParsedCms>, TokenError> {
    let mut hold = memory.hold(0)?;
    let parsed = (|| -> Result<ParsedCms, TokenError> {
        let mut top = DerReader::new(der);
        let ci = top.expect(0x30)?;
        if !top.is_done() {
            return Err(cms_err().into()); // trailing bytes after ContentInfo
        }
        let mut r = DerReader::new(ci.content);
        let content_oid = copy_field(r.expect(0x06)?.content, memory, &mut hold)?;
        if content_oid != OID_SIGNED_DATA.as_bytes() {
            return Err(cms_err().into());
        }
        let sd_wrapper = r.expect(0xA0)?;
        let sd = DerReader::new(sd_wrapper.content).expect(0x30)?;
        if !r.is_done() {
            return Err(cms_err().into());
        }
        let mut s = DerReader::new(sd.content);
        // SignedData.version is enforced below, once eContentType is known:
        // RFC 5652 §5.1 makes the version a FUNCTION of the encapsulated
        // content type, so the two must be checked as a pair.
        let sd_version = s.expect(0x02)?;
        let digest_set = s.expect(0x31)?;
        let mut digest_algs = Vec::new();
        let mut digest_slots = 0;
        let mut dr = DerReader::new(digest_set.content);
        while !dr.is_done() {
            let alg = dr.expect(0x30)?;
            let oid = copy_field(
                DerReader::new(alg.content).expect(0x06)?.content,
                memory,
                &mut hold,
            )?;
            push_field(&mut digest_algs, &mut digest_slots, oid, memory, &mut hold)?;
        }
        let eci = s.expect(0x30)?;
        let mut eci_r = DerReader::new(eci.content);
        let econtent_oid = copy_field(eci_r.expect(0x06)?.content, memory, &mut hold)?;
        let econtent = if eci_r.is_done() {
            None
        } else {
            let wrapper = eci_r.expect(0xA0)?;
            let os = DerReader::new(wrapper.content).expect(0x04)?;
            Some(copy_field(os.content, memory, &mut hold)?)
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
            return Err(cms_err().into());
        };
        if sd_version.content != required_version {
            return Err(cms_err().into());
        }
        let mut certificates = Vec::new();
        let mut certificate_slots = 0;
        let mut seen_certificates = false;
        let mut signer_info_der = None;
        while !s.is_done() {
            let t = s.read()?;
            match t.tag {
                0xA0 => {
                    if seen_certificates {
                        return Err(cms_err().into()); // repeated certificates field
                    }
                    seen_certificates = true;
                    let mut cr = DerReader::new(t.content);
                    while !cr.is_done() {
                        let certificate = copy_field(cr.expect(0x30)?.full, memory, &mut hold)?;
                        push_field(
                            &mut certificates,
                            &mut certificate_slots,
                            certificate,
                            memory,
                            &mut hold,
                        )?;
                    }
                }
                0x31 => {
                    if signer_info_der.is_some() {
                        return Err(cms_err().into()); // a second signerInfos SET must not overwrite
                    }
                    let mut sr = DerReader::new(t.content);
                    let first = sr.expect(0x30)?;
                    if !sr.is_done() {
                        return Err(cms_err().into()); // exactly one SignerInfo
                    }
                    signer_info_der = Some(first.full);
                }
                _ => return Err(cms_err().into()), // crls/other fields not used in v1
            }
        }
        let signer_info_der = signer_info_der.ok_or_else(cms_err)?;
        Ok(ParsedCms {
            content_oid,
            digest_algs,
            econtent_oid,
            econtent,
            certificates,
            signer: parse_signer_info(signer_info_der, memory, &mut hold)?,
        })
    })()?;
    Ok(Held::new(parsed, hold))
}

/// A copy of `certificates` as a chain, the one at `first` first and the
/// others in their order, held on `memory` before it is made (FIX 12260).
///
/// # Errors
/// The ledger's refusal.
pub(crate) fn chain_copy(
    certificates: &[Vec<u8>],
    first: usize,
    memory: &MemoryLedger,
) -> Result<Held<Vec<Vec<u8>>>, SealMemoryRefusal> {
    let bytes = certificates.iter().fold(
        certificates.len().saturating_mul(size_of::<Vec<u8>>()),
        |sum, der| sum.saturating_add(der.len()),
    );
    let hold = memory.hold(bytes)?;
    let mut chain = Vec::with_capacity(certificates.len());
    chain.extend(certificates.get(first).cloned());
    chain.extend(
        certificates
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != first)
            .map(|(_, der)| der.clone()),
    );
    Ok(Held::new(chain, hold))
}

/// Rebuild the RFC 5652 §5.4 signature input from parsed signed attributes:
/// the same content octets under the universal `SET OF` tag.
pub(crate) fn signed_attrs_signature_input(
    signer: &ParsedSignerInfo,
    memory: &MemoryLedger,
) -> Result<Held<Vec<u8>>, SealMemoryRefusal> {
    let content = &signer.signed_attrs_content;
    let be = content.len().to_be_bytes();
    let start = be.iter().position(|b| *b != 0).unwrap_or(be.len() - 1);
    let significant = &be[start..];
    let short = content.len() < 0x80;
    let header = if short { 2 } else { 2 + significant.len() };
    let total = content
        .len()
        .checked_add(header)
        .ok_or(SealMemoryRefusal::Floor {
            needed: u64::MAX,
            available: 0,
        })?;
    let hold = memory.hold(total)?;
    let mut out = Vec::new();
    out.try_reserve_exact(total)
        .map_err(|_| SealMemoryRefusal::Floor {
            needed: u64::try_from(total).unwrap_or(u64::MAX),
            available: 0,
        })?;
    out.push(0x31);
    if short {
        out.push(content.len() as u8);
    } else {
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(content);
    Ok(Held::new(out, hold))
}
