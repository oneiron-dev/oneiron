//! Strict CMS ContentInfo/SignerInfo parsing with version gating.

use std::collections::BTreeMap;
use std::mem::size_of;

use der::{Decode, Encode};

use crate::api::SignatureAlgorithm;
use crate::error::SealError;
use crate::memory::{Held, LedgerHold, MemoryLedger, SealMemoryRefusal};
use crate::native::held_bytes;

use super::cms_err;
use super::der::{DerReader, Tlv};
use super::oids::{OID_ATTR_SIGNING_CERT_V2, OID_CT_TST_INFO, OID_DATA, OID_SIGNED_DATA};
use super::policy::{
    cert_signature_algorithm, ess_cert_id_v2, parse_attribute, sig_alg_permitted,
    verify_signature_value_for_cert,
};

/// Maximum issuer steps the issuer-link fallback follows from the leaf.
/// 10 is pkix-path-builder's default maximum path depth
/// (`DEFAULT_MAX_DEPTH`): a candidate longer than that cannot be the
/// path the builder would have chosen with an anchor, and without an
/// anchor it cannot pass trust however far it is followed.
const MAX_FALLBACK_PATH_DEPTH: usize = 10;

/// Maximum candidate signature verifications in one issuer-link walk.
/// A genuine path takes at most [`MAX_FALLBACK_PATH_DEPTH`] steps and
/// real bags carry a handful of same-subject issuers per step, so 256 is
/// far above a genuine walk; without it a bag of same-subject
/// certificates that sign nothing costs one public-key verification per
/// pair of certificates.
const MAX_FALLBACK_SIGNATURE_CHECKS: usize = 256;

#[cfg(test)]
std::thread_local! {
    /// Candidate signature verifications this thread's issuer-link walks
    /// have made since the last reset (tests only).
    static SIGNATURE_CHECKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn note_signature_check() {
    SIGNATURE_CHECKS.with(|count| count.set(count.get().saturating_add(1)));
}

#[cfg(not(test))]
fn note_signature_check() {}

#[cfg(test)]
fn reset_signature_checks() {
    SIGNATURE_CHECKS.with(|count| count.set(0));
}

#[cfg(test)]
fn signature_checks() -> usize {
    SIGNATURE_CHECKS.with(|count| count.get())
}

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

/// A copy of the certification path selected from `certificates` for the
/// certificate at `first`, held on `memory` before it is made (FIX 12260).
///
/// A CMS certificate bag is a set, not a path: it may carry certificates
/// that belong to no chain for this signer, and those are not copied.
/// When an anchor can decide, the copy is pkix-chain's chosen path: its
/// first path that validates at `at_unix`. Failing that, a candidate
/// path that follows key-bound issuer links from `first` through the
/// bag is copied (a name-only topological path to an anchor never
/// outranks it, so a root key rollover's cross-certificate is kept), or
/// the topological path when no key-bound candidate exists. When no
/// anchor-reachable path is chosen (for example a missing trust root,
/// where the path check is NotRun), the copy is that same issuer-link
/// candidate. Material outside the selected path must
/// not change a genuine result (EN 319 102-1 §5.1.3, §5.2.6.4 step 4).
///
/// # Errors
/// The ledger's refusal.
pub(crate) fn selected_chain_copy(
    certificates: &[Vec<u8>],
    first: usize,
    anchors: &[pkix_chain::TrustAnchor],
    at_unix: u64,
    memory: &MemoryLedger,
) -> Result<Held<Vec<Vec<u8>>>, SealMemoryRefusal> {
    if certificates.get(first).is_none() {
        return Ok(Held::new(Vec::new(), memory.hold(0)?));
    }
    // The bag decoded once, for path selection; its slots and decodes are
    // held while they are read, as in the token validators (FIX 12260).
    let slots = certificates
        .len()
        .saturating_mul(size_of::<Option<x509_cert::Certificate>>());
    let _slots_held = memory.hold(slots)?;
    let decoded: Vec<Option<x509_cert::Certificate>> = certificates
        .iter()
        .map(|der| x509_cert::Certificate::from_der(der).ok())
        .collect();
    let decoded_bytes = decoded
        .iter()
        .zip(certificates.iter())
        .fold(0usize, |sum, (cert, der)| {
            cert.as_ref().map_or(sum, |cert| {
                sum.saturating_add(held_bytes::certificate(cert, der.len()))
            })
        });
    let _decoded_held = memory.hold(decoded_bytes)?;
    let selected = selected_indices(certificates, &decoded, first, anchors, at_unix, memory)?;
    let bytes = selected.iter().fold(
        selected.len().saturating_mul(size_of::<Vec<u8>>()),
        |sum, idx| sum.saturating_add(certificates[*idx].len()),
    );
    let hold = memory.hold(bytes)?;
    let mut chain = Vec::with_capacity(selected.len());
    chain.extend(selected.iter().map(|idx| certificates[*idx].clone()));
    Ok(Held::new(chain, hold))
}

/// A copy of the whole certificate bag, held on `memory` before it is
/// made (FIX 12260). Envelope evidence carries it when the time at
/// which its path must be selected is not known yet: selection itself
/// stays in [`selected_chain_copy`].
///
/// # Errors
/// The ledger's refusal.
pub(crate) fn bag_copy(
    certificates: &[Vec<u8>],
    memory: &MemoryLedger,
) -> Result<Held<Vec<Vec<u8>>>, SealMemoryRefusal> {
    let bytes = certificates.iter().fold(
        certificates.len().saturating_mul(size_of::<Vec<u8>>()),
        |sum, der| sum.saturating_add(der.len()),
    );
    let hold = memory.hold(bytes)?;
    Ok(Held::new(certificates.to_vec(), hold))
}

/// The indices in `certificates` of the path [`selected_chain_copy`]
/// copies, leaf (`first`) first.
fn selected_indices(
    certificates: &[Vec<u8>],
    decoded: &[Option<x509_cert::Certificate>],
    first: usize,
    anchors: &[pkix_chain::TrustAnchor],
    at_unix: u64,
    memory: &MemoryLedger,
) -> Result<Vec<usize>, SealMemoryRefusal> {
    let Some(leaf) = decoded.get(first).and_then(Option::as_ref) else {
        return Ok(vec![first]);
    };
    if !anchors.is_empty() {
        let pool: pkix_chain::pkix_path_builder::CertPool =
            decoded.iter().filter_map(Option::as_ref).cloned().collect();
        let policy = pkix_chain::ValidationPolicy::new(at_unix);
        if let Ok(path) = pkix_chain::pkix_path_builder::build_first_valid_path(
            leaf,
            &pool,
            anchors,
            &policy,
            &pkix_chain::DefaultVerifier,
        ) {
            if let Some(indices) = path_indices(certificates, &path, first) {
                return Ok(indices);
            }
        }
        // No anchor-validated path was chosen. A key-bound issuer-link
        // candidate outranks the signature-unverified topological path
        // below: `build_path` stops at the first issuer name matching
        // an anchor subject, so under a root key rollover it truncates
        // the path at a certificate the old root key signed and never
        // reaches the cross-certificate the new root key signed. The
        // topological path stays the last resort, as in pkix-chain's
        // `build_with_aia`, so a candidate that cannot key-bind keeps
        // the Fail/NotRun shape its validation produces downstream.
        let candidate = issuer_link_indices(certificates, decoded, first, memory)?;
        if candidate.key_bound {
            return Ok(candidate.indices);
        }
        if let Ok(path) = pkix_chain::pkix_path_builder::build_path(leaf, &pool, anchors) {
            if let Some(indices) = path_indices(certificates, &path, first) {
                return Ok(indices);
            }
        }
        return Ok(candidate.indices);
    }
    Ok(issuer_link_indices(certificates, decoded, first, memory)?.indices)
}

/// The issuer-link candidate path from a leaf, and whether every issuer
/// step in it (and its self-signed end, when it has one) was bound by a
/// verified signature rather than by name alone or cut short by a bound.
struct IssuerLinkCandidate {
    indices: Vec<usize>,
    key_bound: bool,
}

/// A candidate issuer's signature algorithm, read from its certificate
/// at most once per issuer-link walk.
#[derive(Clone, Copy)]
enum CachedAlgorithm {
    Unknown,
    Unsupported,
    Supported(SignatureAlgorithm),
}

/// Follow issuer links from `first` through the bag: a key-bound issuer
/// (its key signed the certificate) always wins; a name match is the
/// candidate only when no candidate key verifies, as with a signature
/// suite this crate does not verify itself, and pkix-chain still judges
/// the candidate when an anchor is present.
///
/// The walk is bounded as the builder it stands in for is: candidates
/// are indexed by subject once, each walked certificate's TBS encoding
/// and each candidate's signature algorithm are made once and read from
/// the decoded certificates `selected_chain_copy` already held, and the
/// walk stops after [`MAX_FALLBACK_PATH_DEPTH`] issuer steps or
/// [`MAX_FALLBACK_SIGNATURE_CHECKS`] signature verifications. What was
/// walked is returned either way, so the partial candidate keeps its
/// downstream Fail/NotRun classification.
fn issuer_link_indices(
    certificates: &[Vec<u8>],
    decoded: &[Option<x509_cert::Certificate>],
    first: usize,
    memory: &MemoryLedger,
) -> Result<IssuerLinkCandidate, SealMemoryRefusal> {
    let by_subject = subject_index(decoded, memory)?;
    let _algorithms_held =
        memory.hold(decoded.len().saturating_mul(size_of::<CachedAlgorithm>()))?;
    let mut algorithms = vec![CachedAlgorithm::Unknown; decoded.len()];
    let mut checks = 0usize;
    let mut indices = vec![first];
    let mut key_bound = true;
    loop {
        let Some(&current) = indices.last() else {
            break;
        };
        let Some(cert) = decoded.get(current).and_then(Option::as_ref) else {
            key_bound = false;
            break;
        };
        // The TBS encoding of this certificate, made once for every
        // candidate this step tries (FIX 12260 holds it first).
        let Some(tbs) = tbs_der(cert, memory)? else {
            key_bound = false;
            break;
        };
        if cert.tbs_certificate.subject == cert.tbs_certificate.issuer {
            if checks >= MAX_FALLBACK_SIGNATURE_CHECKS {
                key_bound = false;
                break;
            }
            checks += 1;
            note_signature_check();
            if signature_verifies(
                cert,
                tbs.as_slice(),
                current,
                certificates,
                decoded,
                &mut algorithms,
            ) {
                break; // self-signed: the end of its candidate path
            }
        }
        if indices.len() > MAX_FALLBACK_PATH_DEPTH {
            key_bound = false;
            break;
        }
        let Some(issuer_der) = name_der(&cert.tbs_certificate.issuer, memory)? else {
            key_bound = false;
            break;
        };
        let candidates: &[usize] = by_subject
            .get(issuer_der.as_slice())
            .map_or(&[], Vec::as_slice);
        let mut issuer = None;
        let mut exhausted = false;
        for &idx in candidates {
            if indices.contains(&idx) {
                continue;
            }
            if checks >= MAX_FALLBACK_SIGNATURE_CHECKS {
                exhausted = true;
                break;
            }
            checks += 1;
            note_signature_check();
            if signature_verifies(
                cert,
                tbs.as_slice(),
                idx,
                certificates,
                decoded,
                &mut algorithms,
            ) {
                issuer = Some(idx);
                break;
            }
        }
        if exhausted && issuer.is_none() {
            key_bound = false;
            break;
        }
        let idx = match issuer {
            Some(idx) => idx,
            None => match candidates
                .iter()
                .copied()
                .find(|idx| !indices.contains(idx))
            {
                Some(idx) => {
                    // A name match only: no candidate key verified.
                    key_bound = false;
                    idx
                }
                None => break,
            },
        };
        indices.push(idx);
    }
    Ok(IssuerLinkCandidate { indices, key_bound })
}

/// The bag's decoded certificates by subject encoding: every certificate
/// whose subject could issue a walked certificate, in bag order. The
/// subjects, the index slots and the map are held on `memory` before
/// they are made (FIX 12260), and the returned hold keeps them admitted
/// for the walk. A subject that does not re-encode cannot be indexed
/// and is simply no step's candidate.
fn subject_index(
    decoded: &[Option<x509_cert::Certificate>],
    memory: &MemoryLedger,
) -> Result<Held<BTreeMap<Vec<u8>, Vec<usize>>>, SealMemoryRefusal> {
    let mut subject_bytes = 0usize;
    for cert in decoded.iter().filter_map(Option::as_ref) {
        if let Some(len) = cert
            .tbs_certificate
            .subject
            .encoded_len()
            .ok()
            .and_then(|len| usize::try_from(len).ok())
        {
            subject_bytes = subject_bytes.saturating_add(len);
        }
    }
    let bytes = subject_bytes
        .saturating_add(decoded.len().saturating_mul(size_of::<usize>()))
        .saturating_add(held_bytes::btree::<Vec<u8>, Vec<usize>>(decoded.len()));
    let hold = memory.hold(bytes)?;
    let mut by_subject = BTreeMap::new();
    for (idx, cert) in decoded.iter().enumerate() {
        let Some(cert) = cert.as_ref() else {
            continue;
        };
        let Ok(subject) = cert.tbs_certificate.subject.to_der() else {
            continue;
        };
        by_subject.entry(subject).or_default().push(idx);
    }
    Ok(Held::new(by_subject, hold))
}

/// `cert`'s TBS encoding, held on `memory` before it is made
/// (FIX 12260); `None` when it does not encode.
fn tbs_der(
    cert: &x509_cert::Certificate,
    memory: &MemoryLedger,
) -> Result<Option<Held<Vec<u8>>>, SealMemoryRefusal> {
    let Some(tbs_len) = cert
        .tbs_certificate
        .encoded_len()
        .ok()
        .and_then(|len| usize::try_from(len).ok())
    else {
        return Ok(None);
    };
    let hold = memory.hold(tbs_len)?;
    Ok(match cert.tbs_certificate.to_der() {
        Ok(tbs) => Some(Held::new(tbs, hold)),
        Err(_) => None,
    })
}

/// `name`'s encoding, held on `memory` before it is made (FIX 12260);
/// `None` when it does not encode.
fn name_der(
    name: &x509_cert::name::Name,
    memory: &MemoryLedger,
) -> Result<Option<Held<Vec<u8>>>, SealMemoryRefusal> {
    let Some(name_len) = name
        .encoded_len()
        .ok()
        .and_then(|len| usize::try_from(len).ok())
    else {
        return Ok(None);
    };
    let hold = memory.hold(name_len)?;
    Ok(match name.to_der() {
        Ok(der) => Some(Held::new(der, hold)),
        Err(_) => None,
    })
}

/// Whether the decoded certificate at `issuer_idx` signed `cert`: its
/// key's algorithm (made once per candidate and kept in `algorithms`)
/// is the frozen suite for `cert`'s signature and that signature
/// verifies over `tbs` under its already-decoded key. The caller has
/// matched names through the subject index (or subject with issuer,
/// for the self-signed end) and spends the signature-check budget.
fn signature_verifies(
    cert: &x509_cert::Certificate,
    tbs: &[u8],
    issuer_idx: usize,
    certificates: &[Vec<u8>],
    decoded: &[Option<x509_cert::Certificate>],
    algorithms: &mut [CachedAlgorithm],
) -> bool {
    let Some(issuer) = decoded.get(issuer_idx).and_then(Option::as_ref) else {
        return false;
    };
    let Some(issuer_der) = certificates.get(issuer_idx) else {
        return false;
    };
    let Some(slot) = algorithms.get_mut(issuer_idx) else {
        return false;
    };
    let algorithm = match *slot {
        CachedAlgorithm::Unknown => {
            let algorithm = cert_signature_algorithm(issuer_der)
                .ok()
                .map_or(CachedAlgorithm::Unsupported, CachedAlgorithm::Supported);
            *slot = algorithm;
            algorithm
        }
        cached => cached,
    };
    let CachedAlgorithm::Supported(alg) = algorithm else {
        return false;
    };
    sig_alg_permitted(alg, cert.signature_algorithm.oid.as_bytes())
        && verify_signature_value_for_cert(alg, issuer, tbs, cert.signature.raw_bytes()).is_ok()
}

/// `path` as indices into `certificates`, matched by DER encoding, when
/// every certificate of the path came from the bag and the leaf is first.
fn path_indices(
    certificates: &[Vec<u8>],
    path: &[x509_cert::Certificate],
    first: usize,
) -> Option<Vec<usize>> {
    if path.is_empty() {
        return None;
    }
    let mut indices = Vec::with_capacity(path.len());
    for cert in path {
        let der = cert.to_der().ok()?;
        let idx = certificates
            .iter()
            .enumerate()
            .find_map(|(idx, cand)| (!indices.contains(&idx) && cand == &der).then_some(idx))?;
        indices.push(idx);
    }
    (indices.first() == Some(&first)).then_some(indices)
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use der::Decode;

    use super::*;
    use crate::memory::testing::operation_ledger;

    /// 2026-07-30T08:00:00Z, the other fixtures' seal time.
    const AT_UNIX: u64 = 1_785_398_400;

    fn params_for(cn: &str, is_ca: rcgen::IsCa) -> rcgen::CertificateParams {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn.to_string());
        params.key_usages = if matches!(is_ca, rcgen::IsCa::Ca(_)) {
            vec![
                rcgen::KeyUsagePurpose::DigitalSignature,
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::CrlSign,
            ]
        } else {
            vec![rcgen::KeyUsagePurpose::DigitalSignature]
        };
        params.is_ca = is_ca;
        params
    }

    fn ca_key(cn: &str) -> (rcgen::CertificateParams, rcgen::KeyPair) {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = params_for(cn, rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained));
        (params, key_pair)
    }

    fn leaf_key(cn: &str) -> (rcgen::CertificateParams, rcgen::KeyPair) {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = params_for(cn, rcgen::IsCa::ExplicitNoCa);
        (params, key_pair)
    }

    fn issued_by(
        subject: &rcgen::CertificateParams,
        subject_key: &rcgen::KeyPair,
        issuer_params: &rcgen::CertificateParams,
        issuer_key: &rcgen::KeyPair,
    ) -> Vec<u8> {
        let issuer = rcgen::Issuer::from_params(issuer_params, issuer_key);
        subject
            .signed_by(subject_key, &issuer)
            .unwrap()
            .der()
            .to_vec()
    }

    #[test]
    fn rollover_cross_certificate_is_not_truncated_by_anchor_name() {
        // Root key rollover: the only anchor is the new root (key Kn).
        // The intermediate was signed by the old root key Ko, and the
        // bag carries the OldWithNew cross-certificate (subject
        // CN=rollover-root, key Ko, signed by Kn). The topological
        // builder stops at the intermediate, whose issuer name matches
        // the anchor subject, so a name-bound selection truncates the
        // path there and fails under Kn; the key-bound selection must
        // walk on through the cross-certificate to the new root.
        let (new_params, new_key) = ca_key("rollover-root");
        let new_root = new_params.self_signed(&new_key).unwrap().der().to_vec();
        let (old_params, old_key) = ca_key("rollover-root");
        let old_with_new = issued_by(&old_params, &old_key, &new_params, &new_key);
        let (inter_params, inter_key) = ca_key("rollover-intermediate");
        let inter = issued_by(&inter_params, &inter_key, &old_params, &old_key);
        let (leaf_params, leaf_key) = leaf_key("rollover-leaf");
        let leaf = issued_by(&leaf_params, &leaf_key, &inter_params, &inter_key);

        let anchor = x509_cert::Certificate::from_der(&new_root).unwrap();
        let anchors = vec![pkix_chain::TrustAnchor::from_cert(anchor)];
        // Bag order is a set's: the leaf is last and the path order is
        // nowhere in it.
        let bag = vec![
            new_root.clone(),
            old_with_new.clone(),
            inter.clone(),
            leaf.clone(),
        ];
        let memory = operation_ledger();
        let chain = selected_chain_copy(&bag, 3, &anchors, AT_UNIX, &memory).unwrap();
        assert_eq!(*chain, vec![leaf, inter, old_with_new, new_root]);
        let decoded_chain: Vec<x509_cert::Certificate> = chain
            .iter()
            .map(|der| x509_cert::Certificate::from_der(der).unwrap())
            .collect();
        pkix_chain::verify_chain(
            &decoded_chain,
            &anchors,
            &pkix_chain::ValidationPolicy::new(AT_UNIX),
            &pkix_chain::DefaultVerifier,
            &pkix_chain::NoRevocation,
            &pkix_chain::NoAiaFetcher,
        )
        .unwrap();
    }

    #[test]
    fn same_subject_bag_signature_checks_are_bounded() {
        // No anchors: the leaf's issuer key is not in the bag at all,
        // and 48 further certificates share that issuer's subject
        // (subject = issuer) with keys that signed nothing in the bag.
        // An unbounded issuer-link walk tries every remaining
        // certificate at every step it name-walks (over a thousand
        // verifications and a 49-certificate candidate here); the
        // bounded walk stops at the signature-check budget (256) and
        // the path-depth bound (the leaf plus 10 issuer steps).
        let (ext_params, ext_key) = ca_key("bag-issuer");
        let (leaf_params, leaf_key) = leaf_key("bag-leaf");
        let leaf = issued_by(&leaf_params, &leaf_key, &ext_params, &ext_key);
        let mut bag = vec![leaf];
        for _ in 0..48 {
            let (params, key_pair) = ca_key("bag-issuer");
            bag.push(issued_by(&params, &key_pair, &ext_params, &ext_key));
        }
        let memory = operation_ledger();
        reset_signature_checks();
        let chain = selected_chain_copy(&bag, 0, &[], AT_UNIX, &memory).unwrap();
        let checks = signature_checks();
        assert!(
            checks <= 256,
            "signature checks are budget-bound, got {checks}"
        );
        assert!(
            chain.len() <= 11,
            "candidate path is depth-bound, got {} certificates",
            chain.len()
        );
        assert_eq!(&chain[0], &bag[0], "the leaf stays first");
    }
}
