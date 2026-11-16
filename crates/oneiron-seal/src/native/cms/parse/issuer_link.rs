//! Bounded certificate-signature issuer walks for CMS certificate bags.

use std::collections::BTreeMap;
use std::mem::size_of;

use der::{Encode, referenced::OwnedToRef};
use pkix_chain::SignatureVerifier;

use crate::memory::{Held, MemoryLedger, SealMemoryRefusal};
use crate::native::held_bytes;

use super::{MAX_FALLBACK_PATH_DEPTH, MAX_FALLBACK_SIGNATURE_CHECKS, note_signature_check};

/// The issuer-link candidate path from a leaf, and whether every issuer
/// step in it (and its self-signed end, when it has one) was bound by a
/// verified signature rather than by name alone or cut short by a bound.
pub(super) struct IssuerLinkCandidate {
    pub(super) indices: Vec<usize>,
    pub(super) key_bound: bool,
}

/// Follow issuer links from `first` through the bag: a key-bound issuer
/// (its key signed the certificate) always wins; a name match is the
/// candidate only when no candidate key verifies, and pkix-chain still
/// judges the candidate when an anchor is present.
///
/// The walk is bounded as the builder it stands in for is: candidates
/// are indexed by subject once, each walked certificate's TBS encoding
/// is made once, and issuer keys are read from the decoded certificates
/// [`super::selected_chain_copy`] already held. The walk stops after
/// [`MAX_FALLBACK_PATH_DEPTH`] issuer steps or
/// [`MAX_FALLBACK_SIGNATURE_CHECKS`] signature verifications. What was
/// walked is returned either way, so the partial candidate keeps its
/// downstream Fail/NotRun classification.
pub(super) fn issuer_link_indices(
    decoded: &[Option<x509_cert::Certificate>],
    first: usize,
    memory: &MemoryLedger,
) -> Result<IssuerLinkCandidate, SealMemoryRefusal> {
    let by_subject = subject_index(decoded, memory)?;
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
            if signature_verifies(cert, tbs.as_slice(), current, decoded) {
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
            if signature_verifies(cert, tbs.as_slice(), idx, decoded) {
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
    let mut by_subject: BTreeMap<Vec<u8>, Vec<usize>> = BTreeMap::new();
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

/// Whether the decoded issuer at `issuer_idx` signed `cert`, using the
/// same certificate-signature algorithms as pkix chain validation, not
/// the narrower CMS SignerInfo signing suites. The caller matches names
/// and spends the signature-check budget.
fn signature_verifies(
    cert: &x509_cert::Certificate,
    tbs: &[u8],
    issuer_idx: usize,
    decoded: &[Option<x509_cert::Certificate>],
) -> bool {
    let Some(issuer) = decoded.get(issuer_idx).and_then(Option::as_ref) else {
        return false;
    };
    pkix_chain::DefaultVerifier
        .verify_signature(
            cert.signature_algorithm.owned_to_ref(),
            issuer
                .tbs_certificate
                .subject_public_key_info
                .owned_to_ref(),
            tbs,
            cert.signature.raw_bytes(),
        )
        .is_ok()
}
