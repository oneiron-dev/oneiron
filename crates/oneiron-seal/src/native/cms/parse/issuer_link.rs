//! Bounded certificate-signature issuer walks for CMS certificate bags.

use std::cell::Cell;
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
    first_issuer_link_indices(decoded, first, memory, &Cell::new(0))
}

fn first_issuer_link_indices(
    decoded: &[Option<x509_cert::Certificate>],
    first: usize,
    memory: &MemoryLedger,
    checks: &Cell<usize>,
) -> Result<IssuerLinkCandidate, SealMemoryRefusal> {
    let by_subject = subject_index(decoded, memory)?;
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
            if checks.get() >= MAX_FALLBACK_SIGNATURE_CHECKS {
                key_bound = false;
                break;
            }
            checks.set(checks.get() + 1);
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
            if checks.get() >= MAX_FALLBACK_SIGNATURE_CHECKS {
                exhausted = true;
                break;
            }
            checks.set(checks.get() + 1);
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

/// Keep the first-match candidate for failure reporting, but prefer a
/// complete key-bound path that validates under the caller's policy.
/// The initial walk, alternatives and full validations share one budget.
pub(super) fn validated_issuer_link_indices(
    decoded: &[Option<x509_cert::Certificate>],
    first: usize,
    anchors: &[pkix_chain::TrustAnchor],
    policy: &pkix_chain::ValidationPolicy,
    memory: &MemoryLedger,
) -> Result<IssuerLinkCandidate, SealMemoryRefusal> {
    let checks = Cell::new(0);
    let candidate = first_issuer_link_indices(decoded, first, memory, &checks)?;
    let search = ValidatingSearch {
        decoded,
        by_subject: subject_index(decoded, memory)?,
        anchors,
        policy,
        memory,
        verifier: BoundedVerifier(&checks),
    };
    if candidate.key_bound && search.validates(&candidate.indices)? {
        return Ok(candidate);
    }
    let _indices_held =
        memory.hold((MAX_FALLBACK_PATH_DEPTH + 1).saturating_mul(size_of::<usize>()))?;
    let mut indices = Vec::with_capacity(MAX_FALLBACK_PATH_DEPTH + 1);
    indices.push(first);
    if search.walk(&mut indices, &candidate.indices)? {
        return Ok(IssuerLinkCandidate {
            indices,
            key_bound: true,
        });
    }
    Ok(candidate)
}

struct ValidatingSearch<'a> {
    decoded: &'a [Option<x509_cert::Certificate>],
    by_subject: Held<BTreeMap<Vec<u8>, Vec<usize>>>,
    anchors: &'a [pkix_chain::TrustAnchor],
    policy: &'a pkix_chain::ValidationPolicy,
    memory: &'a MemoryLedger,
    verifier: BoundedVerifier<'a>,
}

impl ValidatingSearch<'_> {
    fn walk(
        &self,
        indices: &mut Vec<usize>,
        rejected: &[usize],
    ) -> Result<bool, SealMemoryRefusal> {
        let Some(&current) = indices.last() else {
            return Ok(false);
        };
        let Some(cert) = self.decoded.get(current).and_then(Option::as_ref) else {
            return Ok(false);
        };
        let Some(tbs) = tbs_der(cert, self.memory)? else {
            return Ok(false);
        };
        if cert.tbs_certificate.subject == cert.tbs_certificate.issuer
            && signature_verifies_with(cert, tbs.as_slice(), current, self.decoded, &self.verifier)
        {
            if indices.as_slice() != rejected && self.validates(indices)? {
                return Ok(true);
            }
            // An untrusted self-signed end may also have a cross-signed
            // issuer alternative; a failed completion must not hide it.
        }
        if indices.len() > MAX_FALLBACK_PATH_DEPTH || self.verifier.exhausted() {
            return Ok(false);
        }
        let Some(issuer_der) = name_der(&cert.tbs_certificate.issuer, self.memory)? else {
            return Ok(false);
        };
        let candidates = self
            .by_subject
            .get(issuer_der.as_slice())
            .map_or(&[][..], Vec::as_slice);
        let capacity = candidates.len().min(MAX_FALLBACK_SIGNATURE_CHECKS);
        let _alternatives_held = self
            .memory
            .hold(capacity.saturating_mul(size_of::<usize>()))?;
        let mut alternatives = Vec::with_capacity(capacity);
        for &idx in candidates {
            if self.verifier.exhausted() {
                break;
            }
            if !indices.contains(&idx)
                && signature_verifies_with(cert, tbs.as_slice(), idx, self.decoded, &self.verifier)
            {
                alternatives.push(idx);
            }
        }
        if alternatives.is_empty() {
            return if indices.as_slice() != rejected {
                self.validates(indices)
            } else {
                Ok(false)
            };
        }
        for idx in alternatives {
            indices.push(idx);
            if self.walk(indices, rejected)? {
                return Ok(true);
            }
            indices.pop();
            if self.verifier.exhausted() {
                break;
            }
        }
        Ok(false)
    }

    fn validates(&self, indices: &[usize]) -> Result<bool, SealMemoryRefusal> {
        let bytes = indices
            .iter()
            .filter_map(|&idx| self.decoded[idx].as_ref())
            .fold(
                indices
                    .len()
                    .saturating_mul(size_of::<x509_cert::Certificate>()),
                |sum, cert| {
                    let der_len = cert
                        .encoded_len()
                        .ok()
                        .and_then(|len| usize::try_from(len).ok())
                        .unwrap_or(0);
                    sum.saturating_add(held_bytes::certificate(cert, der_len))
                },
            );
        let _chain_held = self.memory.hold(bytes)?;
        let mut chain = Vec::with_capacity(indices.len());
        chain.extend(indices.iter().filter_map(|&idx| self.decoded[idx].clone()));
        Ok(
            pkix_chain::pkix_path::validate_path(&chain, self.anchors, self.policy, &self.verifier)
                .is_ok(),
        )
    }
}

/// Full PKIX validation spends the same signature budget as issuer discovery.
struct BoundedVerifier<'a>(&'a Cell<usize>);

impl BoundedVerifier<'_> {
    fn exhausted(&self) -> bool {
        self.0.get() >= MAX_FALLBACK_SIGNATURE_CHECKS
    }
}

impl SignatureVerifier for BoundedVerifier<'_> {
    fn verify_signature(
        &self,
        algorithm: spki::AlgorithmIdentifierRef<'_>,
        issuer_spki: spki::SubjectPublicKeyInfoRef<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), signature::Error> {
        if self.exhausted() {
            return Err(signature::Error::new());
        }
        self.0.set(self.0.get() + 1);
        note_signature_check();
        pkix_chain::DefaultVerifier.verify_signature(algorithm, issuer_spki, message, signature)
    }
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
    signature_verifies_with(cert, tbs, issuer_idx, decoded, &pkix_chain::DefaultVerifier)
}

fn signature_verifies_with(
    cert: &x509_cert::Certificate,
    tbs: &[u8],
    issuer_idx: usize,
    decoded: &[Option<x509_cert::Certificate>],
    verifier: &impl SignatureVerifier,
) -> bool {
    let Some(issuer) = decoded.get(issuer_idx).and_then(Option::as_ref) else {
        return false;
    };
    verifier
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
