//! Resolve signer history separately from archival material coverage.
//! An append cannot erase an earlier trusted proof of existence.
use super::verify_evidence::{EnvelopeEvidence, TimeSource, TrustedTimeProof};

pub(super) struct SignerValidationTime {
    pub at: u64,
    pub source: Option<TimeSource>,
}

pub(super) struct ArchivalCoverage {
    pub timestamp: usize,
    pub signer: usize,
    pub material_end: u64,
    pub at: u64,
}
impl ArchivalCoverage {
    pub(super) fn supports(&self, signer: usize, material_end: u64) -> bool {
        self.signer == signer && self.material_end == material_end
    }
}

fn complete_document_proof(owner: &EnvelopeEvidence, proof: &TrustedTimeProof) -> bool {
    matches!(proof.source, TimeSource::DocumentTimestamp { envelope, revision }
        if envelope == owner.index && owner.revision == Some(revision)
            && proof.covers_to >= revision.eof_end as u64)
}

fn doc_covers_signer(
    owner: &EnvelopeEvidence,
    proof: &TrustedTimeProof,
    signer: &EnvelopeEvidence,
) -> bool {
    complete_document_proof(owner, proof)
        && owner.index != signer.index
        && signer.revision.is_some_and(|signed| {
            owner
                .revision
                .is_some_and(|timestamp| timestamp.index > signed.index)
        })
        && signer
            .byte_range
            .covers_to
            .is_some_and(|end| proof.covers_to >= end)
}

pub(super) fn signer_validation_time(
    signer: &EnvelopeEvidence,
    all: &[EnvelopeEvidence],
    clock: u64,
) -> SignerValidationTime {
    let proof = all
        .iter()
        .filter_map(|envelope| {
            let proof = envelope.time_proof.as_ref()?;
            let eligible = match proof.source {
                TimeSource::SignatureTimestamp { signer: owner } => owner == signer.index,
                TimeSource::DocumentTimestamp { .. } => doc_covers_signer(envelope, proof, signer),
            };
            eligible.then_some((envelope.index, proof))
        })
        .min_by_key(|(index, proof)| (proof.gen_time, *index));
    proof.map_or(
        SignerValidationTime {
            at: clock,
            source: None,
        },
        |(_, proof)| SignerValidationTime {
            at: proof.gen_time,
            source: Some(proof.source),
        },
    )
}

/// A document timestamp is archival only if its own complete revision is
/// proven and it covers the effective DSS as well as this signer.
pub(super) fn archival_coverage(
    signer: &EnvelopeEvidence,
    all: &[EnvelopeEvidence],
    dss_end: Option<u64>,
) -> Option<ArchivalCoverage> {
    let material_end = dss_end?;
    all.iter()
        .filter_map(|envelope| {
            let proof = envelope.time_proof.as_ref()?;
            (doc_covers_signer(envelope, proof, signer) && proof.covers_to >= material_end)
                .then_some((envelope.index, proof))
        })
        .min_by_key(|(index, proof)| (proof.gen_time, *index))
        .map(|(timestamp, proof)| ArchivalCoverage {
            timestamp,
            signer: signer.index,
            material_end,
            at: proof.gen_time,
        })
}

/// Document-level DSS status cannot borrow signer time: use the earliest
/// complete trusted timestamp that covers the effective material.
/// Provisional token time is a diagnostic bound ONLY for the missing-root
/// material probe. It never feeds signer validation or achieved profiles.
pub(super) fn provisional_material_time(
    all: &[EnvelopeEvidence],
    dss_end: Option<u64>,
    signer: Option<&EnvelopeEvidence>,
    clock: u64,
) -> u64 {
    let Some(material_end) = dss_end else {
        return clock;
    };
    all.iter()
        .filter_map(|e| {
            if e.kind != crate::api::SignatureKind::DocumentTimestamp {
                return None;
            }
            let time = e.untrusted_time?;
            let revision = e.revision?;
            let covers = e.byte_range.covers_to?;
            if covers < material_end || covers < revision.eof_end as u64 {
                return None;
            }
            if let Some(signer) = signer {
                let signed = signer.revision?;
                if revision.index <= signed.index {
                    return None;
                }
            }
            Some(time)
        })
        .min()
        .unwrap_or(clock)
}

pub(super) fn material_validation_time(
    all: &[EnvelopeEvidence],
    dss_end: Option<u64>,
    clock: u64,
) -> u64 {
    let Some(material_end) = dss_end else {
        return clock;
    };
    all.iter()
        .filter_map(|envelope| {
            let proof = envelope.time_proof.as_ref()?;
            (complete_document_proof(envelope, proof) && proof.covers_to >= material_end)
                .then_some((envelope.index, proof.gen_time))
        })
        .min_by_key(|(index, time)| (*time, *index))
        .map_or(clock, |(_, time)| time)
}
