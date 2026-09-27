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

#[cfg(test)]
mod tests {
    use super::super::super::pdf::RevisionBoundary;
    use super::*;
    use crate::api::{ByteRangeEvidence, Coverage, SignatureKind};

    fn envelope(
        index: usize,
        kind: SignatureKind,
        time: Option<(TimeSource, u64)>,
    ) -> EnvelopeEvidence {
        let is_doc = kind == SignatureKind::DocumentTimestamp;
        EnvelopeEvidence {
            index,
            id: index.to_string(),
            kind,
            byte_range: ByteRangeEvidence {
                values: [0; 4],
                well_formed: true,
                covers_to: Some(if is_doc { 300 } else { 100 }),
                file_len: 300,
            },
            coverage: Coverage::EntireRevision,
            digest: None,
            revision: Some(RevisionBoundary {
                index: if is_doc { index + 1 } else { index },
                eof_end: if is_doc { 300 } else { 100 },
            }),
            checks: vec![],
            signer_chain: None,
            time_proof: time.map(|(source, gen_time)| TrustedTimeProof {
                source,
                gen_time,
                tsa_chain_ders: vec![],
                covers_to: 300,
            }),
            covered: vec![],
        }
    }

    #[test]
    fn earliest_trusted_time_wins_by_time_not_timestamp_form_or_revision_order() {
        let sig = envelope(
            0,
            SignatureKind::Signature,
            Some((TimeSource::SignatureTimestamp { signer: 0 }, 200)),
        );
        let doc = envelope(
            1,
            SignatureKind::DocumentTimestamp,
            Some((
                TimeSource::DocumentTimestamp {
                    envelope: 1,
                    revision: RevisionBoundary {
                        index: 2,
                        eof_end: 300,
                    },
                },
                100,
            )),
        );
        let items = [sig, doc];
        let chosen = signer_validation_time(&items[0], &items, 400);
        assert_eq!(chosen.at, 100);
        assert!(matches!(
            chosen.source,
            Some(TimeSource::DocumentTimestamp { .. })
        ));
        assert!(
            archival_coverage(&items[0], &items, Some(350)).is_none(),
            "an earlier proof cannot attest later material"
        );
        let archive = archival_coverage(&items[0], &items, Some(250)).unwrap();
        assert!(archive.supports(0, 250));
        assert_eq!(archive.at, 100);
        assert_eq!(archive.timestamp, 1);
        let sig = envelope(
            0,
            SignatureKind::Signature,
            Some((TimeSource::SignatureTimestamp { signer: 0 }, 50)),
        );
        let doc = envelope(
            1,
            SignatureKind::DocumentTimestamp,
            Some((
                TimeSource::DocumentTimestamp {
                    envelope: 1,
                    revision: RevisionBoundary {
                        index: 2,
                        eof_end: 300,
                    },
                },
                100,
            )),
        );
        let items = [sig, doc];
        let chosen = signer_validation_time(&items[0], &items, 400);
        assert_eq!(chosen.at, 50);
        assert!(matches!(
            chosen.source,
            Some(TimeSource::SignatureTimestamp { .. })
        ));
        let archive = archival_coverage(&items[0], &items, Some(250)).unwrap();
        assert_eq!(archive.at, 100);
        assert_eq!(archive.timestamp, 1);
    }
    #[test]
    fn untrusted_or_unbound_timestamp_supplies_neither_signer_nor_material_time() {
        let sig = envelope(0, SignatureKind::Signature, None);
        let mut partial = envelope(
            1,
            SignatureKind::DocumentTimestamp,
            Some((
                TimeSource::DocumentTimestamp {
                    envelope: 1,
                    revision: RevisionBoundary {
                        index: 2,
                        eof_end: 300,
                    },
                },
                100,
            )),
        );
        // Even a forged internal time fact cannot confer coverage without
        // its structural revision proof. Failed/untrusted tokens provide no
        // time proof at all, and follow this same absence branch.
        partial.revision = None;
        let items = [sig, partial];
        let selected = signer_validation_time(&items[0], &items, 400);
        assert_eq!(selected.at, 400);
        assert!(selected.source.is_none());
        assert!(archival_coverage(&items[0], &items, Some(250)).is_none());
        assert_eq!(material_validation_time(&items, Some(250), 400), 400);
    }
}
