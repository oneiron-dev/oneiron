//! Private, bounded evidence collected before trust, time, and profile decisions.
use super::super::pdf::RevisionBoundary;
use super::verify_dss_core::EmbeddedCert;
use crate::api::{ByteRangeEvidence, Coverage, SignatureKind, SignedRangeDigest, VerifyCheck};

/// A timestamp already passed token integrity, trusted TSA path, and clock
/// bounds. Untrusted/invalid tokens are checks, never time proofs.
pub(super) struct ValidatedTimeToken {
    pub gen_time: u64,
    pub tsa_chain_ders: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TimeSource {
    SignatureTimestamp {
        signer: usize,
    },
    DocumentTimestamp {
        envelope: usize,
        revision: RevisionBoundary,
    },
}

pub(super) struct TrustedTimeProof {
    pub source: TimeSource,
    pub gen_time: u64,
    pub tsa_chain_ders: Vec<Vec<u8>>,
    /// For a document timestamp: last byte of its validated signed range.
    /// For a CMS timestamp: the owning signer's range end (the token itself
    /// binds that signer's signature value, not a subsequent PDF revision).
    pub covers_to: u64,
}

pub(super) struct CadesEvidence {
    pub signer_chain: Option<Vec<Vec<u8>>>,
    pub timestamp: Option<ValidatedTimeToken>,
}

/// Evidence has stable identity and a single structural revision binding,
/// but it is NOT the public report. Path/material validation comes later.
pub(super) struct EnvelopeEvidence {
    pub index: usize,
    pub id: String,
    pub kind: SignatureKind,
    pub byte_range: ByteRangeEvidence,
    pub coverage: Coverage,
    pub digest: Option<SignedRangeDigest>,
    pub revision: Option<RevisionBoundary>,
    pub checks: Vec<VerifyCheck>,
    pub signer_chain: Option<Vec<Vec<u8>>>,
    pub time_proof: Option<TrustedTimeProof>,
    pub covered: Vec<EmbeddedCert>,
}

/// Evaluate bytes and token integrity without choosing signer path time or
/// projecting public report fields. The xref chain has already been proven.
pub(super) fn evaluate_envelope(
    bytes: &[u8],
    entry: &super::verify_sig_pipeline::SigEntry,
    index: usize,
    ends: Option<&[usize]>,
    ctx: &super::verify_chain_gates::VerifyCtx<'_>,
    anchors: &[pkix_chain::TrustAnchor],
    is_last: bool,
) -> EnvelopeEvidence {
    use super::super::pdf;
    use super::verify_sig_pipeline::{Checks, check_byte_range, verify_cades_sig, verify_doc_ts};
    use crate::api::{DigestAlgorithm, SignedRangeDigest};
    let br_ok = check_byte_range(bytes, entry);
    let end = entry.byte_range[2].checked_add(entry.byte_range[3]);
    let covers_to = end.filter(|_| br_ok);
    let revision = covers_to.and_then(|end| pdf::bind_range(bytes, ends, end));
    let kind = if entry.is_doc_ts {
        SignatureKind::DocumentTimestamp
    } else {
        SignatureKind::Signature
    };
    let mut checks = Checks::new();
    let mut covered = Vec::new();
    let (signer_chain, token) = if entry.is_doc_ts {
        (
            None,
            verify_doc_ts(
                bytes,
                entry,
                anchors,
                &mut checks,
                is_last,
                &mut covered,
                ctx.clock_ms,
            ),
        )
    } else {
        let cades = verify_cades_sig(bytes, entry, ctx, anchors, &mut checks, &mut covered);
        (cades.signer_chain, cades.timestamp)
    };
    let time_proof = token.and_then(|token| {
        let source = if entry.is_doc_ts {
            TimeSource::DocumentTimestamp {
                envelope: index,
                revision: revision?,
            }
        } else {
            TimeSource::SignatureTimestamp { signer: index }
        };
        Some(TrustedTimeProof {
            source,
            gen_time: token.gen_time,
            tsa_chain_ders: token.tsa_chain_ders,
            covers_to: end?,
        })
    });
    let coverage = if !br_ok {
        Coverage::Unclear
    } else if end.is_some_and(|end| pdf::file_tail_covered(bytes, end)) {
        Coverage::EntireFile
    } else if revision.is_some() {
        Coverage::EntireRevision
    } else {
        Coverage::ContiguousFromStart
    };
    let digest = if br_ok {
        pdf::hash_byte_range(bytes, entry.byte_range)
            .ok()
            .map(|value| SignedRangeDigest {
                alg: DigestAlgorithm::Sha256,
                value,
            })
    } else {
        None
    };
    EnvelopeEvidence {
        index,
        id: format!("{}:{index}", entry.field_name),
        kind,
        byte_range: ByteRangeEvidence {
            values: entry.byte_range,
            well_formed: br_ok,
            covers_to,
            file_len: bytes.len() as u64,
        },
        coverage,
        digest,
        revision,
        checks: checks.list,
        signer_chain,
        time_proof,
        covered,
    }
}
