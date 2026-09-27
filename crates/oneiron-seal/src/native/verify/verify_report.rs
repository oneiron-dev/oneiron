//! Per-envelope report facts, separate from PDF trust and modification policy.

use super::super::pdf;
use super::verify_modifications::eof_tail;
use super::verify_sig_pipeline::{Checks, SigEntry, check_byte_range, check_byte_range_shape};
use crate::api::{
    ByteRangeEvidence, DigestAlgorithm, PadesProfile, Sha256Digest, SignatureCoverage,
    SignatureKind, SignatureVerification, SignedRangeDigest, VerifyCheckKind, VerifyCheckStatus,
    VerifyVerdict,
};

fn axis(checks: &Checks, kinds: &[VerifyCheckKind]) -> VerifyVerdict {
    let selected: Vec<_> = checks
        .list
        .iter()
        .filter(|c| kinds.contains(&c.kind))
        .collect();
    if selected.iter().any(|c| c.status == VerifyCheckStatus::Fail) {
        VerifyVerdict::Failed
    } else if selected.is_empty()
        || !selected.iter().any(|c| c.status == VerifyCheckStatus::Pass)
        || selected
            .iter()
            .any(|c| c.status == VerifyCheckStatus::NotRun)
    {
        VerifyVerdict::Indeterminate
    } else {
        VerifyVerdict::Passed
    }
}

pub(super) fn signature_entry(
    bytes: &[u8],
    e: &SigEntry,
    index: usize,
    checks: Checks,
) -> SignatureVerification {
    let well_formed = check_byte_range_shape(bytes, e);
    let gap_ok = check_byte_range(bytes, e);
    let end = e.byte_range[2].checked_add(e.byte_range[3]);
    let digest: Option<Sha256Digest> = if gap_ok {
        pdf::hash_byte_range(bytes, e.byte_range).ok()
    } else {
        None
    };
    let coverage = if !well_formed {
        SignatureCoverage::Unclear
    } else if end.is_some_and(|n| {
        let Ok(n) = usize::try_from(n) else {
            return false;
        };
        eof_tail(bytes).is_some_and(|eof_end| n >= eof_end && n <= bytes.len())
    }) {
        SignatureCoverage::EntireFile
    } else if end
        .and_then(|n| usize::try_from(n).ok())
        .and_then(|n| bytes.get(..n))
        .is_some_and(|prefix| eof_tail(prefix).is_some())
    {
        SignatureCoverage::EntireRevision
    } else {
        SignatureCoverage::ContiguousFromStart
    };
    let integrity = if e.is_doc_ts {
        axis(
            &checks,
            &[
                VerifyCheckKind::ByteRange,
                VerifyCheckKind::UnsignedGap,
                VerifyCheckKind::DocumentTimestamp,
            ],
        )
    } else {
        axis(
            &checks,
            &[
                VerifyCheckKind::ByteRange,
                VerifyCheckKind::UnsignedGap,
                VerifyCheckKind::CmsEnvelope,
                VerifyCheckKind::SignedAttributes,
                VerifyCheckKind::ContentDigest,
                VerifyCheckKind::SignatureValue,
                VerifyCheckKind::SigningCertificateBinding,
                VerifyCheckKind::SignatureTimestamp,
            ],
        )
    };
    let trust = if e.is_doc_ts {
        axis(&checks, &[VerifyCheckKind::DocumentTimestampTrust])
    } else {
        axis(
            &checks,
            &[
                VerifyCheckKind::CertificatePath,
                VerifyCheckKind::SignatureTimestampTrust,
            ],
        )
    };
    SignatureVerification {
        id: format!("{}:{index}", e.field_name.as_deref().unwrap_or("signature")),
        kind: if e.is_doc_ts {
            SignatureKind::DocumentTimestamp
        } else {
            SignatureKind::Signer
        },
        byte_range: ByteRangeEvidence {
            values: e.byte_range,
            well_formed,
            covers_to: end,
            file_len: bytes.len() as u64,
        },
        coverage,
        digest: digest.map(|value| SignedRangeDigest {
            algorithm: DigestAlgorithm::Sha256,
            value,
        }),
        integrity,
        trust,
        achieved_profile: None::<PadesProfile>,
        checks: checks.list,
    }
}
