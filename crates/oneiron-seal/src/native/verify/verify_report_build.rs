//! Convert envelope checks into separate evidence axes and derived profile rungs.
use super::super::pdf;
use super::verify_sig_pipeline::{Checks, SigEntry, check_byte_range};
use crate::api::{
    ByteRangeEvidence, Coverage, DigestAlgorithm, PadesProfile, SignatureKind, SignatureReport,
    SignedRangeDigest, VerifyCheck, VerifyCheckKind, VerifyCheckStatus, VerifyVerdict,
};

pub(super) fn signature_report(
    bytes: &[u8],
    e: &SigEntry,
    index: usize,
    checks: Vec<VerifyCheck>,
) -> SignatureReport {
    let br_ok = check_byte_range(bytes, e);
    let end = e.byte_range[2].checked_add(e.byte_range[3]);
    let covers_to = end.filter(|_| br_ok);
    let coverage = if !br_ok {
        Coverage::Unclear
    } else if end.is_some_and(|n| {
        usize::try_from(n)
            .ok()
            .and_then(|n| bytes.get(n..))
            .is_some_and(|tail| tail.len() <= 4 && tail.iter().all(|b| *b == b'\r' || *b == b'\n'))
    }) {
        Coverage::EntireFile
    } else if end
        .and_then(|n| usize::try_from(n).ok())
        .and_then(|n| bytes.get(..n))
        .is_some_and(|prefix| {
            prefix
                .iter()
                .rev()
                .take(4)
                .filter(|b| **b == b'\n' || **b == b'\r')
                .count()
                <= 4
                && prefix
                    .iter()
                    .rev()
                    .skip_while(|b| **b == b'\n' || **b == b'\r')
                    .take(5)
                    .copied()
                    .collect::<Vec<_>>()
                    == b"FOE%%"
        })
    {
        Coverage::EntireRevision
    } else {
        Coverage::ContiguousFromStart
    };
    let digest = if br_ok {
        pdf::hash_byte_range(bytes, e.byte_range)
            .ok()
            .map(|value| SignedRangeDigest {
                alg: DigestAlgorithm::Sha256,
                value,
            })
    } else {
        None
    };
    let kind = if e.is_doc_ts {
        SignatureKind::DocumentTimestamp
    } else {
        SignatureKind::Signature
    };
    let trust = checks
        .iter()
        .find(|c| c.kind == VerifyCheckKind::CertificatePath)
        .map_or(VerifyCheckStatus::NotApplicable, |c| c.status);
    let integrity_checks = checks.iter().filter(|c| {
        matches!(
            c.kind,
            VerifyCheckKind::ByteRange
                | VerifyCheckKind::UnsignedGap
                | VerifyCheckKind::CmsEnvelope
                | VerifyCheckKind::SignedAttributes
                | VerifyCheckKind::ContentDigest
                | VerifyCheckKind::SignatureValue
                | VerifyCheckKind::SigningCertificateBinding
                | VerifyCheckKind::DocumentTimestamp
        )
    });
    let integrity = if integrity_checks
        .clone()
        .any(|c| c.status == VerifyCheckStatus::Fail)
    {
        VerifyVerdict::Failed
    } else if integrity_checks
        .clone()
        .any(|c| c.status == VerifyCheckStatus::NotRun)
    {
        VerifyVerdict::Indeterminate
    } else {
        VerifyVerdict::Passed
    };
    SignatureReport {
        id: format!("{}:{index}", e.field_name),
        kind,
        byte_range: ByteRangeEvidence {
            values: e.byte_range,
            well_formed: br_ok,
            covers_to,
            file_len: bytes.len() as u64,
        },
        coverage,
        digest,
        profile: None,
        integrity,
        trust,
        checks,
    }
}

pub(super) fn classify_signature(
    checks: &[VerifyCheck],
    dss_ok: bool,
    covering_dts_valid: bool,
) -> Option<PadesProfile> {
    if checks.iter().any(|c| {
        c.status == VerifyCheckStatus::Fail
            || (c.status == VerifyCheckStatus::NotRun && c.kind != VerifyCheckKind::CertificatePath)
    }) {
        return None;
    }
    let checks = Checks {
        list: checks.to_vec(),
    };
    let t = checks.passed(VerifyCheckKind::SignatureTimestamp);
    let lt = t && dss_ok;
    Some(if lt && covering_dts_valid {
        PadesProfile::BaselineLta
    } else if lt {
        PadesProfile::BaselineLt
    } else if t {
        PadesProfile::BaselineT
    } else {
        PadesProfile::BaselineB
    })
}
