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
    // The revision classifier upgrades this contiguous range only after it
    // matches a structural xref/EOF boundary. Marker-looking stream bytes
    // are never enough to award EntireRevision.
    let coverage = if !br_ok {
        Coverage::Unclear
    } else if end.is_some_and(|n| pdf::file_tail_covered(bytes, n)) {
        Coverage::EntireFile
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
    let paths: Vec<_> = checks
        .iter()
        .filter(|c| {
            matches!(
                c.kind,
                VerifyCheckKind::CertificatePath | VerifyCheckKind::TimestampCertificatePath
            )
        })
        .map(|c| c.status)
        .collect();
    let trust = if paths.contains(&VerifyCheckStatus::Fail) {
        VerifyCheckStatus::Fail
    } else if paths.contains(&VerifyCheckStatus::NotRun) {
        VerifyCheckStatus::NotRun
    } else if paths.contains(&VerifyCheckStatus::Pass) {
        VerifyCheckStatus::Pass
    } else {
        VerifyCheckStatus::NotApplicable
    };
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
    covering_dts_archival: bool,
) -> Option<PadesProfile> {
    if checks.iter().any(|c| {
        (c.status == VerifyCheckStatus::Fail && c.kind != VerifyCheckKind::ValidationMaterial)
            || (c.status == VerifyCheckStatus::NotRun
                && !matches!(
                    c.kind,
                    VerifyCheckKind::CertificatePath | VerifyCheckKind::TimestampCertificatePath
                ))
    }) {
        return None;
    }
    let checks = Checks {
        list: checks.to_vec(),
    };
    let trusted_sig_ts = checks.passed(VerifyCheckKind::SignatureTimestamp)
        && checks.passed(VerifyCheckKind::TimestampCertificatePath);
    let t = trusted_sig_ts || covering_dts_valid;
    let lt = t && dss_ok;
    Some(if lt && covering_dts_archival {
        PadesProfile::BaselineLta
    } else if lt {
        PadesProfile::BaselineLt
    } else if t {
        PadesProfile::BaselineT
    } else {
        PadesProfile::BaselineB
    })
}
