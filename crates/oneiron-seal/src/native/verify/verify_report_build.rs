//! Project completed evidence into the public per-envelope report once.
use super::evidence_time::{ArchivalCoverage, SignerValidationTime};
use super::verify_evidence::EnvelopeEvidence;
use crate::api::{
    PadesProfile, SignatureReport, VerifyCheckKind, VerifyCheckStatus, VerifyVerdict,
};

pub(super) fn signature_report(
    e: EnvelopeEvidence,
    profile: Option<PadesProfile>,
) -> SignatureReport {
    let paths: Vec<_> = e
        .checks
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
    let integrity_checks = e.checks.iter().filter(|c| {
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
        id: e.id,
        kind: e.kind,
        byte_range: e.byte_range,
        coverage: e.coverage,
        digest: e.digest,
        profile,
        integrity,
        trust,
        checks: e.checks,
    }
}

pub(super) fn classify_signature(
    evidence: &EnvelopeEvidence,
    time: &SignerValidationTime,
    dss_ok: bool,
    archival: Option<&ArchivalCoverage>,
    dss_end: Option<u64>,
) -> Option<PadesProfile> {
    if evidence.checks.iter().any(|c| {
        (c.status == VerifyCheckStatus::Fail && c.kind != VerifyCheckKind::ValidationMaterial)
            || (c.status == VerifyCheckStatus::NotRun
                && !matches!(
                    c.kind,
                    VerifyCheckKind::CertificatePath | VerifyCheckKind::TimestampCertificatePath
                ))
    }) {
        return None;
    }
    let t = time.source.is_some();
    let lt = t && dss_ok;
    let lta = lt
        && archival
            .zip(dss_end)
            .is_some_and(|(proof, end)| proof.supports(evidence.index, end));
    Some(if lta {
        PadesProfile::BaselineLta
    } else if lt {
        PadesProfile::BaselineLt
    } else if t {
        PadesProfile::BaselineT
    } else {
        PadesProfile::BaselineB
    })
}
