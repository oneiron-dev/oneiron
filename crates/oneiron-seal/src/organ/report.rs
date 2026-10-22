//! A verdict as the engine reads it: the native report's coarse fields, its
//! full JSON, and the revision classification the engine admits a sealed
//! PDF on (OF-415, C032). The classification is taken from the native
//! report itself, never from its JSON. The JSON's bytes are counted, and
//! reserved, before its buffer is made (FIX 6195).

use oneiron_organ_protocol::seal::{
    SealByteRangeEvidence, SealCheckVerdict, SealModificationLevel, SealModifications,
    SealRevisionClassification, SealRevisionEvidence, SealRevisionKind, SealSignatureEvidence,
    SealSignatureKind,
};
use oneiron_organ_protocol::{ByteBuf, ErrorCode, OrganError};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::api::{
    ModificationLevel, Modifications, PadesProfile, RevisionKind, SignatureKind, VerifyCheckKind,
    VerifyCheckStatus, VerifyFindingCode, VerifyReport, VerifyVerdict,
};

/// A verdict, with the full report as JSON bytes: one value in the reply
/// frame however many signatures the PDF holds, carried whole (Rule 5;
/// past [`super::MAX_REPORT_JSON_BYTES`] the engine's row asks), and never
/// parsed by the engine. Beside it, the revision classification.
#[derive(Serialize)]
pub(super) struct Verdict {
    verdict: VerifyVerdict,
    reasons: Vec<VerifyFindingCode>,
    achieved: Option<PadesProfile>,
    self_verify_ok: bool,
    report_json: ByteBuf,
    classification: SealRevisionClassification,
}

impl Verdict {
    /// The verdict of `report`, the verification of `pdf` when this side
    /// holds it: without the bytes, nothing is classified through. `reserve`
    /// holds the JSON's bytes before they are allocated.
    pub(super) fn of(
        report: &VerifyReport,
        pdf: Option<&[u8]>,
        reserve: &dyn Fn(u64) -> Result<(), OrganError>,
    ) -> Result<Self, OrganError> {
        let failed = |err: &dyn std::fmt::Display| {
            OrganError::new(ErrorCode::Internal, format!("report: {err}"))
        };
        let mut count = Count(0);
        serde_json::to_writer(&mut count, report).map_err(|err| failed(&err))?;
        reserve(count.0)?;
        let mut json = Vec::with_capacity(usize::try_from(count.0).unwrap_or(0));
        serde_json::to_writer(&mut json, report).map_err(|err| failed(&err))?;
        Ok(Self {
            verdict: report.verdict(),
            reasons: report.reasons(),
            achieved: report.achieved_profile(),
            self_verify_ok: report.passes_self_verify(),
            report_json: ByteBuf::from(json),
            classification: classification(report, pdf),
        })
    }
}

/// Bytes written, counted with nothing kept.
struct Count(u64);

impl std::io::Write for Count {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len() as u64);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The native report's revision chain, modification class and signatures,
/// field for field.
fn classification(report: &VerifyReport, pdf: Option<&[u8]>) -> SealRevisionClassification {
    SealRevisionClassification {
        artifact_sha256: ByteBuf::from(report.artifact_sha256.to_vec()),
        classified_through: pdf.and_then(|pdf| classified_through(report, pdf)),
        modifications: match report.modifications {
            Modifications::NotRun => SealModifications::NotRun,
            Modifications::Clean(level) => SealModifications::Clean(match level {
                ModificationLevel::None => SealModificationLevel::None,
                ModificationLevel::LtaUpdates => SealModificationLevel::LtaUpdates,
                ModificationLevel::FormFilling => SealModificationLevel::FormFilling,
                ModificationLevel::Other => SealModificationLevel::Other,
            }),
            Modifications::Suspicious => SealModifications::Suspicious,
        },
        revisions: report
            .revisions
            .iter()
            .map(|revision| SealRevisionEvidence {
                index: u64::try_from(revision.index).unwrap_or(u64::MAX),
                kind: match revision.kind {
                    RevisionKind::Original => SealRevisionKind::Original,
                    RevisionKind::Signature => SealRevisionKind::Signature,
                    RevisionKind::DocumentTimestamp => SealRevisionKind::DocumentTimestamp,
                    RevisionKind::Dss => SealRevisionKind::Dss,
                    RevisionKind::Other => SealRevisionKind::Other,
                },
                byte_end: revision.byte_end,
                signed_by: revision.signed_by.clone(),
            })
            .collect(),
        signatures: report
            .signatures
            .iter()
            .map(|signature| SealSignatureEvidence {
                id: signature.id.clone(),
                kind: match signature.kind {
                    SignatureKind::Signature => SealSignatureKind::Signature,
                    SignatureKind::DocumentTimestamp => SealSignatureKind::DocumentTimestamp,
                },
                byte_range: SealByteRangeEvidence {
                    values: signature.byte_range.values,
                    well_formed: signature.byte_range.well_formed,
                    covers_to: signature.byte_range.covers_to,
                    file_len: signature.byte_range.file_len,
                },
                integrity: check_verdict(signature.integrity),
                verdict: check_verdict(signature.verdict()),
            })
            .collect(),
    }
}

fn check_verdict(verdict: VerifyVerdict) -> SealCheckVerdict {
    match verdict {
        VerifyVerdict::Passed => SealCheckVerdict::Passed,
        VerifyVerdict::Failed => SealCheckVerdict::Failed,
        VerifyVerdict::Indeterminate => SealCheckVerdict::Indeterminate,
    }
}

/// `pdf`'s length when the native verification proved one revision chain
/// over the whole of it and classified every revision: the report is of
/// these bytes, its chain checks passed, its modifications were classified,
/// and nothing but the chain's final EOL framing follows its last
/// revision. `None` otherwise: a part left unproven is never classified.
fn classified_through(report: &VerifyReport, pdf: &[u8]) -> Option<u64> {
    let mut chain = report
        .checks
        .iter()
        .filter(|check| check.kind == VerifyCheckKind::PdfRevision)
        .peekable();
    let proven = chain.peek().is_some()
        && chain.all(|check| check.status == VerifyCheckStatus::Pass)
        && report.modifications != Modifications::NotRun;
    let end = usize::try_from(report.revisions.last()?.byte_end).ok()?;
    let framed = pdf
        .get(end..)?
        .iter()
        .all(|byte| matches!(byte, b'\r' | b'\n'));
    let same: [u8; 32] = Sha256::digest(pdf).into();
    (proven && framed && same == report.artifact_sha256).then_some(pdf.len() as u64)
}
