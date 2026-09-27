//! Evidence-oriented verification report. Verdicts are computed from checks.
use super::{DigestAlgorithm, PadesProfile, Sha256Digest};
use serde::{Deserialize, Serialize, ser::SerializeStruct};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyVerdict {
    Passed,
    Failed,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyCheckKind {
    PdfRevision,
    ByteRange,
    UnsignedGap,
    CmsEnvelope,
    SignedAttributes,
    ContentDigest,
    SignatureValue,
    SigningCertificateBinding,
    CertificatePath,
    TimestampCertificatePath,
    SignatureTimestamp,
    ValidationMaterial,
    DocumentTimestamp,
    Modification,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyCheckStatus {
    Pass,
    Fail,
    NotRun,
    NotApplicable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyFindingCode {
    InvalidPdfRevision,
    InvalidByteRange,
    InvalidUnsignedGap,
    InvalidCms,
    InvalidSignedAttributes,
    DigestMismatch,
    SignatureMismatch,
    CertificateBindingMismatch,
    CertificatePathInvalid,
    TimestampInvalid,
    ValidationMaterialInvalid,
    DocumentTimestampInvalid,
    ModificationNotAllowed,
    NoSignature,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyCheck {
    pub kind: VerifyCheckKind,
    pub status: VerifyCheckStatus,
    pub finding: Option<VerifyFindingCode>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    Unclear,
    ContiguousFromStart,
    EntireRevision,
    EntireFile,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureKind {
    Signature,
    DocumentTimestamp,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteRangeEvidence {
    pub values: [u64; 4],
    pub well_formed: bool,
    pub covers_to: Option<u64>,
    pub file_len: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRangeDigest {
    pub alg: DigestAlgorithm,
    pub value: Sha256Digest,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModificationLevel {
    None,
    LtaUpdates,
    FormFilling,
    Other,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Modifications {
    NotRun,
    Clean(ModificationLevel),
    Suspicious,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionKind {
    Original,
    Signature,
    DocumentTimestamp,
    Dss,
    Other,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionReport {
    pub index: usize,
    pub kind: RevisionKind,
    pub byte_end: u64,
    pub signed_by: Option<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Anomaly {
    DuplicateObjectNumber,
    PointerOnlyRevision,
    RetypedObject,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureReport {
    pub id: String,
    pub kind: SignatureKind,
    pub byte_range: ByteRangeEvidence,
    pub coverage: Coverage,
    pub digest: Option<SignedRangeDigest>,
    pub profile: Option<PadesProfile>,
    pub integrity: VerifyVerdict,
    pub trust: VerifyCheckStatus,
    pub checks: Vec<VerifyCheck>,
}
impl SignatureReport {
    #[must_use]
    pub fn verdict(&self) -> VerifyVerdict {
        rollup(self.checks.iter().copied())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct VerifyReport {
    /// Storage identifier only. A lawful archival append changes this hash.
    pub artifact_sha256: Sha256Digest,
    pub revisions: Vec<RevisionReport>,
    pub signatures: Vec<SignatureReport>,
    pub modifications: Modifications,
    pub anomalies: Vec<Anomaly>,
    /// Document-level checks, distinct from each envelope's checks.
    pub checks: Vec<VerifyCheck>,
}
// Verdict and reasons are report fields on the wire, but are computed on
// serialization and never persisted as independently writable state.
impl Serialize for VerifyReport {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut report = serializer.serialize_struct("VerifyReport", 8)?;
        report.serialize_field("verdict", &self.verdict())?;
        report.serialize_field("reasons", &self.reasons())?;
        report.serialize_field("artifact_sha256", &self.artifact_sha256)?;
        report.serialize_field("revisions", &self.revisions)?;
        report.serialize_field("signatures", &self.signatures)?;
        report.serialize_field("modifications", &self.modifications)?;
        report.serialize_field("anomalies", &self.anomalies)?;
        report.serialize_field("checks", &self.checks)?;
        report.end()
    }
}

fn rollup(checks: impl Iterator<Item = VerifyCheck>) -> VerifyVerdict {
    let mut unknown = false;
    for check in checks {
        match check.status {
            VerifyCheckStatus::Fail => return VerifyVerdict::Failed,
            VerifyCheckStatus::NotRun => unknown = true,
            VerifyCheckStatus::Pass | VerifyCheckStatus::NotApplicable => {}
        }
    }
    if unknown {
        VerifyVerdict::Indeterminate
    } else {
        VerifyVerdict::Passed
    }
}
impl VerifyReport {
    #[must_use]
    pub fn verdict(&self) -> VerifyVerdict {
        if self
            .signatures
            .iter()
            .all(|s| s.kind != SignatureKind::Signature)
        {
            return VerifyVerdict::Failed;
        }
        rollup(
            self.checks
                .iter()
                .chain(self.signatures.iter().flat_map(|s| s.checks.iter()))
                .copied(),
        )
    }
    #[must_use]
    pub fn reasons(&self) -> Vec<VerifyFindingCode> {
        let mut reasons: Vec<_> = self
            .checks()
            .filter_map(|c| {
                if c.status == VerifyCheckStatus::Fail {
                    c.finding
                } else {
                    None
                }
            })
            .collect();
        if self
            .signatures
            .iter()
            .all(|s| s.kind != SignatureKind::Signature)
        {
            reasons.push(VerifyFindingCode::NoSignature);
        }
        reasons
    }
    #[must_use]
    pub fn passes_self_verify(&self) -> bool {
        self.verdict() == VerifyVerdict::Passed
            && self
                .signatures
                .iter()
                .any(|s| s.kind == SignatureKind::Signature && s.profile.is_some())
    }
    #[must_use]
    pub fn valid(&self) -> bool {
        self.verdict() == VerifyVerdict::Passed
    }
    #[must_use]
    pub fn achieved_profile(&self) -> Option<PadesProfile> {
        self.signatures
            .iter()
            .filter(|s| s.kind == SignatureKind::Signature)
            .filter_map(|s| s.profile)
            .min()
    }
    pub fn checks(&self) -> impl Iterator<Item = &VerifyCheck> {
        self.checks
            .iter()
            .chain(self.signatures.iter().flat_map(|s| s.checks.iter()))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rollup_does_not_store_or_launder_unknown() {
        let mut r = VerifyReport {
            artifact_sha256: [0; 32],
            revisions: vec![],
            modifications: Modifications::NotRun,
            anomalies: vec![],
            checks: vec![],
            signatures: vec![SignatureReport {
                id: "sig-0".into(),
                kind: SignatureKind::Signature,
                byte_range: ByteRangeEvidence {
                    values: [0; 4],
                    well_formed: false,
                    covers_to: None,
                    file_len: 0,
                },
                coverage: Coverage::Unclear,
                digest: None,
                profile: None,
                integrity: VerifyVerdict::Indeterminate,
                trust: VerifyCheckStatus::NotRun,
                checks: vec![VerifyCheck {
                    kind: VerifyCheckKind::CertificatePath,
                    status: VerifyCheckStatus::NotRun,
                    finding: None,
                }],
            }],
        };
        assert_eq!(r.verdict(), VerifyVerdict::Indeterminate);
        r.signatures[0].checks.push(VerifyCheck {
            kind: VerifyCheckKind::ContentDigest,
            status: VerifyCheckStatus::Fail,
            finding: Some(VerifyFindingCode::DigestMismatch),
        });
        assert_eq!(r.verdict(), VerifyVerdict::Failed);
        r.signatures[0].checks.pop();
        r.signatures[0].checks[0].status = VerifyCheckStatus::NotApplicable;
        assert_eq!(r.verdict(), VerifyVerdict::Passed);
        let mut json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["verdict"], "passed");
        assert!(json["reasons"].as_array().unwrap().is_empty());
        // Untrusted serialized verdicts cannot override the check rollup.
        json["verdict"] = serde_json::json!("failed");
        let back: VerifyReport = serde_json::from_value(json).unwrap();
        assert_eq!(back.verdict(), VerifyVerdict::Passed);
    }
}
