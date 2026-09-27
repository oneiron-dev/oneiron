//! Frozen orchestration-facing contract for the seal engine (ONE-1837 §4/§5).
//!
//! Prepared-input contract: `seal_pdf` accepts only an already-prepared PDF.
//! Flattening, field burn-in, rejection marks, certificate/audit-page
//! composition, active-content stripping, and clean rewrite are upstream
//! responsibilities. The engine returns [`crate::SealError::InputInvalid`]
//! instead of signing encrypted, malformed/repaired, active-content-bearing,
//! embedded-file-bearing, hybrid-xref, or already-signed input.
//!
//! Retry contract: [`crate::SealError::is_retryable`] classifies outcomes for
//! the orchestration attempt queue. `Retryable`, `BackendUnavailable`, and
//! `VerifyFailed` leave the attempt retryable; `InputInvalid` is fatal for
//! those prepared bytes; `Fatal` is not retried unchanged.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::SealError;

pub type Sha256Digest = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PadesProfile {
    BaselineB,
    BaselineT,
    BaselineLt,
    BaselineLta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DigestAlgorithm {
    Sha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    RsaPkcs1v15Sha256,
    EcdsaP256Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningIdentity {
    pub algorithm: SignatureAlgorithm,
    pub signer_certificate_der: Vec<u8>,
    pub certificate_chain_der: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignDigestRequest {
    pub operation_id: String,
    pub digest_algorithm: DigestAlgorithm,
    pub digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendSignature {
    RsaPkcs1v15 { bytes: Vec<u8> },
    EcdsaP256Der { bytes: Vec<u8> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendRejectCode {
    Unauthorized,
    AlgorithmDenied,
    IdentityUnavailable,
    OperationConflict,
    InvalidResponse,
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("seal backend unavailable")]
    Unavailable { retry_after_ms: Option<u64> },
    #[error("seal backend rate limited")]
    RateLimited { retry_after_ms: Option<u64> },
    #[error("seal backend rejected the operation: {code:?}")]
    Rejected { code: BackendRejectCode },
    #[error("seal backend returned malformed signature bytes")]
    MalformedSignature,
}

/// Signing backend seam. Carries signing identity and a prehashed signing
/// operation only: it does not parse PDFs, assemble CMS, choose attributes,
/// fetch validation data, or store documents. `SignDigestRequest::digest` is
/// SHA-256 over the canonical DER encoding of the signed-attribute SET with
/// the universal `SET OF` tag (RFC 5652 §5.4). `operation_id` is opaque,
/// non-empty, bounded to 256 UTF-8 bytes, and stable for one logical seal.
#[async_trait]
pub trait SealBackend: Send + Sync {
    fn signing_identity(&self) -> Result<SigningIdentity, BackendError>;

    async fn sign_digest(
        &self,
        request: SignDigestRequest,
    ) -> Result<BackendSignature, BackendError>;
}

/// Bound for `operation_id` (§4): opaque, non-empty, at most this many UTF-8
/// bytes, stable for one logical seal. Validated before any signing work.
pub const MAX_OPERATION_ID_BYTES: usize = 256;

/// Reserved headroom for the engine's derived sub-operation-id suffix
/// (`:{16 hex}:{phase}:{capacity}`). Caller-supplied ids must leave this
/// budget so every derived id still fits the backend's 256-byte bound.
pub const OPERATION_ID_SUFFIX_RESERVE: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealRequest {
    pub operation_id: String,
    pub target_profile: PadesProfile,
}

impl SealRequest {
    /// Enforce the `operation_id` contract. Engines must run this before the
    /// request reaches any signing or fetch path. Caller ids are bounded to
    /// [`MAX_OPERATION_ID_BYTES`] minus [`OPERATION_ID_SUFFIX_RESERVE`] so the
    /// suffixed sub-operation ids the engine derives stay inside the bound.
    pub fn validate_operation_id(&self) -> Result<(), SealError> {
        let max_caller = MAX_OPERATION_ID_BYTES - OPERATION_ID_SUFFIX_RESERVE;
        if self.operation_id.is_empty() || self.operation_id.len() > max_caller {
            return Err(SealError::Fatal {
                stage: crate::error::SealStage::InputValidation,
                code: crate::error::FatalCode::InvalidConfiguration,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileDegradeReason {
    TimestampUnavailable,
    ValidationMaterialUnavailable,
    DocumentTimestampUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SealWarning {
    ProfileDegraded {
        requested: PadesProfile,
        achieved: PadesProfile,
        reason: ProfileDegradeReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyCheckKind {
    PdfRevision,
    Modification,
    ByteRange,
    UnsignedGap,
    CmsEnvelope,
    SignedAttributes,
    ContentDigest,
    SignatureValue,
    SigningCertificateBinding,
    CertificatePath,
    SignatureTimestamp,
    SignatureTimestampTrust,
    ValidationMaterial,
    DocumentTimestamp,
    DocumentTimestampTrust,
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
pub enum VerifyVerdict {
    Passed,
    Failed,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyFindingCode {
    InvalidPdfRevision,
    InvalidByteRange,
    InvalidCms,
    InvalidSignedAttributes,
    DigestMismatch,
    SignatureMismatch,
    CertificateBindingMismatch,
    CertificatePathInvalid,
    TrustRootUnavailable,
    TimestampInvalid,
    ValidationMaterialInvalid,
    DocumentTimestampInvalid,
    ModificationNotAllowed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyCheck {
    pub kind: VerifyCheckKind,
    pub status: VerifyCheckStatus,
    pub finding: Option<VerifyFindingCode>,
}

/// Ordered signed-byte coverage. An intact old revision is not the entire file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureCoverage {
    Unclear,
    ContiguousFromStart,
    EntireRevision,
    EntireFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureKind {
    Signer,
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
    pub algorithm: DigestAlgorithm,
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
pub enum ModificationStatus {
    NotRun,
    Clean(ModificationLevel),
    Suspicious,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionKind {
    Signature,
    DocumentTimestamp,
    Unsigned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyRevision {
    pub index: usize,
    pub kind: RevisionKind,
    pub byte_end: u64,
    pub signed_by: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyAnomaly {
    DuplicateObjectNumber,
    PointerOnlyRevision,
    RetypedObject,
}

/// Trust is independent of the signed-byte integrity and modification axes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureVerification {
    pub id: String,
    pub kind: SignatureKind,
    pub byte_range: ByteRangeEvidence,
    pub coverage: SignatureCoverage,
    pub digest: Option<SignedRangeDigest>,
    pub integrity: VerifyVerdict,
    pub trust: VerifyVerdict,
    pub achieved_profile: Option<PadesProfile>,
    pub checks: Vec<VerifyCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    /// Whole-file identifier only; signed-range digests identify signed evidence.
    pub artifact_sha256: Sha256Digest,
    pub revisions: Vec<VerifyRevision>,
    pub signatures: Vec<SignatureVerification>,
    pub modifications: ModificationStatus,
    pub anomalies: Vec<VerifyAnomaly>,
    /// Document-level checks, separate from each envelope's checks.
    pub checks: Vec<VerifyCheck>,
}

impl VerifyReport {
    /// No serialized verdict or validity flag can disagree with the evidence.
    #[must_use]
    pub fn verdict(&self) -> VerifyVerdict {
        if self.modifications == ModificationStatus::Suspicious
            || self
                .all_checks()
                .any(|c| c.status == VerifyCheckStatus::Fail)
        {
            return VerifyVerdict::Failed;
        }
        if !self
            .signatures
            .iter()
            .any(|s| s.kind == SignatureKind::Signer)
            || self
                .all_checks()
                .any(|c| c.status == VerifyCheckStatus::NotRun)
            || self.modifications == ModificationStatus::NotRun
            || self.checks.is_empty()
            || self.signatures.iter().any(|s| s.checks.is_empty())
        {
            return VerifyVerdict::Indeterminate;
        }
        VerifyVerdict::Passed
    }

    pub fn all_checks(&self) -> impl Iterator<Item = &VerifyCheck> {
        self.checks
            .iter()
            .chain(self.signatures.iter().flat_map(|s| s.checks.iter()))
    }

    #[must_use]
    pub fn achieved_profile(&self) -> Option<PadesProfile> {
        self.signatures
            .iter()
            .filter(|s| s.kind == SignatureKind::Signer)
            .filter_map(|s| s.achieved_profile)
            .max()
    }

    /// Named failed-check reasons, derived so they cannot drift from checks.
    #[must_use]
    pub fn reasons(&self) -> Vec<VerifyFindingCode> {
        let mut reasons: Vec<_> = self
            .all_checks()
            .filter(|c| {
                matches!(
                    c.status,
                    VerifyCheckStatus::Fail | VerifyCheckStatus::NotRun
                )
            })
            .filter_map(|c| c.finding)
            .collect();
        if self.modifications == ModificationStatus::Suspicious
            && !reasons.contains(&VerifyFindingCode::ModificationNotAllowed)
        {
            reasons.push(VerifyFindingCode::ModificationNotAllowed);
        }
        reasons
    }

    #[must_use]
    pub fn passes_self_verify(&self) -> bool {
        self.verdict() == VerifyVerdict::Passed
            && self.achieved_profile().is_some()
            && !matches!(
                self.modifications,
                ModificationStatus::NotRun | ModificationStatus::Suspicious
            )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedPdf {
    pub bytes: Vec<u8>,
    pub evidence_sha256: Sha256Digest,
    pub requested_profile: PadesProfile,
    pub achieved_profile: PadesProfile,
    pub warnings: Vec<SealWarning>,
    pub self_verify_report: VerifyReport,
}

/// Seal + verify engine. `seal_pdf` runs the verifier against its candidate
/// output before returning and converts an invalid report into
/// [`crate::SealError::VerifyFailed`]; `verify_sealed_pdf` returns
/// `Ok(VerifyReport)` with a derived `Failed` or `Indeterminate` verdict
/// for a parseable PDF that cannot pass verification.
#[async_trait]
pub trait PdfSealEngine: Send + Sync {
    async fn seal_pdf(
        &self,
        input_bytes: &[u8],
        seal_request: &SealRequest,
    ) -> Result<SealedPdf, SealError>;

    fn verify_sealed_pdf(&self, sealed_bytes: &[u8]) -> Result<VerifyReport, SealError>;
}

pub trait SealClock: Send + Sync {
    fn unix_time_ms(&self) -> u64;
}

// §5 native configuration and fetcher contract. These types ride the
// `native` feature because they name `url::Url` / `ipnet::IpNet`; the
// non-crypto API surface above compiles without them.
#[cfg(feature = "native")]
pub mod config {
    use async_trait::async_trait;

    /// Trusted timestamp authority endpoint.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TsaEndpoint {
        pub url: url::Url,
        pub expected_policy_oid: Option<String>,
    }

    /// Egress policy for the guarded fetcher. Empty `allowed_origins` denies
    /// every remote fetch; AIA/OCSP/CRL URLs discovered in certificates do
    /// not become implicitly trusted origins.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FetchPolicy {
        pub allowed_origins: Vec<url::Url>,
        pub allowed_cidrs: Vec<ipnet::IpNet>,
        pub max_redirects: u8,
        pub timeout_ms: u64,
        pub max_aia_bytes: usize,
        pub max_ocsp_bytes: usize,
        pub max_crl_bytes: usize,
        pub max_tsa_bytes: usize,
    }

    impl Default for FetchPolicy {
        fn default() -> Self {
            Self {
                allowed_origins: Vec::new(),
                allowed_cidrs: Vec::new(),
                max_redirects: 3,
                timeout_ms: 5_000,
                max_aia_bytes: 1_048_576,
                max_ocsp_bytes: 1_048_576,
                max_crl_bytes: 8_388_608,
                max_tsa_bytes: 1_048_576,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SealResourceLimits {
        pub max_input_bytes: usize,
        pub max_output_growth_bytes: usize,
        pub max_pdf_objects: usize,
    }

    impl Default for SealResourceLimits {
        fn default() -> Self {
            Self {
                max_input_bytes: 256 * 1024 * 1024,
                max_output_growth_bytes: 32 * 1024 * 1024,
                max_pdf_objects: 1_000_000,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SealConfig {
        pub trust_anchors_der: Vec<Vec<u8>>,
        pub timestamp_authorities: Vec<TsaEndpoint>,
        pub fetch_policy: FetchPolicy,
        pub resource_limits: SealResourceLimits,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FetchPurpose {
        AuthorityInformationAccess,
        Ocsp,
        Crl,
        Timestamp,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FetchMethod {
        Get,
        Post,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FetchRequest {
        pub purpose: FetchPurpose,
        pub url: url::Url,
        pub method: FetchMethod,
        pub request_body: Vec<u8>,
        pub content_type: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FetchResponse {
        pub body: Vec<u8>,
        pub content_type: Option<String>,
    }

    #[derive(Debug, thiserror::Error)]
    pub enum FetchError {
        #[error("fetch target denied by policy")]
        Denied,
        #[error("fetch timed out")]
        Timeout,
        #[error("fetch transport unavailable")]
        Unavailable,
        #[error("fetch response exceeded the purpose cap")]
        ResponseTooLarge,
        #[error("fetch response was invalid")]
        InvalidResponse,
    }

    /// The one fetch door (GATE-1 amendment A4). Every AIA, OCSP, CRL, and TSA
    /// fetch passes through this trait; no dependency opens its own socket.
    #[async_trait]
    pub trait SealFetcher: Send + Sync {
        async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, FetchError>;
    }

    /// Fetcher for offline / B-B-only compositions: every request returns
    /// [`FetchError::Unavailable`], which the profile assembler converts into
    /// the matching profile-degradation warning.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct OfflineFetcher;

    #[async_trait]
    impl SealFetcher for OfflineFetcher {
        async fn fetch(&self, _request: FetchRequest) -> Result<FetchResponse, FetchError> {
            Err(FetchError::Unavailable)
        }
    }
}

#[cfg(feature = "native")]
pub use config::{
    FetchError, FetchMethod, FetchPolicy, FetchPurpose, FetchRequest, FetchResponse,
    OfflineFetcher, SealConfig, SealFetcher, SealResourceLimits, TsaEndpoint,
};

#[cfg(test)]
mod report_tests {
    use super::*;

    fn report() -> VerifyReport {
        VerifyReport {
            artifact_sha256: [4; 32],
            revisions: vec![VerifyRevision {
                index: 0,
                kind: RevisionKind::Signature,
                byte_end: 100,
                signed_by: Some("name:0".into()),
            }],
            signatures: vec![SignatureVerification {
                id: "name:0".into(),
                kind: SignatureKind::Signer,
                byte_range: ByteRangeEvidence {
                    values: [0, 4, 50, 50],
                    well_formed: true,
                    covers_to: Some(100),
                    file_len: 100,
                },
                coverage: SignatureCoverage::EntireFile,
                digest: Some(SignedRangeDigest {
                    algorithm: DigestAlgorithm::Sha256,
                    value: [2; 32],
                }),
                integrity: VerifyVerdict::Passed,
                trust: VerifyVerdict::Passed,
                achieved_profile: Some(PadesProfile::BaselineB),
                checks: vec![VerifyCheck {
                    kind: VerifyCheckKind::ContentDigest,
                    status: VerifyCheckStatus::Pass,
                    finding: None,
                }],
            }],
            modifications: ModificationStatus::Clean(ModificationLevel::None),
            anomalies: Vec::new(),
            checks: vec![VerifyCheck {
                kind: VerifyCheckKind::PdfRevision,
                status: VerifyCheckStatus::Pass,
                finding: None,
            }],
        }
    }

    #[test]
    fn verdict_is_derived_across_every_envelope_not_the_artifact_hash() {
        let mut report = report();
        assert_eq!(report.verdict(), VerifyVerdict::Passed);
        assert!(report.passes_self_verify());
        report.artifact_sha256 = [8; 32];
        assert_eq!(report.verdict(), VerifyVerdict::Passed);
        report.signatures.push(report.signatures[0].clone());
        report.signatures[1].checks[0].status = VerifyCheckStatus::NotRun;
        assert_eq!(report.verdict(), VerifyVerdict::Indeterminate);
        assert!(!report.passes_self_verify());
        report.signatures[0].checks[0].status = VerifyCheckStatus::Fail;
        assert_eq!(report.verdict(), VerifyVerdict::Failed);
        report.signatures[1].checks[0].status = VerifyCheckStatus::NotApplicable;
        assert_eq!(report.verdict(), VerifyVerdict::Failed);
        report.signatures[0].checks[0].status = VerifyCheckStatus::Pass;
        assert_eq!(report.verdict(), VerifyVerdict::Passed);
        report.signatures[0].checks[0].status = VerifyCheckStatus::Pass;
        report.modifications = ModificationStatus::Suspicious;
        assert_eq!(report.verdict(), VerifyVerdict::Failed);
        report.modifications = ModificationStatus::NotRun;
        assert_eq!(report.verdict(), VerifyVerdict::Indeterminate);
        report.modifications = ModificationStatus::Clean(ModificationLevel::None);
        report.anomalies.push(VerifyAnomaly::RetypedObject);
        assert_eq!(report.verdict(), VerifyVerdict::Passed);
        report.signatures.clear();
        assert_eq!(report.verdict(), VerifyVerdict::Indeterminate);
    }

    #[test]
    fn untrusted_root_does_not_claim_modified_bytes() {
        let mut report = report();
        report.signatures[0].trust = VerifyVerdict::Indeterminate;
        report.signatures[0].checks.push(VerifyCheck {
            kind: VerifyCheckKind::CertificatePath,
            status: VerifyCheckStatus::NotRun,
            finding: Some(VerifyFindingCode::TrustRootUnavailable),
        });
        assert_eq!(report.verdict(), VerifyVerdict::Indeterminate);
        assert_eq!(
            report.reasons(),
            vec![VerifyFindingCode::TrustRootUnavailable]
        );
        assert_eq!(
            report.modifications,
            ModificationStatus::Clean(ModificationLevel::None)
        );
    }
}
