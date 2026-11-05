//! Stable seal error classes and codes (ONE-1837 §6).

use serde::{Deserialize, Serialize};

use crate::api::VerifyReport;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealStage {
    InputValidation,
    PdfIncrementalUpdate,
    CmsAssembly,
    BackendSign,
    Timestamp,
    Revocation,
    Dss,
    DocumentTimestamp,
    Verification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryableCode {
    IoInterrupted,
    ResourceBusy,
    TemporaryBackendFailure,
    TemporaryFetchFailure,
    /// The machine could not hold the memory a decode needed (FIX 7654).
    MemoryFloor,
    /// The memory a decode needed did not fit before its deadline.
    ResourceDeadline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FatalCode {
    InvalidConfiguration,
    UnsupportedSignatureAlgorithm,
    InvalidSigningIdentity,
    BackendRejected,
    CmsEncodingFailed,
    PdfInvariantFailed,
    ContentsCapacityExceeded,
    CertificatePathInvalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputInvalidCode {
    Empty,
    TooLarge,
    NotPdf,
    EncryptedPdf,
    MalformedXref,
    UnsupportedHybridXref,
    ExistingSignature,
    ActiveContentPresent,
    EmbeddedFilePresent,
    MissingPage,
    ObjectLimitExceeded,
    /// Generic PDF structure failure in the ported prepare/inspect pipeline (FIX 7980/8157).
    MalformedPdf,
    /// Rejected PDF construct (OCProperties/XFA/NeedAppearances/non-Flate/predictor).
    UnsupportedPdf,
    /// A page box, rotation, user-unit or field geometry failed its bound.
    InvalidGeometry,
    /// The engine-lent audit-chain replay material failed its check.
    InvalidEvidence,
    /// An esign field row failed its shape or item check.
    InvalidField,
    /// A signature raster failed its decoder bound.
    InvalidSignatureImage,
    /// Unsupported text encoding or extraction path.
    UnsupportedText,
    /// A field value overflowed its burn-in bound.
    FieldOverflow,
    /// The canonical URL failed its check.
    InvalidCanonicalUrl,
}

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("retryable seal failure at {stage:?}: {code:?}")]
    Retryable {
        stage: SealStage,
        code: RetryableCode,
        retry_after_ms: Option<u64>,
    },
    #[error("fatal seal failure at {stage:?}: {code:?}")]
    Fatal { stage: SealStage, code: FatalCode },
    #[error("sealed PDF failed native self-verification")]
    VerifyFailed { report: Box<VerifyReport> },
    #[error("seal backend unavailable")]
    BackendUnavailable { retry_after_ms: Option<u64> },
    #[error("invalid prepared PDF input: {code:?}")]
    InputInvalid { code: InputInvalidCode },
}

impl SealError {
    /// `Retryable`, `BackendUnavailable`, and `VerifyFailed` leave the
    /// orchestration attempt retryable. `InputInvalid` is fatal for those
    /// prepared bytes; `Fatal` is not retried unchanged.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Retryable { .. } | Self::VerifyFailed { .. } | Self::BackendUnavailable { .. }
        )
    }
}
