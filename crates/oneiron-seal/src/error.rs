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
    Fatal {
        stage: SealStage,
        code: FatalCode,
    },
    #[error("sealed PDF failed native self-verification")]
    VerifyFailed {
        report: Box<VerifyReport>,
    },
    #[error("seal backend unavailable")]
    BackendUnavailable {
        retry_after_ms: Option<u64>,
    },
    #[error("invalid prepared PDF input: {code:?}")]
    InputInvalid {
        code: InputInvalidCode,
    },
}

impl SealError {
    /// `Retryable`, `BackendUnavailable`, and `VerifyFailed` leave the
    /// orchestration attempt retryable. `InputInvalid` is fatal for those
    /// prepared bytes; `Fatal` is not retried unchanged.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Retryable { .. }
                | Self::VerifyFailed { .. }
                | Self::BackendUnavailable { .. }
        )
    }
}
