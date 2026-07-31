//! Native Rust PAdES seal and verification engine (ONE-1837).
//!
//! This crate is a pure byte transform and verifier: it mints no entity type,
//! claim predicate, attempt kind, blob version, or audit row, and it performs
//! no orchestration or storage writes. Python, pyHanko, and sidecar processes
//! are absent from the runtime path; pyHanko is a CI-only differential oracle.

pub mod api;
mod error;
#[cfg(feature = "native")]
mod native;

pub use api::{
    BackendError, BackendRejectCode, BackendSignature, DigestAlgorithm, PadesProfile,
    PdfSealEngine, ProfileDegradeReason, SealBackend, SealClock, SealRequest, SealWarning,
    SealedPdf, Sha256Digest, SignDigestRequest, SignatureAlgorithm, SigningIdentity, VerifyCheck,
    VerifyCheckKind, VerifyCheckStatus, VerifyFindingCode, VerifyReport,
};
#[cfg(feature = "native")]
pub use api::{
    FetchError, FetchMethod, FetchPolicy, FetchPurpose, FetchRequest, FetchResponse,
    OfflineFetcher, SealConfig, SealFetcher, SealResourceLimits, TsaEndpoint,
};
pub use error::{FatalCode, InputInvalidCode, RetryableCode, SealError, SealStage};

#[cfg(feature = "native")]
pub use native::NativeSealEngine;
#[cfg(feature = "network-fetch")]
pub use native::SsrfGuardedHttpFetcher;
