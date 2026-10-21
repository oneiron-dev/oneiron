//! Native Rust PAdES seal and verification engine (ONE-1837).
//!
//! This crate is a pure byte transform and verifier: it mints no entity type,
//! claim predicate, attempt kind, blob version, or audit row, and it performs
//! no orchestration or storage writes. Python, pyHanko, and sidecar processes
//! are absent from the runtime path; pyHanko is a CI-only differential oracle.
//!
//! The engine never links it. It runs as its own organ process,
//! `oneiron-seal-organ`, behind the organ host (the `organ` module).

pub mod api;
mod error;
#[cfg(feature = "native")]
mod memory;
#[cfg(feature = "native")]
mod native;
#[cfg(all(unix, feature = "native"))]
pub mod organ;

pub use api::{
    Anomaly, BackendError, BackendRejectCode, BackendSignature, ByteRangeEvidence, Coverage,
    DigestAlgorithm, ModificationLevel, Modifications, PadesProfile, PdfSealEngine,
    PreparedRevision, ProfileDegradeReason, RevisionKind, RevisionReport, SealBackend, SealClock,
    SealRequest, SealWarning, SealedPdf, Sha256Digest, SignDigestRequest, SignRevisionRequest,
    SignatureAlgorithm, SignatureKind, SignatureReport, SignedRangeDigest, SigningIdentity,
    VerifyCheck, VerifyCheckKind, VerifyCheckStatus, VerifyFindingCode, VerifyReport,
    VerifyVerdict,
};
#[cfg(feature = "native")]
pub use api::{
    FetchError, FetchMethod, FetchPolicy, FetchPurpose, FetchRequest, FetchResponse,
    OfflineFetcher, PDF_FORMAT_BYTES, PDF_FORMAT_OBJECTS, SealConfig, SealFetcher,
    SealObservations, SealObserved, SealResourceLimits, TsaEndpoint,
};
pub use error::{FatalCode, InputInvalidCode, RetryableCode, SealError, SealStage};
#[cfg(feature = "native")]
pub use memory::{AdmittedBytes, SealMemory, SealMemoryProvider, SealMemoryRefusal, SharedBytes};

#[cfg(feature = "native")]
pub use native::NativeSealEngine;
#[cfg(feature = "network-fetch")]
pub use native::SsrfGuardedHttpFetcher;
