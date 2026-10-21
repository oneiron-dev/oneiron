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

/// One signature over a signature revision's signed attributes. `digest`
/// is SHA-256 over `signed_attributes_der` under the universal `SET OF`
/// tag, as in [`SignDigestRequest`]. The rest lets a signer across a trust
/// boundary recompute that hash from a revision it wrote itself, rather
/// than sign the one it is given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRevisionRequest {
    pub operation_id: String,
    /// The revision's index among those the caller supplied
    /// ([`PreparedRevision`]); `None` for a revision the engine wrote.
    pub revision_id: Option<u32>,
    pub byte_range: [u64; 4],
    /// The `[0] IMPLICIT` signed attributes, as the CMS carries them.
    pub signed_attributes_der: Vec<u8>,
    pub digest: Sha256Digest,
}

/// A signature revision the caller wrote: the prepared input followed by
/// `suffix` is the whole revision, its `/Contents` hole all ASCII zeros,
/// and `byte_range` leaves out exactly that hole. The engine fills the hole
/// and writes no PDF object of its own into the revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreparedRevision<'a> {
    pub suffix: &'a [u8],
    pub byte_range: [u64; 4],
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

    /// Signs one signature revision. The default signs `request.digest`
    /// through [`Self::sign_digest`]; a backend whose key sits across a
    /// trust boundary sends the rest, so the key's holder computes the hash
    /// it signs.
    async fn sign_revision(
        &self,
        request: SignRevisionRequest,
    ) -> Result<BackendSignature, BackendError> {
        self.sign_digest(SignDigestRequest {
            operation_id: request.operation_id,
            digest_algorithm: DigestAlgorithm::Sha256,
            digest: request.digest,
        })
        .await
    }
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

mod report;
pub use report::{
    Anomaly, ByteRangeEvidence, Coverage, ModificationLevel, Modifications, RevisionKind,
    RevisionReport, SignatureKind, SignatureReport, SignedRangeDigest, VerifyCheck,
    VerifyCheckKind, VerifyCheckStatus, VerifyFindingCode, VerifyReport, VerifyVerdict,
};

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
/// `Ok(VerifyReport)` for a parseable but
/// cryptographically invalid sealed PDF.
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
    /// not become implicitly trusted origins. The redirect count and the
    /// per-purpose byte sizes are thresholds, never refusals (Rule 5): a
    /// response is read to its end, every hop re-checked against the
    /// origins and addresses, inside `timeout_ms`. In the organ, the engine
    /// fetches, and its `[limits]` rows measure each one.
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

    /// The most bytes a PDF the seal reads or writes spans: lopdf records
    /// each object's byte offset as a `u32` (its xref entry), so an object
    /// past 4 GiB could not be addressed. A format bound, not a policy.
    pub const PDF_FORMAT_BYTES: usize = u32::MAX as usize;
    /// The most indirect objects one PDF file holds: ISO 32000-1 Annex C,
    /// section C.2, Table C.1 (8,388,607).
    pub const PDF_FORMAT_OBJECTS: usize = 8_388_607;

    /// The seal's resource limits: format bounds only, which refuse input
    /// the PDF codec cannot carry. Everything the seal used to cap on size
    /// (output growth, objects, revisions, structural work, prefix work,
    /// decoded DSS material, one stream's decoded bytes, nesting, reference
    /// chains, field trees, signature contents) it now counts in `observed`
    /// and serves whole; the host measures those counts against its
    /// `[limits]` rows. What its decodes allocate it reserves first from
    /// `memory`, which refuses only at the machine's floor or a deadline.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SealResourceLimits {
        /// Bytes of a PDF read or written, at most [`PDF_FORMAT_BYTES`].
        pub max_input_bytes: usize,
        /// Objects of one parsed PDF, at most [`PDF_FORMAT_OBJECTS`].
        pub max_pdf_objects: usize,
        /// Where this invocation's counts go.
        pub observed: SealObservations,
        /// The memory service every native decode reserves its bytes from
        /// before it allocates them (FIX 7654). Unconfigured by default: a
        /// native engine refuses to start without one.
        pub memory: crate::memory::SealMemoryProvider,
    }

    impl Default for SealResourceLimits {
        fn default() -> Self {
            Self {
                max_input_bytes: PDF_FORMAT_BYTES,
                max_pdf_objects: PDF_FORMAT_OBJECTS,
                observed: SealObservations::default(),
                memory: crate::memory::SealMemoryProvider::default(),
            }
        }
    }

    /// What the seal's native analysis counted, as the host's `[limits]`
    /// rows read it. Each is the largest of one pass, never a sum over the
    /// self-verifier's repeat passes. A count never stops the work.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
    pub struct SealObserved {
        /// Objects of one strictly parsed snapshot.
        pub pdf_objects: u64,
        /// Raw object definitions of one revision, shadowed and unindexed
        /// ones included.
        pub raw_definitions: u64,
        /// Tokens one structural pass lexed: a revision analysis, or one
        /// classic xref section.
        pub structural_work: u64,
        /// Revisions of one xref `/Prev` chain.
        pub revisions: u64,
        /// Prefix bytes one pass over the revision chain parsed, summed over
        /// its revisions.
        pub prefix_bytes: u64,
        /// Bytes one DSS extraction decoded across its Certs, CRLs and OCSPs.
        pub dss_decode_bytes: u64,
        /// Bytes the largest single stream decoded to: an object or xref
        /// stream the loader decodes, or one DSS entry.
        pub stream_decode_bytes: u64,
        /// Tokens the longest stream-dictionary header lexed to find its
        /// `/Length`.
        pub stream_header_tokens: u64,
        /// The deepest nesting one lexed value reached: literal-string
        /// parentheses, or arrays and dictionaries.
        pub pdf_depth: u64,
        /// Reference links the longest chain behind a security-checked name
        /// (`/Type`, `/FT`, `/S`) took.
        pub security_name_hops: u64,
        /// Reference links the longest other chain the analysis followed took.
        pub reference_hops: u64,
        /// Reference steps one DSS coverage measurement took over all its
        /// chains.
        pub dss_reference_work: u64,
        /// Nodes one AcroForm field-tree descent visited.
        pub field_tree_work: u64,
        /// DER bytes of the largest CMS or timestamp token a signature
        /// revision's `/Contents` hole had to hold.
        pub contents_bytes: u64,
    }

    /// One count [`SealObservations`] keeps.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Counter {
        PdfObjects,
        RawDefinitions,
        StructuralWork,
        Revisions,
        PrefixBytes,
        DssDecodeBytes,
        StreamDecodeBytes,
        StreamHeaderTokens,
        PdfDepth,
        SecurityNameHops,
        ReferenceHops,
        DssReferenceWork,
        FieldTreeWork,
        ContentsBytes,
    }

    /// How many counts [`SealObservations`] keeps: one per [`Counter`].
    const COUNTERS: usize = Counter::ContentsBytes as usize + 1;

    /// Where one invocation's counts go. Clones share it, so the caller
    /// that built a config reads what the engine counted under it; a fresh
    /// default starts at zero. Two are equal when they are the same sink.
    #[derive(Debug, Clone, Default)]
    pub struct SealObservations(std::sync::Arc<[std::sync::atomic::AtomicU64; COUNTERS]>);

    impl SealObservations {
        /// The largest value each count has reached.
        #[must_use]
        pub fn observed(&self) -> SealObserved {
            let read = |counter: Counter| {
                self.0[counter as usize].load(std::sync::atomic::Ordering::Relaxed)
            };
            SealObserved {
                pdf_objects: read(Counter::PdfObjects),
                raw_definitions: read(Counter::RawDefinitions),
                structural_work: read(Counter::StructuralWork),
                revisions: read(Counter::Revisions),
                prefix_bytes: read(Counter::PrefixBytes),
                dss_decode_bytes: read(Counter::DssDecodeBytes),
                stream_decode_bytes: read(Counter::StreamDecodeBytes),
                stream_header_tokens: read(Counter::StreamHeaderTokens),
                pdf_depth: read(Counter::PdfDepth),
                security_name_hops: read(Counter::SecurityNameHops),
                reference_hops: read(Counter::ReferenceHops),
                dss_reference_work: read(Counter::DssReferenceWork),
                field_tree_work: read(Counter::FieldTreeWork),
                contents_bytes: read(Counter::ContentsBytes),
            }
        }

        /// Raises `counter` to `value` if it is below.
        pub(crate) fn note(&self, counter: Counter, value: usize) {
            let value = u64::try_from(value).unwrap_or(u64::MAX);
            self.0[counter as usize].fetch_max(value, std::sync::atomic::Ordering::Relaxed);
        }

        /// Makes these the counts of the analysis this thread runs until the
        /// scope drops, so a helper deep inside it (a reference walk, the
        /// lexer, the field-tree descent) counts through [`note_current`]
        /// without carrying the sink. Entered by synchronous analyses only;
        /// the scope is not `Send`, so it cannot be held across an await.
        pub(crate) fn enter(&self) -> AnalysisScope {
            let previous = ANALYSIS.with(|current| current.replace(Some(self.clone())));
            AnalysisScope {
                previous,
                _thread: std::marker::PhantomData,
            }
        }
    }

    std::thread_local! {
        /// The counts of the analysis running on this thread, while one is.
        static ANALYSIS: std::cell::RefCell<Option<SealObservations>> =
            const { std::cell::RefCell::new(None) };
    }

    /// A [`SealObservations::enter`] in force; dropping it restores the
    /// counts that were current before.
    pub(crate) struct AnalysisScope {
        previous: Option<SealObservations>,
        _thread: std::marker::PhantomData<*const ()>,
    }

    impl Drop for AnalysisScope {
        fn drop(&mut self) {
            let previous = self.previous.take();
            ANALYSIS.with(|current| *current.borrow_mut() = previous);
        }
    }

    /// Raises `counter` to `value` in the counts of the analysis this thread
    /// runs (see [`SealObservations::enter`]); outside one it counts nothing.
    pub(crate) fn note_current(counter: Counter, value: usize) {
        ANALYSIS.with(|current| {
            if let Some(observed) = current.borrow().as_ref() {
                observed.note(counter, value);
            }
        });
    }

    impl PartialEq for SealObservations {
        fn eq(&self, other: &Self) -> bool {
            std::sync::Arc::ptr_eq(&self.0, &other.0)
        }
    }

    impl Eq for SealObservations {}

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
        /// The memory the response's bytes needed was not reserved
        /// (FIX 7654).
        #[error("fetch response memory: {0}")]
        Memory(crate::memory::SealMemoryRefusal),
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
pub(crate) use config::{Counter, note_current};
#[cfg(feature = "native")]
pub use config::{
    FetchError, FetchMethod, FetchPolicy, FetchPurpose, FetchRequest, FetchResponse,
    OfflineFetcher, PDF_FORMAT_BYTES, PDF_FORMAT_OBJECTS, SealConfig, SealFetcher,
    SealObservations, SealObserved, SealResourceLimits, TsaEndpoint,
};
