use crate::claim::ClaimLifecycleStatus;
use crate::types::{ENTITY_TYPE_FACET, EntityId, VadComponent};

/// Result type used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Stable coarse-grained category for [`Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    Storage,
    Io,
    DimensionMismatch,
    InvalidVector,
    InvalidEdgeWeight,
    InvalidVad,
    EmbeddingModelChanged,
    HnswConfigChanged,
    StorageAbiVersionChanged,
    StorageSchemaVersionChanged,
    DbManifestMismatch,
    MapFull,
    InvalidConfig,
    EntityNotFound,
    ConcurrentWrite,
    ArithmeticOverflow,
    InvariantViolation,
    InvalidKey,
    CorruptedIndex,
    IndexOverflow,
    MissingPostingEntry,
    InvalidEntityType,
    InvalidFacet,
    InvalidClaimBody,
    InvalidPredicate,
    ReservedPredicate,
    MaintenanceKindNotWritable,
    EntityTypeImmutable,
    InvalidTimeRange,
    EdgeNotFound,
    ProvenanceOnStructuralEdge,
    ActorClassMismatch,
    InvalidProvenanceBody,
    ClaimAlreadyClosed,
    ClaimSelfSupersession,
    ProvenanceClaimLifecycle,
    NotAProvenanceClaim,
    ProvenanceClaimAlreadyClosed,
    ProvenanceClaimIdInUse,
    ProvenanceSubjectMismatch,
    ProvenanceSelfSupersession,
    ProvenancePrecedenceViolation,
    EdgeIsProvenanced,
    CycleDetected,
    ChildOfCardinality,
    IncompatibleAnalyzer,
    Bm25FieldSchemaChanged,
    InvalidRankProfile,
    AnalyzerAssetMissing,
    AnalyzerError,
    #[cfg(feature = "sync")]
    CrdtDecodeError,
    #[cfg(feature = "sync")]
    WindowNotFound,
    #[cfg(feature = "sync")]
    SyncProtocolError,
    #[cfg(feature = "sync")]
    InvalidRedactionReceiptBody,
    #[cfg(feature = "sync")]
    RedactionReceiptDivergence,
}

/// Crate error type.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// LMDB-backed storage error.
    #[error("storage error: {0}")]
    Storage(heed::Error),
    /// Filesystem or operating system error.
    #[error("io error: {0}")]
    Io(std::io::Error),
    /// Vector dimension does not match vault configuration.
    #[error("dimension mismatch: expected {expected}, got {got}")]
    DimensionMismatch { expected: usize, got: usize },
    /// Vector contains NaN or infinity values.
    #[error("invalid vector component at index {index}: {value}")]
    InvalidVector { index: usize, value: f32 },
    /// Edge weight is NaN, infinite, or outside the contract range \[0, 1\]
    /// (contracts.ts `edgeKinds` weight pin; enforced on every write path).
    #[error("invalid edge weight: {value} (contract range [0, 1])")]
    InvalidEdgeWeight { value: f32 },
    /// VAD tuple contains non-finite or out-of-range values.
    #[error("invalid VAD component {component:?}: {value}")]
    InvalidVad { component: VadComponent, value: f32 },
    /// Stored embedding model differs from requested model.
    #[error("embedding model changed: stored={stored}, requested={requested}")]
    EmbeddingModelChanged { stored: String, requested: String },
    /// Persisted HNSW config differs from the requested runtime config.
    #[error("hnsw config changed: stored={stored}, requested={requested}")]
    HnswConfigChanged { stored: String, requested: String },
    /// The vault was created with a different storage ABI. This gates
    /// on-disk edge-kind discriminants, edge value layouts, and entity type
    /// bytes before callers can silently decode them incorrectly.
    #[error("storage ABI version changed: stored={stored:?}, current={current}")]
    StorageAbiVersionChanged { stored: Option<u16>, current: u16 },
    /// The vault's DB-level schema version is not handled by this build. A
    /// future migration runner can use this as its dispatch point.
    #[error("storage schema version changed: stored={stored:?}, current={current}")]
    StorageSchemaVersionChanged { stored: Option<u16>, current: u16 },
    /// The LMDB named database set does not match the ARCH-0019 manifest.
    #[error("DB manifest mismatch: missing={missing:?}, unexpected={unexpected:?}")]
    DbManifestMismatch {
        missing: Vec<String>,
        unexpected: Vec<String>,
    },
    /// LMDB map is full and requires a larger map size.
    #[error("lmdb map is full")]
    MapFull,
    /// Invalid runtime configuration input.
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    /// Requested entity does not exist.
    #[error("entity not found")]
    EntityNotFound,
    /// A concurrent write invalidated an operation that relied on a stable snapshot.
    #[error("concurrent write detected: {0}")]
    ConcurrentWrite(&'static str),
    /// A counter or version increment exceeded supported bounds.
    #[error("arithmetic overflow: {0}")]
    ArithmeticOverflow(&'static str),
    /// Internal state violated an invariant that should be preserved by the crate.
    #[error("invariant violation: {0}")]
    InvariantViolation(&'static str),
    /// Encountered malformed key or value bytes.
    #[error("invalid key or value bytes")]
    InvalidKey,
    /// Index metadata or neighbor storage is internally inconsistent.
    #[error("corrupted index: {0}")]
    CorruptedIndex(&'static str),
    /// Index bookkeeping overflowed its supported range.
    #[error("index overflow: {0}")]
    IndexOverflow(&'static str),
    /// Expected posting or metadata row is missing from an index.
    #[error("missing posting entry")]
    MissingPostingEntry,
    /// Entity type byte is not in any known range.
    #[error("invalid entity type: {0}")]
    InvalidEntityType(u8),
    /// The active facet supplied to the retrieval pipeline does not resolve to
    /// an EXISTING FACET entity (type byte 13, per contracts.ts §1). Rejected
    /// fail-closed at query setup: a bogus id (`found = None`, no such entity)
    /// or an id whose type byte is not FACET (`found = Some(other_type)`) is a
    /// typed error, never a silent treat-everything-as-other-facet. Strict
    /// mode must never drop every scoped claim because the active facet was
    /// invalid. Nothing is queried.
    #[error(
        "invalid active facet {}: resolved type {found:?}, expected FACET ({ENTITY_TYPE_FACET})",
        facet.to_hex()
    )]
    InvalidFacet { facet: EntityId, found: Option<u8> },
    /// A type-0 (CLAIM) entity body failed the pinned structural validation
    /// (D11 key set / D18 fail-closed gate). Nothing was written.
    #[error("invalid claim body: {0}")]
    InvalidClaimBody(&'static str),
    /// Claim predicate violates the pinned D17 grammar (≥2 segments of
    /// `[a-z][a-z0-9_]*` joined by `.`, total ≤128 bytes).
    #[error("invalid claim predicate {predicate:?}: {reason}")]
    InvalidPredicate {
        predicate: String,
        reason: &'static str,
    },
    /// Claim predicate lives in the reserved `edge.*` namespace, which only
    /// the engine's internal provenance path may write (D17).
    #[error("reserved claim predicate namespace: {predicate:?}")]
    ReservedPredicate { predicate: String },
    /// Registered maintenance-band entity kind (type bytes 120+, e.g.
    /// REDACTION_AUDIT) rejected on a public write path. Maintenance records
    /// are engine-authored only; this is distinct from
    /// [`Error::InvalidEntityType`], which covers genuinely unknown bytes.
    #[error("maintenance entity kind {0} is engine-authored and not writable via the public API")]
    MaintenanceKindNotWritable(u8),
    /// The type byte of an existing entity record is immutable on re-put
    /// (M2 pinned decision D2). The short-id prefix is derived from the type
    /// byte at first insert, so re-typing would leave the record addressed
    /// under another type's prefix. Delete-and-recreate is the escape hatch.
    #[error(
        "entity type is immutable: entity {} has type {existing}, re-put attempted type {attempted}",
        id.to_hex()
    )]
    EntityTypeImmutable {
        id: EntityId,
        existing: u8,
        attempted: u8,
    },
    /// Occurred interval is reversed (`occurred_start > occurred_end`).
    /// The entity envelope stores an interval (ARCH-0002 / contracts.ts
    /// `entityValueEnvelope`); reversed input is rejected fail-closed, never
    /// silently repaired (M2 pinned decision D3). `start == end` is a legal
    /// point event.
    #[error("invalid time range: occurred_start {start} > occurred_end {end}")]
    InvalidTimeRange { start: u64, end: u64 },
    /// Requested edge record does not exist. The provenance path never
    /// upserts a subject edge — it would have to invent weight/created_at.
    #[error("edge not found")]
    EdgeNotFound,
    /// `edge.provenance` may only attach to SEMANTIC edge kinds; structural
    /// kinds (12-byte layout) never carry the two hot flags.
    #[error("edge.provenance subject kind {kind} is structural, not semantic")]
    ProvenanceOnStructuralEdge { kind: u8 },
    /// The caller-supplied `actor_class` is incompatible with the actor
    /// entity's kind (D13: PERSON → human|agent, MACHINE → system, anything
    /// else is never an actor). The engine never defaults an actor class.
    #[error("actor class {actor_class} is incompatible with actor entity type {actor_entity_type}")]
    ActorClassMismatch {
        actor_entity_type: u8,
        actor_class: u8,
    },
    /// An `edge.provenance` value record failed the pinned structural
    /// validation (the 7-field snake_case ABI). Nothing was written.
    #[error("invalid edge.provenance body: {0}")]
    InvalidProvenanceBody(&'static str),
    /// A claim lifecycle transition (`supersede_claim` / `retract_claim`)
    /// targeted a claim whose `life` status is not `active`. Superseded and
    /// retracted claims are closed history (ARCH-0003: all non-current
    /// states are still stored — claims are never silently deleted) and
    /// cannot transition again. Nothing was written.
    #[error("claim already closed: lifecycle status is {status:?}")]
    ClaimAlreadyClosed { status: ClaimLifecycleStatus },
    /// `supersede_claim` was called with `new_id == old_id` — a claim
    /// cannot supersede itself. Nothing was written.
    #[error("claim cannot supersede itself")]
    ClaimSelfSupersession,
    /// A generic claim lifecycle op (`supersede_claim` / `retract_claim`)
    /// targeted a reserved-namespace (`edge.*`) provenance Claim. Provenance
    /// Claims drive the subject edge's derived hot flags, so their lifecycle
    /// is owned exclusively by the edge-provenance lifecycle API (the
    /// `put_edge_provenance` / `retract_edge_provenance` surface), which
    /// re-stamps the edge whenever the Claim changes. The generic ops reject
    /// instead of bypassing that re-stamp. Nothing was written.
    #[error(
        "claim predicate {predicate:?} is a reserved edge.* provenance claim; use the edge-provenance lifecycle API (put_edge_provenance / retract_edge_provenance), not the generic claim lifecycle ops"
    )]
    ProvenanceClaimLifecycle { predicate: String },
    /// A provenance lifecycle operation (retract / supersede) named an
    /// entity that is not an `edge.provenance` Claim — wrong type byte or
    /// wrong predicate. Nothing was written.
    #[error("not an edge.provenance claim: {0}")]
    NotAProvenanceClaim(&'static str),
    /// A provenance lifecycle operation targeted a Claim whose lifecycle is
    /// no longer `active` (double-retract, or supersede-after-close). The
    /// first close wins; nothing was written.
    #[error("edge.provenance claim is already closed: lifecycle is {lifecycle}")]
    ProvenanceClaimAlreadyClosed { lifecycle: &'static str },
    /// A provenance write named a `claim_id` that already exists in storage.
    /// Provenance claim ids are WRITE-ONCE: re-putting an existing id would
    /// overwrite the stored Claim in place — resurrecting a retracted or
    /// superseded wrapper as a fresh `active` body, bypassing
    /// [`Error::ProvenanceClaimAlreadyClosed`] (ARCH-0003: "claims are never
    /// silently deleted"). The lifecycle operations (retract / supersede)
    /// are the only mutators of an existing provenance Claim. Nothing was
    /// written.
    #[error("edge.provenance claim id already in use: provenance claim ids are write-once")]
    ProvenanceClaimIdInUse,
    /// The prior Claim named in a supersede call addresses a different
    /// EdgeRef than the incoming Claim. Supersession is per subject edge —
    /// two Claims naming different EdgeRefs never supersede each other.
    #[error("edge.provenance subject mismatch: prior and new claims address different EdgeRefs")]
    ProvenanceSubjectMismatch,
    /// A provenance Claim cannot supersede itself (`prior_claim_id` equals
    /// `new_claim_id`).
    #[error("edge.provenance claim cannot supersede itself")]
    ProvenanceSelfSupersession,
    /// D14 precedence violation: the incoming Claim's envelope `learned_at`
    /// is older than the live frontier for its subject edge, so it can never
    /// take precedence ("a newer Claim takes precedence"). The engine
    /// refuses to write a dead-on-arrival provenance Claim.
    #[error(
        "edge.provenance precedence violation: incoming learned_at {incoming_learned_at} predates the live frontier {frontier_learned_at}"
    )]
    ProvenancePrecedenceViolation {
        incoming_learned_at: u64,
        frontier_learned_at: u64,
    },
    /// A plain (provenance-free) edge put targeted an edge that carries a
    /// 26-byte provenanced value — the silent-downgrade hole pinned by
    /// ONE-1113 (ARCH-0034 #write-protection, ratified 2026-06-13): "an
    /// unattributed write can never displace attributed truth as current
    /// state". The write is rejected typed and routed — never a silent strip
    /// of the two hot-flag bytes, never a silent preserve of them under the
    /// caller's new value. Both edge directions stay byte-identical and the
    /// live `edge.provenance` Claim stays live; nothing was written.
    #[error(
        "edge (kind {kind}) is provenanced: a plain edge put cannot displace attributed truth; modify the relation via put_edge_provenance / the actor-bound surface (as_actor), set weight via set_edge_weight, set VAD via set_edge_vad"
    )]
    EdgeIsProvenanced { kind: u8 },
    /// Tree operation would create a cycle.
    #[error("cycle detected in tree hierarchy")]
    CycleDetected,
    /// ChildOf write would give a child more than one parent (single-parent
    /// tree pin; validated atomically over each batch).
    #[error("childof requires a single parent")]
    ChildOfCardinality,
    /// Text analyzer manifest on disk does not match the current analyzer
    /// configuration. Per-language mode (Morphological vs Portable) flipped
    /// because a dict appeared or disappeared between index time and open
    /// time (plan ONE-317 §4.2).
    ///
    /// # Recovery
    ///
    /// Reopen with [`VaultConfig::skip_text_index_manifest_check`] set to
    /// `true`, call [`MaintenanceBuilder::clear_text_index`] to drop the
    /// stale postings, reopen with the default `false` value so the empty
    /// index seeds a fresh manifest, then reindex documents to restore
    /// search results.
    ///
    /// [`VaultConfig::skip_text_index_manifest_check`]: crate::VaultConfig::skip_text_index_manifest_check
    /// [`MaintenanceBuilder::clear_text_index`]: crate::MaintenanceBuilder::clear_text_index
    #[error(
        "text analyzer changed since index was built (lang={lang:?}): stored={stored_mode} current={current_mode}; reopen with VaultConfig::skip_text_index_manifest_check=true, run clear_text_index, reopen normally, and reindex documents to restore search"
    )]
    IncompatibleAnalyzer {
        lang: String,
        stored_mode: &'static str,
        current_mode: &'static str,
    },
    /// BM25F field schema on disk does not match the current build. Channels
    /// in [`crate::analyzer::AnalyzerChannel`] were added, removed, or
    /// renumbered between index time and open time.
    ///
    /// # Recovery
    ///
    /// Same as [`Error::IncompatibleAnalyzer`]: reopen with
    /// [`VaultConfig::skip_text_index_manifest_check`] set to `true`, run
    /// [`MaintenanceBuilder::clear_text_index`], reopen normally, then
    /// reindex documents.
    ///
    /// [`VaultConfig::skip_text_index_manifest_check`]: crate::VaultConfig::skip_text_index_manifest_check
    /// [`MaintenanceBuilder::clear_text_index`]: crate::MaintenanceBuilder::clear_text_index
    #[error(
        "bm25f field schema changed since index was built; reopen with VaultConfig::skip_text_index_manifest_check=true, run clear_text_index, reopen normally, and reindex documents to restore search"
    )]
    Bm25FieldSchemaChanged,
    /// A caller-supplied BM25F rank profile carries an invalid scoring
    /// parameter: a non-finite or negative channel weight, a `b` outside
    /// `[0.0, 1.0]`, a non-finite or non-positive BM25+ `delta`, or an
    /// override on a reserved channel that v1 analyzers never emit
    /// (`Shingle` / `Synonym` / `Phonetic`). Rank profiles are
    /// scoring-only (ARCH-0031), so nothing on disk was touched; fix the
    /// profile and retry the query.
    #[error("invalid bm25 rank profile: {parameter} = {value}")]
    InvalidRankProfile { parameter: &'static str, value: f64 },
    /// A dict asset declared in the stored manifest is missing from disk
    /// (e.g., `system.dic` was deleted after indexing). Restore the file or
    /// use the same recovery path as [`Error::IncompatibleAnalyzer`]:
    /// reopen with [`VaultConfig::skip_text_index_manifest_check`] set to
    /// `true`, run [`MaintenanceBuilder::clear_text_index`], reopen
    /// normally, and reindex documents.
    ///
    /// [`VaultConfig::skip_text_index_manifest_check`]: crate::VaultConfig::skip_text_index_manifest_check
    /// [`MaintenanceBuilder::clear_text_index`]: crate::MaintenanceBuilder::clear_text_index
    #[error("analyzer asset missing: {0}")]
    AnalyzerAssetMissing(String),
    /// Generic analyzer error (dict load failure, manifest encode failure,
    /// etc.). Wraps the underlying cause as a string to avoid leaking
    /// transitive Sudachi/jieba/lindera error types into the public surface.
    #[error("analyzer error: {0}")]
    AnalyzerError(String),
    /// Malformed CRDT update bytes.
    #[cfg(feature = "sync")]
    #[error("crdt decode error ({context}): {source}")]
    CrdtDecodeError {
        context: &'static str,
        #[source]
        source: loro::LoroError,
    },
    /// No persisted state for the requested window.
    #[cfg(feature = "sync")]
    #[error("sync window not found: {window_key}")]
    WindowNotFound { window_key: String },
    /// Sync protocol violation.
    #[cfg(feature = "sync")]
    #[error("sync protocol error: {0}")]
    SyncProtocolError(String),
    /// A REDACTION_AUDIT (type 120) blob arriving through a sync replay door
    /// failed structural validation against the pinned contracts.ts
    /// `redactionAuditReceipt` field set (request_id, scope, reason,
    /// requested_at, soft_complete_at, hard_purge_complete_at,
    /// sweep_queued_at?, sweep_complete_at?, affected_revision_ids,
    /// verification — opaque identifiers + timestamps only). Fail-closed:
    /// nothing was written; the replay doors quarantine the blob (`x:`
    /// family, ONE-1134).
    #[cfg(feature = "sync")]
    #[error("invalid redaction audit receipt body: {0}")]
    InvalidRedactionReceiptBody(&'static str),
    /// A sync replay door delivered DIVERGENT bytes for an EXISTING
    /// REDACTION_AUDIT receipt id. Receipts are immutable audit records
    /// (contracts.ts `redactionAuditReceipt.immutability`; the ARCH-0023b
    /// audit/guardrail stream class quarantines divergent same-identity
    /// payloads, never silent LWW): the local bytes are kept and the remote
    /// payload is quarantined (ONE-1134).
    #[cfg(feature = "sync")]
    #[error(
        "redaction audit receipt {} is immutable: divergent remote bytes are quarantined, local bytes kept",
        id.to_hex()
    )]
    RedactionReceiptDivergence { id: EntityId },
}

impl Error {
    pub(crate) fn invalid_vector_component(vector: &[f32]) -> Option<Self> {
        vector
            .iter()
            .copied()
            .enumerate()
            .find_map(|(index, value)| {
                (!value.is_finite()).then_some(Self::InvalidVector { index, value })
            })
    }

    /// Returns the stable category for this error.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Storage(_) => ErrorKind::Storage,
            Self::Io(_) => ErrorKind::Io,
            Self::DimensionMismatch { .. } => ErrorKind::DimensionMismatch,
            Self::InvalidVector { .. } => ErrorKind::InvalidVector,
            Self::InvalidEdgeWeight { .. } => ErrorKind::InvalidEdgeWeight,
            Self::InvalidVad { .. } => ErrorKind::InvalidVad,
            Self::EmbeddingModelChanged { .. } => ErrorKind::EmbeddingModelChanged,
            Self::HnswConfigChanged { .. } => ErrorKind::HnswConfigChanged,
            Self::StorageAbiVersionChanged { .. } => ErrorKind::StorageAbiVersionChanged,
            Self::StorageSchemaVersionChanged { .. } => ErrorKind::StorageSchemaVersionChanged,
            Self::DbManifestMismatch { .. } => ErrorKind::DbManifestMismatch,
            Self::MapFull => ErrorKind::MapFull,
            Self::InvalidConfig(_) => ErrorKind::InvalidConfig,
            Self::EntityNotFound => ErrorKind::EntityNotFound,
            Self::ConcurrentWrite(_) => ErrorKind::ConcurrentWrite,
            Self::ArithmeticOverflow(_) => ErrorKind::ArithmeticOverflow,
            Self::InvariantViolation(_) => ErrorKind::InvariantViolation,
            Self::InvalidKey => ErrorKind::InvalidKey,
            Self::CorruptedIndex(_) => ErrorKind::CorruptedIndex,
            Self::IndexOverflow(_) => ErrorKind::IndexOverflow,
            Self::MissingPostingEntry => ErrorKind::MissingPostingEntry,
            Self::InvalidEntityType(_) => ErrorKind::InvalidEntityType,
            Self::InvalidFacet { .. } => ErrorKind::InvalidFacet,
            Self::InvalidClaimBody(_) => ErrorKind::InvalidClaimBody,
            Self::InvalidPredicate { .. } => ErrorKind::InvalidPredicate,
            Self::ReservedPredicate { .. } => ErrorKind::ReservedPredicate,
            Self::MaintenanceKindNotWritable(_) => ErrorKind::MaintenanceKindNotWritable,
            Self::EntityTypeImmutable { .. } => ErrorKind::EntityTypeImmutable,
            Self::InvalidTimeRange { .. } => ErrorKind::InvalidTimeRange,
            Self::EdgeNotFound => ErrorKind::EdgeNotFound,
            Self::ProvenanceOnStructuralEdge { .. } => ErrorKind::ProvenanceOnStructuralEdge,
            Self::ActorClassMismatch { .. } => ErrorKind::ActorClassMismatch,
            Self::InvalidProvenanceBody(_) => ErrorKind::InvalidProvenanceBody,
            Self::ClaimAlreadyClosed { .. } => ErrorKind::ClaimAlreadyClosed,
            Self::ClaimSelfSupersession => ErrorKind::ClaimSelfSupersession,
            Self::ProvenanceClaimLifecycle { .. } => ErrorKind::ProvenanceClaimLifecycle,
            Self::NotAProvenanceClaim(_) => ErrorKind::NotAProvenanceClaim,
            Self::ProvenanceClaimAlreadyClosed { .. } => ErrorKind::ProvenanceClaimAlreadyClosed,
            Self::ProvenanceClaimIdInUse => ErrorKind::ProvenanceClaimIdInUse,
            Self::ProvenanceSubjectMismatch => ErrorKind::ProvenanceSubjectMismatch,
            Self::ProvenanceSelfSupersession => ErrorKind::ProvenanceSelfSupersession,
            Self::ProvenancePrecedenceViolation { .. } => ErrorKind::ProvenancePrecedenceViolation,
            Self::EdgeIsProvenanced { .. } => ErrorKind::EdgeIsProvenanced,
            Self::CycleDetected => ErrorKind::CycleDetected,
            Self::ChildOfCardinality => ErrorKind::ChildOfCardinality,
            Self::IncompatibleAnalyzer { .. } => ErrorKind::IncompatibleAnalyzer,
            Self::Bm25FieldSchemaChanged => ErrorKind::Bm25FieldSchemaChanged,
            Self::InvalidRankProfile { .. } => ErrorKind::InvalidRankProfile,
            Self::AnalyzerAssetMissing(_) => ErrorKind::AnalyzerAssetMissing,
            Self::AnalyzerError(_) => ErrorKind::AnalyzerError,
            #[cfg(feature = "sync")]
            Self::CrdtDecodeError { .. } => ErrorKind::CrdtDecodeError,
            #[cfg(feature = "sync")]
            Self::WindowNotFound { .. } => ErrorKind::WindowNotFound,
            #[cfg(feature = "sync")]
            Self::SyncProtocolError(_) => ErrorKind::SyncProtocolError,
            #[cfg(feature = "sync")]
            Self::InvalidRedactionReceiptBody(_) => ErrorKind::InvalidRedactionReceiptBody,
            #[cfg(feature = "sync")]
            Self::RedactionReceiptDivergence { .. } => ErrorKind::RedactionReceiptDivergence,
        }
    }

    /// Returns whether retrying the same operation may succeed.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::ConcurrentWrite(_) => true,
            Self::Io(error) => matches!(
                error.kind(),
                std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::NotConnected
            ),
            _ => false,
        }
    }
}

impl From<heed::Error> for Error {
    fn from(value: heed::Error) -> Self {
        match value {
            heed::Error::Mdb(heed::MdbError::MapFull) => Self::MapFull,
            other => Self::Storage(other),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

// Compile-time assertion that Error: Send + Sync + 'static.
// Ungated (runs in all profiles); replaces the previous runtime test
// that was gated behind #[cfg(all(test, feature = "sync"))].
const _: fn() = || {
    fn assert_send_sync_static<T: Send + Sync + 'static>() {}
    assert_send_sync_static::<Error>();
};
