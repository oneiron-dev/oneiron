use crate::types::{EntityId, VadComponent};

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
    MaintenanceKindNotWritable,
    EntityTypeImmutable,
    InvalidTimeRange,
    CycleDetected,
    IncompatibleAnalyzer,
    Bm25FieldSchemaChanged,
    AnalyzerAssetMissing,
    AnalyzerError,
    #[cfg(feature = "sync")]
    CrdtDecodeError,
    #[cfg(feature = "sync")]
    WindowNotFound,
    #[cfg(feature = "sync")]
    SyncProtocolError,
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
    /// Edge weight contains NaN or infinity values.
    #[error("invalid edge weight: {value}")]
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
    /// Tree operation would create a cycle.
    #[error("cycle detected in tree hierarchy")]
    CycleDetected,
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
            Self::MaintenanceKindNotWritable(_) => ErrorKind::MaintenanceKindNotWritable,
            Self::EntityTypeImmutable { .. } => ErrorKind::EntityTypeImmutable,
            Self::InvalidTimeRange { .. } => ErrorKind::InvalidTimeRange,
            Self::CycleDetected => ErrorKind::CycleDetected,
            Self::IncompatibleAnalyzer { .. } => ErrorKind::IncompatibleAnalyzer,
            Self::Bm25FieldSchemaChanged => ErrorKind::Bm25FieldSchemaChanged,
            Self::AnalyzerAssetMissing(_) => ErrorKind::AnalyzerAssetMissing,
            Self::AnalyzerError(_) => ErrorKind::AnalyzerError,
            #[cfg(feature = "sync")]
            Self::CrdtDecodeError { .. } => ErrorKind::CrdtDecodeError,
            #[cfg(feature = "sync")]
            Self::WindowNotFound { .. } => ErrorKind::WindowNotFound,
            #[cfg(feature = "sync")]
            Self::SyncProtocolError(_) => ErrorKind::SyncProtocolError,
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
