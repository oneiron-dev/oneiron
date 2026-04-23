/// Result type used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

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
    #[error("vector contains non-finite values (NaN or Inf)")]
    InvalidVector,
    /// Edge weight contains NaN or infinity values.
    #[error("edge weight is non-finite (NaN or Inf)")]
    InvalidEdgeWeight,
    /// VAD tuple contains non-finite or out-of-range values.
    #[error("vad contains non-finite or out-of-range values")]
    InvalidVad,
    /// Stored embedding model differs from requested model.
    #[error("embedding model changed: stored={stored}, requested={requested}")]
    EmbeddingModelChanged { stored: String, requested: String },
    /// Persisted HNSW config differs from the requested runtime config.
    #[error("hnsw config changed: stored={stored}, requested={requested}")]
    HnswConfigChanged { stored: String, requested: String },
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
    /// `true`, call [`MaintenanceBuilder::clear_text_index`] to rebuild the
    /// postings + rewrite the manifest, then reopen with the default
    /// `false` value.
    ///
    /// [`VaultConfig::skip_text_index_manifest_check`]: crate::VaultConfig::skip_text_index_manifest_check
    /// [`MaintenanceBuilder::clear_text_index`]: crate::MaintenanceBuilder
    #[error("text analyzer changed since index was built (lang={lang:?}): stored={stored_mode} current={current_mode}; reopen with VaultConfig::skip_text_index_manifest_check=true and run clear_text_index to rebuild")]
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
    /// [`MaintenanceBuilder::clear_text_index`], then reopen normally.
    ///
    /// [`VaultConfig::skip_text_index_manifest_check`]: crate::VaultConfig::skip_text_index_manifest_check
    /// [`MaintenanceBuilder::clear_text_index`]: crate::MaintenanceBuilder
    #[error("bm25f field schema changed since index was built; reopen with VaultConfig::skip_text_index_manifest_check=true and run clear_text_index to rebuild")]
    Bm25FieldSchemaChanged,
    /// A dict asset declared in the stored manifest is missing from disk
    /// (e.g., `system.dic` was deleted after indexing). Restore the file or
    /// use the same recovery path as [`Error::IncompatibleAnalyzer`]:
    /// reopen with [`VaultConfig::skip_text_index_manifest_check`] set to
    /// `true`, run [`MaintenanceBuilder::clear_text_index`], reopen.
    ///
    /// [`VaultConfig::skip_text_index_manifest_check`]: crate::VaultConfig::skip_text_index_manifest_check
    /// [`MaintenanceBuilder::clear_text_index`]: crate::MaintenanceBuilder
    #[error("analyzer asset missing: {0}")]
    AnalyzerAssetMissing(String),
    /// Generic analyzer error (dict load failure, manifest encode failure,
    /// etc.). Wraps the underlying cause as a string to avoid leaking
    /// transitive Sudachi/jieba/lindera error types into the public surface.
    #[error("analyzer error: {0}")]
    AnalyzerError(String),
    /// Malformed CRDT update bytes.
    #[cfg(feature = "sync")]
    #[error("crdt decode error: {0}")]
    CrdtDecodeError(String),
    /// No persisted state for the requested window.
    #[cfg(feature = "sync")]
    #[error("window not found: {0}")]
    WindowNotFound(String),
    /// Sync protocol violation.
    #[cfg(feature = "sync")]
    #[error("sync protocol error: {0}")]
    SyncProtocolError(String),
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
