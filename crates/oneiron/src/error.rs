/// Result type used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Crate error type.
#[derive(Debug, thiserror::Error)]
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
