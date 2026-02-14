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
    /// Stored embedding model differs from requested model.
    #[error("embedding model changed: stored={stored}, requested={requested}")]
    EmbeddingModelChanged { stored: String, requested: String },
    /// LMDB map is full and requires a larger map size.
    #[error("lmdb map is full")]
    MapFull,
    /// Invalid runtime configuration input.
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    /// Requested entity does not exist.
    #[error("entity not found")]
    EntityNotFound,
    /// Encountered malformed key or value bytes.
    #[error("invalid key or value bytes")]
    InvalidKey,
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
