//! Store-domain errors: the vault-root preflight and the index/analyzer
//! compatibility refusals a store open or rebuild raises.
//!
//! Reached from the root as `Error::Store(..)`, a transparent wrapper: Display
//! and `source()` are the leaf's, so every message string is what it was when
//! these variants sat flat on `Error`.

use std::fmt;
use std::path::PathBuf;

use super::ErrorKind;

/// LMDB file inside a vault root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VaultRootEntry {
    Data,
    Lock,
}

impl VaultRootEntry {
    pub(crate) fn file_name(self) -> &'static str {
        match self {
            Self::Data => "data.mdb",
            Self::Lock => "lock.mdb",
        }
    }
}

impl fmt::Display for VaultRootEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.file_name())
    }
}

/// Typed reason a vault root failed the filesystem preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VaultRootProblem {
    /// A live store already owns the same root or an aliased LMDB file.
    DuplicateOpenRoot { open_path: PathBuf },
    /// Only one of LMDB's paired environment files exists.
    IncompleteLmdbPair {
        present: VaultRootEntry,
        missing: VaultRootEntry,
    },
    /// An LMDB environment file is not a regular file.
    NonRegularEntry { entry: VaultRootEntry },
    /// An LMDB environment file is a symlink.
    SymlinkEntry { entry: VaultRootEntry },
    /// `data.mdb` and `lock.mdb` point at the same underlying file.
    AliasedLmdbFiles {
        first: VaultRootEntry,
        second: VaultRootEntry,
    },
    /// A hard-linked LMDB file can make multiple filesystem roots name one
    /// vault. Those roots cannot safely own separate LMDB environments.
    MultipleHardLinks {
        entry: VaultRootEntry,
        link_count: u64,
    },
    /// This platform cannot report stable file identity and hard-link counts
    /// for existing LMDB environment files.
    UnsupportedPlatform { entry: VaultRootEntry },
    /// [`crate::Vault::open_existing`] refused this root. Either it was not
    /// already a complete vault root when the door bound it as a descriptor
    /// capability — that door never creates one, so an absent, empty, or
    /// pairless root has nothing to open — or the root it bound stopped being
    /// the root the caller named while the LMDB environment was opening.
    /// One refusal covers both: the existing-only door opens exactly the vault
    /// it bound, at the path it was given, or it opens nothing at all.
    NotAnExistingVaultRoot { after_environment_open: bool },
}

impl fmt::Display for VaultRootProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateOpenRoot { open_path } => {
                write!(f, "duplicates live vault root {}", open_path.display())
            }
            Self::IncompleteLmdbPair { present, missing } => {
                write!(f, "found {present} without {missing}")
            }
            Self::NonRegularEntry { entry } => {
                write!(f, "{entry} is not a regular file")
            }
            Self::SymlinkEntry { entry } => {
                write!(f, "{entry} is a symlink")
            }
            Self::AliasedLmdbFiles { first, second } => {
                write!(f, "{first} and {second} refer to the same file")
            }
            Self::MultipleHardLinks { entry, link_count } => {
                write!(f, "{entry} has {link_count} hard links")
            }
            Self::UnsupportedPlatform { entry } => {
                write!(f, "{entry} cannot be safely preflighted on this platform")
            }
            Self::NotAnExistingVaultRoot {
                after_environment_open: false,
            } => f.write_str("is not already an initialized vault root"),
            Self::NotAnExistingVaultRoot {
                after_environment_open: true,
            } => f.write_str("stopped being the bound vault root while it was opening"),
        }
    }
}

/// Store-domain error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
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
    /// The vault root failed deterministic filesystem preflight before LMDB open.
    #[error("vault root preflight failed at {}: {problem}", path.display())]
    VaultRootPreflight {
        path: PathBuf,
        problem: VaultRootProblem,
    },
    /// Expected posting or metadata row is missing from an index.
    #[error("missing posting entry")]
    MissingPostingEntry,
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
    /// [`MaintenanceBuilder::clear_text_index`]: crate::maintain::MaintenanceBuilder::clear_text_index
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
    /// Same as [`StoreError::IncompatibleAnalyzer`]: reopen with
    /// [`VaultConfig::skip_text_index_manifest_check`] set to `true`, run
    /// [`MaintenanceBuilder::clear_text_index`], reopen normally, then
    /// reindex documents.
    ///
    /// [`VaultConfig::skip_text_index_manifest_check`]: crate::VaultConfig::skip_text_index_manifest_check
    /// [`MaintenanceBuilder::clear_text_index`]: crate::maintain::MaintenanceBuilder::clear_text_index
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
    /// use the same recovery path as [`StoreError::IncompatibleAnalyzer`]:
    /// reopen with [`VaultConfig::skip_text_index_manifest_check`] set to
    /// `true`, run [`MaintenanceBuilder::clear_text_index`], reopen
    /// normally, and reindex documents.
    ///
    /// [`VaultConfig::skip_text_index_manifest_check`]: crate::VaultConfig::skip_text_index_manifest_check
    /// [`MaintenanceBuilder::clear_text_index`]: crate::maintain::MaintenanceBuilder::clear_text_index
    #[error("analyzer asset missing: {0}")]
    AnalyzerAssetMissing(String),
    /// Generic analyzer error (dict load failure, manifest encode failure,
    /// etc.). Wraps the underlying cause as a string to avoid leaking
    /// transitive Sudachi/jieba/lindera error types into the public surface.
    #[error("analyzer error: {0}")]
    AnalyzerError(String),
}

impl StoreError {
    /// Returns the stable category for this error.
    #[must_use]
    pub(crate) fn kind(&self) -> ErrorKind {
        match self {
            Self::EmbeddingModelChanged { .. } => ErrorKind::EmbeddingModelChanged,
            Self::HnswConfigChanged { .. } => ErrorKind::HnswConfigChanged,
            Self::StorageAbiVersionChanged { .. } => ErrorKind::StorageAbiVersionChanged,
            Self::StorageSchemaVersionChanged { .. } => ErrorKind::StorageSchemaVersionChanged,
            Self::DbManifestMismatch { .. } => ErrorKind::DbManifestMismatch,
            Self::VaultRootPreflight { .. } => ErrorKind::VaultRootPreflight,
            Self::MissingPostingEntry => ErrorKind::MissingPostingEntry,
            Self::IncompatibleAnalyzer { .. } => ErrorKind::IncompatibleAnalyzer,
            Self::Bm25FieldSchemaChanged => ErrorKind::Bm25FieldSchemaChanged,
            Self::InvalidRankProfile { .. } => ErrorKind::InvalidRankProfile,
            Self::AnalyzerAssetMissing(_) => ErrorKind::AnalyzerAssetMissing,
            Self::AnalyzerError(_) => ErrorKind::AnalyzerError,
        }
    }
}
