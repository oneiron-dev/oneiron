//! The `oneiron.retrieval_pack.v1` pack format: one manifest per slice, plus an
//! optional little-endian f32 sidecar holding the precomputed vectors.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The contract string every pack manifest carries.
pub const PACK_CONTRACT: &str = "oneiron.retrieval_pack.v1";

/// One of the three slices a pack is split into. Each slice is its own file
/// and holds only its own queries and the records they need.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Slice {
    /// The slice handed out to engine work.
    Search,
    /// The slice kept back for later checks.
    HeldOut,
    /// The slice nobody opens until the final scoring.
    Sealed,
}

impl Slice {
    /// All three slices in pack order.
    pub const ALL: [Slice; 3] = [Slice::Search, Slice::HeldOut, Slice::Sealed];

    /// The file-stem form: `search`, `held_out` or `sealed`.
    pub fn as_str(self) -> &'static str {
        match self {
            Slice::Search => "search",
            Slice::HeldOut => "held_out",
            Slice::Sealed => "sealed",
        }
    }
}

impl fmt::Display for Slice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The kind of a record: a conversation turn or a collection passage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    /// One conversation turn.
    Turn,
    /// One passage of a document collection (MIRACL, Mr.TyDi).
    Passage,
}

/// One slice manifest: the queries of the slice and the records they need.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSlice {
    /// Must equal [`PACK_CONTRACT`].
    pub contract: String,
    /// The pack this slice belongs to. Non-empty.
    pub pack_id: String,
    /// The pack revision. Non-empty.
    pub revision: String,
    /// Which slice this file holds. Every query must agree.
    pub slice: Slice,
    /// Where the content came from.
    pub source: PackSource,
    /// The vector pin. None until vectors are filled in.
    pub embedding: Option<EmbeddingPin>,
    /// Every record some corpus names, in first-seen order.
    pub records: Vec<Record>,
    /// One fresh vault per corpus at run time.
    pub corpora: Vec<Corpus>,
    /// The graded queries of this slice.
    pub queries: Vec<Query>,
}

/// The provenance of a pack slice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSource {
    /// The source dataset, e.g. `LongMemEval-S`.
    pub dataset: String,
    /// 64 lowercase hex: sha256 of the input file.
    pub dataset_sha256: String,
    /// The dataset license, e.g. `MIT`.
    pub license: String,
    /// 64 lowercase hex: the digest of the split used.
    pub split_sha256: String,
}

/// The pin binding a manifest to its precomputed vectors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingPin {
    /// The embedder, e.g. `perplexity-ai/pplx-embed-v1-0.6b@<rev>`.
    pub model_id: String,
    /// The vector width. Greater than zero.
    pub dims: u32,
    /// The transform the vectors went through, as the embedder names it.
    pub transform: String,
    /// 64 lowercase hex: sha256 of the `<slice>.vectors.f32` file bytes.
    pub vectors_sha256: String,
}

/// One embeddable record: the text that is embedded, plus its provenance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// Unique in the file. Non-empty.
    pub record_id: String,
    /// The kind of the record.
    pub kind: RecordKind,
    /// `user` or `assistant` for LongMemEval; `document` for a passage.
    pub speaker: String,
    /// The text that is embedded. Never blank.
    pub text: String,
    /// `<session_id>#<turn_index>` for LongMemEval; the docid `<article>#<n>` for a passage.
    pub source_ref: String,
}

/// One corpus: the sessions one query reads from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Corpus {
    /// Unique in the file.
    pub corpus_id: String,
    /// The sessions of the corpus.
    pub sessions: Vec<CorpusSession>,
}

/// One session inside a corpus.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusSession {
    /// The session id.
    pub session_id: String,
    /// RFC 3339 UTC, exactly `YYYY-MM-DDTHH:MM:SSZ`.
    pub time: String,
    /// The records of this session, in turn order.
    pub record_ids: Vec<String>,
}

/// One graded query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    /// Unique in the file.
    pub query_id: String,
    /// Must equal the file slice.
    pub slice: Slice,
    /// The corpus the query reads from.
    pub corpus_id: String,
    /// The question category. Non-empty.
    pub category: String,
    /// The query text. Non-blank.
    pub text: String,
    /// Same time format as [`CorpusSession::time`].
    pub now: String,
    /// Record id to grade 1..=3. Empty only when `expect_empty`.
    pub qrels: BTreeMap<String, u8>,
    /// Abstention: the right answer is no result.
    pub expect_empty: bool,
}

/// Every way a pack can fail to load, validate or pin.
#[derive(Debug, Error)]
pub enum PackError {
    /// The manifest names another contract.
    #[error("wrong contract: {found}")]
    WrongContract {
        /// The contract the manifest carries.
        found: String,
    },
    /// A field that must be non-empty is empty.
    #[error("empty field: {field}")]
    EmptyField {
        /// Which field is empty.
        field: String,
    },
    /// Two records share an id.
    #[error("duplicate record: {record_id}")]
    DuplicateRecord {
        /// The repeated id.
        record_id: String,
    },
    /// A record has blank text.
    #[error("blank record text: {record_id}")]
    BlankRecord {
        /// The offending record.
        record_id: String,
    },
    /// Two corpora share an id.
    #[error("duplicate corpus: {corpus_id}")]
    DuplicateCorpus {
        /// The repeated id.
        corpus_id: String,
    },
    /// A time is not exactly `YYYY-MM-DDTHH:MM:SSZ` with plausible ranges.
    #[error("bad time at {at}: {value}")]
    BadTime {
        /// Where the bad time sits.
        at: String,
        /// The bad value.
        value: String,
    },
    /// A corpus names a record the file does not hold.
    #[error("corpus {corpus_id} names unknown record {record_id}")]
    UnknownRecordInCorpus {
        /// The corpus.
        corpus_id: String,
        /// The missing record.
        record_id: String,
    },
    /// A corpus names one record twice.
    #[error("corpus {corpus_id} names record {record_id} twice")]
    DuplicateRecordInCorpus {
        /// The corpus.
        corpus_id: String,
        /// The repeated record.
        record_id: String,
    },
    /// Two queries share an id.
    #[error("duplicate query: {query_id}")]
    DuplicateQuery {
        /// The repeated id.
        query_id: String,
    },
    /// A query belongs to another slice than the file.
    #[error("query {query_id} is for slice {query_slice} but the file holds {file_slice}")]
    QueryOfAnotherSlice {
        /// The query.
        query_id: String,
        /// The slice the query claims.
        query_slice: Slice,
        /// The slice the file holds.
        file_slice: Slice,
    },
    /// A query names a corpus the file does not hold.
    #[error("query {query_id} names unknown corpus {corpus_id}")]
    UnknownCorpus {
        /// The query.
        query_id: String,
        /// The missing corpus.
        corpus_id: String,
    },
    /// A query grades a record the file does not hold.
    #[error("query {query_id} grades unknown record {record_id}")]
    UnknownRecordInQrels {
        /// The query.
        query_id: String,
        /// The missing record.
        record_id: String,
    },
    /// A query grades a record outside its own corpus.
    #[error("query {query_id} grades record {record_id} outside its corpus")]
    QrelOutsideCorpus {
        /// The query.
        query_id: String,
        /// The outside record.
        record_id: String,
    },
    /// A grade is not 1..=3.
    #[error("query {query_id} gives record {record_id} bad grade {grade}")]
    BadGrade {
        /// The query.
        query_id: String,
        /// The graded record.
        record_id: String,
        /// The bad grade.
        grade: u8,
    },
    /// An abstention query still carries qrels.
    #[error("query {query_id} expects empty results but has qrels")]
    ExpectEmptyWithQrels {
        /// The query.
        query_id: String,
    },
    /// A non-abstention query grades nothing.
    #[error("query {query_id} has no relevant records")]
    NoRelevantRecords {
        /// The query.
        query_id: String,
    },
    /// A record no corpus names.
    #[error("orphan record: {record_id}")]
    OrphanRecord {
        /// The orphan.
        record_id: String,
    },
    /// A corpus no query names.
    #[error("orphan corpus: {corpus_id}")]
    OrphanCorpus {
        /// The orphan.
        corpus_id: String,
    },
    /// The embedding pin (or vector buffer) has zero dims.
    #[error("embedding dims must be positive")]
    BadDims,
    /// The pinned digest is not 64 lowercase hex.
    #[error("bad digest: {value}")]
    BadDigest {
        /// The bad value.
        value: String,
    },
    /// The slice file holds another slice than requested.
    #[error("slice file holds {found} but {expected} was requested")]
    SliceFileMismatch {
        /// The requested slice.
        expected: Slice,
        /// The slice the file holds.
        found: Slice,
    },
    /// The vectors do not match the pinned digest (or dims).
    #[error("vector digest mismatch: expected {expected}, found {found}")]
    VectorDigestMismatch {
        /// The pinned digest.
        expected: String,
        /// The digest of the bytes at hand.
        found: String,
    },
    /// The vectors have the wrong row count (or byte length on load).
    #[error("vector length mismatch: expected {expected}, found {found}")]
    VectorLength {
        /// The wanted count.
        expected: usize,
        /// The count at hand.
        found: usize,
    },
    /// A vector row holds a non-finite value.
    #[error("non-finite vector at row {row}")]
    NonFiniteVector {
        /// The first bad row.
        row: usize,
    },
    /// The manifest pins vectors but none were given, or the reverse.
    #[error("vectors missing")]
    VectorsMissing,
    /// The vector bytes are not a multiple of one row.
    #[error("bad vector bytes length: {len}")]
    BadVectorBytes {
        /// The byte length at hand.
        len: usize,
    },
    /// A slice file could not be read or written.
    #[error("io error at {path:?}: {source}")]
    Io {
        /// The file path.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The manifest is not valid JSON for this shape.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// The manifest has no canonical JSON form.
    #[error("canonical JSON error: {0}")]
    Canonical(String),
}

/// Row-major precomputed vectors: one row per record, then one row per query.
#[derive(Clone, Debug, PartialEq)]
pub struct Vectors {
    dims: usize,
    data: Vec<f32>,
}

impl Vectors {
    /// Build vectors from a flat row-major buffer. Every value must be finite.
    pub fn new(dims: usize, data: Vec<f32>) -> Result<Self, PackError> {
        if dims == 0 {
            return Err(PackError::BadDims);
        }
        if !data.len().is_multiple_of(dims) {
            return Err(PackError::BadVectorBytes {
                len: data.len() * 4,
            });
        }
        for (index, value) in data.iter().enumerate() {
            if !value.is_finite() {
                return Err(PackError::NonFiniteVector { row: index / dims });
            }
        }
        Ok(Self { dims, data })
    }

    /// Parse little-endian f32 bytes into vectors.
    pub fn from_le_bytes(dims: usize, bytes: &[u8]) -> Result<Self, PackError> {
        if dims == 0 {
            return Err(PackError::BadDims);
        }
        let stride = dims
            .checked_mul(4)
            .ok_or(PackError::BadVectorBytes { len: bytes.len() })?;
        if !bytes.len().is_multiple_of(stride) {
            return Err(PackError::BadVectorBytes { len: bytes.len() });
        }
        let mut data = Vec::with_capacity(bytes.len() / 4);
        for chunk in bytes.chunks_exact(4) {
            let mut word = [0u8; 4];
            word.copy_from_slice(chunk);
            data.push(f32::from_le_bytes(word));
        }
        Self::new(dims, data)
    }

    /// The exact file bytes these vectors were (or will be) stored as.
    pub fn to_le_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.data.len() * 4);
        for value in &self.data {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out
    }

    /// The sha256 of the file bytes, as lowercase hex.
    pub fn sha256_hex(&self) -> String {
        sha256_hex(&self.to_le_bytes())
    }

    /// The embedding width every row shares.
    pub fn dims(&self) -> usize {
        self.dims
    }

    /// How many rows the buffer holds.
    pub fn rows(&self) -> usize {
        self.data.len() / self.dims
    }

    /// One row, or None when the index is out of range.
    pub fn row(&self, index: usize) -> Option<&[f32]> {
        let start = index.checked_mul(self.dims)?;
        let end = start.checked_add(self.dims)?;
        self.data.get(start..end)
    }
}

/// A validated slice plus its vectors (when the manifest pins them).
#[derive(Clone, Debug, PartialEq)]
pub struct LoadedPack {
    /// The validated manifest.
    pub slice: PackSlice,
    /// The vectors, or None when the manifest has no embedding pin.
    pub vectors: Option<Vectors>,
    /// The pack digest of the manifest.
    pub pack_digest: String,
}

impl LoadedPack {
    /// The vector of record `ordinal` (its position in `records`), when pinned.
    pub fn record_vector(&self, ordinal: usize) -> Option<&[f32]> {
        self.vectors
            .as_ref()
            .and_then(|vectors| vectors.row(ordinal))
    }

    /// The vector of query `index` (its position in `queries`), when pinned.
    pub fn query_vector(&self, index: usize) -> Option<&[f32]> {
        let base = self.slice.records.len().checked_add(index)?;
        self.vectors.as_ref().and_then(|vectors| vectors.row(base))
    }
}

impl PackSlice {
    /// Check every rule of the pack contract, returning the first failure.
    /// The checks run in contract order: manifest, records, corpora, queries,
    /// orphans, then the embedding pin.
    pub fn validate(&self) -> Result<(), PackError> {
        if self.contract != PACK_CONTRACT {
            return Err(PackError::WrongContract {
                found: self.contract.clone(),
            });
        }
        if self.pack_id.is_empty() {
            return Err(PackError::EmptyField {
                field: "pack_id".to_owned(),
            });
        }
        if self.revision.is_empty() {
            return Err(PackError::EmptyField {
                field: "revision".to_owned(),
            });
        }
        let mut known_records = BTreeSet::new();
        for record in &self.records {
            if record.record_id.is_empty() {
                return Err(PackError::EmptyField {
                    field: "record_id".to_owned(),
                });
            }
            if !known_records.insert(record.record_id.as_str()) {
                return Err(PackError::DuplicateRecord {
                    record_id: record.record_id.clone(),
                });
            }
            if record.text.trim().is_empty() {
                return Err(PackError::BlankRecord {
                    record_id: record.record_id.clone(),
                });
            }
        }
        let mut known_corpora = BTreeSet::new();
        let mut corpus_records: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for corpus in &self.corpora {
            let corpus_id = corpus.corpus_id.as_str();
            if corpus_id.is_empty() {
                return Err(PackError::EmptyField {
                    field: "corpus_id".to_owned(),
                });
            }
            if !known_corpora.insert(corpus_id) {
                return Err(PackError::DuplicateCorpus {
                    corpus_id: corpus.corpus_id.clone(),
                });
            }
            let mut in_corpus = BTreeSet::new();
            for session in &corpus.sessions {
                if !is_time(&session.time) {
                    let session_id = session.session_id.as_str();
                    return Err(PackError::BadTime {
                        at: format!("corpus {corpus_id} session {session_id}"),
                        value: session.time.clone(),
                    });
                }
                for record_id in &session.record_ids {
                    if !known_records.contains(record_id.as_str()) {
                        return Err(PackError::UnknownRecordInCorpus {
                            corpus_id: corpus.corpus_id.clone(),
                            record_id: record_id.clone(),
                        });
                    }
                    if !in_corpus.insert(record_id.as_str()) {
                        return Err(PackError::DuplicateRecordInCorpus {
                            corpus_id: corpus.corpus_id.clone(),
                            record_id: record_id.clone(),
                        });
                    }
                }
            }
            corpus_records.insert(corpus_id, in_corpus);
        }
        let mut known_queries = BTreeSet::new();
        for query in &self.queries {
            let query_id = query.query_id.as_str();
            if query_id.is_empty() {
                return Err(PackError::EmptyField {
                    field: "query_id".to_owned(),
                });
            }
            if !known_queries.insert(query_id) {
                return Err(PackError::DuplicateQuery {
                    query_id: query.query_id.clone(),
                });
            }
            if query.slice != self.slice {
                return Err(PackError::QueryOfAnotherSlice {
                    query_id: query.query_id.clone(),
                    query_slice: query.slice,
                    file_slice: self.slice,
                });
            }
            if !known_corpora.contains(query.corpus_id.as_str()) {
                return Err(PackError::UnknownCorpus {
                    query_id: query.query_id.clone(),
                    corpus_id: query.corpus_id.clone(),
                });
            }
            if query.category.is_empty() {
                return Err(PackError::EmptyField {
                    field: format!("query {query_id} category"),
                });
            }
            if query.text.trim().is_empty() {
                return Err(PackError::EmptyField {
                    field: format!("query {query_id} text"),
                });
            }
            if !is_time(&query.now) {
                return Err(PackError::BadTime {
                    at: format!("query {query_id}"),
                    value: query.now.clone(),
                });
            }
            let owned = corpus_records.get(query.corpus_id.as_str());
            for (record_id, grade) in &query.qrels {
                if !known_records.contains(record_id.as_str()) {
                    return Err(PackError::UnknownRecordInQrels {
                        query_id: query.query_id.clone(),
                        record_id: record_id.clone(),
                    });
                }
                let inside = owned.is_some_and(|set| set.contains(record_id.as_str()));
                if !inside {
                    return Err(PackError::QrelOutsideCorpus {
                        query_id: query.query_id.clone(),
                        record_id: record_id.clone(),
                    });
                }
                if !(1..=3).contains(grade) {
                    return Err(PackError::BadGrade {
                        query_id: query.query_id.clone(),
                        record_id: record_id.clone(),
                        grade: *grade,
                    });
                }
            }
            if query.expect_empty {
                if !query.qrels.is_empty() {
                    return Err(PackError::ExpectEmptyWithQrels {
                        query_id: query.query_id.clone(),
                    });
                }
            } else if query.qrels.is_empty() {
                return Err(PackError::NoRelevantRecords {
                    query_id: query.query_id.clone(),
                });
            }
        }
        let mut named_records = BTreeSet::new();
        for corpus in &self.corpora {
            for session in &corpus.sessions {
                for record_id in &session.record_ids {
                    named_records.insert(record_id.as_str());
                }
            }
        }
        for record in &self.records {
            if !named_records.contains(record.record_id.as_str()) {
                return Err(PackError::OrphanRecord {
                    record_id: record.record_id.clone(),
                });
            }
        }
        let mut named_corpora = BTreeSet::new();
        for query in &self.queries {
            named_corpora.insert(query.corpus_id.as_str());
        }
        for corpus in &self.corpora {
            if !named_corpora.contains(corpus.corpus_id.as_str()) {
                return Err(PackError::OrphanCorpus {
                    corpus_id: corpus.corpus_id.clone(),
                });
            }
        }
        if let Some(embedding) = &self.embedding {
            if embedding.dims == 0 {
                return Err(PackError::BadDims);
            }
            if !is_digest(&embedding.vectors_sha256) {
                return Err(PackError::BadDigest {
                    value: embedding.vectors_sha256.clone(),
                });
            }
        }
        Ok(())
    }

    /// The pack digest: sha256 (lowercase hex) of the RFC 8785 canonical
    /// bytes of the manifest. The manifest holds no floats, so the digest is
    /// reproducible from Python over the parsed JSON.
    pub fn pack_digest(&self) -> Result<String, PackError> {
        let value = serde_json::to_value(self)?;
        let canonical = serde_json_canonicalizer::to_vec(&value)
            .map_err(|error| PackError::Canonical(error.to_string()))?;
        Ok(sha256_hex(&canonical))
    }

    /// Pin precomputed vectors to this manifest.
    pub fn pin_vectors(
        &mut self,
        model_id: &str,
        transform: &str,
        vectors: &Vectors,
    ) -> Result<(), PackError> {
        let rows = self.records.len() + self.queries.len();
        if vectors.rows() != rows {
            return Err(PackError::VectorLength {
                expected: rows,
                found: vectors.rows(),
            });
        }
        let dims = u32::try_from(vectors.dims()).map_err(|_| PackError::BadDims)?;
        self.embedding = Some(EmbeddingPin {
            model_id: model_id.to_owned(),
            dims,
            transform: transform.to_owned(),
            vectors_sha256: vectors.sha256_hex(),
        });
        Ok(())
    }
}

/// The manifest file name of a slice: `<slice>.json`.
pub fn slice_file_name(slice: Slice) -> String {
    let name = slice.as_str();
    format!("{name}.json")
}

/// The vectors file name of a slice: `<slice>.vectors.f32`.
pub fn vectors_file_name(slice: Slice) -> String {
    let name = slice.as_str();
    format!("{name}.vectors.f32")
}

/// Load and validate one slice file, plus its vectors when pinned. The digest
/// of the manifest comes back with the pack.
pub fn load_slice(dir: &Path, slice: Slice) -> Result<LoadedPack, PackError> {
    let json_path = dir.join(slice_file_name(slice));
    let json = std::fs::read(&json_path).map_err(|source| PackError::Io {
        path: json_path.clone(),
        source,
    })?;
    let pack: PackSlice = serde_json::from_slice(&json)?;
    if pack.slice != slice {
        return Err(PackError::SliceFileMismatch {
            expected: slice,
            found: pack.slice,
        });
    }
    pack.validate()?;
    let vectors = match &pack.embedding {
        None => None,
        Some(pin) => {
            let vectors_path = dir.join(vectors_file_name(slice));
            let raw = std::fs::read(&vectors_path).map_err(|source| PackError::Io {
                path: vectors_path.clone(),
                source,
            })?;
            let found = sha256_hex(&raw);
            if found != pin.vectors_sha256 {
                return Err(PackError::VectorDigestMismatch {
                    expected: pin.vectors_sha256.clone(),
                    found,
                });
            }
            let dims = usize::try_from(pin.dims).map_err(|_| PackError::BadDims)?;
            let rows = pack.records.len() + pack.queries.len();
            let expected = rows.saturating_mul(dims).saturating_mul(4);
            if raw.len() != expected {
                return Err(PackError::VectorLength {
                    expected,
                    found: raw.len(),
                });
            }
            Some(Vectors::from_le_bytes(dims, &raw)?)
        }
    };
    let pack_digest = pack.pack_digest()?;
    Ok(LoadedPack {
        slice: pack,
        vectors,
        pack_digest,
    })
}

/// Validate and write one slice file: the pretty manifest plus a trailing
/// newline, and the vectors sidecar when pinned. Returns the pack digest.
pub fn write_slice(
    dir: &Path,
    pack: &PackSlice,
    vectors: Option<&Vectors>,
) -> Result<String, PackError> {
    pack.validate()?;
    match (vectors, &pack.embedding) {
        (None, None) => {}
        (None, Some(_)) => return Err(PackError::VectorsMissing),
        (Some(unpinned), None) => {
            return Err(PackError::VectorDigestMismatch {
                expected: String::new(),
                found: unpinned.sha256_hex(),
            });
        }
        (Some(candidate), Some(pin)) => {
            let found = candidate.sha256_hex();
            let dims_ok = usize::try_from(pin.dims).is_ok_and(|dims| dims == candidate.dims());
            if !dims_ok || found != pin.vectors_sha256 {
                return Err(PackError::VectorDigestMismatch {
                    expected: pin.vectors_sha256.clone(),
                    found,
                });
            }
        }
    }
    let json_path = dir.join(slice_file_name(pack.slice));
    let mut pretty = serde_json::to_vec_pretty(pack)?;
    pretty.push(b'\n');
    std::fs::write(&json_path, pretty).map_err(|source| PackError::Io {
        path: json_path.clone(),
        source,
    })?;
    if let Some(vectors) = vectors {
        let vectors_path = dir.join(vectors_file_name(pack.slice));
        std::fs::write(&vectors_path, vectors.to_le_bytes()).map_err(|source| PackError::Io {
            path: vectors_path.clone(),
            source,
        })?;
    }
    pack.pack_digest()
}

/// Lowercase hex sha256 of bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(Sha256::output_size() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// True for exactly `YYYY-MM-DDTHH:MM:SSZ` with plausible ranges: month
/// 1..=12, day 1..=31, hour <= 23, minute and second <= 59.
fn is_time(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return false;
    }
    for position in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
        if !bytes[position].is_ascii_digit() {
            return false;
        }
    }
    let two = |high: usize, low: usize| -> u32 {
        u32::from(bytes[high] - b'0') * 10 + u32::from(bytes[low] - b'0')
    };
    let month = two(5, 6);
    let day = two(8, 9);
    let hour = two(11, 12);
    let minute = two(14, 15);
    let second = two(17, 18);
    (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && hour <= 23
        && minute <= 59
        && second <= 59
}

/// True for 64 lowercase hex digits.
fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
