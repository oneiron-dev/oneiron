use std::collections::HashMap;
use std::path::PathBuf;

use uuid::Uuid;

pub(crate) const ENTITY_ID_LEN: usize = 16;
pub(crate) const EDGE_KEY_LEN: usize = 33;
pub(crate) const EDGE_VALUE_LEN: usize = 24;

/// A time-ordered entity identifier backed by UUIDv7 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntityId([u8; ENTITY_ID_LEN]);

impl EntityId {
    /// Creates a new identifier using the current UUIDv7 timestamp.
    #[must_use]
    pub fn now() -> Self {
        Self(Uuid::now_v7().into_bytes())
    }

    /// Creates an identifier from raw bytes, rejecting reserved sentinel IDs.
    ///
    /// The all-zero, all-`0xFF`, and known `[entity_type, 0xFF×15]` short-id
    /// counter sentinel patterns are reserved at the public `EntityId` layer.
    /// Other byte patterns remain valid IDs even if other LMDB indexes use
    /// similar-looking internal sentinel keys.
    pub fn from_bytes(bytes: [u8; 16]) -> crate::error::Result<Self> {
        if is_reserved_entity_id_bytes(&bytes) {
            return Err(crate::error::Error::InvalidKey);
        }
        Ok(Self(bytes))
    }

    /// Creates an identifier from raw bytes without validating sentinel patterns.
    ///
    /// Reserved for internal construction where the caller already knows the
    /// bytes are either valid entity IDs or intentional sentinel values.
    #[cfg(test)]
    pub(crate) fn from_bytes_unchecked(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the raw identifier bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Returns the lowercase hex-encoded string (32 chars).
    pub fn to_hex(&self) -> String {
        bytes_to_hex_lower(&self.0)
    }

    /// Parses a 32-char hex string (case-insensitive) into an EntityId.
    pub fn from_hex(s: &str) -> crate::error::Result<Self> {
        if s.len() != 32 {
            return Err(crate::error::Error::InvalidKey);
        }
        let mut bytes = [0u8; 16];
        for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
            let hi = hex_nibble(chunk[0]).ok_or(crate::error::Error::InvalidKey)?;
            let lo = hex_nibble(chunk[1]).ok_or(crate::error::Error::InvalidKey)?;
            bytes[i] = (hi << 4) | lo;
        }
        Self::from_bytes(bytes)
    }
}

fn is_reserved_entity_id_bytes(bytes: &[u8; ENTITY_ID_LEN]) -> bool {
    if *bytes == [0x00; ENTITY_ID_LEN] || *bytes == [0xFF; ENTITY_ID_LEN] {
        return true;
    }

    bytes[1..].iter().all(|&b| b == 0xFF) && short_id_prefix(bytes[0]).is_ok()
}

/// Lowercase hex-encodes an arbitrary byte slice. Shared with the
/// analyzer manifest hasher so every hex rendering in the crate goes
/// through one implementation.
pub(crate) fn bytes_to_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Converts an ASCII hex character to its nibble value.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Returns the short ID prefix for an entity type byte.
///
/// Returns an error for unknown entity type IDs.
pub fn short_id_prefix(entity_type: u8) -> crate::error::Result<&'static str> {
    match entity_type {
        // Core (0-19)
        0 => Ok("cl"),  // Claim
        1 => Ok("tn"),  // Turn
        2 => Ok("ss"),  // Session
        3 => Ok("ms"),  // Message
        4 => Ok("pr"),  // Person
        5 => Ok("rl"),  // Relationship
        6 => Ok("ev"),  // Event
        7 => Ok("sk"),  // Skill
        8 => Ok("sm"),  // Summary
        9 => Ok("pl"),  // Place
        10 => Ok("tx"), // Text
        11 => Ok("cv"), // Conversation
        12 => Ok("og"), // Organization
        13 => Ok("fc"), // Facet
        14 => Ok("wd"), // World
        // Productivity (60-79)
        60 => Ok("tl"), // TaskList
        61 => Ok("tk"), // Task
        62 => Ok("mc"), // Machine
        _ => Err(crate::error::Error::InvalidEntityType(entity_type)),
    }
}

/// Relationship kind used by graph edges.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EdgeKind {
    /// Entity belongs to another entity.
    BelongsTo = 0,
    /// Entity participates in another entity.
    ParticipatesIn = 1,
    /// Entity is attached to another entity.
    Attached = 2,
    /// Entity was authored by another entity.
    AuthoredBy = 3,
    /// Entity mentions another entity.
    Mentions = 4,
    /// Entity is about another entity.
    About = 5,
    /// Entity supports another entity.
    Supports = 6,
    /// Entity opposes another entity.
    Opposes = 7,
    /// Entity is a claim of another entity.
    ClaimOf = 8,
    /// Entity is scoped to another entity.
    ScopedTo = 9,
    /// Entity supersedes another entity.
    Supersedes = 10,
    /// Entity is derived from another entity.
    DerivedFrom = 11,
    /// Entity is part of another entity.
    PartOf = 12,
    /// Person is employed by an organization.
    EmployedBy = 13,
    /// Person has a behavioral facet.
    HasFacet = 14,
    /// Person exists in a world context.
    InWorld = 15,
    /// Claim is scoped to a facet.
    FacetOf = 16,
    /// Relationship is set in a world context.
    SetIn = 17,
    /// Task is a child of another task (tree hierarchy).
    /// No PPR hop limit — unlike PartOf which caps at 2.
    ChildOf = 18,
    /// Task is assigned to a machine for execution.
    AssignedTo = 19,
}

impl EdgeKind {
    /// Returns the default propagation weight for this edge kind.
    pub fn default_weight(self) -> f32 {
        match self {
            Self::BelongsTo => 1.0,
            Self::ParticipatesIn => 1.0,
            Self::Attached => 0.8,
            Self::AuthoredBy => 0.9,
            Self::Mentions => 0.6,
            Self::About => 0.5,
            Self::Supports => 1.0,
            Self::Opposes => 0.0,
            Self::ClaimOf => 1.0,
            Self::ScopedTo => 0.7,
            Self::Supersedes => 0.3,
            Self::DerivedFrom => 0.2,
            Self::PartOf => 0.8,
            Self::EmployedBy => 0.8,
            Self::HasFacet => 0.7,
            Self::InWorld => 0.7,
            Self::FacetOf => 0.7,
            Self::SetIn => 0.7,
            Self::ChildOf => 1.0,
            Self::AssignedTo => 0.8,
        }
    }

    /// Converts a raw discriminant into an edge kind.
    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::BelongsTo),
            1 => Some(Self::ParticipatesIn),
            2 => Some(Self::Attached),
            3 => Some(Self::AuthoredBy),
            4 => Some(Self::Mentions),
            5 => Some(Self::About),
            6 => Some(Self::Supports),
            7 => Some(Self::Opposes),
            8 => Some(Self::ClaimOf),
            9 => Some(Self::ScopedTo),
            10 => Some(Self::Supersedes),
            11 => Some(Self::DerivedFrom),
            12 => Some(Self::PartOf),
            13 => Some(Self::EmployedBy),
            14 => Some(Self::HasFacet),
            15 => Some(Self::InWorld),
            16 => Some(Self::FacetOf),
            17 => Some(Self::SetIn),
            18 => Some(Self::ChildOf),
            19 => Some(Self::AssignedTo),
            _ => None,
        }
    }
}

/// Bi-temporal interval represented as UNIX timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeRange {
    /// Inclusive start timestamp.
    pub start: u64,
    /// Inclusive end timestamp.
    pub end: u64,
}

/// HNSW configuration values.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HnswConfig {
    /// Maximum neighbors per node in layer 0.
    pub m_max_0: usize,
    /// Beam width used during graph construction.
    pub ef_construction: usize,
    /// Beam width used during search.
    pub ef_search: usize,
}

impl Default for HnswConfig {
    fn default() -> Self {
        Self {
            m_max_0: 64,
            ef_construction: 200,
            ef_search: 128,
        }
    }
}

/// Vault runtime configuration.
///
/// The struct is `#[non_exhaustive]`, so downstream callers cannot build it
/// with a struct literal. Use one of the presets (`VaultConfig::device()`
/// or `VaultConfig::server()`, or `VaultConfig::default()` which aliases
/// `device()`) and mutate fields as needed:
///
/// ```
/// # use oneiron::VaultConfig;
/// let mut cfg = VaultConfig::default();
/// cfg.dimensions = 768;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VaultConfig {
    /// Embedding vector dimension.
    pub dimensions: usize,
    /// Embedding model identifier used for vector compatibility checks.
    pub embedding_model: Option<String>,
    /// LMDB map size in bytes.
    pub map_size: usize,
    /// Maximum LMDB reader slots.
    pub max_readers: u32,
    /// HNSW tuning configuration.
    pub hnsw: HnswConfig,
    /// Text analyzer configuration (plan ONE-317 §2.3).
    pub text_analyzer: TextAnalyzerConfig,
    /// Roots probed at open time for per-language dictionaries
    /// (`<path>/ja/system.dic`, `<path>/ko/system.dic`,
    /// `<path>/zh/jieba.dict.utf8`). First-found wins per-language; missing
    /// dicts silently downgrade the affected language to Portable mode.
    ///
    /// **Security.** Every path here is opened and (for Sudachi/jieba)
    /// read in full at `Vault::open`. Callers MUST only include paths they
    /// trust — e.g. the iOS app bundle's `Resources/` directory, or a
    /// packager-controlled cache directory. Do NOT pass user-uploaded
    /// directories, network mounts, or world-writable locations: a hostile
    /// dict file can drive Sudachi / jieba / Lindera into unexpected
    /// behavior, and the dict-bytes hash is then baked into the LMDB
    /// analyzer manifest, silently pinning the vault to that dict.
    pub dict_search_paths: Vec<PathBuf>,
    /// Skip the text-index manifest handshake at [`crate::Vault::open`] so the
    /// caller can reach [`crate::MaintenanceBuilder::clear_text_index`]
    /// after a dict swap or BM25 field-schema change. Without this escape
    /// hatch, [`crate::Error::IncompatibleAnalyzer`] and
    /// [`crate::Error::Bm25FieldSchemaChanged`] trap the user before any
    /// `Vault` exists to call `.maintain()` on.
    ///
    /// Only use this to immediately run `clear_text_index`. On a populated
    /// vault, [`crate::Vault::open`] marks the text index untrusted and
    /// [`crate::Vault::search_text`] (and the pipeline / context_pack
    /// callers that go through the same internal trust gate)
    /// returns [`crate::Error::CorruptedIndex`] until the clear commits.
    pub skip_text_index_manifest_check: bool,
}

/// Text analyzer configuration. Kept minimal in v1 — the full analyzer
/// manifest (normalization policy, per-channel schema, lang modes) is
/// computed from dict discovery at open time and stored in the vault's
/// on-disk manifest. Fields here cover caller-controllable knobs only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TextAnalyzerConfig {}

/// Per-call overrides for `BatchBuilder::text`. Reserved; v1 ignores all
/// fields but the struct is public so downstream can adopt without a
/// minor-version bump later.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TextIndexOptions {
    /// Explicit language hint for this batch of text fields. Overrides
    /// `whichlang` detection on Latin/Cyrillic/Greek runs and the
    /// DualHanFallback decision on Han runs. Unambiguous-script runs
    /// (Hiragana, Katakana, Hangul, Hebrew, Thai, Lao, Khmer, Myanmar)
    /// route by their own script class regardless of this hint — the
    /// script is the stronger signal.
    pub language_hint: Option<crate::analyzer::LanguageHint>,
}

impl Default for VaultConfig {
    /// Aliases `VaultConfig::device()` — the common default. Call
    /// `VaultConfig::server()` explicitly if you want the server preset.
    fn default() -> Self {
        Self::device()
    }
}

impl VaultConfig {
    /// Returns a device-optimized preset.
    #[must_use]
    pub fn device() -> Self {
        Self {
            dimensions: 1024,
            embedding_model: None,
            map_size: 1 << 30,
            max_readers: 126,
            hnsw: HnswConfig::default(),
            text_analyzer: TextAnalyzerConfig::default(),
            dict_search_paths: Vec::new(),
            skip_text_index_manifest_check: false,
        }
    }

    /// Returns a server-optimized preset.
    #[must_use]
    pub fn server() -> Self {
        Self {
            dimensions: 4096,
            embedding_model: None,
            map_size: 1 << 33,
            max_readers: 126,
            hnsw: HnswConfig::default(),
            text_analyzer: TextAnalyzerConfig::default(),
            dict_search_paths: Vec::new(),
            skip_text_index_manifest_check: false,
        }
    }
}

/// A scored entity result.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScoredEntity {
    /// Entity identifier.
    pub id: EntityId,
    /// Ranking score.
    pub score: f32,
}

/// Retrieval signal type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Signal {
    Vector,
    Text,
    Phonetic,
    Temporal,
    Ppr,
}

/// Temporal query precision controls sigmoid width for temporal scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TemporalGranularity {
    Exact,
    Hour,
    Day,
    Week,
    Month,
    Season,
    Year,
    Vague,
}

impl TemporalGranularity {
    /// Returns the scoring sigma in seconds for this granularity.
    pub fn sigma_secs(self) -> u64 {
        match self {
            Self::Exact => 3_600,
            Self::Hour => 14_400,
            Self::Day => 86_400,
            Self::Week => 604_800,
            Self::Month => 2_592_000,
            Self::Season => 7_776_000,
            Self::Year => 15_552_000,
            Self::Vague => 31_536_000,
        }
    }
}

/// Temporal anchor intent for bitemporal scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum TemporalAnchorMode {
    Occurred,
    Learned,
    Both,
    #[default]
    Auto,
}

/// Output serialization format for context packing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum PackFormat {
    #[default]
    Json,
    Yaml,
    Toon,
    Markdown,
    Plaintext,
}

/// Field selection profile for context packing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum FieldProfile {
    Minimal,
    #[default]
    Standard,
    Full,
}

/// Hydrated entity with decoded fields, edges, and provenance.
#[derive(Debug, Clone)]
pub struct ContextEntity {
    pub id: EntityId,
    pub short_id: String,
    pub content_hash: u8,
    pub entity_type: u8,
    pub score: f32,
    pub fields: Option<HashMap<String, serde_json::Value>>,
    pub edges: Option<Vec<EdgeInfo>>,
    pub vector: Option<Vec<f32>>,
}

/// Edge info for hydrated context entities.
#[derive(Debug, Clone)]
pub struct EdgeInfo {
    pub kind: EdgeKind,
    pub target: EntityId,
    pub target_short_id: Option<String>,
    pub weight: f32,
    pub created_at: u64,
    pub vad: Vad,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Vad {
    pub valence: f32,
    pub arousal: f32,
    pub dominance: f32,
}

impl Vad {
    pub const NEUTRAL: Self = Self {
        valence: 0.0,
        arousal: 0.0,
        dominance: 0.0,
    };

    pub fn is_finite(&self) -> bool {
        self.valence.is_finite() && self.arousal.is_finite() && self.dominance.is_finite()
    }

    pub fn is_in_range(&self) -> bool {
        (-1.0..=1.0).contains(&self.valence)
            && (0.0..=1.0).contains(&self.arousal)
            && (0.0..=1.0).contains(&self.dominance)
    }
}

pub(crate) fn parse_vad(value: &[u8]) -> Vad {
    let f = |offset: usize| -> f32 {
        value
            .get(offset..offset + 4)
            .and_then(|b| b.try_into().ok())
            .map(f32::from_le_bytes)
            .unwrap_or(0.0)
    };
    Vad {
        valence: f(12),
        arousal: f(16),
        dominance: f(20),
    }
}

/// Stats about the context pack query.
#[derive(Debug, Clone)]
pub struct PackStats {
    pub candidates_considered: usize,
    pub signals_used: Vec<Signal>,
    pub query_time_us: u64,
    pub entities_hydrated: usize,
    pub neighbors_hydrated: usize,
}

/// A fully hydrated context pack ready for serialization or programmatic use.
#[derive(Debug, Clone)]
pub struct ContextPack {
    pub results: Vec<ContextEntity>,
    pub neighbors: Vec<ContextEntity>,
    pub stats: PackStats,
}

/// Token budget allocation across entity types.
#[derive(Debug, Clone, Copy)]
pub struct TokenAllocation {
    pub claims: f32,
    pub turns: f32,
    pub summaries: f32,
    pub other: f32,
}

impl Default for TokenAllocation {
    fn default() -> Self {
        Self {
            claims: 0.45,
            turns: 0.10,
            summaries: 0.25,
            other: 0.20,
        }
    }
}
