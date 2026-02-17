use std::collections::HashMap;

use uuid::Uuid;

pub(crate) const ENTITY_ID_LEN: usize = 16;

/// A time-ordered entity identifier backed by UUIDv7 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntityId([u8; ENTITY_ID_LEN]);

impl EntityId {
    /// Creates a new identifier using the current UUIDv7 timestamp.
    pub fn now() -> Self {
        Self(Uuid::now_v7().into_bytes())
    }

    /// Creates an identifier from raw bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the raw identifier bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub(crate) fn lower_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(self.0.len() * 2);
        for byte in self.0 {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}

/// Returns the short ID prefix for an entity type byte.
pub fn short_id_prefix(entity_type: u8) -> &'static str {
    match entity_type {
        0 => "cl",
        1 => "tn",
        2 => "ss",
        3 => "ms",
        4 => "pr",
        5 => "rl",
        6 => "ev",
        7 => "sk",
        8 => "sm",
        9 => "pl",
        10 => "tx",
        11 => "cv",
        _ => "xx",
    }
}

/// Relationship kind used by graph edges.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

impl VaultConfig {
    /// Returns a device-optimized preset.
    pub fn device() -> Self {
        Self {
            dimensions: 1024,
            embedding_model: None,
            map_size: 1 << 30,
            max_readers: 126,
            hnsw: HnswConfig::default(),
        }
    }

    /// Returns a server-optimized preset.
    pub fn server() -> Self {
        Self {
            dimensions: 4096,
            embedding_model: None,
            map_size: 1 << 33,
            max_readers: 126,
            hnsw: HnswConfig::default(),
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
pub enum Signal {
    Vector,
    Text,
    Phonetic,
    Temporal,
    Ppr,
}

/// Temporal query precision controls sigmoid width for temporal scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
pub enum TemporalAnchorMode {
    Occurred,
    Learned,
    Both,
    #[default]
    Auto,
}

/// Output serialization format for context packing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
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
}

/// Which retrieval signal produced a hit and its raw score.
#[derive(Debug, Clone, Copy)]
pub struct SignalHit {
    pub signal: Signal,
    pub score: f32,
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
