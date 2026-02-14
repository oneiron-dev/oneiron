use uuid::Uuid;

/// A time-ordered entity identifier backed by UUIDv7 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntityId([u8; 16]);

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

/// Output serialization format for context packing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PackFormat {
    Json,
    Yaml,
    Toon,
    Markdown,
    Plaintext,
}

/// Field selection profile for context packing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldProfile {
    Minimal,
    Standard,
    Full,
}
