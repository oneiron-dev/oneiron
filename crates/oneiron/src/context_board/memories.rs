//! MEMORIES section — what retrieval pulled: typed rows, the slot budget, the companion echo, and the per-session retrieval cursor (ARCH-0067 §1 MEMORIES row, §3 board state).

use serde::Deserialize;
use serde::Serialize;

pub const MEMORIES_SECTION_VERSION_V4: &str = "v4";

/// Stable MEMORIES section slot names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemorySlot {
    Claims,
    Turns,
    Summaries,
    Facets,
    Companions,
    Other,
}

impl MemorySlot {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claims => "claims",
            Self::Turns => "turns",
            Self::Summaries => "summaries",
            Self::Facets => "facets",
            Self::Companions => "companions",
            Self::Other => "other",
        }
    }

    #[must_use]
    pub const fn sort_rank(self) -> u8 {
        match self {
            Self::Claims => 0,
            Self::Turns => 1,
            Self::Summaries => 2,
            Self::Facets => 3,
            Self::Companions => 4,
            Self::Other => 5,
        }
    }
}

/// Source section for one memory-board row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemorySource {
    Result,
    Neighbor,
}

impl MemorySource {
    #[must_use]
    pub const fn sort_rank(self) -> u8 {
        match self {
            Self::Result => 0,
            Self::Neighbor => 1,
        }
    }
}

/// Per-slot row caps for a MEMORIES section.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MemoriesBudget {
    pub claims: usize,
    pub turns: usize,
    pub summaries: usize,
    pub facets: usize,
    pub companions: usize,
    pub other: usize,
}

impl MemoriesBudget {
    #[must_use]
    pub const fn new(
        claims: usize,
        turns: usize,
        summaries: usize,
        facets: usize,
        companions: usize,
        other: usize,
    ) -> Self {
        Self {
            claims,
            turns,
            summaries,
            facets,
            companions,
            other,
        }
    }

    #[must_use]
    pub const fn get(self, slot: MemorySlot) -> usize {
        match slot {
            MemorySlot::Claims => self.claims,
            MemorySlot::Turns => self.turns,
            MemorySlot::Summaries => self.summaries,
            MemorySlot::Facets => self.facets,
            MemorySlot::Companions => self.companions,
            MemorySlot::Other => self.other,
        }
    }

    pub fn increment(&mut self, slot: MemorySlot) {
        let counter = match slot {
            MemorySlot::Claims => &mut self.claims,
            MemorySlot::Turns => &mut self.turns,
            MemorySlot::Summaries => &mut self.summaries,
            MemorySlot::Facets => &mut self.facets,
            MemorySlot::Companions => &mut self.companions,
            MemorySlot::Other => &mut self.other,
        };
        *counter = counter.saturating_add(1);
    }
}

/// Companion scope that influenced MEMORIES assembly.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CompanionAssembly {
    pub caller: Option<String>,
    pub scope: Option<String>,
    pub scope_source: Option<String>,
    pub person_ref: Option<String>,
    pub persona_ref: Option<String>,
    pub expression: Option<String>,
}

/// One stable row in the MEMORIES section.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MemoryRow {
    pub row_index: usize,
    pub slot: MemorySlot,
    pub source: MemorySource,
    pub id: String,
    pub short_id: String,
    pub content_hash: String,
    pub entity_type: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_ref: Option<String>,
    pub score: f32,
}

/// Deterministic MEMORIES section envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MemoriesSection {
    pub version: String,
    pub budget: MemoriesBudget,
    pub rows: Vec<MemoryRow>,
    pub companion: Option<CompanionAssembly>,
    /// OF-365 disclosure block for the assembly that produced this board.
    /// Absent (and skipped in serialization, keeping pre-ILD board refs
    /// stable) when no disclosure context was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<crate::disclosure::DisclosureAssembly>,
}

/// Session-scoped retrieval cursor returned by MEMORIES surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MemoriesCursor {
    pub session_id: String,
    pub revision: u64,
    pub query_count: u64,
    pub last_retrieval_run_id: Option<String>,
    pub last_result_ids: Vec<String>,
}

impl MemoriesCursor {
    #[must_use]
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            revision: 0,
            query_count: 0,
            last_retrieval_run_id: None,
            last_result_ids: Vec::new(),
        }
    }
}

impl Default for MemoriesCursor {
    fn default() -> Self {
        Self::new("default")
    }
}
