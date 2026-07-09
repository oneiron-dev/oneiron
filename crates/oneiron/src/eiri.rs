//! Eiri Context v4 board + session-RAG + companion resume wire types.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::Serialize;

pub const EIRI_CONTEXT_VERSION_V4: &str = "v4";

/// Stable Eiri Context v4 memory-board slot names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EiriMemoryBoardSlot {
    Claims,
    Turns,
    Summaries,
    Facets,
    Companions,
    Other,
}

impl EiriMemoryBoardSlot {
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
pub enum EiriMemoryBoardSource {
    Result,
    Neighbor,
}

impl EiriMemoryBoardSource {
    #[must_use]
    pub const fn sort_rank(self) -> u8 {
        match self {
            Self::Result => 0,
            Self::Neighbor => 1,
        }
    }
}

/// Per-slot row caps for an Eiri Context v4 memory board.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EiriMemoryBoardBudget {
    pub claims: usize,
    pub turns: usize,
    pub summaries: usize,
    pub facets: usize,
    pub companions: usize,
    pub other: usize,
}

impl EiriMemoryBoardBudget {
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
    pub const fn get(self, slot: EiriMemoryBoardSlot) -> usize {
        match slot {
            EiriMemoryBoardSlot::Claims => self.claims,
            EiriMemoryBoardSlot::Turns => self.turns,
            EiriMemoryBoardSlot::Summaries => self.summaries,
            EiriMemoryBoardSlot::Facets => self.facets,
            EiriMemoryBoardSlot::Companions => self.companions,
            EiriMemoryBoardSlot::Other => self.other,
        }
    }

    pub fn increment(&mut self, slot: EiriMemoryBoardSlot) {
        let counter = match slot {
            EiriMemoryBoardSlot::Claims => &mut self.claims,
            EiriMemoryBoardSlot::Turns => &mut self.turns,
            EiriMemoryBoardSlot::Summaries => &mut self.summaries,
            EiriMemoryBoardSlot::Facets => &mut self.facets,
            EiriMemoryBoardSlot::Companions => &mut self.companions,
            EiriMemoryBoardSlot::Other => &mut self.other,
        };
        *counter = counter.saturating_add(1);
    }
}

/// Companion scope that influenced Eiri Context v4 assembly.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EiriCompanionAssembly {
    pub caller: Option<String>,
    pub scope: Option<String>,
    pub scope_source: Option<String>,
    pub person_ref: Option<String>,
    pub persona_ref: Option<String>,
    pub expression: Option<String>,
}

/// One stable row in the Eiri Context v4 memory board.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EiriMemoryBoardRow {
    pub row_index: usize,
    pub slot: EiriMemoryBoardSlot,
    pub source: EiriMemoryBoardSource,
    pub id: String,
    pub short_id: String,
    pub content_hash: String,
    pub entity_type: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_ref: Option<String>,
    pub score: f32,
}

/// Deterministic Eiri Context v4 memory-board envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EiriMemoryBoard {
    pub version: String,
    pub budget: EiriMemoryBoardBudget,
    pub rows: Vec<EiriMemoryBoardRow>,
    pub companion: Option<EiriCompanionAssembly>,
}

/// Session-scoped RAG cursor returned by Eiri Context v4 surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EiriSessionRagState {
    pub session_id: String,
    pub revision: u64,
    pub query_count: u64,
    pub last_retrieval_run_id: Option<String>,
    pub last_result_ids: Vec<String>,
}

impl EiriSessionRagState {
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

impl Default for EiriSessionRagState {
    fn default() -> Self {
        Self::new("default")
    }
}

/// Read-only ambient context returned by the companion resume endpoint.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionContext {
    pub api_version: String,
    pub counts: BTreeMap<String, u64>,
    pub last_activity: Option<u64>,
    #[serde(default)]
    pub rag_state: EiriSessionRagState,
}

/// Pending notification surfaced during companion resume hydration.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct NotificationItem {
    pub id: String,
    pub learned_at: u64,
    pub body: serde_json::Value,
}

/// Existing work item that still needs caller-side processing.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct UnprocessedItem {
    pub id: String,
    pub entity_type: u8,
    pub learned_at: u64,
    pub body: serde_json::Value,
}

/// Token meter snapshot included in every companion resume bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResumeBudget {
    pub tokens_used: u64,
    pub tokens_limit: u64,
    pub tokens_remaining: u64,
}

impl ResumeBudget {
    #[must_use]
    pub fn from_meter(tokens_used: u64, tokens_limit: u64) -> Self {
        Self {
            tokens_used,
            tokens_limit,
            tokens_remaining: tokens_limit.saturating_sub(tokens_used),
        }
    }
}

/// Single-call companion hydration bundle.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ResumeBundle {
    pub session: SessionContext,
    pub notifications: Vec<NotificationItem>,
    pub unprocessed: Vec<UnprocessedItem>,
    pub budget: ResumeBudget,
}

impl ResumeBundle {
    #[must_use]
    pub fn new(
        session: SessionContext,
        notifications: Vec<NotificationItem>,
        unprocessed: Vec<UnprocessedItem>,
        budget: ResumeBudget,
    ) -> Self {
        Self {
            session,
            notifications,
            unprocessed,
            budget,
        }
    }
}
