//! MEMORIES section — what retrieval pulled: typed rows, the slot budget, the companion echo, and the per-session retrieval cursor (ARCH-0067 §1 MEMORIES row, §3 board state).

use serde::Deserialize;
use serde::Serialize;

pub const MEMORIES_SECTION_VERSION_V4: &str = "v4";

#[doc(hidden)]
pub use oneiron_records::context_board::memories::{
    CompanionAssembly, MemoriesBudget, MemoriesCursor, MemoryRow, MemorySlot, MemorySource,
    MemoryTier,
};

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
