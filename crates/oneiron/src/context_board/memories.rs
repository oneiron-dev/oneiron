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
    /// The optional rows the projection cut past their slot's cap or the
    /// shared cap, per slot. Absent (and skipped in serialization, keeping
    /// the state ref of a board that cut nothing) when it cut none.
    #[serde(default, skip_serializing_if = "MemoriesCut::is_empty")]
    pub cut: MemoriesCut,
}

/// How many optional rows a MEMORIES projection cut, per slot: each one past
/// its slot's cap or the shared cap (FIX MEMORIES-SLOT-BUDGET-CUT-UNCOUNTED).
/// A pinned row is never cut. A cut row stays stored, so a later query can
/// find it again. The count is of cuts: a row a pin brings back after a pass
/// cut it stays counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MemoriesCut {
    pub claims: usize,
    pub turns: usize,
    pub summaries: usize,
    pub facets: usize,
    pub other: usize,
}

impl MemoriesCut {
    /// Every slot's count, added.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.claims
            .saturating_add(self.turns)
            .saturating_add(self.summaries)
            .saturating_add(self.facets)
            .saturating_add(self.other)
    }

    /// No row was cut.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total() == 0
    }

    /// Counts one row of `slot` as cut.
    pub fn increment(&mut self, slot: MemorySlot) {
        let counter = match slot {
            MemorySlot::Claims => &mut self.claims,
            MemorySlot::Turns => &mut self.turns,
            MemorySlot::Summaries => &mut self.summaries,
            MemorySlot::Facets => &mut self.facets,
            MemorySlot::Other => &mut self.other,
        };
        *counter = counter.saturating_add(1);
    }

    /// Adds the cuts an earlier pass counted.
    pub fn accumulate(&mut self, earlier: Self) {
        self.claims = self.claims.saturating_add(earlier.claims);
        self.turns = self.turns.saturating_add(earlier.turns);
        self.summaries = self.summaries.saturating_add(earlier.summaries);
        self.facets = self.facets.saturating_add(earlier.facets);
        self.other = self.other.saturating_add(earlier.other);
    }
}
