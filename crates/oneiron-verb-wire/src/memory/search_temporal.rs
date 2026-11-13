//! Moved from `crates/oneiron/src/memory/search_temporal.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use serde::Deserialize;
use serde::Serialize;

/// An inclusive UTC range in Unix seconds. An outer range only narrows results;
/// it is not an anchor and adaptive widening never removes it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TemporalSearchRange {
    pub start: u64,
    pub end: u64,
}

impl TemporalSearchRange {
    fn validate(self) -> MemoryResult<()> {
        caps::check_as_of(Some(self.start))?;
        caps::check_as_of(Some(self.end))?;
        if self.start > self.end {
            return Err(MemoryError::bad_request(
                "temporal range start must not exceed end",
            ));
        }
        Ok(())
    }

    fn overlaps(self, start: u64, end: u64) -> bool {
        self.start <= end && start <= self.end
    }
}

/// One admitted result, with dates from the same source revision the run pinned.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TemporalSearchHit {
    pub entity_ref: String,
    pub source_revision_ref: Option<String>,
    pub score: f32,
    pub occurred_start: u64,
    pub occurred_end: u64,
    pub learned_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TemporalSearchResult {
    pub hits: Vec<TemporalSearchHit>,
    /// None when authority prevented the temporal channel from running.
    pub widening: Option<TemporalSearchReport>,
}
