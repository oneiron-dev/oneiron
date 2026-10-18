//! Explicit bitemporal search over the caller's ordinary scoped retrieval lane.

use serde::{Deserialize, Serialize};

use super::{Memory, MemoryError, MemoryResult, caps};
use crate::batch::EntityMetadataHeader;
use crate::claim::{ClaimReadStatus, PointRead, ScopedReadResult};
use crate::pipeline::TemporalSearchReport;
use crate::ports::EntityStoreRead;
use crate::temporal::TemporalAnchorMode;

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

/// The engine's explicit temporal controls. `start` and `end` anchor the selected
/// axis; `both` uses them for occurrence and requires the separate learned range.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TemporalSearchRequest {
    pub start: u64,
    pub end: u64,
    /// Zero selects the engine's default sigma; adaptive rounds may double it.
    pub sigma_secs: u64,
    #[serde(default)]
    pub anchor_mode: TemporalAnchorMode,
    #[serde(default)]
    pub learned_start: Option<u64>,
    #[serde(default)]
    pub learned_end: Option<u64>,
    /// Defaults to the engine's adaptive behavior, at most three rounds total.
    #[serde(default = "adaptive_enabled")]
    pub adaptive: bool,
    #[serde(default)]
    pub occurred_range: Option<TemporalSearchRange>,
    #[serde(default)]
    pub learned_range: Option<TemporalSearchRange>,
    pub limit: usize,
}

fn adaptive_enabled() -> bool {
    true
}

impl TemporalSearchRequest {
    pub fn validate(&self) -> MemoryResult<()> {
        caps::check_limit_nonzero(self.limit)?;
        TemporalSearchRange {
            start: self.start,
            end: self.end,
        }
        .validate()?;
        match (self.anchor_mode, self.learned_start, self.learned_end) {
            (TemporalAnchorMode::Both, Some(start), Some(end)) => {
                TemporalSearchRange { start, end }.validate()?;
            }
            (TemporalAnchorMode::Both, _, _) => {
                return Err(MemoryError::bad_request(
                    "both anchors require learned_start and learned_end",
                ));
            }
            (_, None, None) => {}
            _ => {
                return Err(MemoryError::bad_request(
                    "learned_start and learned_end require both anchor mode",
                ));
            }
        }
        for range in [self.occurred_range, self.learned_range]
            .into_iter()
            .flatten()
        {
            range.validate()?;
        }
        Ok(())
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

impl Memory<'_> {
    pub fn query_temporal(
        &self,
        input: &TemporalSearchRequest,
    ) -> MemoryResult<ScopedReadResult<TemporalSearchResult>> {
        input.validate()?;
        let (limit, _) = caps::clamp_search_limit(input.limit);
        let lane = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let (filter, policy) = lane.recall_plan()?;
        let admitted = |store: &crate::store::StoreRead<'_>,
                        txn: &heed::RoTxn<'_>,
                        id: &crate::EntityId|
         -> crate::Result<bool> {
            if !lane.recall_candidate_in(txn, &policy, &filter, id)? {
                return Ok(false);
            }
            if input.occurred_range.is_none() && input.learned_range.is_none() {
                return Ok(true);
            }
            // Outer ranges also constrain the adaptive stop's admitted count.
            let Some(raw) = store.port_entity_raw(txn, id)? else {
                return Ok(false);
            };
            let Some(header) = EntityMetadataHeader::parse(&raw) else {
                return Ok(false);
            };
            Ok(input
                .occurred_range
                .is_none_or(|range| range.overlaps(header.occurred_start, header.occurred_end))
                && input
                    .learned_range
                    .is_none_or(|range| range.overlaps(header.learned_at, header.learned_at)))
        };
        let mut pipeline = self
            .vault
            .query()
            .reading(lane.store_read())
            .authority_filter(filter.clone())
            .scoped_note_reader(lane.actor_key().clone())
            .caller_off_device(lane.off_device())
            .filter_candidates(&admitted)
            .temporal_adaptive(input.adaptive)
            .limit(limit);
        pipeline = match (input.anchor_mode, input.learned_start, input.learned_end) {
            (TemporalAnchorMode::Both, Some(start), Some(end)) => pipeline
                .search_temporal_bitemporal(
                    input.start,
                    input.end,
                    start,
                    end,
                    input.sigma_secs,
                    limit,
                ),
            _ => pipeline.search_temporal_with_sigma(
                input.start,
                input.end,
                input.sigma_secs,
                input.anchor_mode,
                limit,
            ),
        };
        if let Some(range) = input.occurred_range {
            pipeline = pipeline.filter_occurred_range(range.start, range.end);
        }
        if let Some(range) = input.learned_range {
            pipeline = pipeline.filter_learned_range(range.start, range.end);
        }
        let output = pipeline.run_for_pack()?;
        lane.end_recall_plan()?;
        let mut results = lane.filter_search_results(
            output.scores,
            limit,
            None,
            &filter,
            &policy,
            output.read_suppressed,
            &output.revisions,
        )?;
        let reads = results
            .value
            .iter()
            .map(|hit| {
                let read = PointRead::id(hit.id);
                match output.revisions.get(&hit.id) {
                    Some(revision) => read.at(crate::vault::ReadMode::Pinned(*revision)),
                    None => read,
                }
            })
            .collect::<Vec<_>>();
        let rows = lane.read(&reads, None)?;
        results.receipt.restrict_with(&rows.receipt);
        let mut produced = Vec::new();
        let hits = results
            .value
            .into_iter()
            .zip(rows.value)
            .filter_map(|(hit, row)| {
                let row = row.filter(|row| row.body.is_some())?;
                produced.push(hit.id);
                Some(TemporalSearchHit {
                    entity_ref: hit.id.to_hex(),
                    source_revision_ref: output
                        .revisions
                        .get(&hit.id)
                        .map(|revision| revision.to_hex()),
                    score: hit.score,
                    occurred_start: row.occurred.start,
                    occurred_end: row.occurred.end,
                    learned_at: row.learned_at,
                })
            })
            .collect::<Vec<_>>();
        self.produced_from(produced);
        Ok(ScopedReadResult {
            value: TemporalSearchResult {
                hits,
                widening: output.temporal_report,
            },
            receipt: results.receipt,
        })
    }
}
