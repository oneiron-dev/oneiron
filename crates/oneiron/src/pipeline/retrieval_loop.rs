//! OF-183: the engine's read-only, receipt-aware loop over entity handles.
//!
//! A host supplies the normal deterministic pipeline and its planner. The first
//! observation is that pipeline's result, not a benchmark substitute. A planner
//! (an engine-run skill or a code-mode host) then issues exactly one typed verb
//! per turn. Prompts, models, score thresholds and learned policy stay outside
//! this mechanism. `Read` alone returns content; all other verbs return handles.

mod types;
pub use types::{
    RetrievalEvidence, RetrievalHandle, RetrievalLoopAction, RetrievalLoopObservation,
    RetrievalLoopStatus,
};

use super::PipelineBuilder;
use crate::claim::{PointRead, ScopedRead};
use crate::gate::RetrievalFilter;
use crate::store::{RetrievalScoreBreakdown, RetrievalState};
use crate::vault::ReadMode;
use crate::{EntityId, Error, Result};
use std::collections::HashSet;
use std::future::Future;

/// A live retrieval skill invocation. Its scope and policy cannot be supplied
/// by a guest action; they are inherited from the host's pipeline and reader.
pub struct ReadOnlyRetrievalLoop<'r, 'v> {
    reader: &'r ScopedRead<'v>,
    plan: PipelineBuilder<'r>,
    observation: RetrievalLoopObservation,
    /// Every handle any observation so far has held (FIX 7797): what the
    /// loop has explored. Novelty is measured against it, and the frontier
    /// is what lies one hop past it.
    explored: HashSet<EntityId>,
    /// One fully admitted ranking; only refreshed pages reach observations.
    ranked: Vec<RetrievalHandle>,
    /// Raw offset of the next unreleased page, not a caller bearer token.
    page_offset: usize,
    page_size: usize,
}

impl<'r> PipelineBuilder<'r> {
    /// Seeds the agentic loop from this deterministic multi-signal plan.
    /// The reader is mandatory, including for an embedded owner.
    pub fn read_only_loop<'v>(
        self,
        reader: &'r ScopedRead<'v>,
    ) -> Result<ReadOnlyRetrievalLoop<'r, 'v>>
    where
        'v: 'r,
    {
        ReadOnlyRetrievalLoop::new(reader, self, None)
    }
}

impl<'r, 'v: 'r> ReadOnlyRetrievalLoop<'r, 'v> {
    /// Start with a host-authored request as well as the mandatory actor ceiling.
    /// Every later request carries forward the applied intersection.
    pub fn new(
        reader: &'r ScopedRead<'v>,
        plan: PipelineBuilder<'r>,
        requested: Option<&RetrievalFilter>,
    ) -> Result<Self> {
        if reader.vault().vault_id() != plan.vault.vault_id() {
            return Err(Error::InvalidConfig(
                "retrieval loop reader belongs to another vault".into(),
            ));
        }
        let requested_limit = plan.result_limit;
        if requested_limit == 0 {
            return Err(Error::InvalidConfig(
                "retrieval loop limit must be greater than zero".into(),
            ));
        }
        let page_size = requested_limit.min(crate::memory::caps::MAX_SEARCH_LIMIT);
        let plan = plan.reading(reader.store_read()).memory_lane_only();
        let seeded =
            reader.retrieval_loop_search(plan.clone(), plan.candidate_filter, requested)?;
        let ranked = seeded.handles;
        let quality = seeded.quality;
        let mut narrowing = seeded.receipt;
        let (page_offset, released) = release_page(
            reader,
            &ranked,
            0,
            page_size,
            &narrowing.applied.as_filter(),
        )?;
        narrowing.restrict_with(&released.receipt);
        let last_narrowing = released.receipt;
        let mut observation = RetrievalLoopObservation {
            status: RetrievalLoopStatus::Running,
            iteration: 0,
            action: None,
            state: plan.retrieval_state.clone().unwrap_or_default(),
            handles: released.value,
            evidence: Vec::new(),
            retrieval_quality: quality,
            last_narrowing,
            narrowing,
            requested_limit,
            effective_page_size: page_size,
            limit_clamped: false,
            next_cursor: None,
            end: false,
        };
        update_page_metadata(
            &mut observation,
            &ranked,
            page_offset,
            requested_limit,
            page_size,
        );
        let mut explored = HashSet::new();
        let frontier = Self::frontier(reader, &observation, &mut explored)?;
        update_state(&mut observation, &HashSet::new(), frontier, 0);
        Ok(Self {
            reader,
            plan,
            observation,
            explored,
            ranked,
            page_offset,
            page_size,
        })
    }

    #[must_use]
    pub fn observation(&self) -> &RetrievalLoopObservation {
        &self.observation
    }

    /// Execute one verb, then publish the new score-gap and read receipt.
    /// Failed actions leave the loop's plan and observation unchanged.
    pub fn step(&mut self, action: RetrievalLoopAction) -> Result<&RetrievalLoopObservation> {
        if matches!(
            self.observation.status,
            RetrievalLoopStatus::Stopped | RetrievalLoopStatus::Abstained
        ) {
            return Err(Error::InvalidConfig(
                "retrieval loop is already terminal".into(),
            ));
        }
        let mut next = self.observation.clone();
        next.status = RetrievalLoopStatus::Running;
        next.evidence.clear();
        let requested = next.narrowing.applied.as_filter();
        // Unknown ids are refused; a known handle that becomes unreadable is
        // instead removed under a receipt, allowing the planner to re-plan.
        match &action {
            RetrievalLoopAction::Expand { anchors } => {
                known_handles(&next.handles, anchors)?;
            }
            RetrievalLoopAction::Read { handles } => {
                known_handles(&next.handles, handles)?;
            }
            RetrievalLoopAction::DrillUp { anchor } | RetrievalLoopAction::DrillDown { anchor } => {
                known_handles(&next.handles, &[*anchor])?;
            }
            _ => {}
        }
        let mut plan = self.plan.clone();
        let mut ranked = self.ranked.clone();
        let mut page_offset = self.page_offset;
        // Refresh handles before they become graph seeds, evidence or a final
        // answer. A past receipt is never a grant for a later snapshot.
        let refreshed = self
            .reader
            .retrieval_loop_refresh(&next.handles, &requested)?;
        next.handles = refreshed.value;
        let mut cumulative = next.narrowing.clone();
        cumulative.restrict_with(&refreshed.receipt);
        let mut receipt = refreshed.receipt;
        let requested = cumulative.applied.as_filter();
        let mut hops = next.state.hops;
        match &action {
            RetrievalLoopAction::Continue => {
                if page_offset < ranked.len() {
                    let (next_offset, released) = release_page(
                        self.reader,
                        &ranked,
                        page_offset,
                        self.page_size,
                        &cumulative.applied.as_filter(),
                    )?;
                    page_offset = next_offset;
                    next.handles = released.value;
                    cumulative.restrict_with(&released.receipt);
                    receipt = released.receipt;
                } else {
                    // Past end, retain the refreshed current page for inspection.
                    // No new page is released and Continue is not an error.
                }
            }
            RetrievalLoopAction::Search {
                query,
                vector,
                phonetic,
            } => {
                if query.trim().is_empty() || query.len() > crate::memory::caps::MAX_QUERY_BYTES {
                    return Err(Error::InvalidConfig(
                        "retrieval loop search requires a bounded nonempty query".into(),
                    ));
                }
                // Dense and phonetic inputs belong to these words, not the
                // previous query. Never reuse an old query's embedding.
                plan.text_search = Some((query.clone(), plan.result_limit));
                plan.vector_search = vector
                    .as_ref()
                    .map(|vector| (vector.clone(), plan.result_limit));
                plan.phonetic_search = (!phonetic.is_empty()).then(|| phonetic.clone());
                plan.ppr_search = None;
                plan.ppr_expand = None;
                let searched = self.search(&plan, &requested)?;
                cumulative.restrict_with(&searched.receipt);
                ranked = searched.handles;
                let (next_offset, released) = release_page(
                    self.reader,
                    &ranked,
                    0,
                    self.page_size,
                    &cumulative.applied.as_filter(),
                )?;
                page_offset = next_offset;
                next.handles = released.value;
                next.retrieval_quality = searched.quality;
                cumulative.restrict_with(&released.receipt);
                receipt = released.receipt;
            }
            RetrievalLoopAction::Expand { anchors } => {
                let anchors: Vec<_> = if anchors.is_empty() {
                    next.handles.iter().map(|handle| handle.id).collect()
                } else {
                    next.handles
                        .iter()
                        .filter(|handle| anchors.contains(&handle.id))
                        .map(|handle| handle.id)
                        .collect()
                };
                if !anchors.is_empty() {
                    plan = plan.expand_ppr(&anchors, 1);
                    let searched = self.search(&plan, &requested)?;
                    cumulative.restrict_with(&searched.receipt);
                    ranked = searched.handles;
                    let (next_offset, released) = release_page(
                        self.reader,
                        &ranked,
                        0,
                        self.page_size,
                        &cumulative.applied.as_filter(),
                    )?;
                    page_offset = next_offset;
                    next.handles = released.value;
                    next.retrieval_quality = searched.quality;
                    cumulative.restrict_with(&released.receipt);
                    receipt = released.receipt;
                }
                hops = hops.saturating_add(1);
            }
            RetrievalLoopAction::DrillUp { anchor } | RetrievalLoopAction::DrillDown { anchor } => {
                if let Some(anchor) = next.handles.iter().find(|handle| handle.id == *anchor) {
                    let drilled = self.reader.retrieval_loop_drill(
                        anchor,
                        matches!(action, RetrievalLoopAction::DrillUp { .. }),
                        plan.result_limit,
                        &requested,
                    )?;
                    receipt.restrict_with(&drilled.receipt);
                    cumulative.restrict_with(&drilled.receipt);
                    let seeds: Vec<_> = drilled.value.iter().map(|handle| handle.id).collect();
                    if seeds.is_empty() {
                        ranked.clear();
                        page_offset = 0;
                        next.handles.clear();
                    } else {
                        // A grain move still obeys every host query filter
                        // (world, facet, corpus, type and time), then re-blends.
                        let mut grain = plan.clone();
                        grain.text_search = None;
                        grain.vector_search = None;
                        grain.phonetic_search = None;
                        grain.temporal_search = None;
                        grain.ppr_expand = None;
                        grain.turn_fold = super::TurnFold::Off;
                        let searched = self.search(&grain.search_ppr(&seeds, 0), &requested)?;
                        cumulative.restrict_with(&searched.receipt);
                        ranked = searched.handles;
                        let (next_offset, released) = release_page(
                            self.reader,
                            &ranked,
                            0,
                            self.page_size,
                            &cumulative.applied.as_filter(),
                        )?;
                        page_offset = next_offset;
                        next.handles = released.value;
                        next.retrieval_quality = searched.quality;
                        cumulative.restrict_with(&released.receipt);
                        receipt = released.receipt;
                    }
                } else {
                    ranked.clear();
                    page_offset = 0;
                    next.handles.clear();
                }
                hops = hops.saturating_add(1);
            }
            RetrievalLoopAction::WidenTemporal {
                start,
                end,
                sigma_secs,
            } => {
                widen_temporal(&mut plan, *start, *end, *sigma_secs)?;
                let searched = self.search(&plan, &requested)?;
                cumulative.restrict_with(&searched.receipt);
                ranked = searched.handles;
                let (next_offset, released) = release_page(
                    self.reader,
                    &ranked,
                    0,
                    self.page_size,
                    &cumulative.applied.as_filter(),
                )?;
                page_offset = next_offset;
                next.handles = released.value;
                next.retrieval_quality = searched.quality;
                cumulative.restrict_with(&released.receipt);
                receipt = released.receipt;
            }
            RetrievalLoopAction::Read { handles } => {
                let selected: Vec<_> = next
                    .handles
                    .iter()
                    .filter(|handle| handles.contains(&handle.id))
                    .cloned()
                    .collect();
                let reads: Vec<_> = selected.iter().map(point_read).collect();
                let read = self.reader.read(&reads, Some(&requested))?;
                let mut retained = HashSet::new();
                for (handle, row) in selected.into_iter().zip(read.value) {
                    let Some(row) = row else { continue };
                    let Some(body) = row.body else { continue };
                    let mut input = body.as_slice();
                    let value = rmpv::decode::read_value(&mut input)
                        .map_err(|_| Error::CorruptedIndex("retrieval evidence body"))?;
                    if !input.is_empty() {
                        return Err(Error::CorruptedIndex("retrieval evidence trailing bytes"));
                    }
                    retained.insert(handle.id);
                    next.evidence.push(RetrievalEvidence {
                        handle,
                        entity_type: row.entity_type,
                        occurred: row.occurred,
                        learned_at: row.learned_at,
                        body: crate::batch::export::served_stored_messagepack_json(&body, value),
                    });
                }
                next.handles.retain(|handle| {
                    !handles.contains(&handle.id) || retained.contains(&handle.id)
                });
                receipt.restrict_with(&read.receipt);
                cumulative.restrict_with(&read.receipt);
            }
            RetrievalLoopAction::Stop => next.status = RetrievalLoopStatus::Stopped,
            RetrievalLoopAction::Abstain => {
                ranked.clear();
                page_offset = 0;
                next.handles.clear();
                next.status = RetrievalLoopStatus::Abstained;
            }
        }
        update_page_metadata(
            &mut next,
            &ranked,
            page_offset,
            self.observation.requested_limit,
            self.page_size,
        );
        next.iteration = next.iteration.saturating_add(1);
        next.action = Some(action);
        next.narrowing = cumulative;
        next.last_narrowing = receipt;
        let mut explored = self.explored.clone();
        let frontier = Self::frontier(self.reader, &next, &mut explored)?;
        update_state(&mut next, &self.explored, frontier, hops);
        self.plan = plan;
        self.observation = next;
        self.explored = explored;
        self.ranked = ranked;
        self.page_offset = page_offset;
        Ok(&self.observation)
    }

    /// Adds `observation`'s handles to `explored`, then counts the frontier
    /// (FIX 7798): the one-hop graph neighbours of every explored handle
    /// that the reader may retrieve now, under the observation's applied
    /// request, and that no observation has held.
    fn frontier(
        reader: &ScopedRead<'_>,
        observation: &RetrievalLoopObservation,
        explored: &mut HashSet<EntityId>,
    ) -> Result<usize> {
        explored.extend(observation.handles.iter().map(|handle| handle.id));
        reader.retrieval_loop_frontier_size(explored, &observation.narrowing.applied.as_filter())
    }

    /// Run one planner decision per observation. The planner gets the seed,
    /// every score gap, and every clamp hint before choosing the next verb.
    /// The host chooses the turn allowance; exhaustion yields resumable work,
    /// never an implicit Stop or an unsupported answer. Model usage is charged
    /// by the host's normal LlmBackend/lease door, not estimated per iteration.
    pub async fn run_with<F, Fut>(
        &mut self,
        turn_allowance: u32,
        mut planner: F,
    ) -> Result<&RetrievalLoopObservation>
    where
        F: FnMut(RetrievalLoopObservation) -> Fut,
        Fut: Future<Output = Result<RetrievalLoopAction>>,
    {
        for remaining in (0..turn_allowance).rev() {
            if matches!(
                self.observation.status,
                RetrievalLoopStatus::Stopped | RetrievalLoopStatus::Abstained
            ) {
                return Ok(&self.observation);
            }
            self.observation.state.budget_remaining =
                remaining.saturating_add(1).min(u32::from(u8::MAX)) as u8;
            let action = planner(self.observation.clone()).await?;
            self.step(action)?;
            self.observation.state.budget_remaining = remaining.min(u32::from(u8::MAX)) as u8;
        }
        if self.observation.status == RetrievalLoopStatus::Running {
            self.observation.status = RetrievalLoopStatus::Yielded;
        }
        Ok(&self.observation)
    }

    fn search(
        &self,
        plan: &PipelineBuilder<'r>,
        requested: &RetrievalFilter,
    ) -> Result<LoopSearch> {
        self.reader.retrieval_loop_search(
            plan.clone().retrieval_state(self.observation.state.clone()),
            plan.candidate_filter,
            Some(requested),
        )
    }
}

pub(crate) struct LoopSearch {
    pub(crate) handles: Vec<RetrievalHandle>,
    pub(crate) receipt: crate::claim::ScopedReadReceipt,
    pub(crate) quality: crate::retrieval_quality::RetrievalQualityReport,
}

fn release_page(
    reader: &ScopedRead<'_>,
    ranked: &[RetrievalHandle],
    offset: usize,
    page_size: usize,
    requested: &RetrievalFilter,
) -> Result<(usize, crate::claim::ScopedReadResult<Vec<RetrievalHandle>>)> {
    let end = offset.saturating_add(page_size).min(ranked.len());
    let released = reader.retrieval_loop_refresh(&ranked[offset..end], requested)?;
    // Advance over the raw slice, not just surviving handles, so a withheld row
    // cannot repeat the same page forever. Every released row was re-admitted.
    Ok((end, released))
}

fn update_page_metadata(
    observation: &mut RetrievalLoopObservation,
    ranked: &[RetrievalHandle],
    page_offset: usize,
    requested_limit: usize,
    page_size: usize,
) {
    observation.requested_limit = requested_limit;
    observation.effective_page_size = page_size;
    observation.limit_clamped = requested_limit > page_size;
    observation.next_cursor = (page_offset < ranked.len()).then_some(page_offset as u64);
    observation.end = page_offset >= ranked.len();
}

fn known_handles(current: &[RetrievalHandle], ids: &[EntityId]) -> Result<Vec<RetrievalHandle>> {
    let mut seen = HashSet::new();
    ids.iter()
        .filter(|id| seen.insert(**id))
        .map(|id| {
            current
                .iter()
                .find(|handle| handle.id == *id)
                .cloned()
                .ok_or_else(|| {
                    Error::InvalidConfig(
                        "retrieval action requires a current readable handle".into(),
                    )
                })
        })
        .collect()
}

pub(crate) fn point_read(handle: &RetrievalHandle) -> PointRead<'static> {
    PointRead::id(handle.id).at(handle.revision.map_or(ReadMode::Live, ReadMode::Pinned))
}

fn widen_temporal(plan: &mut PipelineBuilder<'_>, start: u64, end: u64, sigma: u64) -> Result<()> {
    let temporal = plan.temporal_search.as_ref().ok_or_else(|| {
        Error::InvalidConfig("temporal widening requires a configured time window".into())
    })?;
    let (old_start, old_end) = plan
        .occurred_range
        .unwrap_or((temporal.anchor_start, temporal.anchor_end));
    if start > old_start || end < old_end || start > end || sigma < temporal.sigma_secs {
        return Err(Error::InvalidConfig(
            "temporal widening must contain the previous window and sigma".into(),
        ));
    }
    let temporal = plan.temporal_search.as_mut().expect("time window checked");
    temporal.anchor_start = start;
    temporal.anchor_end = end;
    temporal.sigma_secs = sigma;
    temporal.query_occurred_range = Some((start, end));
    plan.occurred_range = Some((start, end));
    Ok(())
}

/// Publishes `observation`'s state: its novelty against every handle the
/// loop `explored` before it (FIX 7797), and the `frontier` count.
fn update_state(
    observation: &mut RetrievalLoopObservation,
    explored: &HashSet<EntityId>,
    frontier: usize,
    hops: u8,
) {
    let scores: Vec<_> = observation
        .handles
        .iter()
        .enumerate()
        .map(|(rank, handle)| RetrievalScoreBreakdown {
            result_id: *handle.id.as_bytes(),
            final_rank: rank as u32,
            final_score: handle.score,
            components: Vec::new(),
            access_factor: None,
        })
        .collect();
    let old = &observation.state;
    let mut state = RetrievalState::one_shot(&scores);
    state.iteration = observation.iteration.min(u32::from(u8::MAX)) as u8;
    state.budget_remaining = old.budget_remaining;
    state.intent_class = old.intent_class;
    state.hops = hops;
    state.last_action = observation
        .action
        .as_ref()
        .map_or(0, RetrievalLoopAction::state_tag);
    state.frontier_size = frontier.min(u32::MAX as usize) as u32;
    state.novelty_vs_prior = if observation.handles.is_empty() {
        0.0
    } else {
        observation
            .handles
            .iter()
            .filter(|handle| !explored.contains(&handle.id))
            .count() as f32
            / observation.handles.len() as f32
    };
    observation.state = state;
}
