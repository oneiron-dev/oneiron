//! The native raw read's scoped pipeline and pack arms: pre-rank authority
//! gates plus the caller's own builder configuration, on the composed view.
//! Only the `NativeRawRead` adapter calls these, through its retrieval lane.

use super::*;
use crate::off_record::SessionRetrievalTelemetry;

impl ScopedRead<'_> {
    /// Runs `configure`'s pipeline under this lane's authority on its composed
    /// view, registering retrieval telemetry through `telemetry` when the read
    /// runs inside a live room. Candidates pass the plan gate before ranking
    /// and the lane's recheck before return; text and vector are `configure`
    /// specializations of this one arm.
    pub(in crate::claim::scoped_read) fn native_query(
        &self,
        configure: impl for<'b> Fn(crate::PipelineBuilder<'b>) -> crate::PipelineBuilder<'b>,
        telemetry: Option<&SessionRetrievalTelemetry<'_>>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        // The key's own rows and those its own live Grants add (FIX 7528).
        let SearchPlan {
            filter,
            candidates,
            policy,
        } = self.search_plan(None)?;
        if candidates.deny_all {
            return Ok(ScopedReadResult {
                value: Vec::new(),
                receipt: self.receipt_for(None, &policy, &candidates, 0),
            });
        }
        let excluded = self.request_exclusions(&policy, None)?;
        let admitted = self.plan_gate(&filter, &policy, &excluded, None);
        let mut builder = self
            .vault
            .query()
            .reading(self.store_read())
            .authority_filter(candidates)
            .scoped_note_reader(self.actor_key.clone())
            .filter_candidates(&super::plan_row_decodes)
            .gate_candidates(&admitted);
        if let Some(telemetry) = telemetry {
            builder = builder.in_session(telemetry);
        }
        let results = configure(builder).run_for_pack()?;
        let limit = results.scores.len();
        self.filter_search_results(
            results.scores,
            limit,
            None,
            &filter,
            &policy,
            results.read_suppressed.saturating_add(excluded.count()?),
            &results.revisions,
        )
    }

    /// Runs `configure`'s pack under this lane's authority on its composed
    /// view, registering telemetry through `telemetry` when inside a live
    /// room. Candidates pass the plan gate before ranking; the lane's filter
    /// and instruction projection run before serialization, inside
    /// `run_serialized_scoped`. The same reader also narrows L2 evidence and
    /// private-note/PPR candidate work before assembly.
    pub(in crate::claim::scoped_read) fn native_pack(
        &self,
        configure: impl for<'b> Fn(crate::ContextPackBuilder<'b>) -> crate::ContextPackBuilder<'b>,
        telemetry: Option<&SessionRetrievalTelemetry<'_>>,
    ) -> Result<ScopedReadResult<Vec<u8>>> {
        let SearchPlan {
            filter,
            candidates,
            policy,
        } = self.search_plan(None)?;
        let excluded = self.request_exclusions(&policy, None)?;
        let admitted = self.plan_gate(&filter, &policy, &excluded, None);
        let mut builder = self
            .vault
            .context_pack()
            .reading(self.store_read())
            .l2_summary_reader(self)
            .scoped_note_reader(self.actor_key.clone())
            .authority_filter(candidates)
            .filter_candidates(&super::plan_row_decodes)
            .gate_candidates(&admitted);
        if let Some(telemetry) = telemetry {
            builder = builder.in_session(telemetry);
        }
        configure(builder).run_serialized_scoped(self)
    }
}
