//! The credential-scoped serialized pack terminal: the lane's filter and
//! instruction projection run before serialization, and telemetry finalizes
//! with the terminal serialized ids/stats — never structured-then-serialized.

use super::*;

impl ContextPackBuilder<'_> {
    /// Runs the configured pack, filters it to what `lane` may serve, and
    /// serializes it, finalizing the run row with the serialized terminal.
    /// Mirrors `run_serialized_with_stats` (config capture, serialization,
    /// terminal finalize) around `run_scoped_with_run_status`'s pre-serialize
    /// lane filter: no late filter after run publication.
    pub(crate) fn run_serialized_scoped(
        self,
        lane: &crate::claim::ScopedRead<'_>,
    ) -> Result<crate::claim::ScopedReadResult<Vec<u8>>> {
        let tokenizer = self.tokenizer;
        let config = SerializeConfig {
            format: self.format,
            profile: self.field_profile,
            budget: self.effective_token_budget(),
            allocation: self.token_allocation,
            include_stats: self.include_stats,
            merge_neighbors: self.merge_neighbors,
            max_field_chars: self.max_field_chars,
            max_item_tokens: self.max_item_tokens,
        };
        let disclosure = self.disclosure.clone();
        let run = self
            .for_destination(lane.actor_key().destination())
            .run_unfinalized()?;
        let mut pending = UnfinalizedContextPack {
            value: run.pack,
            telemetry_run_id: run.telemetry_run_id,
            telemetry: run.telemetry,
            total_in_scope: run.total_in_scope,
            clamped: run.clamped,
            replay_config: run.replay_config,
            critical: run.critical,
            world_share: run.world_share,
        };
        if let Err(error) = lane.end_recall_plan() {
            pending.discard_telemetry();
            return Err(error);
        }
        let receipt = match pending.filter_scoped_under(lane, disclosure.as_ref()) {
            Ok(receipt) => receipt,
            Err(error) => {
                pending.discard_telemetry();
                return Err(error);
            }
        };
        // Instruction files name only units this read returns (FIX 9761).
        pending.project_instruction_files_under(lane, disclosure.as_ref())?;
        // Counts exposed refer only to rows admitted by this read.
        pending.value.stats.candidates_considered = pending.value.results.len();
        let (bytes, telemetry) = serialize_pack_with_telemetry(&pending.value, &config, tokenizer);
        let run_id = pending.telemetry_run_id.take();
        let mut replay_config = pending.replay_config.take();
        if let Some(value) = replay_config.as_mut() {
            value["terminal_kind"] = "serialized".into();
        }
        if let Err(error) = finalize_context_pack_telemetry(
            pending.telemetry,
            run_id,
            telemetry.stats.query_time_us,
            pending.total_in_scope,
            telemetry.stats.claims_suppressed,
            &telemetry.result_ids,
            serialized_context_pack_empty_reason(&pending.value, &telemetry),
            replay_config,
        ) {
            discard_failed_context_pack_telemetry(pending.telemetry, run_id);
            return Err(error);
        }
        Ok(crate::claim::ScopedReadResult {
            value: bytes,
            receipt,
        })
    }
}
