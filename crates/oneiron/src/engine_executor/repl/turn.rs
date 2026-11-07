//! One model turn of the durable REPL: its hooks, its request, and the
//! program the model's reply heals to, recorded beside its step.
//! Entry: `EngineNativeExecutor::generate_step_program`.
//! The step that runs the program and its commit stay in `repl`.

use super::*;
use crate::code_run::ExecutorWireRepairs;

/// The program one step runs, with what its commit keeps of the model turn
/// that wrote it.
pub(super) struct StepProgram<'m> {
    /// The canonical hash of the model request the program answers.
    pub(super) request_hash: [u8; 32],
    /// The healed program, recorded at the step's script path.
    pub(super) script: String,
    /// The reply's ONE-1686 implicit-speak payload.
    pub(super) trailing_speak: Option<String>,
    /// The repairs the ONE-1929 normalization made to the reply. A step its
    /// deadline parks keeps them on its pending step (FIX 7703).
    pub(super) repairs: ExecutorWireRepairs,
    /// The reply's correction record (FIX 4411). It commits with the step's
    /// checkpoint, on every path that commits one, and the reply's heal
    /// tally moves in that commit, once.
    pub(super) correction: CodeRunCorrectionDraft<'m>,
}

/// How one model turn ended: with the program its step runs, or with the
/// status that ends the entry before any program exists.
pub(super) enum TurnProgram<'m> {
    Generated(StepProgram<'m>),
    Ended(EngineExecutorStatus),
}

impl EngineNativeExecutor<'_> {
    /// The model turn of step `completed_steps`: its turn hooks, its request
    /// and compaction feed, the model's reply recorded as evidence, and the
    /// program healed out of it recorded at the step's script path. A turn
    /// hook's ask that stays pending, or a full window, ends the entry with
    /// its status instead.
    pub(super) async fn generate_step_program<'c>(
        &mut self,
        config: &'c EngineExecutorConfig,
        record: &mut CodeRunReplayRecord,
        wire_prompt: &str,
        prompt_fingerprint: &str,
        continuation: Option<&ContinuationNote>,
        completed_steps: u64,
    ) -> EngineExecutorResult<TurnProgram<'c>> {
        self.land_finished_compaction()?;
        // A turn hook's ask parks the run before the turn, as a call's
        // ask parks the call; a skip or a hidden result ends the entry.
        let turn = match self.pre_turn_hooks(config, completed_steps)? {
            Ok(turn) => turn,
            Err(stop) => {
                let Some(wait) = turn_hook_wait(&stop) else {
                    return Err(Error::from(stop).into());
                };
                let key = wait_key(record, &wait);
                if !self.storage.park_wait(&key)? {
                    return Ok(TurnProgram::Ended(EngineExecutorStatus::Waiting(wait)));
                }
                // The ask settled before the park: the turn's hooks take
                // its answer now, and any stop then ends the entry.
                self.storage.clear_wait(&key)?;
                self.pre_turn_hooks(config, completed_steps)?
                    .map_err(Error::from)?
            }
        };
        let (mut request, mut console) =
            self.build_llm_request(config, record, wire_prompt, continuation)?;
        match self.feed_compaction(config, record, &request)? {
            Ok(Some(reason)) => {
                return Ok(TurnProgram::Ended(EngineExecutorStatus::WindowFull {
                    next_step_seq: completed_steps,
                    reason,
                }));
            }
            Ok(None) => {}
            Err(stop) => {
                let Some(wait) = turn_hook_wait(&stop) else {
                    return Err(Error::from(stop).into());
                };
                let key = wait_key(record, &wait);
                if !self.storage.park_wait(&key)? {
                    return Ok(TurnProgram::Ended(EngineExecutorStatus::Waiting(wait)));
                }
                // The ask settled before the park: retry the same sealed
                // invocation once, with its fold marks still pending.
                self.storage.clear_wait(&key)?;
                match self.feed_compaction(config, record, &request)? {
                    Ok(Some(reason)) => {
                        return Ok(TurnProgram::Ended(EngineExecutorStatus::WindowFull {
                            next_step_seq: completed_steps,
                            reason,
                        }));
                    }
                    Ok(None) => {}
                    Err(stop) => return Err(Error::from(stop).into()),
                }
            }
        }
        // FIX 17594 (map §2.2): folds by kind the feed landed after this
        // request was built are a brief boundary. With a brief port bound,
        // the request is built and counted again before it is hashed,
        // captured or sent, with the console slot it carries (FIX 3608).
        let refreshed = self.refresh_brief_request(&mut request, completed_steps, |this| {
            let (rebuilt, slot) =
                this.build_llm_request(config, record, wire_prompt, continuation)?;
            console = slot;
            Ok(rebuilt)
        })?;
        if let Some(status) = refreshed {
            return Ok(TurnProgram::Ended(status));
        }
        // Rule 5 (FIX 4197): the first step past the `[limits]
        // executor_run_steps` row asks whether everything is okay, once
        // per run however often it re-enters, and the run keeps going.
        let steps = self.storage.limit_watch();
        if completed_steps == steps.bound(EngineLimit::ExecutorRunSteps) {
            steps.measure(EngineLimit::ExecutorRunSteps, completed_steps + 1);
        }
        let request_hash = request.canonical_hash()?;
        self.capture_step_start(
            config,
            completed_steps,
            &request,
            console,
            record,
            prompt_fingerprint,
        );
        let response = {
            let sources = self.step_source_rows(config, record);
            let _generating = self.gated_write.activity_generating();
            self.backend
                .generate_sourced(request, self.lease, sources)
                .await
        }?;
        // FIX 17594 (Engine call C): the backend answered a request that
        // carried the run's brief, so the host's prefix is delivered.
        self.brief_delivered();
        let execution_text = self.post_turn_hooks(turn, &response)?;
        // Only the post-hook execution view is healed below, as its text:
        // no copy of the reply is made for it (FIX 448). The raw provider
        // response stays separate as evidence (FIX 9840).
        // The provider that answered is the one this turn's program
        // speaks for: each verb call it makes carries the name (OF-560).
        self.gated_write
            .observe_model_provider(response.usage.served_provider());
        // The reply as the provider gave it, kept apart from the program
        // healed out of it: evidence, never executed.
        record_reply_evidence(&self.storage, record, completed_steps, &response.message)?;
        // ONE-1929: the ONE normalization seam. Only `code` is executed,
        // staged, hashed, or replayed; the reply's own console bytes are
        // already gone, and `trailing_speak` belongs to ONE-1686. A reply
        // the seam refuses keeps its correction record before its error
        // returns (FIX 4412).
        let HealedExecutorReply {
            code: script,
            trailing_speak,
            repairs,
        } = self.heal_reply_or_record_rejection(
            config,
            completed_steps,
            &response,
            &execution_text,
        )?;
        // The accepted reply's correction record commits with the step's
        // checkpoint, on every path that commits one (FIX 4411).
        let correction = CodeRunCorrectionDraft::accepted(
            config.run_id,
            completed_steps,
            &config.model,
            repairs,
        );
        record_script_output(
            &self.storage,
            record,
            script_output_path(completed_steps),
            &script,
        )?;
        Ok(TurnProgram::Generated(StepProgram {
            request_hash,
            script,
            trailing_speak,
            repairs,
            correction,
        }))
    }
}
