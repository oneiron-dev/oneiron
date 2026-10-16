//! `host.turn.generate` (ARCH-0080 §5) around the executor's model call. The
//! pre chain runs before a step's request is built, so a block a hook adds
//! lands this turn; the post chain runs once the model answered, and a block
//! it adds lands the next turn.

use serde_json::{Value, json};

use super::driver::EngineNativeExecutor;
use super::types::{EngineExecutorConfig, EngineExecutorResult};
use crate::code_run::ExecutorStorage;
use crate::runtime_hooks::{InvocationId, VerbCall, VerbDomain, VerbHookPre, VerbHookStop};
use crate::skill_hub::pack_catalog::HookActorClass;
use crate::{ContentPart, LlmResponse};

/// The host verb a turn's model call runs under.
const HOST_TURN_GENERATE: &str = "host.turn.generate";

/// A turn past its pre chain, as its post chain picks it up. `None` for a run
/// bound to an off-record session: its receipts would land on record.
#[allow(
    dead_code,
    reason = "the REPL loop splices the turn's hooks around its model call (OF-580)"
)]
pub(super) struct TurnHooks(Option<VerbHookPre>);

#[allow(
    dead_code,
    reason = "the REPL loop splices the turn's hooks around its model call (OF-580)"
)]
impl EngineNativeExecutor<'_> {
    /// Runs the pre chain of `host.turn.generate` for step `step_seq`, before
    /// the step's request is built. `Err(stop)` when a hook skipped the turn,
    /// or asked first: the turn ends there, with the stop's reason.
    ///
    /// # Errors
    ///
    /// Storage errors as they occur.
    pub(super) fn pre_turn_hooks(
        &self,
        config: &EngineExecutorConfig,
        step_seq: u64,
    ) -> EngineExecutorResult<Result<TurnHooks, VerbHookStop>> {
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return Ok(Ok(TurnHooks(None)));
        };
        // A canonical run sits in no room and freezes no board epoch.
        let args = json!({"room": Value::Null, "scope": Value::Null, "board_epoch": Value::Null});
        let call = VerbCall {
            verb: HOST_TURN_GENERATE.to_owned(),
            invocation: turn_invocation(config.run_id.as_bytes(), step_seq),
            actor: self.gated_write.actor().entity_ref(),
            // A write a host verb causes stamps the System class.
            class: HookActorClass::System,
            scope: None,
            board_epoch: None,
            domain: VerbDomain::Write,
        };
        let check = |rewritten: &Value| host_args_kept(&args, rewritten);
        Ok(vault
            .pre_verb_hooks(call, args.clone(), &check)?
            .map(|pre| TurnHooks(Some(pre))))
    }

    /// Runs the post chain of `host.turn.generate` over the model's answer.
    /// The turn stands whatever a post-hook says: its stop is the hook's
    /// receipt, not the turn's.
    ///
    /// # Errors
    ///
    /// Storage errors as they occur.
    pub(super) fn post_turn_hooks(
        &self,
        turn: TurnHooks,
        response: &LlmResponse,
    ) -> EngineExecutorResult<()> {
        let (Some(pre), ExecutorStorage::Canonical(vault)) = (turn.0, &self.storage) else {
            return Ok(());
        };
        let text: String = response
            .message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        let result = json!({
            "text": text,
            "finish_reason": response.finish_reason,
            "usage": response.usage,
        });
        let _ = vault.post_verb_hooks(pre, result)?;
        Ok(())
    }
}

/// The invocation of one turn's model call: the same across a replay of the
/// step, and apart from every bridge call's, which counts other positions.
fn turn_invocation(run: &[u8], step_seq: u64) -> InvocationId {
    InvocationId::of_run_step(&[run, HOST_TURN_GENERATE.as_bytes()].concat(), step_seq)
}

/// A host verb's args are the host's: a hook's rewrite of them is refused.
fn host_args_kept(args: &Value, rewritten: &Value) -> Result<(), String> {
    if rewritten == args {
        Ok(())
    } else {
        Err("a host verb's args are the host's".to_owned())
    }
}
