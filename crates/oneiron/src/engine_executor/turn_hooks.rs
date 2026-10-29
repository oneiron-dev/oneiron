//! `host.turn.generate` (ARCH-0080 §5) around the executor's model call. The
//! pre chain runs before a step's request is built, so a block a hook adds
//! lands this turn; the post chain runs once the model answered, and a block
//! it adds lands the next turn. A run bound to an off-record session runs its
//! turns' hooks in its room, on the route the run captured (FIX 5563): the
//! room keeps their records, never the vault, a hook's ask pauses the turn
//! in RAM as a room's call does (FIX 5524), and 2c's Room rules hold for
//! what a hook would land.

use serde_json::{Value, json};

use super::driver::EngineNativeExecutor;
use super::types::{EngineExecutorConfig, EngineExecutorResult};
use crate::code_run::ExecutorStorage;
use crate::runtime_hooks::verb::RoomHookCall;
use crate::runtime_hooks::{InvocationId, VerbCall, VerbDomain, VerbHookPre, VerbHookStop};
use crate::skill_hub::pack_catalog::HookActorClass;
use crate::{ContentPart, LlmResponse};

/// The host verb a turn's model call runs under.
const HOST_TURN_GENERATE: &str = "host.turn.generate";

/// A turn past its pre chain, as its post chain picks it up, by the storage
/// that owns the chain: its post chain runs in the same one.
pub(super) enum TurnHooks {
    /// The vault's, for a canonical run.
    Vault(VerbHookPre),
    /// The run's room's, on the route it captured (FIX 5563).
    Room(VerbHookPre),
}

impl EngineNativeExecutor<'_> {
    /// Runs the pre chain of `host.turn.generate` for step `step_seq`, before
    /// the step's request is built. `Err(stop)` when a hook skipped the turn,
    /// or asked first: the turn ends there, with the stop's reason. A run
    /// bound to an off-record session runs it in its room; a turn there
    /// whose hooks cannot be read runs without them, as it did before they
    /// ran in a room.
    ///
    /// # Errors
    ///
    /// Storage errors as they occur; in a room, its authority refusals.
    pub(super) fn pre_turn_hooks(
        &self,
        config: &EngineExecutorConfig,
        step_seq: u64,
    ) -> EngineExecutorResult<Result<TurnHooks, VerbHookStop>> {
        // A run sits in no room turn and freezes no board epoch.
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
            // The run's verified credential-bound key, independent of the
            // host's System write attribution (FIX 9841).
            reader: Some(self.gated_write.host_turn_read_key()),
        };
        let check = |rewritten: &Value| host_args_kept(&args, rewritten);
        Ok(match &self.storage {
            ExecutorStorage::Canonical(vault) => vault
                .pre_verb_hooks(call, args.clone(), &check)?
                .map(TurnHooks::Vault),
            ExecutorStorage::Session(binding) => {
                let how = RoomHookCall {
                    answers_unread: true,
                    ..RoomHookCall::default()
                };
                let (pre, _) = binding.session.pre_verb_hooks_in_room(
                    &binding.route,
                    call,
                    args.clone(),
                    &check,
                    how,
                )?;
                pre.map(TurnHooks::Room)
            }
        })
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
    ) -> EngineExecutorResult<String> {
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
            "text": text.as_str(),
            "finish_reason": response.finish_reason,
            "usage": response.usage,
        });
        let view = match (turn, &self.storage) {
            (TurnHooks::Vault(pre), ExecutorStorage::Canonical(vault)) => {
                vault.post_verb_hooks(pre, result)?
            }
            (TurnHooks::Room(pre), ExecutorStorage::Session(binding)) => {
                let session = &binding.session;
                let (view, _) =
                    session.post_verb_hooks_in_room(&binding.route, pre, result, true)?;
                view
            }
            // A turn's storage is its run's, which never changes mid-run.
            (TurnHooks::Vault(_) | TurnHooks::Room(_), _) => return Ok(text),
        };
        // A post-hook stop keeps today's original-response behavior. A
        // successful view, including a null or empty redaction, is the only
        // text the executor may heal and run (FIX 9840).
        Ok(match view {
            Ok(view) => view
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            Err(_) => text,
        })
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
