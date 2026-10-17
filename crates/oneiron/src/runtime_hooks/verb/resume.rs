//! Settlement resumes a stopped call once (ARCH-0080 §3 Ask). The settling
//! write only marks the saved call ready. The hook runner's pass then calls
//! the row again through the generated dispatcher, outside any write and at
//! hook depth 0, so the row boundary runs the pre chain, finds the settled
//! proceed and resumes after the asking hook. The saved args are checked
//! again and the verb's own gate runs as on any call. What the call returned
//! waits in the saved row for the caller's retry.
//!
//! Only a call the drain can make as its caller made it has a target: a
//! memory row the generated dispatcher runs, for an on-device caller with no
//! credential. Any other call resumes on its caller's retry.

use serde::{Deserialize, Serialize};

use crate::memory::MEMORY_CODE_INTERNAL;
use crate::runtime_hooks::filter;
use crate::session_lifecycle::SessionKey;
use crate::task_verb::TaskAskResult;
use crate::{EntityId, Result, Vault};

use super::{InvocationId, VerbHookStop, ask};

/// How settlement runs a stopped call again without its caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VerbResume {
    /// A memory row the generated dispatcher runs: the caller's sitting and
    /// the room its turn ran in, if any.
    Row {
        session: Option<SessionKey>,
        room: Option<EntityId>,
    },
}

/// The settlement hook: in the settling write, marks the call stopped on
/// ask `group` ready when `result` said proceed and the call has a resume
/// target. Any ask but a verb hook's passes at once. It runs nothing.
pub(crate) fn verb_ask_settled_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    group: EntityId,
    result: &TaskAskResult,
    now: u64,
) -> Result<()> {
    let Some((invocation, binding)) = result
        .settlement
        .requested
        .intent_key
        .strip_prefix("hook.verb/")
        .and_then(|rest| rest.split_once('/'))
    else {
        return Ok(());
    };
    let (Some(invocation), Ok(binding)) = (
        InvocationId::parse_hex(invocation),
        EntityId::from_hex(binding),
    ) else {
        return Ok(());
    };
    ask::settled_in_txn(vault, txn, invocation.0, binding, group, result, now)
}

impl Vault {
    /// Runs each call a settled proceed made ready, once, as its caller: the
    /// caller's actor and class, the invocation, its sitting and, for a room
    /// turn, the room, whose current terms admit the call again or refuse
    /// it. Saves what each returned for the caller's retry. With hooks off
    /// or suppressed it runs nothing: the chain would pass through without
    /// using the answer up. Returns how many calls ran.
    ///
    /// # Errors
    ///
    /// Reading the saved calls. A storage error on one call leaves it ready
    /// for the next pass.
    pub fn drain_verb_asks(&self) -> Result<usize> {
        if self.verb_hook_state.suppressed() || !self.hooks_enabled()? {
            return Ok(0);
        }
        let mut ran = 0;
        for ready in ask::ready(self)? {
            let group = ready.ask.to_hex();
            match self.resume_verb_ask(ready) {
                Ok(true) => ran += 1,
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(%error, ask = %group, "a settled verb hook ask waits for the next pass");
                }
            }
        }
        Ok(ran)
    }

    /// Calls one ready row again and saves its outcome; false when it did
    /// not run.
    fn resume_verb_ask(&self, ready: ask::Ready) -> Result<bool> {
        let ask::Ready {
            key,
            verb,
            actor,
            class,
            args,
            resume,
            ask: group,
        } = ready;
        let Ok(args) = serde_json::from_str(&args) else {
            ask::unready(self, key, group)?;
            return Ok(false);
        };
        let VerbResume::Row { session, room } = resume;
        let mut memory = self
            .memory(actor, filter::edge_class(class))
            .with_invocation(InvocationId(key));
        if let Some(session) = session {
            memory = memory.with_session(session);
        }
        let ran = match room {
            Some(room) => memory
                .for_room_turn(room)
                .and_then(|turn| turn.invoke(&verb, args)),
            None => crate::task_verb::sdk::invoke(&memory, &verb, args),
        };
        let (outcome, transient) = match ran {
            Ok(value) => (
                ask::SavedOutcome::Ok {
                    result: serde_json::to_string(&value).map_err(|_| {
                        crate::Error::InvariantViolation("verb hook ask outcome encode")
                    })?,
                },
                false,
            ),
            Err(error) => match error.hook.as_deref() {
                // A later hook asked: its own ask now stands under the key,
                // or this one no longer reads as settled.
                Some(VerbHookStop::Pending { .. }) => {
                    ask::unready(self, key, group)?;
                    return Ok(false);
                }
                // A caller's retry resumed it first and got its answer.
                Some(stop) if ask::is_used(stop) => return Ok(false),
                hook => {
                    let transient = hook.is_none() && error.code == MEMORY_CODE_INTERNAL;
                    (
                        ask::SavedOutcome::Err {
                            code: error.code,
                            message: error.message,
                        },
                        transient,
                    )
                }
            },
        };
        ask::finish(self, key, group, outcome, transient)?;
        Ok(!transient)
    }
}
