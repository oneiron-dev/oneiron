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
//! credential, or a credential caller's row its host can run again through
//! the door it came in by, under the credential as it stands then
//! ([`super::credential`]). Any other call resumes on its caller's retry.
//!
//! While the drain runs a call, the call's invocation is held for it, so a
//! retry in this process waits Pending rather than running the verb too. Each
//! pass also deletes the rows [`VERB_ASK_KEEP`] outlived.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::memory::MEMORY_CODE_INTERNAL;
use crate::runtime_hooks::filter;
use crate::session_lifecycle::SessionKey;
use crate::task_verb::TaskAskResult;
use crate::{EntityId, Result, Vault};

use super::credential::{RefusalReceipt, VerbAskCredentialRef, VerbAskResumed};
use super::state::DrainScope;
use super::{InvocationId, VerbHookStop, ask, credential};

/// How long a stopped call's row stays once its answer is used, or once its
/// ask settled without a proceed: a retry within it still gets what the call
/// returned. After it, the invocation reads as new.
const VERB_ASK_KEEP: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// The most rows one drain pass deletes.
const VERB_ASK_PRUNE_MAX: usize = 256;

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
    /// A credential caller's row, run again through the door it came in by,
    /// once the host's check verified the credential again.
    Credential { reference: VerbAskCredentialRef },
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
    /// it. A credential caller's call runs through its host's check, under
    /// the credential as it stands then; a refusal ends it, with one
    /// receipt. Saves what each returned for the caller's retry. A call whose
    /// retry is in flight is left to that retry. With hooks off or suppressed
    /// it runs nothing: the chain would pass through without using the
    /// answer up. Then deletes old rows. Returns how many calls ran.
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
        let cutoff = self
            .store
            .clock
            .now_recorded_at()
            .saturating_sub(VERB_ASK_KEEP.as_secs());
        if let Err(error) = ask::prune(self, cutoff, VERB_ASK_PRUNE_MAX) {
            tracing::warn!(%error, "old verb hook asks wait for the next pass");
        }
        Ok(ran)
    }

    /// Calls one ready row again and saves its outcome; false when it did
    /// not run. The invocation is held from before the call until its
    /// outcome is saved, and the row is marked running meanwhile.
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
        let invocation = InvocationId(key);
        let Ok(args) = serde_json::from_str(&args) else {
            ask::unready(self, key, group)?;
            return Ok(false);
        };
        // A retry of the call in flight now resumes it itself.
        let Some(_held) = self
            .verb_hook_state
            .hold_for_drain(invocation, actor, group)
        else {
            return Ok(false);
        };
        if !ask::mark_running(self, key, group)? {
            return Ok(false);
        }
        let mut receipt = None;
        let ran = match resume {
            VerbResume::Row { session, room } => {
                let mut memory = self
                    .memory(actor, filter::edge_class(class))
                    .with_invocation(invocation);
                if let Some(session) = session {
                    memory = memory.with_session(session);
                }
                let _draining = DrainScope::enter(invocation);
                match room {
                    Some(room) => memory
                        .for_room_turn(room)
                        .and_then(|turn| turn.invoke(&verb, args)),
                    None => crate::task_verb::sdk::invoke(&memory, &verb, args),
                }
            }
            VerbResume::Credential { reference } => {
                let class = filter::edge_class(class);
                receipt = Some(RefusalReceipt::new(&reference, &verb, actor, class, &args));
                let resumed =
                    credential::resume(self, key, group, verb, actor, class, args, reference)?;
                match resumed {
                    VerbAskResumed::Ran(ran) => ran,
                    VerbAskResumed::Refused(refusal) => Err(refusal.error()),
                }
            }
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
                Some(stop) if ask::is_used(stop) => {
                    ask::idle(self, key, group)?;
                    return Ok(false);
                }
                hook => {
                    let transient = hook.is_none() && error.code == MEMORY_CODE_INTERNAL;
                    (
                        ask::SavedOutcome::Err {
                            code: error.code,
                            message: error.message,
                            receipt: None,
                        },
                        transient,
                    )
                }
            },
        };
        // A credential call that ends refused or failed leaves one receipt,
        // committed with its outcome.
        let receipt = match (receipt, &outcome) {
            (Some(receipt), ask::SavedOutcome::Err { code, message, .. }) if !transient => {
                Some(receipt.refused(code, message))
            }
            _ => None,
        };
        ask::finish(self, key, group, outcome, transient, receipt)?;
        Ok(!transient)
    }
}
