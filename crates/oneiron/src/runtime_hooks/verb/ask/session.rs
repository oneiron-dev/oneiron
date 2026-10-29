//! A session-only call's hook ask (L13 PR-D, FIX 4283, FIX 5383; Engine
//! 10-19 16:1x ruling (a), 17:3x). A call that keeps no record, with no room
//! overlay, runs its hooks as any call does, and a hook asks as on any call:
//! its author opens the ask through the tasks.ask door, on the task-work turn
//! the calling operation holds, and the caller gets Pending. Only the paused
//! call stays out of the vault: its args, the hook's place and the ask handle
//! wait in the in-memory keep under the call's session key
//! (`SessionHookKeep`), never in the vault's saved asks, and the ask's intent
//! key names the invocation's hidden id, never the invocation. Settlement's
//! drain finds no saved call under that id, so it never runs one. Only the
//! caller's retry under the same key, in this process, resumes the call, and
//! its chain's commit uses the answer up in the keep, once, before the verb
//! runs. The pause goes with its session: a resume that names a pause the
//! keep no longer holds refuses ([`SESSION_PAUSE_GONE`]), never running as a
//! new call. A hook in an off-record room asks the same way (FIX 5524): its
//! pause waits under the room's stretch, with the route its run captured,
//! and a resume runs only once that route, the route the call runs on now
//! and the run's place on the room's roster all hold again.

use std::sync::Arc;

use serde_json::Value;

use crate::error::OffRecordError;
use crate::skill_hub::pack_catalog::PackHookBinding;
use crate::task_verb::{
    ConsultPayloadRef, TaskAskDefault, TaskAskHandle, TaskAskOptionId, TaskAskQuestion,
    TaskAskSettlementReason, TaskAskSpec, TaskAskStatus,
};
use crate::work_line::TaskWorkTurn;
use crate::{EntityId, Error, MemoryError, Result, Vault};

use super::super::storage::{PausedRoute, SessionHookKey, SessionHooks, SessionVerbAsk};
use super::super::{InvocationId, VerbCall, VerbHookStop};
use super::{
    AskToken, HOLD, PROCEED, Retry, USED, VERB_HOOK_INTENT, author_memory, cut, pending, proceeds,
};

/// What a session-only call's hook ask tells whoever answers it, after the
/// hook's own words.
const SESSION_ASK_NOTE: &str = "This call is off the record: an answer runs it only on its \
     caller's retry while its session lasts on this server. After the session ends or the server \
     restarts, the answer runs nothing.";

/// Why a resume of a session-only call's hook pause refuses once the keep no
/// longer holds it (CALLS: FIX 4283 restart refusal text).
const SESSION_PAUSE_GONE: &str = "This hook pause was off the record and lived only in \
     its session on this server. That session ended or the server restarted; it cannot be \
     resumed. Start a new call.";

/// Whether a recorded call's retry that names its ask after the drain's pass
/// forgot the call it saved (`ask::prune`, past `VERB_ASK_KEEP`) runs as a
/// new call, as it did before the thin client named the ask on every retry
/// (FIX 5693): true keeps that path, false refuses it as a gone pause. A
/// session-only call's pause that is gone refuses either way.
const PRUNED_RECORDED_ASK_RUNS_NEW: bool = true;

/// What the hook receipts of a recorded call run as new that way say (FIX
/// 5693; Engine 10-20): its own text, never the off-record one. Its hooks
/// run again, so an asking hook asks again; the earlier approval is never
/// replayed.
pub(in crate::runtime_hooks::verb) const PRUNED_RECORDED_ASK_NOTE: &str =
    "The earlier approval expired, so this ran as a new call.";

/// The stop a resume of a gone pause ends with; `hook` names the asking hook
/// when the keep still knows it.
fn gone(hook: &str) -> VerbHookStop {
    VerbHookStop::Skipped {
        hook: hook.to_owned(),
        reason: SESSION_PAUSE_GONE.to_owned(),
    }
}

/// Reads the call a previous try of this invocation paused under `key`, as
/// [`super::retry`] reads a saved one: still open, the same Pending; answered
/// proceed, the call resumes after the asking hook, and its commit uses the
/// answer up in the keep ([`take`]); declined or expired, Skipped. A call
/// that names the pause it resumes (`hooks`' resume) and finds no such pause
/// refuses with [`SESSION_PAUSE_GONE`]; one that names none and finds none is
/// a new call. A pause another call under `key` took is that call's: one
/// that names it takes its own path, as if it named none. The ask is read
/// on `turn`, the calling operation's task-work turn.
pub(in crate::runtime_hooks::verb) fn retry(
    vault: &Vault,
    hooks: &SessionHooks<'_>,
    key: &SessionHookKey,
    call: &VerbCall,
    turn: Option<&Arc<TaskWorkTurn>>,
) -> Result<Retry> {
    let invocation = call.invocation.0;
    let keep = &vault.verb_hook_state.session;
    // A pause another call of the same request took is that call's to
    // resume (FIX 5526): this one takes its own path.
    let named = hooks
        .resumed_ask()
        .filter(|ask| !keep.paused_elsewhere(key, invocation, *ask));
    let row = match (keep.ask(key, invocation), named) {
        (Some(row), Some(ask)) if row.ask != ask => return Ok(Retry::Stop(gone(&row.hook))),
        (Some(row), _) => row,
        (None, Some(_)) => return Ok(Retry::Stop(gone(""))),
        (None, None) => return Ok(Retry::Fresh),
    };
    let skipped = |reason: &str| -> Result<Retry> {
        Ok(Retry::Stop(VerbHookStop::Skipped {
            hook: row.hook.clone(),
            reason: reason.to_owned(),
        }))
    };
    if row.verb != call.verb || row.actor != call.actor || row.class != call.class {
        return skipped("this invocation belongs to another call");
    }
    if row.used {
        return skipped(USED);
    }
    let status = author_memory(vault, row.author, row.author_class, turn)
        .tasks_ask_status(TaskAskHandle { group_ref: row.ask });
    let result = match status {
        Ok(TaskAskStatus::Pending { .. } | TaskAskStatus::Changed { .. }) => {
            return Ok(Retry::Stop(pending(call.invocation, row.ask)));
        }
        Ok(TaskAskStatus::Settled(result)) => result,
        Ok(TaskAskStatus::WorldPrivacy(_)) => return skipped("the hook's ask is no ask group"),
        Err(error) => return skipped(&format!("the hook's ask is unreadable: {}", error.message)),
    };
    if !proceeds(&result) {
        return skipped(match result.settlement.reason {
            TaskAskSettlementReason::Deadline | TaskAskSettlementReason::Stale => {
                "the hook's ask expired"
            }
            TaskAskSettlementReason::FirstWord | TaskAskSettlementReason::AllResponded => {
                "the hook's ask was declined"
            }
        });
    }
    // A room's call resumes only where its pause was taken (FIX 5524).
    hooks.readmit(row.route.as_ref())?;
    Ok(Retry::Resume {
        binding: row.binding,
        position: row.position,
        args: row.args,
        token: AskToken {
            key: invocation,
            ask: row.ask,
            hook: row.hook,
        },
    })
}

/// Opens the asking hook's ask as its author, on `turn`, as [`super::open`]
/// does, and keeps the paused call under `key`, in the ask's own write: its
/// args, the hook's place and the ask handle. `write` puts the chain's own
/// vault rows (its hooks' blocks and intents) in that write first, and again
/// on its own when the ask stood from an earlier try. The ask's intent key names the
/// invocation's hidden id (`SessionHookKeep::hidden_invocation`), so
/// settlement finds no saved call and runs nothing, and the vault keeps no
/// way to run the call again. A session that ended meanwhile opens no ask.
/// A room's pause keeps `route`, the route its run captured (FIX 5524).
/// The ask's group, or `Err(reason)` when the ask door refused or the
/// session ended: nothing was kept.
#[expect(
    clippy::too_many_arguments,
    reason = "the call, its key, the hook, its place, the args, the label, the call's turn, a room's route and the chain's write"
)]
pub(in crate::runtime_hooks::verb) fn open(
    vault: &Vault,
    key: &SessionHookKey,
    call: &VerbCall,
    hook: (EntityId, &PackHookBinding),
    position: usize,
    args: &Value,
    label: &str,
    turn: Option<&Arc<TaskWorkTurn>>,
    route: Option<PausedRoute>,
    write: &dyn Fn(&mut heed::RwTxn<'_>) -> Result<()>,
) -> Result<std::result::Result<EntityId, String>> {
    let (binding_id, binding) = hook;
    let keep = &vault.verb_hook_state.session;
    let mut what = TaskAskQuestion::new(ConsultPayloadRef::Claim(binding_id));
    what.label = Some(format!("{label} {SESSION_ASK_NOTE}"));
    for (option, text) in [
        (PROCEED, format!("Run {}", cut(&call.verb, 200))),
        (HOLD, "Do not run it".to_owned()),
    ] {
        let option = TaskAskOptionId::new(option)
            .map_err(|_| Error::InvariantViolation("verb hook ask option"))?;
        what.options.insert(option, text);
    }
    let mut spec = TaskAskSpec::shorthand(None, what, None, TaskAskDefault::Hold);
    let hidden = InvocationId(keep.hidden_invocation(key, call.invocation.0));
    spec.intent_key = format!(
        "{VERB_HOOK_INTENT}{}/{}",
        hidden.to_hex(),
        binding_id.to_hex()
    );
    let parts = match author_memory(vault, binding.author_id(), binding.author_class(), turn)
        .session_ask_parts(&spec)
    {
        Ok(parts) => parts,
        Err(error) => return Ok(Err(format!("{}: {}", error.code, error.message))),
    };
    let group = parts.group_ref;
    let paused = SessionVerbAsk {
        verb: call.verb.clone(),
        actor: call.actor,
        class: call.class,
        args: args.clone(),
        position,
        binding: binding_id,
        hook: format!("{}/{}", binding.pack, binding.hook),
        author: binding.author_id(),
        author_class: binding.author_class(),
        ask: group,
        used: false,
        route: route.clone(),
    };
    let Some((_receipt, idempotent, pause_existed)) = keep.open_ask(
        vault,
        key,
        parts,
        paused,
        call.invocation.0,
        vault.store.clock.now_recorded_at(),
    ) else {
        return Ok(Err(ended(key).to_string()));
    };
    if let Err(error) = vault.with_write_txn_grouped(write) {
        keep.discard_ask(key, group, call.invocation.0, idempotent, pause_existed);
        return Err(error);
    }
    Ok(Ok(group))
}

/// Uses the answer `token` names up under `key`, in the resumed chain's
/// commit, before the verb runs: false when the keep holds no unused pause
/// of that ask there.
pub(in crate::runtime_hooks::verb) fn take(
    vault: &Vault,
    key: &SessionHookKey,
    token: &AskToken,
) -> bool {
    vault
        .verb_hook_state
        .session
        .use_ask(vault, key, token.key, token.ask)
}

/// Forgets the session-only pauses `cutoff` (vault-clock seconds) left
/// behind, on the saved calls' own horizon (FIX 5528): used ones used
/// before it, and unused ones paused before it whose ask settled without a
/// proceed, read as its author with no task-work turn, as [`super::prune`]
/// reads an open saved call. Pending and approved-but-unused pauses stay.
/// Returns how many it forgot.
pub(in crate::runtime_hooks::verb) fn prune(vault: &Vault, cutoff: u64) -> usize {
    vault.verb_hook_state.session.prune(cutoff, |row| {
        let status = author_memory(vault, row.author, row.author_class, None)
            .tasks_ask_status(TaskAskHandle { group_ref: row.ask });
        matches!(status, Ok(TaskAskStatus::Settled(result)) if !proceeds(&result))
    })
}

/// The refusal a pause meets once its session closed.
fn ended(key: &SessionHookKey) -> Error {
    Error::OffRecord(OffRecordError::OffRecordSessionClosing {
        session_ref: match key {
            SessionHookKey::Session { key, .. } => key.clone(),
            SessionHookKey::Process => String::new(),
        },
    })
}

impl Vault {
    /// The stop of a call that names `ask`, a hook pause it resumes under
    /// `invocation`, but runs as a call that keeps its record now (L13 PR-D,
    /// FIX 4283): when the vault holds no call paused under `invocation`,
    /// the pause was a session-only call's whose session ended or whose
    /// server restarted, and it refuses with [`SESSION_PAUSE_GONE`] rather
    /// than run as a new call. `None` when the vault holds one: its own
    /// retry reads it. `None` too, while [`PRUNED_RECORDED_ASK_RUNS_NEW`]
    /// holds, when `ask` was this recorded call's own, whose saved call the
    /// drain's pass forgot (FIX 5693): the call runs as new, and its chain's
    /// receipts carry [`PRUNED_RECORDED_ASK_NOTE`].
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn gone_hook_pause(
        &self,
        invocation: InvocationId,
        ask: EntityId,
    ) -> Result<Option<VerbHookStop>> {
        if super::saved(self, invocation)? {
            return Ok(None);
        }
        if PRUNED_RECORDED_ASK_RUNS_NEW && recorded_ask(self, invocation, ask)? {
            self.verb_hook_state.note_expired(invocation);
            return Ok(None);
        }
        Ok(Some(gone("")))
    }
}

/// Whether `ask` is the settled ask a recorded call's hook opened under
/// `invocation`: its intent key names that invocation itself. A
/// session-only call's ask names its hidden id instead
/// (`SessionHookKeep::hidden_invocation`), never the caller's.
fn recorded_ask(vault: &Vault, invocation: InvocationId, ask: EntityId) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(result) = crate::task_verb::ask_settlement_in(vault, &rtxn, ask)? else {
        return Ok(false);
    };
    Ok(result
        .settlement
        .requested
        .intent_key
        .strip_prefix(VERB_HOOK_INTENT)
        .and_then(|rest| rest.split_once('/'))
        .and_then(|(named, _)| InvocationId::parse_hex(named))
        == Some(invocation))
}
