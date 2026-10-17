//! A pre-hook's Ask (ARCH-0080 §3 Ask). Before the caller gets Pending, the
//! engine opens the ask through the tasks.ask door, as the hook's author, and
//! saves the stopped call in the same write: its args, the hook's place in the
//! chain, the ask handle and, for a call settlement can run again without its
//! caller, how to. A retry with the same invocation reads the ask: still open,
//! the same Pending; answered proceed, the saved call resumes once after the
//! asking hook, and the chain's own write uses the answer up; declined or
//! expired, Skipped. Once settlement's drain ran the call, a retry gets what it
//! returned. The answer is evidence, never effect authority
//! (`NotEvaluatedByAsk`): the verb's own gate runs on the resumed call.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::side_table::{self, Named, SideTable};
use crate::skill_hub::pack_catalog::{HookActorClass, PackHookBinding};
use crate::task_verb::{
    ConsultPayloadRef, TaskAskDecision, TaskAskDefault, TaskAskHandle, TaskAskOptionId,
    TaskAskQuestion, TaskAskResult, TaskAskSettlementReason, TaskAskSpec, TaskAskStatus,
};
use crate::{EntityId, Error, MemoryError, Result, Vault};

use super::{InvocationId, VerbCall, VerbDomain, VerbHookStop, VerbResume};

/// Calls stopped on a hook's ask, by invocation.
const ASKS: SideTable<[u8; 16], VerbAsk, Named> = SideTable::new(&side_table::HOOKS_VERB_ASK);
/// The answer that lets the verb run.
const PROCEED: &str = "proceed";
const HOLD: &str = "hold";
pub(super) const USED: &str =
    "this invocation's ask was already used; call again with a new invocation";

/// One stopped call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VerbAsk {
    verb: String,
    #[serde(with = "crate::serialize::entity_ref")]
    actor: EntityId,
    class: HookActorClass,
    scope: Option<String>,
    domain: VerbDomain,
    /// The args the asking hook saw, re-validated, as JSON.
    args: String,
    /// The asking hook's place in the pre chain.
    position: u32,
    #[serde(with = "crate::serialize::entity_ref")]
    binding: EntityId,
    /// `<pack>/<hook>`.
    hook: String,
    /// The hook's author, who asked and reads the answer.
    #[serde(with = "crate::serialize::entity_ref")]
    author: EntityId,
    author_class: HookActorClass,
    /// The ask's group: its handle.
    #[serde(with = "crate::serialize::entity_ref")]
    ask: EntityId,
    state: VerbAskState,
    created_at: u64,
    consumed_at: Option<u64>,
    /// How settlement runs the call again without its caller; `None` for a
    /// call only its caller's retry resumes.
    resume: Option<VerbResume>,
    /// When the ask settled.
    settled_at: Option<u64>,
    /// Settled proceed with a resume target: the drain runs the call.
    ready: bool,
    /// What the drained call returned, for the caller's retry.
    outcome: Option<SavedOutcome>,
}

/// What a call the drain ran returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SavedOutcome {
    /// The caller's view of the result, as JSON.
    Ok {
        result: String,
    },
    Err {
        code: String,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VerbAskState {
    /// Waiting for an answer, or answered and not yet resumed.
    Open,
    /// A retry resumed the call on a proceed answer.
    Consumed,
}

/// What a call finds under its invocation before the chain runs.
pub(super) enum Retry {
    /// No saved ask: the chain runs from its start.
    Fresh,
    Stop(VerbHookStop),
    /// Answered proceed: the chain resumes after `binding` with the saved
    /// args, and its commit uses up the answer `token` names.
    Resume {
        binding: EntityId,
        position: usize,
        args: Value,
        token: AskToken,
    },
}

/// The proceed answer a resumed chain uses up in its own commit: the
/// invocation's key and the ask it answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AskToken {
    key: [u8; 16],
    ask: EntityId,
    /// `<pack>/<hook>`: the asking hook.
    pub(super) hook: String,
}

/// Reads the ask a previous try of this invocation saved, if any. `resume`
/// is how the caller could be resumed without it: only a caller whose call
/// the drain would run the same way reads the drained outcome.
pub(super) fn retry(vault: &Vault, call: &VerbCall, resume: Option<&VerbResume>) -> Result<Retry> {
    let key = call.invocation.0;
    let row = {
        let rtxn = vault.store.env.read_txn()?;
        ASKS.get(&vault.store, &rtxn, &key)?
    };
    let Some(row) = row else {
        return Ok(Retry::Fresh);
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
    if row.state == VerbAskState::Consumed {
        return match (&row.outcome, resume) {
            (Some(outcome), Some(resume)) if row.resume.as_ref() == Some(resume) => {
                Ok(Retry::Stop(completed(call.invocation, outcome)?))
            }
            _ => skipped(USED),
        };
    }
    let status = vault
        .memory(
            row.author,
            super::super::filter::edge_class(row.author_class),
        )
        .tasks_ask_status(TaskAskHandle { group_ref: row.ask });
    let result = match status {
        Ok(TaskAskStatus::Pending { .. } | TaskAskStatus::Changed { .. }) => {
            return Ok(Retry::Stop(pending(call.invocation, row.ask)));
        }
        Ok(TaskAskStatus::Settled(result)) => result,
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
    let args =
        serde_json::from_str(&row.args).map_err(|_| Error::CorruptedIndex("verb hook ask args"))?;
    Ok(Retry::Resume {
        binding: row.binding,
        position: usize::try_from(row.position).unwrap_or(usize::MAX),
        args,
        token: AskToken {
            key,
            ask: row.ask,
            hook: row.hook,
        },
    })
}

/// Uses up the answer `token` names, in the resumed chain's commit: false
/// when the row is gone, no longer Open, or names another ask (a newer ask
/// of this invocation, which stands).
pub(super) fn consume_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    token: &AskToken,
) -> Result<bool> {
    let Some(mut row) = ASKS.get(&vault.store, txn, &token.key)? else {
        return Ok(false);
    };
    if row.state != VerbAskState::Open || row.ask != token.ask {
        return Ok(false);
    }
    row.state = VerbAskState::Consumed;
    row.consumed_at = Some(vault.store.clock.now_recorded_at());
    row.ready = false;
    ASKS.put(&vault.store, txn, &token.key, &row)?;
    Ok(true)
}

/// The error a resumed chain's write fails with when its answer was used
/// meanwhile, so the write does not commit.
pub(super) fn used_error() -> Error {
    Error::InvariantViolation("verb hook ask already used")
}

/// Whether `stop` is the Skipped a used answer ends a call with.
pub(super) fn is_used(stop: &VerbHookStop) -> bool {
    matches!(stop, VerbHookStop::Skipped { reason, .. } if reason == USED)
}

/// The stop a retry of a drained call gets: what the call returned.
fn completed(invocation: InvocationId, outcome: &SavedOutcome) -> Result<VerbHookStop> {
    Ok(match outcome {
        SavedOutcome::Ok { result } => VerbHookStop::Completed {
            invocation: invocation.to_hex(),
            result: serde_json::from_str(result)
                .map_err(|_| Error::CorruptedIndex("verb hook ask outcome"))?,
        },
        SavedOutcome::Err { code, message } => VerbHookStop::CompletedWithError {
            invocation: invocation.to_hex(),
            code: code.clone(),
            message: message.clone(),
        },
    })
}

/// Opens the hook's ask as its author and saves the stopped call, with the
/// chain's own rows (`write`), in the ask's write. `write` runs first, so a
/// resumed chain uses up its old answer before the new ask's row takes the
/// key. `resume` is saved with the call. `Err(reason)` when the ask door
/// refused: nothing was saved.
#[expect(
    clippy::too_many_arguments,
    reason = "the call, the hook, its place, the args, the label, the resume target and the chain's write"
)]
pub(super) fn open(
    vault: &Vault,
    call: &VerbCall,
    hook: (EntityId, &PackHookBinding),
    position: usize,
    args: &Value,
    label: &str,
    resume: Option<&VerbResume>,
    write: &dyn Fn(&mut heed::RwTxn<'_>) -> Result<()>,
) -> Result<std::result::Result<VerbHookStop, String>> {
    let (binding_id, binding) = hook;
    let mut what = TaskAskQuestion::new(ConsultPayloadRef::Claim(binding_id));
    what.label = Some(cut(label, crate::context_board::TASK_LABEL_MAX_BYTES));
    for (option, text) in [
        (PROCEED, format!("Run {}", cut(&call.verb, 200))),
        (HOLD, "Do not run it".to_owned()),
    ] {
        let option = TaskAskOptionId::new(option)
            .map_err(|_| Error::InvariantViolation("verb hook ask option"))?;
        what.options.insert(option, text);
    }
    let mut spec = TaskAskSpec::shorthand(None, what, None, TaskAskDefault::Hold);
    spec.intent_key = format!(
        "hook.verb/{}/{}",
        call.invocation.to_hex(),
        binding_id.to_hex()
    );
    let row = |ask: EntityId| -> Result<VerbAsk> {
        Ok(VerbAsk {
            verb: call.verb.clone(),
            actor: call.actor,
            class: call.class,
            scope: call.scope.clone(),
            domain: call.domain,
            args: serde_json::to_string(args)
                .map_err(|_| Error::InvariantViolation("verb hook ask args encode"))?,
            position: u32::try_from(position).unwrap_or(u32::MAX),
            binding: binding_id,
            hook: format!("{}/{}", binding.pack, binding.hook),
            author: binding.author_id(),
            author_class: binding.author_class(),
            ask,
            state: VerbAskState::Open,
            created_at: vault.store.clock.now_recorded_at(),
            consumed_at: None,
            resume: resume.cloned(),
            settled_at: None,
            ready: false,
            outcome: None,
        })
    };
    let key = call.invocation.0;
    let opened = vault
        .memory(
            binding.author_id(),
            super::super::filter::edge_class(binding.author_class()),
        )
        .tasks_ask_with_txn_effect(&spec, |txn, ask| {
            let row = row(ask).map_err(MemoryError::from)?;
            write(txn).map_err(MemoryError::from)?;
            ASKS.put(&vault.store, txn, &key, &row)
                .map_err(MemoryError::from)
        });
    let receipt = match opened {
        Ok(receipt) => receipt,
        Err(error) => return Ok(Err(format!("{}: {}", error.code, error.message))),
    };
    if receipt.idempotent_replay {
        // The ask stood from an earlier try whose write did not land here.
        // An Open row under the key stands.
        vault.with_write_txn_grouped(|txn| {
            write(txn)?;
            let open = ASKS
                .get(&vault.store, txn, &key)?
                .is_some_and(|row| row.state == VerbAskState::Open);
            if !open {
                ASKS.put(&vault.store, txn, &key, &row(receipt.handle.group_ref)?)?;
            }
            Ok(())
        })?;
    }
    Ok(Ok(pending(call.invocation, receipt.handle.group_ref)))
}

/// Marks the call stopped on ask `group` settled, in the settling write:
/// ready for the drain when the answer said proceed and the call has a
/// resume target. `binding` is the asking hook's, from the ask's intent key.
/// Nothing runs here, and a saved row that does not decode never fails the
/// settlement: its retry reports it.
pub(super) fn settled_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: [u8; 16],
    binding: EntityId,
    group: EntityId,
    result: &TaskAskResult,
    now: u64,
) -> Result<()> {
    let Some(mut row) = ASKS.get_lenient(&vault.store, txn, &key)? else {
        return Ok(());
    };
    if row.ask != group || row.binding != binding || row.state != VerbAskState::Open {
        return Ok(());
    }
    row.settled_at = Some(now);
    row.ready = row.resume.is_some() && proceeds(result);
    ASKS.put(&vault.store, txn, &key, &row)?;
    if row.ready {
        // The hook runner wakes on the commit, not only on its tick.
        crate::batch::queue_proactivity_change(vault, txn);
    }
    Ok(())
}

/// One call the drain runs: what it needs to call the row again.
pub(super) struct Ready {
    pub(super) key: [u8; 16],
    pub(super) verb: String,
    pub(super) actor: EntityId,
    pub(super) class: HookActorClass,
    /// The saved args, as JSON.
    pub(super) args: String,
    pub(super) resume: VerbResume,
    pub(super) ask: EntityId,
}

/// Every Open call a settled proceed made ready. A row that does not decode
/// is passed over: its retry reports it.
pub(super) fn ready(vault: &Vault) -> Result<Vec<Ready>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut ready = Vec::new();
    for entry in ASKS.iter_raw_from(&vault.store, &rtxn, &[])? {
        let (key, value) = entry?;
        let (Ok(key), Ok(row)) = (
            <[u8; 16]>::try_from(key.as_slice()),
            ASKS.decode_value(&value),
        ) else {
            continue;
        };
        if row.state != VerbAskState::Open || !row.ready {
            continue;
        }
        let Some(resume) = row.resume else {
            continue;
        };
        ready.push(Ready {
            key,
            verb: row.verb,
            actor: row.actor,
            class: row.class,
            args: row.args,
            resume,
            ask: row.ask,
        });
    }
    Ok(ready)
}

/// Saves what the drained call of ask `group` returned and uses the answer
/// up, unless a newer ask stands under the key or an outcome is saved.
/// `transient` (a storage error) leaves a row the call did not use up ready
/// for the next pass.
pub(super) fn finish(
    vault: &Vault,
    key: [u8; 16],
    group: EntityId,
    outcome: SavedOutcome,
    transient: bool,
) -> Result<()> {
    let now = vault.store.clock.now_recorded_at();
    vault.with_write_txn_grouped(|txn| {
        let Some(mut row) = ASKS.get(&vault.store, txn, &key)? else {
            return Ok(());
        };
        if row.ask != group || row.outcome.is_some() {
            return Ok(());
        }
        if transient && row.state == VerbAskState::Open {
            return Ok(());
        }
        row.state = VerbAskState::Consumed;
        row.consumed_at.get_or_insert(now);
        row.ready = false;
        row.outcome = Some(outcome);
        ASKS.put(&vault.store, txn, &key, &row)
    })
}

/// Takes ask `group`'s Open call off the drain: its settlement no longer
/// reads as a proceed, or its saved args do not decode. A retry still finds
/// the row.
pub(super) fn unready(vault: &Vault, key: [u8; 16], group: EntityId) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        let Some(mut row) = ASKS.get(&vault.store, txn, &key)? else {
            return Ok(());
        };
        if row.ask != group || row.state != VerbAskState::Open || !row.ready {
            return Ok(());
        }
        row.ready = false;
        ASKS.put(&vault.store, txn, &key, &row)
    })
}

/// The caller's Pending: the invocation to retry and the ask handle's
/// group, both as lowercase hex.
fn pending(invocation: InvocationId, ask: EntityId) -> VerbHookStop {
    VerbHookStop::Pending {
        invocation: invocation.to_hex(),
        ask: ask.to_hex(),
    }
}

/// Whether the settled ask said proceed, by a word rather than a fallback.
fn proceeds(result: &TaskAskResult) -> bool {
    if result.fallback.is_some() {
        return false;
    }
    match &result.decision {
        TaskAskDecision::Answer(option) => option.as_str() == PROCEED,
        TaskAskDecision::First(answer) => result.evidence.iter().any(|entry| {
            entry.answer == *answer
                && entry
                    .word
                    .option
                    .as_ref()
                    .is_some_and(|option| option.as_str() == PROCEED)
        }),
        _ => false,
    }
}

/// `text`, cut to `max` bytes on a character boundary.
pub(super) fn cut(text: &str, max: usize) -> String {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}
