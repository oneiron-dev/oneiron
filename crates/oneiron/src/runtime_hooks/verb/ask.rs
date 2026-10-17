//! A pre-hook's Ask (ARCH-0080 §3 Ask). Before the caller gets Pending, the
//! engine opens the ask through the tasks.ask door, as the hook's author, and
//! saves the stopped call in the same write: its args, the hook's place in the
//! chain and the ask handle. A retry with the same invocation reads the ask:
//! still open, the same Pending; answered proceed, the saved call resumes once
//! after the asking hook; declined or expired, Skipped. The answer is evidence,
//! never effect authority (`NotEvaluatedByAsk`): the verb's own gate runs on
//! the resumed call.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::side_table::{self, Named, SideTable};
use crate::skill_hub::pack_catalog::{HookActorClass, PackHookBinding};
use crate::task_verb::{
    ConsultPayloadRef, TaskAskDecision, TaskAskDefault, TaskAskHandle, TaskAskOptionId,
    TaskAskQuestion, TaskAskResult, TaskAskSettlementReason, TaskAskSpec, TaskAskStatus,
};
use crate::{EntityId, Error, MemoryError, Result, Vault};

use super::{InvocationId, VerbCall, VerbDomain, VerbHookStop};

/// Calls stopped on a hook's ask, by invocation.
const ASKS: SideTable<[u8; 16], VerbAsk, Named> = SideTable::new(&side_table::HOOKS_VERB_ASK);
/// The answer that lets the verb run.
const PROCEED: &str = "proceed";
const HOLD: &str = "hold";
const USED: &str = "this invocation's ask was already used; call again with a new invocation";

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
    /// Answered proceed and consumed: the chain resumes after `binding`
    /// with the saved args.
    Resume {
        binding: EntityId,
        position: usize,
        args: Value,
    },
}

/// Reads the ask a previous try of this invocation saved, if any.
pub(super) fn retry(vault: &Vault, call: &VerbCall) -> Result<Retry> {
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
        return skipped(USED);
    }
    let status = vault
        .memory(row.author, super::super::filter::edge_class(row.author_class))
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
    let now = vault.store.clock.now_recorded_at();
    let consumed = vault.with_write_txn_grouped(|txn| {
        let Some(mut current) = ASKS.get(&vault.store, txn, &key)? else {
            return Ok(false);
        };
        if current.state != VerbAskState::Open {
            return Ok(false);
        }
        current.state = VerbAskState::Consumed;
        current.consumed_at = Some(now);
        ASKS.put(&vault.store, txn, &key, &current)?;
        Ok(true)
    })?;
    if !consumed {
        return skipped(USED);
    }
    let args =
        serde_json::from_str(&row.args).map_err(|_| Error::CorruptedIndex("verb hook ask args"))?;
    Ok(Retry::Resume {
        binding: row.binding,
        position: usize::try_from(row.position).unwrap_or(usize::MAX),
        args,
    })
}

/// Opens the hook's ask as its author and saves the stopped call, with the
/// chain's own rows (`write`), in the ask's write. `Err(reason)` when the ask
/// door refused: nothing was saved.
pub(super) fn open(
    vault: &Vault,
    call: &VerbCall,
    hook: (EntityId, &PackHookBinding),
    position: usize,
    args: &Value,
    label: &str,
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
            ASKS.put(&vault.store, txn, &key, &row)
                .map_err(MemoryError::from)?;
            write(txn).map_err(MemoryError::from)
        });
    let receipt = match opened {
        Ok(receipt) => receipt,
        Err(error) => return Ok(Err(format!("{}: {}", error.code, error.message))),
    };
    if receipt.idempotent_replay {
        // The ask stood from an earlier try whose write did not land here.
        vault.with_write_txn_grouped(|txn| {
            if ASKS.get(&vault.store, txn, &key)?.is_none() {
                ASKS.put(&vault.store, txn, &key, &row(receipt.handle.group_ref)?)?;
            }
            write(txn)
        })?;
    }
    Ok(Ok(pending(call.invocation, receipt.handle.group_ref)))
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
