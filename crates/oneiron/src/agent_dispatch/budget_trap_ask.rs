//! The owner's ask about a Dreamer try parked at its budget trap on a wait
//! only an owner act ends (Engine ruling RUNBUDGET-SCOPE = B, 13 Nov 17:30):
//! the hard cap of a spend scope (`Budget`), or a resident's pinned share
//! (`ResidentShare`). The ask is the run-budget family's, on its own queue,
//! so a held run's answers and a parked try's never mix.
//!
//! - The trap's park queues one ask to the owner role in the park's own write
//!   ([`queue_budget_trap_ask_in_txn`]), keyed by the parked try, as the
//!   vault's first live owner's question. A spend scope's park asks only when
//!   the owner may raise that scope: an open hard root scope paid by him or
//!   by no named payer. A `PassBudget` park asks nothing: a later pass with
//!   room wakes it, as the owner's nightly budget renews. A host check, a
//!   typed refusal and a park that wakes in its own write ask nothing either.
//! - `stay_parked` leaves the try parked. `overdraft` lets the try spend the
//!   cap the owner names past the limit that stopped it, in the answer's
//!   write: the scope's cap rises by it, as the owner's top-up raises a cap,
//!   or the resident's pinned share rises by it, as the owner's share write
//!   sets a share, and that write wakes every park the new room covers. With
//!   no cap named, the cap is one more call: the units the refused call asked
//!   of the scope, or the units the resident's share falls short of the share
//!   the refused call needed.
//! - Any wake of the park (that write, the owner's own top-up or share write,
//!   or his release) withdraws the open ask in the wake's write
//!   ([`withdraw_budget_trap_ask_in_txn`]). With no answer the try stays
//!   parked.
//! - `GET /v1/ai/status` lists the open asks ([`budget_trap_questions`]).

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{DreamerParkWait, PARKED};
use crate::error::Result;
use crate::llm::decision::{
    AnswerContract, AskRole, AskTo, DecisionAnswer, DecisionAsk, DecisionRung, HolderKind,
    HumanAskReason, HumanDecisionRequest, ProviderPin, catalogue::RUN_BUDGET_SPENT,
};
use crate::llm::run_admission::ResidentShare;
use crate::{EntityId, Vault};

use super::run_budget_ask::RunBudgetChoice;
use super::spend_record::{SCOPE, SpendScope, SpendScopeId, SpendState};
use super::widen_record::invalid;

/// The queue identity of budget trap asks. Its model string also keeps every
/// other decision ask out of [`apply_budget_trap_answer_in_txn`].
pub(crate) const BUDGET_TRAP_ASK_QUEUE: &str = "models.budget_trap_questions";
const BUDGET_TRAP_ASK_QUEUE_VERSION: &str = "1";

/// The limit that stopped a parked try, as the AI status lists it: what an
/// `overdraft` answer raises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BudgetTrapLimit {
    /// The hard cap of this spend scope.
    SpendScope { scope: String },
    /// This resident's pinned share of the host-paid allocation, hex.
    ResidentShare { resident: String },
}

/// One open budget trap ask, as the AI status lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BudgetTrapQuestion {
    /// The ask's arrival number: the owner answers it at the decision ask door.
    pub seq: u64,
    /// The parked try, hex.
    pub attempt: String,
    /// Vault clock seconds when the ask was queued.
    pub asked_at: u64,
    pub choices: Vec<RunBudgetChoice>,
    /// The cap an `overdraft` answer approves when the owner names none, as
    /// the limit reads now.
    pub default_overdraft_units: u64,
    pub limit: BudgetTrapLimit,
}

/// The ask about the try `attempt` parked on `wait`, put to the owner role for
/// `principal`, stating `default_units`: keyed by the try, so an open ask of
/// the try is that ask.
fn budget_trap_request(
    attempt: AttemptId,
    principal: EntityId,
    wait: &DreamerParkWait,
    default_units: u64,
) -> Result<HumanDecisionRequest> {
    let options = [RunBudgetChoice::StayParked, RunBudgetChoice::Overdraft]
        .iter()
        .map(|choice| choice.token().to_owned())
        .collect();
    // Fixed machine-lifecycle wording, as the run hold's is: the host renders
    // the try and its choices.
    let text = match wait {
        DreamerParkWait::ResidentShare { .. } => format!(
            "This resident's background work is parked at its pinned share. Keep it parked, or \
             approve an overdraft of its share (by default {default_units} units, one more call)?"
        ),
        _ => format!(
            "This background work is parked at its spend cap. Keep it parked, or approve a \
             one-off overdraft (by default {default_units} units, one more call)?"
        ),
    };
    let question = RUN_BUDGET_SPENT.question(
        &[attempt.as_bytes().as_slice()],
        text,
        AnswerContract::Choice { options },
    )?;
    Ok(HumanDecisionRequest {
        question,
        principal,
        evidence: Vec::new(),
        reason: HumanAskReason::OwnerSelected,
        prior: None,
        prior_provider: None,
        queue_pin: ProviderPin {
            rung: DecisionRung::Human,
            model: BUDGET_TRAP_ASK_QUEUE.to_owned(),
            version: BUDGET_TRAP_ASK_QUEUE_VERSION.to_owned(),
        },
        to: AskTo::owner(),
        correlation: Some(EntityId::from_bytes(*attempt.as_bytes())?),
    })
}

/// The parked try a budget trap ask is about; `None` for any other ask.
fn asked_try(ask: &DecisionAsk) -> Option<AttemptId> {
    if ask.queue_pin.model != BUDGET_TRAP_ASK_QUEUE {
        return None;
    }
    ask.correlation
        .and_then(|attempt| AttemptId::from_bytes(attempt.as_bytes()).ok())
}

/// Whether a decision ask is a budget trap ask: its answer's writer wakes the
/// queue's observers, so a woken try is claimed at once.
pub(crate) fn is_budget_trap_ask(ask: &DecisionAsk) -> bool {
    asked_try(ask).is_some()
}

/// Whether the owner `owner` may raise `scope`'s cap: an open hard scope,
/// carved from no parent, paid by the owner or by no named payer. Another
/// payer's accepted cap is that payer's to raise, and a carved scope's room
/// is its parent's.
fn scope_raisable_by(scope: &SpendScope, owner: EntityId) -> bool {
    scope.state == SpendState::Open
        && scope.hard
        && scope.parent.is_none()
        && scope
            .payer
            .as_ref()
            .is_none_or(|payer| payer.party == owner)
}

/// The share on record for `resident` in units, `0` for the default split or
/// a share this vault never set.
fn share_units_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, resident: EntityId) -> Result<u64> {
    Ok(crate::llm::resident_share_in_txn(vault, txn, resident)?
        .and_then(|share| share.units)
        .unwrap_or(0))
}

/// The cap one more call needs past the limit `wait` names, as it reads now:
/// the units the refused call asked of the scope, or the units the resident's
/// share falls short of the share the refused call needed (at least one).
/// `None` for a wait no owner act ends.
fn default_overdraft_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    wait: &DreamerParkWait,
) -> Result<Option<u64>> {
    Ok(match wait {
        DreamerParkWait::Budget { asked_units, .. } => Some(*asked_units),
        DreamerParkWait::ResidentShare {
            resident,
            needed_units,
        } => Some(
            needed_units
                .saturating_sub(share_units_in_txn(vault, txn, *resident)?)
                .max(1),
        ),
        _ => None,
    })
}

/// Queues the owner's ask about the try `attempt` parked at its budget trap
/// on `wait`, in the park's own write, as the vault's first live owner's
/// question. `None` when nothing is asked: a wait no owner act ends, no live
/// owner, or a spend scope the owner may not raise.
///
/// # Errors
///
/// Storage errors, or an ask the queue refuses.
pub(crate) fn queue_budget_trap_ask_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    wait: &DreamerParkWait,
) -> Result<Option<u64>> {
    let Some(default_units) = default_overdraft_in_txn(vault, wtxn, wait)? else {
        return Ok(None);
    };
    let Some(principal) = crate::policy_model::owners_in_txn(vault, wtxn)?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };
    if let DreamerParkWait::Budget { scope, .. } = wait {
        let raisable = SCOPE
            .get(&vault.store, wtxn, &scope.0)?
            .is_some_and(|scope| scope_raisable_by(&scope, principal));
        if !raisable {
            return Ok(None);
        }
    }
    let request = budget_trap_request(attempt, principal, wait, default_units)?;
    vault
        .queue_decision_ask_in_txn(wtxn, &request, None)
        .map(Some)
}

/// Withdraws the open budget trap ask about the try `attempt`, in the write
/// that woke its park: a woken try waits on no answer. Nothing waits on the
/// ask's answer itself (the park waits on its trap), so no waiter is woken.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn withdraw_budget_trap_ask_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
) -> Result<()> {
    let correlation = Some(EntityId::from_bytes(*attempt.as_bytes())?);
    let open: Vec<u64> = vault
        .open_queue_asks_in_txn(wtxn, BUDGET_TRAP_ASK_QUEUE)?
        .into_iter()
        .filter(|ask| ask.correlation == correlation)
        .map(|ask| ask.seq)
        .collect();
    for seq in open {
        vault.withdraw_decision_ask_in_txn(wtxn, seq)?;
    }
    Ok(())
}

/// Applies an answered budget trap ask in the generic answer's own write: an
/// owner person's `overdraft` approves the default cap; `stay_parked` leaves
/// the try parked. Any other answerer, and every other ask, is untouched.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn apply_budget_trap_answer_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    ask: &DecisionAsk,
) -> Result<()> {
    let Some(attempt) = asked_try(ask) else {
        return Ok(());
    };
    let Some(answer) = &ask.answer else {
        return Ok(());
    };
    let Some(by) = answer.by.id() else {
        return Ok(());
    };
    if answer.role != AskRole::Owner || answer.kind != HolderKind::Person {
        return Ok(());
    }
    if answer.answer == DecisionAnswer::Choice(RunBudgetChoice::Overdraft.token().to_owned()) {
        approve_trap_overdraft_in_txn(vault, wtxn, attempt, by, None, answer.answered_at)?;
    }
    Ok(())
}

/// The owner `by`'s approved overdraft of `cap_units` (one more call when
/// `None`) past the limit the try `attempt` is parked at, in the answer's
/// write: the spend scope's cap or the resident's pinned share raised by it,
/// and every park the new room covers woken. `true` when a park woke. Nothing
/// moves when the try is no longer parked on such a wait, or the owner may
/// not raise its scope.
fn approve_trap_overdraft_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    by: EntityId,
    cap_units: Option<u64>,
    now: u64,
) -> Result<bool> {
    let Some(wait) = PARKED
        .get(&vault.store, wtxn, &attempt)?
        .and_then(|park| park.wait)
        .map(|wait| wait.wait)
    else {
        return Ok(false);
    };
    let Some(default_units) = default_overdraft_in_txn(vault, wtxn, &wait)? else {
        return Ok(false);
    };
    let cap = cap_units.unwrap_or(default_units);
    if cap == 0 {
        return Err(invalid("an overdraft names a cap above zero"));
    }
    let now_ms = now.saturating_mul(1000);
    let woken = match &wait {
        DreamerParkWait::Budget { scope, .. } => {
            raise_scope_cap_in_txn(vault, wtxn, scope, by, cap, now_ms)?
        }
        DreamerParkWait::ResidentShare { resident, .. } => {
            let current = crate::llm::resident_share_in_txn(vault, wtxn, *resident)?;
            let units = current
                .and_then(|share| share.units)
                .unwrap_or(0)
                .checked_add(cap)
                .ok_or(crate::Error::ArithmeticOverflow("resident share overdraft"))?;
            let share = ResidentShare {
                units: Some(units),
                pinned: current.is_none_or(|share| share.pinned),
            };
            vault.set_resident_share_in_txn(wtxn, *resident, share, now_ms)?
        }
        _ => return Ok(false),
    };
    Ok(!woken.is_empty())
}

/// Raises `scope`'s cap by `cap` as the owner `by`, as his top-up does, and
/// wakes the parks its new room covers. Nothing moves, and no park wakes, for
/// a scope he may not raise.
fn raise_scope_cap_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: &SpendScopeId,
    by: EntityId,
    cap: u64,
    now_ms: u64,
) -> Result<Vec<AttemptId>> {
    let Some(mut record) = SCOPE.get(&vault.store, wtxn, &scope.0)? else {
        return Ok(Vec::new());
    };
    if !scope_raisable_by(&record, by) {
        return Ok(Vec::new());
    }
    record.cap_units = record
        .cap_units
        .checked_add(cap)
        .ok_or(crate::Error::ArithmeticOverflow("spend scope overdraft"))?;
    if let Some(payer) = &mut record.payer {
        payer.granted_by = Some(by);
        payer.at_ms = now_ms;
    }
    SCOPE.put(&vault.store, wtxn, &scope.0, &record)?;
    crate::llm::wake_budget_traps_in_txn(vault, wtxn, scope, now_ms)
}

/// The owner's press on a budget trap ask: his `choice`, and for `overdraft`
/// the cap he names (one more call when `None`), answered and applied in one
/// write, his proof revalidated in it. The same answer again is a no-op.
///
/// # Errors
///
/// The owner refusal; an ask that is withdrawn, answered another way, or does
/// not offer `choice`; a zero cap; storage errors.
pub(super) fn press_budget_trap_ask(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    seq: u64,
    choice: RunBudgetChoice,
    cap_units: Option<u64>,
) -> Result<()> {
    let woke = vault.with_write_txn_grouped(|txn| {
        let by = owner.revalidate_in_txn(vault, txn)?;
        let ask = vault
            .decision_ask_in_txn(txn, seq)?
            .ok_or_else(|| invalid("no such decision ask"))?;
        let attempt = asked_try(&ask).ok_or_else(|| invalid("not a budget trap ask"))?;
        let answer = DecisionAnswer::Choice(choice.token().to_owned());
        if !vault.answer_owner_queue_ask_in_txn(txn, BUDGET_TRAP_ASK_QUEUE, seq, by, answer)? {
            return Ok(None);
        }
        let woke = match choice {
            RunBudgetChoice::Overdraft => approve_trap_overdraft_in_txn(
                vault,
                txn,
                attempt,
                by,
                cap_units,
                vault.store.clock.now_recorded_at(),
            )?,
            RunBudgetChoice::StayParked | RunBudgetChoice::ContinueOnLocal => false,
        };
        Ok(Some(woke))
    })?;
    if let Some(woke) = woke {
        vault.signal_decision_answer(seq);
        if woke {
            vault.store.notify_attempt_observers();
            vault.store.notify_proactivity_changes();
        }
    }
    Ok(())
}

/// Every open budget trap ask whose try is still parked on its wait, oldest
/// first: what `GET /v1/ai/status` shows.
///
/// # Errors
///
/// Storage errors.
pub fn budget_trap_questions(vault: &Vault) -> Result<Vec<BudgetTrapQuestion>> {
    let txn = vault.store.env.read_txn()?;
    let mut questions = Vec::new();
    for ask in vault.open_queue_asks_in_txn(&txn, BUDGET_TRAP_ASK_QUEUE)? {
        let Some(attempt) = asked_try(&ask) else {
            continue;
        };
        let Some(wait) = PARKED
            .get(&vault.store, &txn, &attempt)?
            .and_then(|park| park.wait)
            .map(|wait| wait.wait)
        else {
            continue;
        };
        let limit = match &wait {
            DreamerParkWait::Budget { scope, .. } => BudgetTrapLimit::SpendScope {
                scope: scope.as_str().to_owned(),
            },
            DreamerParkWait::ResidentShare { resident, .. } => BudgetTrapLimit::ResidentShare {
                resident: resident.to_hex(),
            },
            _ => continue,
        };
        let Some(default_overdraft_units) = default_overdraft_in_txn(vault, &txn, &wait)? else {
            continue;
        };
        let AnswerContract::Choice { options } = &ask.question.contract else {
            continue;
        };
        questions.push(BudgetTrapQuestion {
            seq: ask.seq,
            attempt: crate::entity_id::bytes_to_hex_lower(attempt.as_bytes()),
            asked_at: ask.asked_at,
            choices: options
                .iter()
                .filter_map(|token| RunBudgetChoice::of_token(token))
                .collect(),
            default_overdraft_units,
            limit,
        });
    }
    Ok(questions)
}
