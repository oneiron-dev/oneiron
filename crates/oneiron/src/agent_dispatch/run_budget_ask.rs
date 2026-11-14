//! The owner's ask about a run held at its spend cap (ARCH-0026 depletion
//! ladder, policy knob; ARCH-0036 #offers-ask-home). A paid overdraft runs
//! only when the owner approves one; otherwise the ladder asks up through
//! decide()'s person rung, the ladder's human decision queue, and never
//! downgrades the run by itself.
//!
//! - The budget hold queues one ask to the owner role in the hold's own write
//!   ([`queue_run_budget_ask_in_txn`]), once per held stretch of the run: a
//!   replayed or second hold of a run that is still held asks nothing new.
//! - The owner's answer applies in the answer's own write: at the generic
//!   answer door ([`apply_run_budget_answer_in_txn`]), or at the owner's press
//!   ([`Vault::press_run_budget_ask`]), which also takes the overdraft's cap.
//!   `stay_parked` leaves the run held. `overdraft` records the run's
//!   overdraft ([`RunOverdraft`]), raises the run's open root spend scope by
//!   its cap, and resumes the run: its meters then run with
//!   `Overdraft{cap}` ([`AgentDispatcher::run_overdraft_units`]). With no cap
//!   named, the cap is the units one more call of the run reserves.
//! - The next hold of the run spends the overdraft: it is deleted and the
//!   owner is asked again. A resume at the hold's own door withdraws the open
//!   ask ([`withdraw_run_budget_ask_in_txn`]). With no answer the run stays
//!   held.
//! - `GET /v1/ai/status` lists the open asks ([`run_budget_questions`]); the
//!   status shows them and does not own them.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::llm::DEFAULT_BUDGET_RESERVE_UNITS;
use crate::llm::decision::{
    AnswerContract, AskRole, AskTo, DecisionAnswer, DecisionAsk, DecisionRung, HolderKind,
    HumanAskReason, HumanDecisionRequest, ProviderPin, catalogue::RUN_BUDGET_SPENT,
};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

use super::AgentDispatcher;
use super::spend_record::{SCOPE, SpendScopeId, SpendState};
use super::widen_record::invalid;

/// The queue identity of run-budget asks. Its model string also keeps
/// unrelated decision asks out of [`apply_run_budget_answer_in_txn`].
pub(crate) const RUN_BUDGET_ASK_QUEUE: &str = "models.run_budget_questions";
const RUN_BUDGET_ASK_QUEUE_VERSION: &str = "1";

/// The overdraft an `overdraft` answer approves when the owner names no cap
/// (Engine ruling RUNBUDGET-OVERDRAFT, 13 Nov 17:30): the units one more call
/// of a workflow step reserves.
pub const RUN_BUDGET_DEFAULT_OVERDRAFT_UNITS: u64 = DEFAULT_BUDGET_RESERVE_UNITS;

/// What the owner may answer about a run held at its spend cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunBudgetChoice {
    /// The run stays held; the owner may still resume it at the hold's door.
    StayParked,
    /// The run resumes on a one-off overdraft of the cap the owner names, or
    /// [`RUN_BUDGET_DEFAULT_OVERDRAFT_UNITS`] when he names none.
    Overdraft,
}

impl RunBudgetChoice {
    /// The answer token: the choice's wire name.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::StayParked => "stay_parked",
            Self::Overdraft => "overdraft",
        }
    }

    /// The choice an answer token names, if any.
    #[must_use]
    pub fn of_token(token: &str) -> Option<Self> {
        [Self::StayParked, Self::Overdraft]
            .into_iter()
            .find(|choice| choice.token() == token)
    }
}

/// One open run-budget ask, as the AI status lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunBudgetQuestion {
    /// The ask's arrival number: the owner answers it at the decision ask door.
    pub seq: u64,
    /// The held run's root attempt, hex.
    pub run: String,
    /// Vault clock seconds when the ask was queued.
    pub asked_at: u64,
    pub choices: Vec<RunBudgetChoice>,
    /// The cap an `overdraft` answer approves when the owner names none.
    pub default_overdraft_units: u64,
}

/// The one-off overdraft the owner approved for a held run: its meters run
/// with `Overdraft{cap_units}` until the run is held again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunOverdraft {
    pub cap_units: u64,
    /// The arrival number of the ask whose answer approved it.
    pub ask: u64,
    /// Vault clock seconds when the answer approved it.
    pub approved_at: u64,
}

/// Approved overdrafts keyed by the run's root attempt.
const OVERDRAFT: SideTable<AttemptId, RunOverdraft, Named> =
    SideTable::new(&side_table::AGENT_DISPATCH_RUN_OVERDRAFT);

/// The run-budget ask about the run rooted at `root`, put to the owner role
/// for `principal`, offering `choices`: keyed by the run, so an open ask of
/// the run is that ask.
fn run_budget_request(
    root: AttemptId,
    principal: EntityId,
    choices: &[RunBudgetChoice],
) -> Result<HumanDecisionRequest> {
    let options = choices
        .iter()
        .map(|choice| choice.token().to_owned())
        .collect();
    // Fixed machine-lifecycle wording, as the campaign pause's is: the host
    // renders the run and its choices.
    let text = format!(
        "This run is held at its spend cap. Keep it parked, or approve a one-off overdraft \
         (by default {RUN_BUDGET_DEFAULT_OVERDRAFT_UNITS} units, one more call)?"
    );
    let question = RUN_BUDGET_SPENT.question(
        &[root.as_bytes().as_slice()],
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
            model: RUN_BUDGET_ASK_QUEUE.to_owned(),
            version: RUN_BUDGET_ASK_QUEUE_VERSION.to_owned(),
        },
        to: AskTo::owner(),
        correlation: Some(EntityId::from_bytes(*root.as_bytes())?),
    })
}

/// The root attempt a run-budget ask is about; `None` for any other ask.
fn asked_run(ask: &DecisionAsk) -> Option<AttemptId> {
    if ask.queue_pin.model != RUN_BUDGET_ASK_QUEUE {
        return None;
    }
    ask.correlation
        .and_then(|run| AttemptId::from_bytes(run.as_bytes()).ok())
}

/// Whether the owner `owner` may overdraft the run rooted at `root`: a run
/// with no spend scope, or one whose root scope is open, carved from no
/// parent, and paid by the owner or by no named payer. Another payer's
/// accepted cap is that payer's to raise.
fn overdraft_open_to_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: AttemptId,
    owner: EntityId,
) -> Result<bool> {
    let scope = SpendScopeId::for_attempt(&root);
    Ok(match SCOPE.get(&vault.store, txn, &scope.0)? {
        None => true,
        Some(scope) => {
            scope.state == SpendState::Open
                && scope.parent.is_none()
                && scope
                    .payer
                    .as_ref()
                    .is_none_or(|payer| payer.party == owner)
        }
    })
}

/// Queues the owner's ask about the run rooted at `root` in the hold's own
/// write, as the vault's first live owner's question, and spends the run's
/// approved overdraft: the run is held again. An open ask of the run is that
/// ask. `None` when no ask is queued: the vault has no live owner, or the
/// owner has no choice but to keep the run parked. The run stays held and its
/// notice still goes out.
///
/// # Errors
///
/// Storage errors, or an ask the queue refuses.
pub(crate) fn queue_run_budget_ask_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    root: AttemptId,
) -> Result<Option<u64>> {
    OVERDRAFT.delete(&vault.store, wtxn, &root)?;
    let Some(principal) = crate::policy_model::owners_in_txn(vault, wtxn)?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };
    if !overdraft_open_to_in_txn(vault, wtxn, root, principal)? {
        return Ok(None);
    }
    let choices = [RunBudgetChoice::StayParked, RunBudgetChoice::Overdraft];
    let request = run_budget_request(root, principal, &choices)?;
    vault
        .queue_decision_ask_in_txn(wtxn, &request, None)
        .map(Some)
}

/// Withdraws the open run-budget ask about the run rooted at `root`, in the
/// write that resumed the run: a resumed run waits on no answer. `None` when
/// none was open; else its arrival number, whose waiters the caller wakes
/// once that write committed.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn withdraw_run_budget_ask_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    root: AttemptId,
) -> Result<Option<u64>> {
    let correlation = Some(EntityId::from_bytes(*root.as_bytes())?);
    let open = vault
        .open_queue_asks_in_txn(wtxn, RUN_BUDGET_ASK_QUEUE)?
        .into_iter()
        .find(|ask| ask.correlation == correlation);
    let Some(ask) = open else {
        return Ok(None);
    };
    Ok(vault
        .withdraw_decision_ask_in_txn(wtxn, ask.seq)?
        .then_some(ask.seq))
}

/// Applies an answered run-budget ask in the generic answer's own write: an
/// owner person's `overdraft` approves the default cap and resumes the run;
/// `stay_parked` leaves it held. Any other answerer, and every other question
/// family, is untouched. `true` when it resumed the run.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn apply_run_budget_answer_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    ask: &DecisionAsk,
) -> Result<bool> {
    let Some(root) = asked_run(ask) else {
        return Ok(false);
    };
    let Some(answer) = &ask.answer else {
        return Ok(false);
    };
    let Some(by) = answer.by.id() else {
        return Ok(false);
    };
    if answer.role != AskRole::Owner || answer.kind != HolderKind::Person {
        return Ok(false);
    }
    let DecisionAnswer::Choice(token) = &answer.answer else {
        return Ok(false);
    };
    match RunBudgetChoice::of_token(token) {
        Some(RunBudgetChoice::Overdraft) => approve_overdraft_in_txn(
            vault,
            wtxn,
            root,
            by,
            ask.seq,
            RUN_BUDGET_DEFAULT_OVERDRAFT_UNITS,
            answer.answered_at,
        ),
        Some(RunBudgetChoice::StayParked) | None => Ok(false),
    }
}

/// Whether a settled ask is a run-budget ask: its answer's writer wakes the
/// attempt observers, so a resumed run is claimed at once.
pub(crate) fn is_run_budget_ask(ask: &DecisionAsk) -> bool {
    asked_run(ask).is_some()
}

/// The owner `by`'s approved overdraft of `cap_units` for the held run
/// rooted at `root`, in the answer's write: the run's overdraft row, its open
/// root spend scope raised by the cap, and the run resumed as `by`. `false`
/// when the run is no longer held, or the owner may not overdraft it.
fn approve_overdraft_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    root: AttemptId,
    by: EntityId,
    seq: u64,
    cap_units: u64,
    now: u64,
) -> Result<bool> {
    if cap_units == 0 {
        return Err(invalid("an overdraft names a cap above zero"));
    }
    let dispatcher = AgentDispatcher::new(vault);
    if !dispatcher.budget_held_in_txn(wtxn, root)?
        || !overdraft_open_to_in_txn(vault, wtxn, root, by)?
    {
        return Ok(false);
    }
    OVERDRAFT.put(
        &vault.store,
        wtxn,
        &root,
        &RunOverdraft {
            cap_units,
            ask: seq,
            approved_at: now,
        },
    )?;
    let scope_id = SpendScopeId::for_attempt(&root);
    if let Some(mut scope) = SCOPE.get(&vault.store, wtxn, &scope_id.0)? {
        scope.cap_units = scope
            .cap_units
            .checked_add(cap_units)
            .ok_or(crate::Error::ArithmeticOverflow("run overdraft"))?;
        let now_ms = now.saturating_mul(1000);
        if let Some(payer) = &mut scope.payer {
            payer.granted_by = Some(by);
            payer.at_ms = now_ms;
        }
        SCOPE.put(&vault.store, wtxn, &scope_id.0, &scope)?;
        crate::llm::wake_budget_traps_in_txn(vault, wtxn, &scope_id, now_ms)?;
    }
    dispatcher.resume_budget_hold_in_txn(wtxn, root, &by.to_hex(), now)?;
    Ok(true)
}

impl Vault {
    /// The owner's press on a run-budget ask (Engine ruling RUNBUDGET-OVERDRAFT):
    /// his `choice`, and for `overdraft` the cap he names (the default when
    /// `None`), answered and applied in one write, his proof revalidated in it.
    /// Any other ask passes unchanged, for the generic answer door. The same
    /// answer again is a no-op.
    ///
    /// # Errors
    ///
    /// The owner refusal; an ask that is withdrawn, answered another way, or
    /// does not offer `choice`; a zero cap; storage errors.
    pub fn press_run_budget_ask(
        &self,
        owner: &AuthenticatedOwner,
        seq: u64,
        choice: RunBudgetChoice,
        cap_units: Option<u64>,
    ) -> Result<()> {
        if !self
            .decision_ask(seq)?
            .is_some_and(|ask| asked_run(&ask).is_some())
        {
            return Ok(());
        }
        let resumed = self.with_write_txn_grouped(|txn| {
            let by = owner.revalidate_in_txn(self, txn)?;
            let ask = self
                .decision_ask_in_txn(txn, seq)?
                .ok_or_else(|| invalid("no such decision ask"))?;
            let root = asked_run(&ask).ok_or_else(|| invalid("not a run-budget ask"))?;
            let answer = DecisionAnswer::Choice(choice.token().to_owned());
            if !self.answer_owner_queue_ask_in_txn(txn, RUN_BUDGET_ASK_QUEUE, seq, by, answer)? {
                return Ok(None);
            }
            let resumed = match choice {
                RunBudgetChoice::StayParked => false,
                RunBudgetChoice::Overdraft => approve_overdraft_in_txn(
                    self,
                    txn,
                    root,
                    by,
                    seq,
                    cap_units.unwrap_or(RUN_BUDGET_DEFAULT_OVERDRAFT_UNITS),
                    self.store.clock.now_recorded_at(),
                )?,
            };
            Ok(Some(resumed))
        })?;
        if let Some(resumed) = resumed {
            self.signal_decision_answer(seq);
            if resumed {
                self.store.notify_attempt_observers();
            }
        }
        Ok(())
    }
}

impl AgentDispatcher<'_> {
    /// The overdraft the owner approved for the run `attempt` belongs to (the
    /// root or any attempt of its run), while the run has not been held again:
    /// its meters run with `Overdraft{cap}`. `None` with none approved.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn run_overdraft_units(&self, attempt: AttemptId) -> Result<Option<u64>> {
        let txn = self.vault.store.env.read_txn()?;
        if let Some(overdraft) = OVERDRAFT.get(&self.vault.store, &txn, &attempt)? {
            return Ok(Some(overdraft.cap_units));
        }
        let queue = AttemptQueue::new(self.vault);
        let Some(record) = queue.get_in_txn(&txn, attempt)? else {
            return Ok(None);
        };
        let Some(run) = record.run_id.as_deref() else {
            return Ok(None);
        };
        for row in queue.list_run_in_txn(&txn, run)? {
            if let Some(overdraft) = OVERDRAFT.get(&self.vault.store, &txn, &row.id)? {
                return Ok(Some(overdraft.cap_units));
            }
        }
        Ok(None)
    }
}

/// Every open run-budget ask, oldest first: what `GET /v1/ai/status` shows.
///
/// # Errors
///
/// Storage errors.
pub fn run_budget_questions(vault: &Vault) -> Result<Vec<RunBudgetQuestion>> {
    let txn = vault.store.env.read_txn()?;
    Ok(vault
        .open_queue_asks_in_txn(&txn, RUN_BUDGET_ASK_QUEUE)?
        .into_iter()
        .filter_map(|ask| {
            let run = asked_run(&ask)?;
            let AnswerContract::Choice { options } = &ask.question.contract else {
                return None;
            };
            Some(RunBudgetQuestion {
                seq: ask.seq,
                run: crate::entity_id::bytes_to_hex_lower(run.as_bytes()),
                asked_at: ask.asked_at,
                choices: options
                    .iter()
                    .filter_map(|token| RunBudgetChoice::of_token(token))
                    .collect(),
                default_overdraft_units: RUN_BUDGET_DEFAULT_OVERDRAFT_UNITS,
            })
        })
        .collect())
}
