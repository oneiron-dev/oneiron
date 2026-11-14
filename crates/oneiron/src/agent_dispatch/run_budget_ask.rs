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
//! - When the host names a free local chat model that serves the run's
//!   calls now, the ask also offers `continue_on_local` ([`RunLocalRoute`]).
//!   That answer resumes the run, and each of its later calls runs on that
//!   model alone, on its free route ([`AgentDispatcher::run_local_route`]),
//!   until the run is held again. The owner's `on_budget_exhausted` knob set
//!   to `continue_on_local` is his standing answer: with a free local model
//!   named, the hold resumes the run on it in the hold's own write and asks
//!   nothing; with none named, he is asked (Engine ruling RUNBUDGET-KNOB = A).
//! - The next hold of the run spends the overdraft and the local route: both
//!   are deleted and the owner is asked again. A resume at the hold's own
//!   door withdraws the open ask ([`withdraw_run_budget_ask_in_txn`]). With no
//!   answer the run stays held.
//! - `GET /v1/ai/status` lists the open asks ([`run_budget_questions`]); the
//!   status shows them and does not own them.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::llm::decision::{
    AnswerContract, AskRole, AskTo, DecisionAnswer, DecisionAsk, DecisionRung, HolderKind,
    HumanAskReason, HumanDecisionRequest, ProviderPin, catalogue::RUN_BUDGET_SPENT,
};
use crate::llm::{BudgetExhaustionPolicy, DEFAULT_BUDGET_RESERVE_UNITS, ModelId};
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
    /// The run resumes on the free local chat model the host named when it
    /// was held, and spends nothing more. Offered only when one was named.
    ContinueOnLocal,
}

impl RunBudgetChoice {
    /// The answer token: the choice's wire name.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::StayParked => "stay_parked",
            Self::Overdraft => "overdraft",
            Self::ContinueOnLocal => "continue_on_local",
        }
    }

    /// The choice an answer token names, if any.
    #[must_use]
    pub fn of_token(token: &str) -> Option<Self> {
        [Self::StayParked, Self::Overdraft, Self::ContinueOnLocal]
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
    /// The free local chat model a `continue_on_local` answer runs the run
    /// on; `None` when the ask does not offer it.
    pub local_model: Option<ModelId>,
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

/// The free local chat model the host named when a run was held, and the
/// owner's choice of it: while chosen, each call of the run runs on that model
/// alone, on its free route, until the run is held again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunLocalRoute {
    /// The free local chat model the host named at the hold.
    pub model: ModelId,
    /// The owner's choice of it; `None` while it is only offered.
    pub chosen: Option<LocalRouteChoice>,
}

/// How the owner chose a held run's local route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRouteChoice {
    /// The arrival number of the ask whose answer chose it; `None` when his
    /// standing answer, the `on_budget_exhausted` knob, chose it at the hold.
    pub ask: Option<u64>,
    /// Vault clock seconds when it was chosen.
    pub chosen_at: u64,
}

/// Local routes keyed by the run's root attempt.
const LOCAL_ROUTE: SideTable<AttemptId, RunLocalRoute, Named> =
    SideTable::new(&side_table::AGENT_DISPATCH_RUN_LOCAL_ROUTE);

/// The run-budget ask about the run rooted at `root`, put to the owner role
/// for `principal`: keyed by the run, so an open ask of the run is that ask.
/// It offers `continue_on_local` when the host named `local_model`.
fn run_budget_request(
    root: AttemptId,
    principal: EntityId,
    local_model: Option<&ModelId>,
) -> Result<HumanDecisionRequest> {
    let mut choices = vec![RunBudgetChoice::StayParked, RunBudgetChoice::Overdraft];
    if local_model.is_some() {
        choices.push(RunBudgetChoice::ContinueOnLocal);
    }
    let options = choices
        .iter()
        .map(|choice| choice.token().to_owned())
        .collect();
    // Fixed machine-lifecycle wording, as the campaign pause's is: the host
    // renders the run and its choices.
    let overdraft = format!(
        "approve a one-off overdraft (by default {RUN_BUDGET_DEFAULT_OVERDRAFT_UNITS} units, one \
         more call)"
    );
    let text = match local_model {
        Some(model) => format!(
            "This run is held at its spend cap. Keep it parked, {overdraft}, or continue it on \
             the free local model {model}?"
        ),
        None => format!("This run is held at its spend cap. Keep it parked, or {overdraft}?"),
    };
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

/// What the hold of a run asked its owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeldRunAsk {
    /// The ask queued, by its arrival number.
    Asked(u64),
    /// The owner's standing answer resumed the run on the free local model
    /// the host named, in the hold's own write: nothing is asked.
    ContinuedOnLocal,
    /// Nothing is asked: the vault has no live owner, or the run is not the
    /// owner's to overdraft or continue.
    NotAsked,
}

/// Queues the owner's ask about the run rooted at `root` in the hold's own
/// write, as the vault's first live owner's question, and spends the run's
/// approved overdraft and local route: the run is held again. An open ask of
/// the run is that ask. With `local_model`, the free local chat model the host
/// names for the run now, the ask offers `continue_on_local`; and when the
/// owner's `on_budget_exhausted` knob is `continue_on_local`, his standing
/// answer resumes the run on it at once, at `now`, and nothing is asked. A run
/// nothing is asked about stays held, and its notice still goes out.
///
/// # Errors
///
/// Storage errors, or an ask the queue refuses.
pub(crate) fn queue_run_budget_ask_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    root: AttemptId,
    local_model: Option<&ModelId>,
    now: u64,
) -> Result<HeldRunAsk> {
    OVERDRAFT.delete(&vault.store, wtxn, &root)?;
    LOCAL_ROUTE.delete(&vault.store, wtxn, &root)?;
    let Some(principal) = crate::policy_model::owners_in_txn(vault, wtxn)?
        .into_iter()
        .next()
    else {
        return Ok(HeldRunAsk::NotAsked);
    };
    if !overdraft_open_to_in_txn(vault, wtxn, root, principal)? {
        return Ok(HeldRunAsk::NotAsked);
    }
    if let Some(model) = local_model {
        let standing = crate::gate::resolve_policy_manifest(&vault.store, wtxn)?
            .on_budget_exhausted()
            == BudgetExhaustionPolicy::ContinueOnLocal;
        let chosen = standing.then_some(LocalRouteChoice {
            ask: None,
            chosen_at: now,
        });
        LOCAL_ROUTE.put(
            &vault.store,
            wtxn,
            &root,
            &RunLocalRoute {
                model: model.clone(),
                chosen,
            },
        )?;
        if standing {
            AgentDispatcher::new(vault).resume_budget_hold_in_txn(
                wtxn,
                root,
                &principal.to_hex(),
                now,
            )?;
            return Ok(HeldRunAsk::ContinuedOnLocal);
        }
    }
    let request = run_budget_request(root, principal, local_model)?;
    vault
        .queue_decision_ask_in_txn(wtxn, &request, None)
        .map(HeldRunAsk::Asked)
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
/// `continue_on_local` resumes it on the local model the ask offered;
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
        Some(RunBudgetChoice::ContinueOnLocal) => {
            continue_on_local_in_txn(vault, wtxn, root, by, ask.seq, answer.answered_at)
        }
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

/// The owner `by`'s choice, answering ask `seq`, to continue the held run
/// rooted at `root` on the free local chat model its hold offered, in the
/// answer's write: the local route chosen and the run resumed as `by`. `false`
/// when the run is no longer held, no local model was offered, or the run is
/// not the owner's.
fn continue_on_local_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    root: AttemptId,
    by: EntityId,
    seq: u64,
    now: u64,
) -> Result<bool> {
    let dispatcher = AgentDispatcher::new(vault);
    if !dispatcher.budget_held_in_txn(wtxn, root)?
        || !overdraft_open_to_in_txn(vault, wtxn, root, by)?
    {
        return Ok(false);
    }
    let Some(mut route) = LOCAL_ROUTE.get(&vault.store, wtxn, &root)? else {
        return Ok(false);
    };
    route.chosen = Some(LocalRouteChoice {
        ask: Some(seq),
        chosen_at: now,
    });
    LOCAL_ROUTE.put(&vault.store, wtxn, &root, &route)?;
    dispatcher.resume_budget_hold_in_txn(wtxn, root, &by.to_hex(), now)?;
    Ok(true)
}

impl Vault {
    /// The owner's press on a run-budget ask (Engine ruling RUNBUDGET-OVERDRAFT):
    /// his `choice`, and for `overdraft` the cap he names (the default when
    /// `None`), answered and applied in one write, his proof revalidated in it.
    /// `continue_on_local` resumes the run on the local model the ask offered.
    /// The family's ask about a Dreamer try parked at its budget trap takes
    /// the same press (`budget_trap_ask`). Any other ask passes unchanged, for
    /// the generic answer door. The same answer again is a no-op.
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
        let Some(asked) = self.decision_ask(seq)? else {
            return Ok(());
        };
        if super::is_budget_trap_ask(&asked) {
            return super::budget_trap_ask::press_budget_trap_ask(
                self, owner, seq, choice, cap_units,
            );
        }
        if asked_run(&asked).is_none() {
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
                RunBudgetChoice::ContinueOnLocal => continue_on_local_in_txn(
                    self,
                    txn,
                    root,
                    by,
                    seq,
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
        for key in self.run_keys_in_txn(&txn, attempt)? {
            if let Some(overdraft) = OVERDRAFT.get(&self.vault.store, &txn, &key)? {
                return Ok(Some(overdraft.cap_units));
            }
        }
        Ok(None)
    }

    /// The free local chat model the owner chose to continue the run
    /// `attempt` belongs to on (the root or any attempt of its run), while the
    /// run has not been held again: each of its calls runs on that model
    /// alone, on its free route. `None` with none chosen.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn run_local_route(&self, attempt: AttemptId) -> Result<Option<ModelId>> {
        let txn = self.vault.store.env.read_txn()?;
        for key in self.run_keys_in_txn(&txn, attempt)? {
            if let Some(route) = LOCAL_ROUTE.get(&self.vault.store, &txn, &key)? {
                return Ok(route.chosen.is_some().then_some(route.model));
            }
        }
        Ok(None)
    }

    /// The attempts a row keyed by the root of `attempt`'s run may sit under:
    /// `attempt` itself, then every attempt of its run.
    fn run_keys_in_txn(&self, txn: &heed::RoTxn<'_>, attempt: AttemptId) -> Result<Vec<AttemptId>> {
        let mut keys = vec![attempt];
        let queue = AttemptQueue::new(self.vault);
        let run = queue
            .get_in_txn(txn, attempt)?
            .and_then(|record| record.run_id);
        if let Some(run) = run {
            keys.extend(
                queue
                    .list_run_in_txn(txn, &run)?
                    .into_iter()
                    .map(|row| row.id),
            );
        }
        Ok(keys)
    }
}

/// Every open run-budget ask, oldest first: what `GET /v1/ai/status` shows.
///
/// # Errors
///
/// Storage errors.
pub fn run_budget_questions(vault: &Vault) -> Result<Vec<RunBudgetQuestion>> {
    let txn = vault.store.env.read_txn()?;
    let mut questions = Vec::new();
    for ask in vault.open_queue_asks_in_txn(&txn, RUN_BUDGET_ASK_QUEUE)? {
        let Some(run) = asked_run(&ask) else {
            continue;
        };
        let AnswerContract::Choice { options } = &ask.question.contract else {
            continue;
        };
        let choices: Vec<RunBudgetChoice> = options
            .iter()
            .filter_map(|token| RunBudgetChoice::of_token(token))
            .collect();
        let local_model = if choices.contains(&RunBudgetChoice::ContinueOnLocal) {
            LOCAL_ROUTE
                .get(&vault.store, &txn, &run)?
                .map(|route| route.model)
        } else {
            None
        };
        questions.push(RunBudgetQuestion {
            seq: ask.seq,
            run: crate::entity_id::bytes_to_hex_lower(run.as_bytes()),
            asked_at: ask.asked_at,
            choices,
            default_overdraft_units: RUN_BUDGET_DEFAULT_OVERDRAFT_UNITS,
            local_model,
        });
    }
    Ok(questions)
}
