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
//!   its cap, and resumes the run: each of its meters, fresh or restored
//!   from a saved cursor, then takes the cap once on top of what it had
//!   ([`AgentDispatcher::run_overdraft`]; the ask's arrival number names the
//!   grant). With no cap named, the cap is the units one more call of the
//!   run reserves.
//! - When the vault's USD quote prices the unit of the run's open root
//!   scope, the ask also offers `add_funds` (owner ruling RUN-BUDGET-SPENT =
//!   B, 15 Nov 2026: "you can dedicate more money"). The owner names dollars
//!   at his press ([`Vault::press_run_budget_add_funds`]); they buy whole
//!   units at the quote's upper-bound rate, so never more than he named, and
//!   the root scope's cap rises by them for good: no hold takes the raise
//!   back ([`RunFunds`]). The run resumes, and each of its meters takes the
//!   bought units once, as it takes an overdraft's cap, so a step whose own
//!   line is spent goes on under them (Engine ruling
//!   RUNBUDGET-ADDFUNDS-METER = A).
//! - The advance check (owner ruling RUN-BUDGET-SPENT = B, "you can also
//!   check it in advance"; Engine ruling RUNBUDGET-ADVANCE-FLOW = A): a root
//!   launch whose expected spend is above what its hard root scope has left
//!   asks the owner in the launch's own write ([`queue_forecast_ask_in_txn`]),
//!   stating the projected spend and the room. The run starts as today. The
//!   early ask offers `add_funds` (the root's cap rises now, for good; the
//!   run is not held, so no meter takes a grant) and `stay_parked` (the run
//!   goes on and holds at zero as usual). The run's hold withdraws an early
//!   ask still open and asks its own choices in its place, so a run has one
//!   open ask at a time.
//! - When the host names a free local chat model that serves the run's
//!   calls now, the ask also offers `continue_on_local` ([`RunLocalRoute`]).
//!   That answer resumes the run, and each of its later calls runs on that
//!   model alone, on its free route ([`AgentDispatcher::run_local_route`]),
//!   until the run is held again. The owner's `on_budget_exhausted` knob set
//!   to `continue_on_local` is his standing answer: with a free local model
//!   named, the hold resumes the run on it in the hold's own write and asks
//!   nothing; with none named, he is asked (Engine ruling RUNBUDGET-KNOB = A).
//! - The next hold of the run spends the overdraft (or the units added
//!   dollars bought) and the local route: both are deleted and the owner is
//!   asked again; an added amount's raise of the root scope stays. A resume
//!   at the hold's own door withdraws the open ask
//!   ([`withdraw_run_budget_ask_in_txn`]). With no answer the run stays held.
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
use super::spend_calibration::{UsdPriceTarget, UsdUnitPrice};
use super::spend_record::{SCOPE, SpendScope, SpendScopeId, SpendState};
use super::widen_record::invalid;
use crate::llm::run_admission::LeaseUnit;

mod answers;
mod forecast;
mod press;
mod reads;

use self::answers::{approve_overdraft_in_txn, continue_on_local_in_txn};
pub(crate) use self::forecast::queue_forecast_ask_in_txn;
use self::forecast::{asked_forecast, withdraw_forecast_ask_in_txn};
pub use self::reads::run_budget_questions;

/// The queue identity of run-budget asks. Its model string also keeps
/// unrelated decision asks out of [`apply_run_budget_answer_in_txn`].
pub(crate) const RUN_BUDGET_ASK_QUEUE: &str = "models.run_budget_questions";
const RUN_BUDGET_ASK_QUEUE_VERSION: &str = "1";

/// The queue identity of the early asks a launch's projection makes.
pub(crate) const RUN_BUDGET_FORECAST_QUEUE: &str = "models.run_budget_forecasts";
const RUN_BUDGET_FORECAST_QUEUE_VERSION: &str = "1";

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
    /// The owner adds dollars: the run's root scope cap rises for good by the
    /// whole units they buy at the vault's USD quote, and the run resumes.
    /// Offered only when the quote prices the scope's unit.
    AddFunds,
}

impl RunBudgetChoice {
    /// The answer token: the choice's wire name.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::StayParked => "stay_parked",
            Self::Overdraft => "overdraft",
            Self::ContinueOnLocal => "continue_on_local",
            Self::AddFunds => "add_funds",
        }
    }

    /// The choice an answer token names, if any.
    #[must_use]
    pub fn of_token(token: &str) -> Option<Self> {
        [
            Self::StayParked,
            Self::Overdraft,
            Self::ContinueOnLocal,
            Self::AddFunds,
        ]
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
    /// What an `add_funds` dollar buys now; `None` when the ask does not
    /// offer it.
    pub add_funds_price: Option<FundsPrice>,
    /// An early ask's projected spend of the run, in its root's unit; `None`
    /// on a held run's ask.
    pub projected_units: Option<u64>,
    /// An early ask's room under the run's root at launch; `None` on a held
    /// run's ask.
    pub available_units: Option<u64>,
}

/// What a root launch's projection asked the owner about: the hard root
/// scope the run spends under, the launch's expected spend and the room left
/// at launch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunBudgetForecast {
    pub scope: SpendScopeId,
    pub unit: LeaseUnit,
    pub expected_units: u64,
    /// The expected spend in millionths of a dollar, when priced.
    pub expected_usd_micros: Option<u64>,
    pub available_units: u64,
    /// Vault clock seconds when the launch asked.
    pub asked_at: u64,
}

/// Early asks keyed by the launched run's root attempt.
const FORECAST: SideTable<AttemptId, RunBudgetForecast, Named> =
    SideTable::new(&side_table::AGENT_DISPATCH_RUN_BUDGET_FORECAST);

/// The vault's USD quote for one budget unit, as an `add_funds` answer
/// spends it: `usd_micros` millionths of a dollar per `per_units` units, at
/// the model's highest catalogue rate (an upper bound).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FundsPrice {
    pub unit: LeaseUnit,
    pub usd_micros: u64,
    pub per_units: u64,
}

impl FundsPrice {
    /// The whole units `amount_usd_micros` buys at this price, rounded down
    /// so they never cost more than the amount. `None` on overflow or a zero
    /// price.
    #[must_use]
    pub fn units_for(&self, amount_usd_micros: u64) -> Option<u64> {
        (u128::from(amount_usd_micros) * u128::from(self.per_units))
            .checked_div(u128::from(self.usd_micros))
            .and_then(|units| u64::try_from(units).ok())
    }

    /// The price as the ask states it: `$0.000150 per 1000 tokens`.
    pub(super) fn stated(&self) -> String {
        format!(
            "{} per {} {}",
            usd(self.usd_micros),
            self.per_units,
            self.unit.as_str()
        )
    }
}

/// Millionths of a dollar as `$D.DDDDDD`.
fn usd(micros: u64) -> String {
    format!("${}.{:06}", micros / 1_000_000, micros % 1_000_000)
}

/// The vault's USD quote for `unit` on a held run, read in `txn`. `None`
/// with no quote installed, a quote that fails or knows no price, or a free
/// rate: dollars never buy units at an unknown or zero price.
pub(super) fn funds_price_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    unit: &LeaseUnit,
) -> Option<FundsPrice> {
    let prices = vault.launch_usd_prices.get()?;
    let UsdUnitPrice {
        usd_micros,
        per_units,
    } = prices
        .quote(vault, txn, UsdPriceTarget::HeldRun, unit)
        .ok()
        .flatten()?;
    (usd_micros != 0 && per_units != 0).then(|| FundsPrice {
        unit: unit.clone(),
        usd_micros,
        per_units,
    })
}

/// The `add_funds` price of the run rooted at `root`: the quote for its
/// open root scope's unit. `None` when the run has no open root scope or the
/// unit has no price.
fn run_funds_price_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: AttemptId,
) -> Result<Option<FundsPrice>> {
    Ok(run_root_scope_in_txn(vault, txn, root)?
        .filter(|scope| scope.state == SpendState::Open)
        .and_then(|scope| funds_price_in_txn(vault, txn, &scope.unit)))
}

/// The root scope of the run rooted at `root`. That is the run's own scope
/// (keyed by `root`) when it is hard or carved from no parent, as a pinned
/// budget's or a carve's is. For a soft scope the run reserved under a spend
/// scope, it is the hard scope whose cap binds what the run draws there: the
/// scope its launch statement named ([`super::LaunchStatement::scope`]), such
/// as the owner's root the launch projected against. `None` for a run with no
/// spend scope. The early ask, the hold's ask and their answers all resolve
/// this one scope, so a hold asks what its early ask promised (review round 2
/// of #8217).
fn run_root_scope_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: AttemptId,
) -> Result<Option<SpendScope>> {
    let Some(own) = SCOPE.get(&vault.store, txn, &SpendScopeId::for_attempt(&root).0)? else {
        return Ok(None);
    };
    let parent = match &own.parent {
        Some(parent) if !own.hard => parent.clone(),
        _ => return Ok(Some(own)),
    };
    AgentDispatcher::new(vault)
        .reservable_in_txn(txn, &parent)
        .map(|(_, binding)| Some(binding))
}

/// One amount the owner added to a run or a parked try.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunFundsEntry {
    pub usd_micros: u64,
    /// The whole units it bought, in `price.unit`.
    pub units: u64,
    pub price: FundsPrice,
    /// The arrival number of the ask whose answer added it.
    pub ask: u64,
    /// Vault clock seconds when it was added.
    pub added_at: u64,
}

/// Every amount the owner added to a run (or a parked try), oldest first.
/// A lasting record: no hold deletes it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunFunds {
    pub entries: Vec<RunFundsEntry>,
}

/// Added funds keyed by the run's root attempt, or by a parked try.
const FUNDS: SideTable<AttemptId, RunFunds, Named> =
    SideTable::new(&side_table::AGENT_DISPATCH_RUN_FUNDS);

/// Appends `entry` to the funds of `key`, in the answer's write.
pub(super) fn record_funds_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: AttemptId,
    entry: RunFundsEntry,
) -> Result<()> {
    let mut funds = FUNDS.get(&vault.store, wtxn, &key)?.unwrap_or_default();
    funds.entries.push(entry);
    FUNDS.put(&vault.store, wtxn, &key, &funds)
}

/// The whole units `amount_usd_micros` buys at `price`, refusing a zero
/// amount and an amount too small to buy one unit.
pub(super) fn funds_units(price: &FundsPrice, amount_usd_micros: u64) -> Result<u64> {
    if amount_usd_micros == 0 {
        return Err(invalid("add_funds names an amount above zero"));
    }
    price
        .units_for(amount_usd_micros)
        .filter(|units| *units > 0)
        .ok_or_else(|| {
            invalid("add_funds names an amount that buys no whole unit at the USD price")
        })
}

/// The one-off grant the owner approved for a held run: an overdraft's cap,
/// or the whole units his `add_funds` dollars bought. Each of its meters
/// takes `cap_units` once, as the grant `ask`, until the run is held again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunOverdraft {
    pub cap_units: u64,
    /// The arrival number of the ask whose answer approved it.
    pub ask: u64,
    /// Vault clock seconds when the answer approved it.
    pub approved_at: u64,
}

/// Approved overdrafts and added-funds grants keyed by the run's root
/// attempt.
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
/// It offers `continue_on_local` when the host named `local_model`, and
/// `add_funds` when `funds` prices the run's root scope.
fn run_budget_request(
    root: AttemptId,
    principal: EntityId,
    local_model: Option<&ModelId>,
    funds: Option<&FundsPrice>,
) -> Result<HumanDecisionRequest> {
    let mut choices = vec![RunBudgetChoice::StayParked, RunBudgetChoice::Overdraft];
    if local_model.is_some() {
        choices.push(RunBudgetChoice::ContinueOnLocal);
    }
    if funds.is_some() {
        choices.push(RunBudgetChoice::AddFunds);
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
    let mut text = match local_model {
        Some(model) => format!(
            "This run is held at its spend cap. Keep it parked, {overdraft}, or continue it on \
             the free local model {model}?"
        ),
        None => format!("This run is held at its spend cap. Keep it parked, or {overdraft}?"),
    };
    if let Some(price) = funds {
        text.push_str(&format!(
            " Or add dollars to its budget for good (at {}).",
            price.stated()
        ));
    }
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
/// with no spend scope, or one whose root scope ([`run_root_scope_in_txn`])
/// is open, carved from no parent, and paid by the owner or by no named
/// payer. Another payer's accepted cap is that payer's to raise, and a
/// carve's room is its parent's.
fn overdraft_open_to_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: AttemptId,
    owner: EntityId,
) -> Result<bool> {
    Ok(match run_root_scope_in_txn(vault, txn, root)? {
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
    withdraw_forecast_ask_in_txn(vault, wtxn, root)?;
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
    let funds = run_funds_price_in_txn(vault, wtxn, root)?;
    let request = run_budget_request(root, principal, local_model, funds.as_ref())?;
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
    if asked_forecast(ask).is_some() {
        let add_funds = DecisionAnswer::Choice(RunBudgetChoice::AddFunds.token().to_owned());
        return match &ask.answer {
            Some(answer) if answer.answer == add_funds => Err(add_funds_needs_amount()),
            _ => Ok(false),
        };
    }
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
        Some(RunBudgetChoice::AddFunds) => Err(add_funds_needs_amount()),
        Some(RunBudgetChoice::StayParked) | None => Ok(false),
    }
}

/// An `add_funds` answer without its dollars: only the owner's press names
/// them.
pub(super) fn add_funds_needs_amount() -> crate::Error {
    invalid("an add_funds answer names its dollars: press it with amount_usd_micros")
}

/// Whether a settled ask is a run-budget ask: its answer's writer wakes the
/// attempt observers, so a resumed run is claimed at once.
pub(crate) fn is_run_budget_ask(ask: &DecisionAsk) -> bool {
    asked_run(ask).is_some()
}
