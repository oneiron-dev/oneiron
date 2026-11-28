//! Slot deciders (pass 34, `34-compute-general/DESIGN.md` sections 1.2, 4.4, 4.5 and 4.7; row
//! P1): the Grant the owner named for a slot (`policy.slots.decider`) answers it in place of the
//! slot's rule, through the host's decision ladder, the path every typed model read takes
//! (ARCH-0076). The loop asks only when the slot lists at least two lawful options, and shows
//! the decider those options and the facts 1.2 lists for them, nothing more. An answer that is
//! one of the options and comes inside the slot's deadline is the decision. Anything else keeps
//! the rule's pick (I9): an answer outside the options, an abstention, a failure, no model, or
//! silence. The decision records which. A decider never grants and never spends a job's money:
//! the start's own write checks the order, its authority, the fit and the room again.
//!
//! The ask runs outside every transaction. Its inference is the decider's own read: the host
//! meters it on the Grant's agent, and the decision keeps the read's receipt, never model text.
//! One pass waits about one slot deadline on its deciders in all ([`PassAsks`]).
//!
//! - RANK: one ask per pass among the first [`RANK_OPTIONS_MAX`] runnable orders; the decider
//!   picks which goes first, and the rest keep the rule's order and its decisions.
//! - PLACE: the rule's candidates, and [`PLACE_WAIT`] when the order may wait; only a decider
//!   picks wait, and the order then waits with the blocker `decider_wait` until
//!   `policy.slots.wait_reask_ms` has passed.
//! - AFTER: asked only when the rule would retry, among the options the end cause allows: a
//!   decider may give up sooner, never retry past the owner's `jobs.retry` count.

pub(crate) mod setting_keys;

use std::cell::Cell;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::authority::principal_standing_in_txn;
use crate::{EdgeActorClass, EntityId, Vault};

use super::after::{AFTER_RULE, AfterPick};
use super::blocker::{BlockedOn, Blocker};
use super::fit::MachineFacts;
use super::pass::{OrderHost, PassReport};
use super::place::PLACE_RULE;
use super::rank::{RANK_OPTIONS_MAX, RANK_RULE, rank_decision};
use super::record::{DecidedBy, EndKind, OrderCharge, SlotDecision, SlotName, WaitRule, WorkOrder};

pub use setting_keys::{
    DeciderGrant, PLACE_GRACE_MS_DEFAULT, PLACE_GRACE_MS_MAX, PLACE_WAIT_REASK_MS_DEFAULT,
    PLACE_WAIT_REASK_MS_MAX, SLOT_DEADLINE_MS_DEFAULT, SLOT_DEADLINE_MS_MAX,
    SLOT_MAX_ASKS_PER_HOUR_DEFAULT,
};

/// The verb a decider's Grant names: each answer is one typed model read.
pub const DECIDER_VERB: &str = "ai.verdict";

/// PLACE's option to start nothing now and look again at the next pass (4.4). The rule never
/// picks it while a machine fits; only a decider does.
pub const PLACE_WAIT: &str = "wait";

/// One hour, the span of a slot's ask ceiling.
const HOUR_MS: u64 = 3_600_000;

/// The slot's name as its setting rows' item spells it.
#[must_use]
pub const fn slot_item(slot: SlotName) -> &'static str {
    match slot {
        SlotName::Rank => "rank",
        SlotName::Place => "place",
        SlotName::After => "after",
    }
}

/// Why the named decider's answer did not decide, so the rule's pick stands (I9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeciderMiss {
    /// It answered a label that is not one of the options.
    Outside,
    /// No answer inside the slot's deadline.
    Silent,
    /// It read the question and abstained.
    Abstained,
    /// The read failed.
    Failed,
    /// No decision model on the issuer takes the question.
    NoModel,
    /// The named Grant does not stand for its agent and [`DECIDER_VERB`]: it was not asked.
    NotLive,
    /// The slot's asks this hour reached `policy.slots.max_asks_per_hour`, or this pass's ask
    /// budget ([`PassAsks`]) has run out: it was not asked.
    Ceiling,
}

/// What a decision keeps of the decider's read (ARCH-0076's receipt), and no model text.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeciderReceipt {
    /// The typed question's id, 32 lower hex. It names the question, not this one read.
    pub question: String,
    /// The providers the ladder tried, as `rung:model@version`.
    #[serde(default)]
    pub providers: Vec<String>,
    /// The rung that answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rung: Option<String>,
    /// The answer's probability, in thousandths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p_permille: Option<u16>,
    /// The receipt's cost of a thousand such reads at the answering model's catalogue price,
    /// in millionths of the price's unit; absent when the receipt states none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_per_thousand_micros: Option<u64>,
}

impl DeciderReceipt {
    /// The receipt of one read of `question` (32 lower hex): the `providers` the ladder tried,
    /// the `rung` that answered, the probability `p` (0 to 1) and the read's
    /// `cost_per_thousand`, as the ladder's receipt states them.
    #[must_use]
    pub fn of_read(
        question: String,
        providers: Vec<String>,
        rung: Option<String>,
        p: Option<f64>,
        cost_per_thousand: Option<f64>,
    ) -> Self {
        Self {
            question,
            providers,
            rung,
            p_permille: p.filter(|p| p.is_finite()).map(permille),
            cost_per_thousand_micros: cost_per_thousand
                .filter(|cost| cost.is_finite() && *cost >= 0.0)
                .map(micros),
        }
    }
}

/// `p`, a probability, in thousandths: 0 to 1000.
fn permille(p: f64) -> u16 {
    let scaled = (p.clamp(0.0, 1.0) * 1000.0).round();
    (0..=1000_u16)
        .find(|step| f64::from(*step) >= scaled)
        .unwrap_or(1000)
}

/// `amount`, finite and at least zero, in millionths, saturating at `u64::MAX`.
fn micros(amount: f64) -> u64 {
    // A float cast saturates at the integer's bounds; the caller passed a finite amount >= 0.
    (amount * 1_000_000.0).round() as u64
}

/// One ask of a slot's named decider, as the loop hands it to the host.
#[derive(Debug, Clone, PartialEq)]
pub struct SlotAsk {
    pub slot: SlotName,
    /// What the ask is about: a work order, or an agent run at its first claim.
    pub subject: SlotSubject,
    /// The Grant the owner named.
    pub grant: EntityId,
    /// The Grant's agent: the read's principal, whose own line meters it.
    pub agent: EntityId,
    pub class: EdgeActorClass,
    /// The lawful options, in the rule's order; the answer must be one of them.
    pub options: Vec<String>,
    /// What the slot shows its decider (1.2), and nothing more.
    pub facts: Value,
    pub deadline_ms: u64,
    pub max_asks_per_hour: u32,
}

impl SlotAsk {
    /// The question the slot puts to its decider.
    #[must_use]
    pub const fn question(&self) -> &'static str {
        match (self.slot, self.subject) {
            (SlotName::Place, SlotSubject::NativeRun) => {
                "Which machine should this agent run run on? Each option is a candidate machine id; the state lists each candidate's facts from the vault (its GPUs, the agents it can run, the open runs placed on it, whether it is the home), the run's agent and world, and the rule's pick."
            }
            (SlotName::Rank, _) => {
                "Which of these runnable work orders should be dispatched first? Each option is an order id; the state lists each one's class, charge, age, attempts and running family count, and the rule's pick."
            }
            (SlotName::Place, SlotSubject::WorkOrder) => {
                "Which machine should this work order's next attempt run on, or should it wait for a better one? Each option is a candidate machine id, or wait; the state lists each candidate's reported facts, the order's request and wishes, and the rule's pick."
            }
            (SlotName::After, _) => {
                "What should follow this work order's ended attempt? The options are the steps its end allows; the state lists the end, the attempts so far and the rule's pick."
            }
        }
    }
}

/// What a slot's ask is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotSubject {
    /// A work order of the issuer's loop.
    WorkOrder,
    /// An agent run at its first claim, which PLACE puts on a machine (row P4).
    NativeRun,
}

/// What the host got for one ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeciderReply {
    /// The decider answered `label`; the loop checks it against the options.
    Answered {
        label: String,
        receipt: DeciderReceipt,
    },
    Abstained {
        receipt: Option<DeciderReceipt>,
    },
    /// The read's clock ran out before an answer.
    Silent {
        receipt: Option<DeciderReceipt>,
    },
    Failed {
        why: String,
        receipt: Option<DeciderReceipt>,
    },
    /// No decision model on this host takes the question.
    NoModel,
    /// The slot's ceiling of asks this hour is reached: nothing was asked.
    Ceiling,
}

/// The asks an issuer sent this hour, per slot and decider: the ceiling
/// `policy.slots.max_asks_per_hour` counts them in a fixed one-hour window. It is kept in
/// memory, so an issuer that restarts opens a new window.
#[derive(Debug, Clone, Default)]
pub struct SlotAskWindow {
    /// (slot item, decider) -> (the window's hour, asks counted in it).
    asks: BTreeMap<(&'static str, EntityId), (u64, u32)>,
}

impl SlotAskWindow {
    /// Counts one ask of `grant` for `slot` at `now_ms` and answers true; or answers false, and
    /// counts nothing, when `max_per_hour` asks were already counted in this hour.
    pub fn admit(
        &mut self,
        slot: SlotName,
        grant: EntityId,
        max_per_hour: u32,
        now_ms: u64,
    ) -> bool {
        let hour = now_ms / HOUR_MS;
        let counted = self
            .asks
            .entry((slot_item(slot), grant))
            .or_insert((hour, 0));
        if counted.0 != hour {
            *counted = (hour, 0);
        }
        if counted.1 >= max_per_hour {
            return false;
        }
        counted.1 += 1;
        true
    }
}

/// One pass's asks of its slot deciders: the host that asks them, and the pass's ask budget
/// (Engine F1 = a, 25 Nov 20:4x). The pass's first ask opens the budget for that ask's
/// deadline, and each later ask in the pass may take only what is left of it. Once it has run
/// out, the later slots keep the rule's pick, as past the hourly ceiling
/// ([`DeciderMiss::Ceiling`]). So a pass, and a `vault.jobs.order` call that runs one, waits
/// about one slot deadline on its deciders, however many slots name one.
pub(crate) struct PassAsks<'h> {
    /// The host's decision ladder: it asks the decider and waits for its answer.
    decide: Box<dyn Fn(&SlotAsk) -> DeciderReply + 'h>,
    /// When the budget runs out; none before the pass's first ask.
    closes_at: Cell<Option<Instant>>,
}

impl<'h> PassAsks<'h> {
    /// A pass's asks through `host`, with its budget not yet opened.
    pub(super) fn new(host: &'h dyn OrderHost) -> Self {
        Self::through(move |ask| host.decide(ask))
    }

    /// Asks through `decide`, the host's decision ladder, with the budget not yet opened: one
    /// agent run's placement is one such budget.
    pub(crate) fn through(decide: impl Fn(&SlotAsk) -> DeciderReply + 'h) -> Self {
        Self {
            decide: Box::new(decide),
            closes_at: Cell::new(None),
        }
    }

    /// The deadline the next ask of a slot whose own deadline is `deadline_ms` may take: all of
    /// it for the pass's first ask, which opens the budget; after that, at most what is left.
    /// `None` once the budget has run out.
    fn deadline_ms(&self, deadline_ms: u64) -> Option<u64> {
        let now = Instant::now();
        let Some(closes_at) = self.closes_at.get() else {
            self.closes_at
                .set(now.checked_add(Duration::from_millis(deadline_ms)));
            return Some(deadline_ms);
        };
        let left = closes_at.saturating_duration_since(now).as_millis();
        let left = u64::try_from(left).unwrap_or(u64::MAX);
        (left > 0).then_some(left.min(deadline_ms))
    }
}

impl SlotDecision {
    /// The decision of the named decider `grant`, which picked `pick` among `options` in time.
    fn by_decider(
        slot: SlotName,
        options: Vec<String>,
        pick: String,
        grant: EntityId,
        receipt: DeciderReceipt,
    ) -> Self {
        let why = match receipt.p_permille {
            Some(p) => format!(
                "the decider the owner named picked it (p {}.{:03})",
                p / 1000,
                p % 1000
            ),
            None => "the decider the owner named picked it".to_owned(),
        };
        Self {
            slot,
            options,
            pick,
            by: DecidedBy::Grant { grant, receipt },
            why,
        }
    }

    /// This rule's decision, kept because the named decider `grant` did not decide (`miss`).
    fn kept(mut self, grant: EntityId, miss: DeciderMiss, receipt: Option<DeciderReceipt>) -> Self {
        if let DecidedBy::Rule { name } = &self.by {
            self.by = DecidedBy::RuleKept {
                name: name.clone(),
                decider: grant,
                miss,
                receipt,
            };
        }
        self
    }
}

/// Whose rows of the slot keys hold for a question.
#[derive(Clone, Copy)]
pub(crate) enum SlotScope<'o> {
    /// The vault's.
    Vault,
    /// The order's line's project's, or the vault's for an offer's order.
    Order(&'o WorkOrder),
    /// The project's, or the vault's for none: an agent run's own project.
    Project(Option<EntityId>),
}

/// A slot's question to its decider.
pub(crate) struct SlotQuestion<'o> {
    pub(crate) slot: SlotName,
    pub(crate) subject: SlotSubject,
    pub(crate) scope: SlotScope<'o>,
    pub(crate) options: Vec<String>,
    /// The facts the decider reads, made only when it is asked.
    pub(crate) facts: Box<dyn FnOnce() -> Value + 'o>,
}

/// `value` as JSON, or null when it does not encode.
fn fact<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

/// The rule's own decision, as a decider reads it.
pub(crate) fn rule_fact(rule: &SlotDecision) -> Value {
    json!({ "pick": rule.pick, "why": rule.why, "by": fact(&rule.by) })
}

/// Whether `wait` lets an order wait at `now_ms`.
const fn may_wait(wait: WaitRule, now_ms: u64) -> bool {
    match wait {
        WaitRule::No => false,
        WaitRule::Until { ms } => ms > now_ms,
        WaitRule::Open => true,
    }
}

/// The agent the Grant `grant` names, and its class, when the standing rule picks that Grant
/// for its agent and [`DECIDER_VERB`] now (the start gate's exact-Grant test).
fn decider_agent_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grant: &EntityId,
) -> crate::Result<Option<(EntityId, EdgeActorClass)>> {
    let Some(agent) = crate::federation::agent_grants_for_store_in_txn(&vault.store, txn)?
        .into_iter()
        .find(|standing| standing.id == *grant)
        .map(|standing| standing.grant.member_ref)
    else {
        return Ok(None);
    };
    for class in [EdgeActorClass::Agent, EdgeActorClass::System] {
        let standing = principal_standing_in_txn(vault, txn, agent, class, DECIDER_VERB)?;
        if standing.and_then(|standing| standing.grant) == Some(*grant) {
            return Ok(Some((agent, class)));
        }
    }
    Ok(None)
}

impl Vault {
    /// The project whose rows of the slot keys hold for `order`: its line's, for a line's
    /// unit; none (the vault's) for an offer's order.
    fn order_project_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        order: &WorkOrder,
    ) -> crate::Result<Option<EntityId>> {
        match &order.charge {
            OrderCharge::Line { arm, .. } => {
                Ok(self.experiment_arm_in_txn(txn, arm)?.map(|arm| arm.line))
            }
            OrderCharge::Offer { .. } => Ok(None),
        }
    }

    /// `rule`, or the named decider's pick among `question.options` when it answers one of them
    /// inside the slot's deadline, cut to what is left of the pass's ask budget (1.2, I9).
    pub(crate) fn decide_slot(
        &self,
        asks: &PassAsks<'_>,
        question: SlotQuestion<'_>,
        rule: SlotDecision,
    ) -> crate::Result<SlotDecision> {
        if question.options.len() < 2 {
            return Ok(rule);
        }
        let (policy, grant, stands) = {
            let txn = self.store.env.read_txn()?;
            let project = match question.scope {
                SlotScope::Vault => None,
                SlotScope::Order(order) => self.order_project_in_txn(&txn, order)?,
                SlotScope::Project(project) => project,
            };
            let policy = setting_keys::slot_policy_in_txn(self, &txn, question.slot, project)?;
            let Some(grant) = policy.decider else {
                return Ok(rule);
            };
            let stands = decider_agent_in_txn(self, &txn, &grant)?;
            (policy, grant, stands)
        };
        let Some((agent, class)) = stands else {
            return Ok(rule.kept(grant, DeciderMiss::NotLive, None));
        };
        let Some(deadline_ms) = asks.deadline_ms(policy.deadline_ms) else {
            return Ok(rule.kept(grant, DeciderMiss::Ceiling, None));
        };
        let ask = SlotAsk {
            slot: question.slot,
            subject: question.subject,
            grant,
            agent,
            class,
            options: question.options,
            facts: (question.facts)(),
            deadline_ms,
            max_asks_per_hour: policy.max_asks_per_hour,
        };
        let started = Instant::now();
        let reply = (asks.decide)(&ask);
        let in_time = started.elapsed() <= Duration::from_millis(deadline_ms);
        Ok(match reply {
            DeciderReply::Answered { receipt, .. } if !in_time => {
                rule.kept(grant, DeciderMiss::Silent, Some(receipt))
            }
            DeciderReply::Answered { label, receipt } if ask.options.contains(&label) => {
                SlotDecision::by_decider(ask.slot, ask.options, label, grant, receipt)
            }
            DeciderReply::Answered { receipt, .. } => {
                rule.kept(grant, DeciderMiss::Outside, Some(receipt))
            }
            DeciderReply::Abstained { receipt } => {
                rule.kept(grant, DeciderMiss::Abstained, receipt)
            }
            DeciderReply::Silent { receipt } => rule.kept(grant, DeciderMiss::Silent, receipt),
            DeciderReply::Failed { why, receipt } => {
                tracing::warn!(
                    slot = slot_item(ask.slot),
                    decider = %grant.to_hex(),
                    why = %why,
                    "work order: the slot's decider did not answer; the rule decides"
                );
                rule.kept(grant, DeciderMiss::Failed, receipt)
            }
            DeciderReply::NoModel => rule.kept(grant, DeciderMiss::NoModel, None),
            DeciderReply::Ceiling => rule.kept(grant, DeciderMiss::Ceiling, None),
        })
    }

    /// RANK (4.5): each order of `ranked` (the rule's order) with its rank decision. The named
    /// decider picks which of the first [`RANK_OPTIONS_MAX`] goes first, and that order moves
    /// there with the decider's decision; the others keep the rule's order, and each keeps the
    /// rule's own decision from before the move (Engine F2, 25 Nov 20:4x).
    pub(super) fn ranked_by_decider<'o>(
        &self,
        asks: &PassAsks<'_>,
        ranked: &[&'o WorkOrder],
        running: &BTreeMap<String, u32>,
        now_ms: u64,
    ) -> crate::Result<Vec<(&'o WorkOrder, SlotDecision)>> {
        let ids: Vec<EntityId> = ranked.iter().map(|order| order.id).collect();
        let mut decided: Vec<(&'o WorkOrder, SlotDecision)> = ranked
            .iter()
            .enumerate()
            .map(|(position, order)| (*order, rank_decision(&ids, position)))
            .collect();
        if ranked.len() < 2 {
            return Ok(decided);
        }
        let rule = rank_decision(&ids, 0);
        let rule_pick = rule_fact(&rule);
        let facts = move || {
            let orders: Vec<Value> = ranked
                .iter()
                .take(RANK_OPTIONS_MAX)
                .map(|order| {
                    json!({
                        "order": order.id.to_hex(),
                        "class": fact(&order.class),
                        "charge": fact(&order.charge),
                        "age_ms": now_ms.saturating_sub(order.ordered_at_ms),
                        "attempts": order.attempts.len(),
                        "family_running": running.get(&order.family_key()).copied().unwrap_or(0),
                    })
                })
                .collect();
            json!({ "rule": RANK_RULE, "orders": orders, "rule_pick": rule_pick })
        };
        let question = SlotQuestion {
            slot: SlotName::Rank,
            subject: SlotSubject::WorkOrder,
            scope: SlotScope::Vault,
            options: rule.options.clone(),
            facts: Box::new(facts),
        };
        let decision = self.decide_slot(asks, question, rule)?;
        if let Some(position) = decided
            .iter()
            .position(|(order, _)| order.id.to_hex() == decision.pick)
        {
            let (first, _) = decided.remove(position);
            decided.insert(0, (first, decision));
        }
        Ok(decided)
    }

    /// PLACE (4.4): the named decider picks among the rule's candidates (`placed` lists their
    /// top ones, `chosen` is the rule's pick), or [`PLACE_WAIT`] when the order may wait. No
    /// ask when the order's limits name one machine. `None` when the decider picked wait: the
    /// order then waits with the blocker `decider_wait`, written here, until
    /// `policy.slots.wait_reask_ms` has passed.
    pub(super) fn decide_place<'a>(
        &self,
        asks: &PassAsks<'_>,
        order: &WorkOrder,
        candidates: &[&'a MachineFacts],
        (chosen, placed): (&'a MachineFacts, SlotDecision),
        now_ms: u64,
        report: &mut PassReport,
    ) -> crate::Result<Option<(&'a MachineFacts, SlotDecision)>> {
        if order.limits.machines.len() == 1 {
            return Ok(Some((chosen, placed)));
        }
        let mut options = placed.options.clone();
        if may_wait(order.wait, now_ms) {
            options.push(PLACE_WAIT.to_owned());
        }
        let rule = placed.clone();
        let facts = || {
            let machines: Vec<Value> = rule
                .options
                .iter()
                .filter_map(|id| {
                    candidates
                        .iter()
                        .find(|facts| facts.machine.to_hex() == *id)
                })
                .map(|facts| fact(*facts))
                .collect();
            json!({
                "rule": PLACE_RULE,
                "order": {
                    "class": fact(&order.class),
                    "request": fact(&order.request),
                    "wait": fact(&order.wait),
                    "wishes": fact(&order.wishes),
                },
                "candidates": machines,
                "rule_pick": rule_fact(&rule),
            })
        };
        let question = SlotQuestion {
            slot: SlotName::Place,
            subject: SlotSubject::WorkOrder,
            scope: SlotScope::Order(order),
            options,
            facts: Box::new(facts),
        };
        let decision = self.decide_slot(asks, question, placed)?;
        let decider = match &decision.by {
            DecidedBy::Grant { grant, .. } => Some(*grant),
            _ => None,
        };
        let Some(decider) = decider else {
            return Ok(Some((chosen, decision)));
        };
        if decision.pick == PLACE_WAIT {
            let reask_ms = {
                let txn = self.store.env.read_txn()?;
                let project = self.order_project_in_txn(&txn, order)?;
                setting_keys::place_wait_reask_ms_in_txn(self, &txn, project)?
            };
            let blocked = vec![BlockedOn {
                machine: None,
                blocker: Blocker::DeciderWait {
                    decider: decider.to_hex(),
                    until_ms: now_ms.saturating_add(reask_ms),
                },
            }];
            self.block_order(order, blocked, false, now_ms, report)?;
            return Ok(None);
        }
        Ok(Some(
            match candidates
                .iter()
                .find(|facts| facts.machine.to_hex() == decision.pick)
                .copied()
            {
                Some(machine) => (machine, decision),
                // The options are the candidates', so this does not happen; the rule stands.
                None => (chosen, rule),
            },
        ))
    }

    /// AFTER (4.7): when the rule would retry `order` after its last attempt's `end`, the named
    /// decider picks among the options the end allows (`decision` lists them). It may give up
    /// sooner, or retry now where the rule waits; it never retries where the rule would not.
    pub(super) fn decide_after(
        &self,
        asks: &PassAsks<'_>,
        order: &WorkOrder,
        end: EndKind,
        pick: AfterPick,
        decision: SlotDecision,
        now_ms: u64,
    ) -> crate::Result<(AfterPick, SlotDecision)> {
        if matches!(pick, AfterPick::Done | AfterPick::GiveUp) || order.cancel.is_some() {
            return Ok((pick, decision));
        }
        let rule_pick = rule_fact(&decision);
        let facts = move || {
            json!({
                "rule": AFTER_RULE,
                "end": fact(&end),
                "attempt": order.attempts.len(),
                "ends": order
                    .attempts
                    .iter()
                    .filter_map(|attempt| attempt.end.as_ref().map(|ended| fact(&ended.kind)))
                    .collect::<Vec<Value>>(),
                "retry_on": fact(&order.retry_on),
                "rule_pick": rule_pick,
            })
        };
        let question = SlotQuestion {
            slot: SlotName::After,
            subject: SlotSubject::WorkOrder,
            scope: SlotScope::Order(order),
            options: decision.options.clone(),
            facts: Box::new(facts),
        };
        let decided = self.decide_slot(asks, question, decision)?;
        if !matches!(decided.by, DecidedBy::Grant { .. }) {
            return Ok((pick, decided));
        }
        let chosen = match decided.pick.as_str() {
            "retry_now" => AfterPick::RetryNow,
            "retry_at" => match pick {
                AfterPick::RetryAt(at_ms) => AfterPick::RetryAt(at_ms),
                _ => AfterPick::RetryAt(now_ms),
            },
            "done" => AfterPick::Done,
            _ => AfterPick::GiveUp,
        };
        Ok((chosen, decided))
    }
}
