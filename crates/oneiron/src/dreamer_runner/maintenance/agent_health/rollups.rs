//! The daily trend pass's rollups (OF-568 L3; agent-mind §3, "Daily. A trend
//! pass per actor and per project, over the rollups", and §4.4, "Rollups are
//! views, never a source of truth"): a read-only view over retained
//! evidence, computed at trend time from one read snapshot, never stored.
//!
//! It reads the attempt ledger with its retained archives (never restoring
//! one); each agent dispatch's actor, `project_ref` and task type; the call
//! receipts that witness an attempt; the agent-health DIAGNOSTICs, never the
//! trend pass's own; each attempt's launch spend scope; and the review jobs
//! that covered it. A bucket is one UTC day of witnessed terminal times, for
//! one actor or one direct project, within one task type and executor model.
//! The two margins are kept apart and never summed. Work bound to no project
//! is its own margin, never an ancestor's.
//!
//! Unknown stays unknown: a missing field, an erased or deleted source and a
//! failed read leave their items out of both sides of a ratio, with the
//! coverage saying so, and never count as zero. A failed read names its
//! source in [`HealthTrendRollups::failed`], with a kind-only warning, and
//! the other sources still read.

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use super::targeted::HealthReviewInput;
use super::trend_output::{TREND_DETECTOR_PREFIX, soft};
use super::trend_policy::{SECONDS_PER_DAY, TrendPeriods};
use super::{
    COACH_AGENT_HEALTH_FACET, Dispatched, WAIT_PERSON, covered, entity, read_dials, settled,
};
use crate::agent_dispatch::{AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatcher, SpendScope, SpendState};
use crate::attempt_queue::{AttemptId, AttemptRecord, AttemptState, decode_record};
use crate::dreamer_runner::maintenance::MAINTENANCE_QUEUE_KIND;
use crate::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload};
use crate::learning::{TeamEvent, team_events_from_attempts};
use crate::limit_ask::EngineLimit;
use crate::llm::run_admission::LeaseUnit;
use crate::ports::{EntityStoreRead, TombstoneStoreRead};
use crate::receipt::CallReceipt;
use crate::self_heal::{
    AgentHealthSignal, DiagnosticEventClass, ENTITY_TYPE_DIAGNOSTIC, decode_diagnostic_event_body,
};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};

/// The call receipt ledger, read in place.
const CALL_RECEIPTS: SideTable<EntityId, CallReceipt, Named> =
    SideTable::new(&side_table::CALL_RECEIPT);

/// Which margin a bucket counts toward. The two are never summed together.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TrendMargin {
    /// The dispatch's actor, over every project it worked in.
    Actor(EntityId),
    /// The dispatch's own `project_ref`; `None` is work bound to no project,
    /// its own margin, never folded into an ancestor.
    Project(Option<EntityId>),
}

/// What a comparison stays within, so a change of task mix or executor is
/// never read as the actor's or the project's.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrendStratum {
    /// The dispatch's task-type node, across tree versions.
    pub type_node: String,
    /// The executor model the attempt ran on; `None` when none was stamped.
    pub model: Option<String>,
}

/// One ratio with its coverage: `numerator / denominator` over the `known`
/// of `eligible` items. An unknown item is left out of both sides, never
/// counted as zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrendRatio {
    /// What is counted or summed.
    pub numerator: u64,
    /// What it is counted or summed over.
    pub denominator: u64,
    /// The items whose numbers are known.
    pub known: u64,
    /// Every item the ratio is about.
    pub eligible: u64,
}

impl TrendRatio {
    /// The ratio; `None` with nothing to divide by.
    #[must_use]
    pub fn value(&self) -> Option<f64> {
        (self.denominator > 0).then(|| self.numerator as f64 / self.denominator as f64)
    }

    /// Adds `other`'s counts to this one's.
    pub fn add(&mut self, other: &Self) {
        self.numerator = self.numerator.saturating_add(other.numerator);
        self.denominator = self.denominator.saturating_add(other.denominator);
        self.known = self.known.saturating_add(other.known);
        self.eligible = self.eligible.saturating_add(other.eligible);
    }
}

/// One T1 signal in one bucket: each attempt it was found on, once however
/// many findings name it, and the findings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrendSignalTally {
    /// The distinct affected attempts.
    pub attempts: BTreeSet<EntityId>,
    /// The DIAGNOSTICs that name them.
    pub diagnostics: BTreeSet<EntityId>,
    /// The detector ids those DIAGNOSTICs carry.
    pub detectors: BTreeSet<String>,
}

/// Own-scope launch spend in one unit: each scope once across its retries,
/// on its newest attempt, its closed children's spend taken out. An open
/// scope's spend is unknown.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrendSpendTally {
    /// Own spend over the closed scopes; known closed, eligible every scope.
    pub ratio: TrendRatio,
    /// The attempts whose closed scope is counted.
    pub attempts: BTreeSet<EntityId>,
    /// Every scope counted here, closed or open.
    pub scopes: BTreeSet<String>,
}

/// One UTC day of one margin and stratum: each number with its numerator,
/// denominator and coverage, and the typed refs it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthTrendRollup {
    /// The actor or the direct project.
    pub margin: TrendMargin,
    /// The task type and executor model.
    pub stratum: TrendStratum,
    /// The UTC day number (days since the epoch) of the witnessed terminal
    /// times.
    pub day: u64,
    /// The settled agent attempts.
    pub attempts: BTreeSet<EntityId>,
    /// Of those, the retries.
    pub retries: BTreeSet<EntityId>,
    /// Of those, the ones a review covered: a completed terminal review, a
    /// nightly review within its window after it settled, or a finding.
    pub checked: BTreeSet<EntityId>,
    /// Witnessed calls over the attempts whose calls are known.
    pub calls: TrendRatio,
    /// The call receipts counted.
    pub call_refs: BTreeSet<EntityId>,
    /// Distinct affected attempts per T1 signal found here.
    pub signals: BTreeMap<AgentHealthSignal, TrendSignalTally>,
    /// Own-scope spend, by unit.
    pub spend: BTreeMap<LeaseUnit, TrendSpendTally>,
    /// Attempts that launched unmetered: their spend is unknown.
    pub unmetered: u64,
    /// Observed wait seconds, not on a person, over attempt life seconds.
    /// Queue, backoff and pause spans only: never proof of no other wait.
    pub wait: TrendRatio,
    /// Observed wait seconds by reason.
    pub wait_by_reason: BTreeMap<String, u64>,
    /// The projects its attempts were bound to: an actor's span several.
    pub projects: BTreeSet<Option<EntityId>>,
}

/// A source the rollups read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TrendSource {
    /// The attempt ledger, archived rows included.
    Attempts,
    /// The comparison period.
    Policy,
    /// The witnessed call receipts.
    Calls,
    /// The agent-health DIAGNOSTICs.
    Diagnostics,
    /// The launch spend scopes.
    Spend,
    /// The review dials each attempt's scope resolves.
    Dials,
    /// The owner rows over the detection dials.
    DialRows,
}

/// The rollups, and what could not be read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HealthTrendRollups {
    /// One bucket per margin, stratum and day.
    pub buckets: Vec<HealthTrendRollup>,
    /// The period in force for each margin; `None` when it could not be read.
    pub periods: Option<TrendPeriods>,
    /// Sources whose read failed: every number they feed is unknown.
    pub failed: BTreeSet<TrendSource>,
    /// Ledger rows that did not decode, or agent dispatches whose actor,
    /// project or type did not: they reach no margin.
    pub unreadable_attempts: u64,
    /// DIAGNOSTIC rows deleted or undecodable: each may have been a finding.
    pub withheld_diagnostics: u64,
    /// Agent-health findings that name no attempt, so join no day.
    pub unjoined_diagnostics: u64,
}

/// The rollups for each margin over its own two periods before `today`, a
/// UTC day number, from one read snapshot. It never fails: a failed read
/// names its source in [`HealthTrendRollups::failed`].
#[must_use]
pub fn health_trend_rollups(vault: &Vault, today: u64) -> HealthTrendRollups {
    let mut out = HealthTrendRollups::default();
    let failed = &mut out.failed;
    let opened = vault.store.env.read_txn().map_err(Error::from);
    let Some(rtxn) = soft(failed, TrendSource::Attempts, opened) else {
        return out;
    };
    let Some(ledger) = soft(failed, TrendSource::Attempts, read_ledger(vault, &rtxn)) else {
        return out;
    };
    out.unreadable_attempts = ledger.unreadable;
    let projects: BTreeSet<EntityId> = ledger
        .agents
        .iter()
        .filter(|(record, _)| settled(record.state))
        .filter_map(|(_, dispatch)| dispatch.project)
        .collect();
    let periods = TrendPeriods::read_in(vault, &rtxn, &projects);
    let Some(periods) = soft(&mut out.failed, TrendSource::Policy, periods) else {
        return out;
    };
    let members = cohort(&ledger.agents, &periods, today);
    out.periods = Some(periods);
    let Some(earliest) = members
        .iter()
        .map(|member| ledger.agents[member.index].0.created_at)
        .min()
    else {
        return out;
    };
    let index: BTreeMap<[u8; 16], usize> = members
        .iter()
        .enumerate()
        .map(|(at, member)| (*member.id.as_bytes(), at))
        .collect();
    let mut facts: Vec<Facts> = members
        .iter()
        .map(|member| Facts {
            wait: wait_of(&ledger.agents[member.index].0),
            ..Facts::default()
        })
        .collect();

    let failed = &mut out.failed;
    let calls = read_calls(vault, &rtxn, &ledger.agents, &members, &index, earliest);
    if let Some(calls) = soft(failed, TrendSource::Calls, calls) {
        for (facts, calls) in facts.iter_mut().zip(calls) {
            facts.calls = calls;
        }
    }
    let found = read_findings(vault, &rtxn, &index, members.len());
    if let Some(found) = soft(failed, TrendSource::Diagnostics, found) {
        out.withheld_diagnostics = found.withheld;
        out.unjoined_diagnostics = found.unjoined;
        for (facts, signals) in facts.iter_mut().zip(found.by_member) {
            facts.signals = signals;
        }
    }
    let spend = read_spend(vault, &rtxn, &ledger.agents, &members, earliest);
    if let Some(spend) = soft(&mut out.failed, TrendSource::Spend, spend) {
        for (facts, spend) in facts.iter_mut().zip(spend) {
            facts.spend = spend;
        }
    }
    let checked = read_checked(vault, &rtxn, &ledger, &members);
    if let Some(checked) = soft(&mut out.failed, TrendSource::Dials, checked) {
        for (facts, checked) in facts.iter_mut().zip(checked) {
            facts.checked = checked;
        }
    }
    out.buckets = fold(&ledger.agents, &members, &facts);
    out
}

/// The ledger as the rollups read it.
#[derive(Default)]
struct Ledger {
    /// Every agent dispatch, any state.
    agents: Vec<(AttemptRecord, Dispatched)>,
    /// Rows that did not decode, and agent dispatches that did not.
    unreadable: u64,
    /// Attempts a terminal review completed on, by id bytes.
    terminal_reviews: BTreeSet<[u8; 16]>,
    /// When each nightly review completed, ascending.
    nightly_reviews: Vec<u64>,
}

/// Every ledger row, archived ones included, read in place and never
/// restored (as `learning::coordination` reads its teams).
fn read_ledger(vault: &Vault, rtxn: &heed::RoTxn<'_>) -> Result<Ledger> {
    let mut ledger = Ledger::default();
    let mut read: u64 = 0;
    for row in vault.store.attempt_records.iter(rtxn)? {
        read += 1;
        let (key, raw_record) = row?;
        let Ok(record) = AttemptId::from_bytes(&key).and_then(|id| decode_record(&raw_record, id))
        else {
            ledger.unreadable += 1;
            continue;
        };
        if record.kind == MAINTENANCE_QUEUE_KIND {
            if record.state == AttemptState::Completed
                && let Ok(payload) = decode_dreamer_attempt_payload(&record.payload)
                && payload.attempt_type == COACH_AGENT_HEALTH_FACET
            {
                match review_input(&payload.input) {
                    Some(HealthReviewInput::Nightly) => {
                        ledger.nightly_reviews.push(record.updated_at);
                    }
                    Some(HealthReviewInput::Terminal { attempt, .. }) => {
                        ledger.terminal_reviews.insert(*attempt.as_bytes());
                    }
                    Some(HealthReviewInput::Live { .. }) | None => {}
                }
            }
            continue;
        }
        if record.kind != DREAMER_RUNNER_ATTEMPT_KIND {
            continue;
        }
        let Ok(payload) = decode_dreamer_attempt_payload(&record.payload) else {
            ledger.unreadable += 1;
            continue;
        };
        if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
            continue;
        }
        match Dispatched::of(&record) {
            Some(dispatch) => ledger.agents.push((record, dispatch)),
            None => ledger.unreadable += 1,
        }
    }
    let _ = vault.measure_limit(EngineLimit::MaintenanceScanRows, read);
    ledger.nightly_reviews.sort_unstable();
    Ok(ledger)
}

/// A `coach.agent_health` job's input, as the job reads it: Nil is the
/// nightly review.
fn review_input(input: &Value) -> Option<HealthReviewInput> {
    if input.is_nil() {
        return Some(HealthReviewInput::Nightly);
    }
    serde_json::from_str(input.as_str()?).ok()
}

/// One settled agent attempt the rollups count, and the margins it counts in.
struct Member {
    /// Its row in the ledger's agents.
    index: usize,
    id: EntityId,
    /// The UTC day of its witnessed terminal time.
    day: u64,
    /// It falls in the actor's two periods.
    actor_span: bool,
    /// It falls in its project's two periods.
    project_span: bool,
}

/// Each settled agent attempt whose terminal day falls in its actor's or
/// its project's two periods before `today`. Today's partial day is never
/// read.
fn cohort(
    agents: &[(AttemptRecord, Dispatched)],
    periods: &TrendPeriods,
    today: u64,
) -> Vec<Member> {
    let mut members = Vec::new();
    for (index, (record, dispatch)) in agents.iter().enumerate() {
        if !settled(record.state) {
            continue;
        }
        let day = record.updated_at / SECONDS_PER_DAY;
        let within = |days: u64| day < today && day >= today.saturating_sub(days.saturating_mul(2));
        let actor_span = within(periods.vault);
        let project_span = within(periods.of_project(dispatch.project));
        if !actor_span && !project_span {
            continue;
        }
        let Some(id) = entity(record.id) else {
            continue;
        };
        members.push(Member {
            index,
            id,
            day,
            actor_span,
            project_span,
        });
    }
    members
}

/// One member's spend.
#[derive(Debug, Clone, Default)]
enum Spend {
    /// The spend read failed: nothing counted.
    #[default]
    Unread,
    /// It launched with no scope: its spend is unknown.
    Unmetered,
    /// Its scope is counted on a newer try of the same launch.
    Shared,
    /// Its scope, counted here: own spend once closed, else unknown.
    Scope {
        id: String,
        unit: LeaseUnit,
        own: Option<u64>,
    },
}

/// What one member adds to each bucket it counts in.
#[derive(Default)]
struct Facts {
    checked: bool,
    /// Its witnessed call receipts; `None` when they cannot be known.
    calls: Option<Vec<EntityId>>,
    /// Its findings by signal: the DIAGNOSTICs and their detectors.
    signals: BTreeMap<AgentHealthSignal, (BTreeSet<EntityId>, BTreeSet<String>)>,
    spend: Spend,
    /// Observed wait seconds, life seconds and wait by reason; `None` for an
    /// attempt with no life.
    wait: Option<(u64, u64, BTreeMap<String, u64>)>,
}

/// An attempt's observed waits not on a person, as the nightly review reads
/// them: queue, backoff and pause spans, their union over its life.
fn wait_of(record: &AttemptRecord) -> Option<(u64, u64, BTreeMap<String, u64>)> {
    let life = record.updated_at.saturating_sub(record.created_at);
    if life == 0 {
        return None;
    }
    let mut spans = Vec::new();
    let mut reasons: BTreeMap<String, u64> = BTreeMap::new();
    for event in team_events_from_attempts(std::slice::from_ref(record)) {
        if let TeamEvent::Wait {
            reason, start, end, ..
        } = event
            && reason != WAIT_PERSON
        {
            let seconds = reasons.entry(reason).or_default();
            *seconds = seconds.saturating_add(end.saturating_sub(start));
            spans.push((start, end));
        }
    }
    Some((covered(spans), life, reasons))
}

/// Each member's witnessed call receipts, by the attempt each names, newest
/// first back to the earliest member's creation. A member whose actor is no
/// longer live reads `None`: an erased actor's receipts no longer name their
/// attempts.
fn read_calls(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    agents: &[(AttemptRecord, Dispatched)],
    members: &[Member],
    index: &BTreeMap<[u8; 16], usize>,
    earliest: u64,
) -> Result<Vec<Option<Vec<EntityId>>>> {
    let mut live: BTreeMap<EntityId, bool> = BTreeMap::new();
    let mut calls = Vec::with_capacity(members.len());
    for member in members {
        let actor = agents[member.index].1.actor;
        let alive = match live.get(&actor) {
            Some(alive) => *alive,
            None => {
                let alive =
                    crate::vault::live_entity_row_in_txn(&vault.store, rtxn, &actor)?.is_live();
                live.insert(actor, alive);
                alive
            }
        };
        calls.push(alive.then(Vec::new));
    }
    let mut read: u64 = 0;
    for row in CALL_RECEIPTS.iter_rev_from(&vault.store, rtxn, &[])? {
        read += 1;
        let (id, receipt) = row?;
        if receipt.at < earliest {
            break;
        }
        let Some(witness) = receipt.attempt_ref else {
            continue;
        };
        if let Some(&at) = index.get(witness.attempt.as_bytes())
            && let Some(rows) = &mut calls[at]
        {
            rows.push(id);
        }
    }
    let _ = vault.measure_limit(EngineLimit::MaintenanceScanRows, read);
    Ok(calls)
}

/// The agent-health findings on each member.
struct Findings {
    by_member: Vec<BTreeMap<AgentHealthSignal, (BTreeSet<EntityId>, BTreeSet<String>)>>,
    withheld: u64,
    unjoined: u64,
}

/// Every agent-health DIAGNOSTIC but the trend pass's own, joined to the
/// attempt its replay coordinate names, deduped per attempt and signal by
/// the tally. A deleted or undecodable row is withheld, never read as no
/// finding.
fn read_findings(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    index: &BTreeMap<[u8; 16], usize>,
    members: usize,
) -> Result<Findings> {
    let mut found = Findings {
        by_member: vec![BTreeMap::new(); members],
        withheld: 0,
        unjoined: 0,
    };
    let mut read: u64 = 0;
    for entry in vault
        .store
        .port_entity_ids_by_type(rtxn, ENTITY_TYPE_DIAGNOSTIC, None)?
    {
        read += 1;
        let id = entry?;
        let state = vault.store.port_deletion_state(rtxn, &id)?;
        let event = match vault.store.port_entity_record(rtxn, &id)? {
            Some(row) if !state.deleted && !state.stale => {
                decode_diagnostic_event_body(&row.body).ok()
            }
            _ => None,
        };
        let Some(event) = event else {
            found.withheld += 1;
            continue;
        };
        let (DiagnosticEventClass::AgentHealth, Some(signal)) = (event.event_class, event.signal)
        else {
            continue;
        };
        if event.detector_id.starts_with(TREND_DETECTOR_PREFIX) {
            continue;
        }
        let attempt = event
            .replay
            .run_ref
            .as_deref()
            .and_then(|run| run.strip_prefix("attempt:"))
            .and_then(|hex| EntityId::from_hex(hex).ok());
        let Some(attempt) = attempt else {
            found.unjoined += 1;
            continue;
        };
        if let Some(&at) = index.get(attempt.as_bytes()) {
            let (diagnostics, detectors) = found.by_member[at].entry(signal).or_default();
            diagnostics.insert(id);
            detectors.insert(event.detector_id);
        }
    }
    let _ = vault.measure_limit(EngineLimit::MaintenanceScanRows, read);
    Ok(found)
}

/// Each member's launch spend. A launch's retries share one scope, counted
/// once on its newest try; a member that is not that try is `Shared`. Every
/// child a member's scope spawned was created after it, so the scopes of the
/// agent attempts created from the earliest member on hold every child to
/// take out.
fn read_spend(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    agents: &[(AttemptRecord, Dispatched)],
    members: &[Member],
    earliest: u64,
) -> Result<Vec<Spend>> {
    let dispatcher = AgentDispatcher::new(vault);
    let mut scopes: BTreeMap<String, SpendScope> = BTreeMap::new();
    let mut scope_of: BTreeMap<usize, String> = BTreeMap::new();
    let mut newest: BTreeMap<String, usize> = BTreeMap::new();
    for (at, (record, _)) in agents.iter().enumerate() {
        if record.created_at < earliest {
            continue;
        }
        let Some(scope) = dispatcher.attempt_spend_scope_in_txn(rtxn, record.id)? else {
            continue;
        };
        let name = scope.scope.to_string();
        let newer = newest.get(&name).is_none_or(|held| {
            let held = &agents[*held].0;
            (held.updated_at, held.id.as_bytes()) <= (record.updated_at, record.id.as_bytes())
        });
        if newer {
            newest.insert(name.clone(), at);
        }
        scope_of.insert(at, name.clone());
        scopes.entry(name).or_insert(scope);
    }
    let mut children: BTreeMap<String, u64> = BTreeMap::new();
    for scope in scopes.values() {
        if scope.state == SpendState::Closed
            && let Some(parent) = &scope.parent
        {
            let spent = children.entry(parent.to_string()).or_default();
            *spent = spent.saturating_add(scope.spent_units);
        }
    }
    let mut spend = Vec::with_capacity(members.len());
    for member in members {
        let Some(name) = scope_of.get(&member.index) else {
            spend.push(Spend::Unmetered);
            continue;
        };
        if newest.get(name) != Some(&member.index) {
            spend.push(Spend::Shared);
            continue;
        }
        let scope = &scopes[name];
        spend.push(Spend::Scope {
            id: name.clone(),
            unit: scope.unit.clone(),
            own: (scope.state == SpendState::Closed).then(|| {
                scope
                    .spent_units
                    .saturating_sub(children.get(name).copied().unwrap_or(0))
            }),
        });
    }
    Ok(spend)
}

/// Whether a review covered each member: its scope's review is on, and a
/// terminal review of it completed, or a nightly review completed within
/// its scope's review window after it settled.
fn read_checked(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    ledger: &Ledger,
    members: &[Member],
) -> Result<Vec<bool>> {
    let mut dials: BTreeMap<(Option<EntityId>, String), (bool, u64)> = BTreeMap::new();
    let mut checked = Vec::with_capacity(members.len());
    for member in members {
        let (record, dispatch) = &ledger.agents[member.index];
        let key = (dispatch.project, dispatch.type_node.clone());
        let (review, window) = match dials.get(&key) {
            Some(scope) => *scope,
            None => {
                let read = read_dials(vault, rtxn, dispatch.project, Some(&dispatch.type_node))?;
                let scope = (read.review, read.window_secs);
                dials.insert(key, scope);
                scope
            }
        };
        let end = record.updated_at;
        let next = ledger.nightly_reviews.partition_point(|at| *at < end);
        let nightly = ledger
            .nightly_reviews
            .get(next)
            .is_some_and(|at| *at <= end.saturating_add(window));
        let terminal = ledger.terminal_reviews.contains(record.id.as_bytes());
        checked.push(review && (nightly || terminal));
    }
    Ok(checked)
}

/// Each member folded into its actor's and its project's bucket, as its
/// spans allow.
fn fold(
    agents: &[(AttemptRecord, Dispatched)],
    members: &[Member],
    facts: &[Facts],
) -> Vec<HealthTrendRollup> {
    let mut buckets: BTreeMap<(TrendMargin, TrendStratum, u64), HealthTrendRollup> =
        BTreeMap::new();
    for (member, facts) in members.iter().zip(facts) {
        let (record, dispatch) = &agents[member.index];
        let stratum = TrendStratum {
            type_node: dispatch.type_node.clone(),
            model: record.executor_model.clone(),
        };
        let margins = [
            member
                .actor_span
                .then_some(TrendMargin::Actor(dispatch.actor)),
            member
                .project_span
                .then_some(TrendMargin::Project(dispatch.project)),
        ];
        for margin in margins.into_iter().flatten() {
            let key = (margin.clone(), stratum.clone(), member.day);
            buckets
                .entry(key)
                .or_insert_with(|| HealthTrendRollup::empty(margin, stratum.clone(), member.day))
                .add(
                    member.id,
                    record.retry_of.is_some(),
                    dispatch.project,
                    facts,
                );
        }
    }
    buckets.into_values().collect()
}

impl HealthTrendRollup {
    fn empty(margin: TrendMargin, stratum: TrendStratum, day: u64) -> Self {
        Self {
            margin,
            stratum,
            day,
            attempts: BTreeSet::new(),
            retries: BTreeSet::new(),
            checked: BTreeSet::new(),
            calls: TrendRatio::default(),
            call_refs: BTreeSet::new(),
            signals: BTreeMap::new(),
            spend: BTreeMap::new(),
            unmetered: 0,
            wait: TrendRatio::default(),
            wait_by_reason: BTreeMap::new(),
            projects: BTreeSet::new(),
        }
    }

    /// Counts one attempt. An attempt with a finding was reviewed.
    fn add(&mut self, id: EntityId, retry: bool, project: Option<EntityId>, facts: &Facts) {
        self.attempts.insert(id);
        self.projects.insert(project);
        if retry {
            self.retries.insert(id);
        }
        if facts.checked || !facts.signals.is_empty() {
            self.checked.insert(id);
        }
        self.calls.eligible += 1;
        if let Some(calls) = &facts.calls {
            self.calls.add(&TrendRatio {
                numerator: calls.len() as u64,
                denominator: 1,
                known: 1,
                eligible: 0,
            });
            self.call_refs.extend(calls.iter().copied());
        }
        for (signal, (diagnostics, detectors)) in &facts.signals {
            let tally = self.signals.entry(*signal).or_default();
            tally.attempts.insert(id);
            tally.diagnostics.extend(diagnostics.iter().copied());
            tally.detectors.extend(detectors.iter().cloned());
        }
        match &facts.spend {
            Spend::Scope {
                id: scope,
                unit,
                own,
            } => {
                let tally = self.spend.entry(unit.clone()).or_default();
                tally.scopes.insert(scope.clone());
                tally.ratio.eligible += 1;
                if let Some(own) = own {
                    tally.ratio.add(&TrendRatio {
                        numerator: *own,
                        denominator: 1,
                        known: 1,
                        eligible: 0,
                    });
                    tally.attempts.insert(id);
                }
            }
            Spend::Unmetered => self.unmetered += 1,
            Spend::Unread | Spend::Shared => {}
        }
        self.wait.eligible += 1;
        if let Some((wait, life, reasons)) = &facts.wait {
            self.wait.add(&TrendRatio {
                numerator: *wait,
                denominator: *life,
                known: 1,
                eligible: 0,
            });
            for (reason, seconds) in reasons {
                let total = self.wait_by_reason.entry(reason.clone()).or_default();
                *total = total.saturating_add(*seconds);
            }
        }
    }
}
