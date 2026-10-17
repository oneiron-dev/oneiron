//! The Coach's agent-health review (OF-568, agent-mind §3): a closed-form T1
//! recipe on the gated maintenance lane, run on the Coach's timer wake. It
//! reads call receipts, attempt rows, run coordination and sealed attempt
//! receipts. Each finding is one `agent_health` DIAGNOSTIC, merged into one
//! card per actor, signal and task.
//!
//! It never stops an agent and never narrows a grant or scope: its output is
//! cards and proposed moves, and an agent-health event never feeds the auto
//! arm (`Vault::is_signed_tripwire`). It reads no diary.

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchInput, agent_dispatch_actor,
    decode_agent_dispatch_input,
};
use crate::agent_inbox_lens::{
    AgentInboxConcern, AgentInboxItemKind, AgentInboxLensItem, AgentInboxParticipant, InboxImpact,
};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::consent::AuthenticatedOwner;
use crate::learning::{TeamEvent, project_run_coordination, team_events_from_attempts};
use crate::learning_setting::{SettingSpec, setting_value_in_txn};
use crate::receipt::{CallOutcome, CallReceipt};
use crate::self_heal::{
    AgentHealthSignal, DiagnosticCriticality, DiagnosticEvent, DiagnosticEventClass,
    DiagnosticReplayCoordinate, DiagnosticSourceKind, diagnostic_event_id,
    encode_diagnostic_event_body,
};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};

/// The recipe's facet. It rides the Coach's timer jobs (`MAINTENANCE_FACETS`),
/// deduped per wake.
pub const COACH_AGENT_HEALTH_FACET: &str = "coach.agent_health";

/// The review runs at all (1) or not (0).
pub const HEALTH_REVIEW: SettingSpec = SettingSpec {
    key: "health.review",
    min: 0.0,
    max: 1.0,
    seed: 1.0,
};

/// `loop`: identical calls in a row, with no other call between them.
pub const HEALTH_LOOP_REPEATS: SettingSpec = SettingSpec {
    key: "health.loop.repeats",
    min: 2.0,
    max: 100.0,
    seed: 3.0,
};

/// `failed_check_repeat`: the canon failure-ladder N. No capture reads it yet.
pub const HEALTH_CHECK_FAILS: SettingSpec = SettingSpec {
    key: "health.check.fails",
    min: 2.0,
    max: 100.0,
    seed: 3.0,
};

/// `long_wait`: the share of an attempt's life spent waiting, not on a person.
pub const HEALTH_WAIT_SHARE: SettingSpec = SettingSpec {
    key: "health.wait.share",
    min: 0.05,
    max: 1.0,
    seed: 0.5,
};

/// `long_wait`: the shortest attempt life the share is judged over.
pub const HEALTH_WAIT_MINUTES: SettingSpec = SettingSpec {
    key: "health.wait.minutes",
    min: 1.0,
    max: 1440.0,
    seed: 10.0,
};

/// `silent`: minutes a leased attempt may go without a call.
pub const HEALTH_SILENT_MINUTES: SettingSpec = SettingSpec {
    key: "health.silent.minutes",
    min: 1.0,
    max: 10080.0,
    seed: 30.0,
};

/// `misalignment`: widen denials in one attempt. No capture reads it yet.
pub const HEALTH_WIDEN_DENIALS: SettingSpec = SettingSpec {
    key: "health.widen.denials",
    min: 1.0,
    max: 100.0,
    seed: 3.0,
};

/// Hours an open card waits on its leader before the owner gets a copy.
pub const HEALTH_ESCALATE_TTL_HOURS: SettingSpec = SettingSpec {
    key: "health.escalate.ttl_hours",
    min: 1.0,
    max: 720.0,
    seed: 24.0,
};

/// How far back one review reads receipts and settled attempts.
const LOOKBACK_SECS: u64 = 24 * 60 * 60;
/// Most call receipts one review reads, newest first.
const MAX_CALL_SCAN: usize = 50_000;
/// Most evidence refs one card keeps, newest kept.
const MAX_CARD_EVIDENCE: usize = 256;
/// Most DIAGNOSTIC ids one card keeps, newest kept.
const MAX_CARD_DIAGNOSTICS: usize = 64;
/// A DIAGNOSTIC cites at most this many evidence refs.
const MAX_EVENT_EVIDENCE: usize = 64;
/// A wait on a person is not a problem (agent-mind §3.4).
const WAIT_PERSON: &str = "person";
const HEALTH_DIGEST_DOMAIN: &[u8] = b"oneiron.coach.agent_health.evidence.v1";
const CARD_REF_PREFIX: &str = "health:";

/// Open cards, keyed `(actor, signal, task or zero)`.
const CARDS: SideTable<([u8; 16], [u8; 1], [u8; 16]), AgentHealthCard, Named> =
    SideTable::new(&side_table::COACH_AGENT_HEALTH_CARD);
/// The call receipt ledger, read in place.
const CALL_RECEIPTS: SideTable<EntityId, CallReceipt, Named> =
    SideTable::new(&side_table::CALL_RECEIPT);

/// How a card reads (agent-mind §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentHealthTone {
    /// Loops, failed checks, silence, long waits, cost.
    Struggling,
    /// Drift from the brief. No v1 signal reads this way.
    OffCourse,
    /// Misalignment. Always reaches the owner.
    Concern,
}

impl AgentHealthTone {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Struggling => "struggling",
            Self::OffCourse => "off_course",
            Self::Concern => "concern",
        }
    }

    #[must_use]
    pub const fn of(signal: AgentHealthSignal) -> Self {
        match signal {
            AgentHealthSignal::Misalignment => Self::Concern,
            AgentHealthSignal::Loop
            | AgentHealthSignal::FailedCheckRepeat
            | AgentHealthSignal::CostSpike
            | AgentHealthSignal::LongWait
            | AgentHealthSignal::Silent
            | AgentHealthSignal::DuplicateWork
            | AgentHealthSignal::UnsupportedDone => Self::Struggling,
        }
    }

    const fn impact(self) -> u16 {
        match self {
            Self::Struggling => 100,
            Self::OffCourse => 150,
            Self::Concern => 200,
        }
    }
}

/// A move the card proposes. A leader or the owner takes it; the Coach never
/// does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentHealthMove {
    /// Say a note to the agent.
    Note,
    /// Steer it at its next safe breakpoint.
    Steer,
    /// Change its budget.
    Budget,
    /// Give the task to another seat.
    Reassign,
    /// Ask the Coach: a skill edit, or a prompt-inject plus fork-resume.
    AskCoach,
    /// Hold the run, resumably.
    Hold,
}

/// What lowers a signal, or names another possible cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentHealthCounter {
    /// The repeated call got different answers: it may be polling.
    ResultsChanged,
    /// The repeated call was refused each time: the cause may be systemic.
    RefusedCalls,
    /// Most of the wait was in the queue: the cause may be systemic.
    QueueWait,
}

/// Low when counter-evidence stands against the signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentHealthConfidence {
    High,
    Low,
}

/// Set by the leader or the owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentHealthOutcome {
    Open,
    Confirmed,
    Dismissed,
    Unresolved,
}

impl AgentHealthOutcome {
    /// Parses an outcome a person sets; `open` is the review's alone.
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "confirmed" => Some(Self::Confirmed),
            "dismissed" => Some(Self::Dismissed),
            "unresolved" => Some(Self::Unresolved),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Confirmed => "confirmed",
            Self::Dismissed => "dismissed",
            Self::Unresolved => "unresolved",
        }
    }
}

/// One agent-health card (agent-mind §3.5): one per actor, signal and task.
/// Repeats merge into it. It holds refs and numbers, never a diary body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthCard {
    /// The agent the card is about.
    pub subject: EntityId,
    pub signal: AgentHealthSignal,
    pub task: Option<EntityId>,
    /// The newest attempt the evidence came from.
    pub attempt: Option<EntityId>,
    pub tone: AgentHealthTone,
    /// 1: deterministic counts over receipts.
    pub tier: u8,
    pub confidence: AgentHealthConfidence,
    /// The `agent_health` DIAGNOSTIC events, newest last.
    pub diagnostics: Vec<EntityId>,
    /// Receipt and attempt ids, newest last.
    pub evidence: Vec<EntityId>,
    pub window_from: u64,
    pub window_to: u64,
    /// The number the dial was held against, and the dial.
    pub measured: i64,
    pub dial: i64,
    pub counter_evidence: Vec<AgentHealthCounter>,
    /// The agent said it was stuck: its TASK is Blocked.
    pub agent_blocked: bool,
    /// The attempt whose sealed receipt holds the agent's confession.
    pub confession: Option<EntityId>,
    pub moves: Vec<AgentHealthMove>,
    /// The leader, the spawner, and the owners when they get a copy.
    pub recipients: Vec<EntityId>,
    pub owner_copy: bool,
    pub outcome: AgentHealthOutcome,
    pub outcome_by: Option<EntityId>,
    pub outcome_at: Option<u64>,
    /// Evidence count when the outcome was set. A settled card reopens only
    /// when its evidence grows past it.
    pub watermark: usize,
    pub opened_at: u64,
    pub updated_at: u64,
}

impl AgentHealthCard {
    /// The card's handle: `health:<subject>:<signal>:<task or zeros>`.
    #[must_use]
    pub fn card_ref(&self) -> String {
        card_ref(&card_key(self.subject, self.signal, self.task))
    }
}

/// One detection before it merges into its card.
struct Finding {
    subject: EntityId,
    signal: AgentHealthSignal,
    task: Option<EntityId>,
    attempt: Option<AttemptId>,
    evidence: Vec<EntityId>,
    window: (u64, u64),
    /// The stable number the DIAGNOSTIC carries, and the dial.
    actual: i64,
    dial: i64,
    /// The number the card shows; it may move while the evidence holds.
    measured: i64,
    counter: Vec<AgentHealthCounter>,
    confession: Option<EntityId>,
}

/// The working set's attempts, and its agent dispatches, by attempt bytes.
type Attempts = BTreeMap<[u8; 16], AttemptRecord>;
type Dispatches = BTreeMap<[u8; 16], Dispatched>;

/// The dials in force for one review.
struct Dials {
    loop_repeats: u64,
    wait_share: f64,
    wait_secs: u64,
    silent_secs: u64,
    ttl_secs: u64,
}

/// One review: detect, emit, merge, escalate. Returns the cards it touched.
pub(super) fn run(vault: &Vault, now: u64) -> Result<u64> {
    let dials = {
        let rtxn = vault.store.env.read_txn()?;
        let value = |spec: &SettingSpec| setting_value_in_txn(&vault.store, &rtxn, spec);
        if value(&HEALTH_REVIEW)? < 0.5 {
            return Ok(0);
        }
        Dials {
            loop_repeats: value(&HEALTH_LOOP_REPEATS)?.round() as u64,
            wait_share: value(&HEALTH_WAIT_SHARE)?,
            wait_secs: (value(&HEALTH_WAIT_MINUTES)? * 60.0).round() as u64,
            silent_secs: (value(&HEALTH_SILENT_MINUTES)? * 60.0).round() as u64,
            ttl_secs: (value(&HEALTH_ESCALATE_TTL_HOURS)? * 3600.0).round() as u64,
        }
    };
    let since = now.saturating_sub(LOOKBACK_SECS);
    let calls = agent_calls(vault, since)?;
    let attempts: Attempts = AttemptQueue::new(vault)
        .list()?
        .into_iter()
        .map(|record| (*record.id.as_bytes(), record))
        .collect();
    let dispatched: Dispatches = attempts
        .iter()
        .filter_map(|(key, record)| Dispatched::of(record).map(|dispatch| (*key, dispatch)))
        .collect();

    let mut findings = loop_findings(&calls, &dispatched, &attempts, dials.loop_repeats);
    findings.extend(silent_findings(
        vault,
        &calls,
        &dispatched,
        &attempts,
        &dials,
        now,
    )?);
    findings.extend(long_wait_findings(&dispatched, &attempts, &dials, since));
    findings.extend(duplicate_findings(
        vault,
        &dispatched,
        &attempts,
        since,
        now,
    )?);
    findings.extend(misalignment_findings(vault, &dispatched, &attempts, since)?);

    // Each finding's DIAGNOSTIC, in its own write: the event door opens one.
    let mut emitted = Vec::with_capacity(findings.len());
    for finding in &findings {
        emitted.push(emit(vault, finding)?);
    }

    // Recipients from live authority: the project's effective leader, the
    // spawner by dispatch lineage, and the vault's live owners.
    let (owners, routes) = {
        let rtxn = vault.store.env.read_txn()?;
        let owners = crate::policy_model::owners_in_txn(vault, &rtxn)?;
        let mut routes = Vec::with_capacity(findings.len());
        for finding in &findings {
            routes.push(route(vault, &rtxn, finding, &dispatched, &attempts)?);
        }
        (owners, routes)
    };

    vault.with_write_txn_grouped(|txn| {
        let mut touched = BTreeSet::new();
        for ((finding, diagnostic), route) in findings.iter().zip(&emitted).zip(&routes) {
            let key = card_key(finding.subject, finding.signal, finding.task);
            let card = CARDS.get(&vault.store, txn, &key)?;
            let card = merge(card, finding, *diagnostic, route, &owners, now);
            CARDS.put(&vault.store, txn, &key, &card)?;
            touched.insert(key);
        }
        // A card its leader leaves open past the TTL goes up to the owner.
        for (key, mut card) in CARDS.scan(&vault.store, txn)? {
            if card.outcome == AgentHealthOutcome::Open
                && !card.owner_copy
                && now >= card.opened_at.saturating_add(dials.ttl_secs)
            {
                card.owner_copy = true;
                add_recipients(&mut card.recipients, card.subject, &owners);
                CARDS.put(&vault.store, txn, &key, &card)?;
                touched.insert(key);
            }
        }
        Ok(touched.len() as u64)
    })
}

/// An agent-dispatch attempt's actor, project and parent.
struct Dispatched {
    actor: EntityId,
    project: Option<EntityId>,
    parent: Option<AttemptId>,
}

impl Dispatched {
    fn of(record: &AttemptRecord) -> Option<Self> {
        if record.kind != crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND {
            return None;
        }
        let payload =
            crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload).ok()?;
        if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
            return None;
        }
        let input: AgentDispatchInput = decode_agent_dispatch_input(&payload.input).ok()?;
        Some(Self {
            actor: agent_dispatch_actor(&input).ok()?.entity_ref(),
            project: input.project_ref,
            parent: payload.parent_attempt,
        })
    }
}

/// Each agent's calls in the lookback, oldest first.
fn agent_calls(
    vault: &Vault,
    since: u64,
) -> Result<BTreeMap<EntityId, Vec<(EntityId, CallReceipt)>>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut calls: BTreeMap<EntityId, Vec<(EntityId, CallReceipt)>> = BTreeMap::new();
    for row in CALL_RECEIPTS
        .iter_rev_from(&vault.store, &rtxn, &[])?
        .take(MAX_CALL_SCAN)
    {
        let Ok((id, receipt)) = row else {
            continue;
        };
        if receipt.at < since {
            break;
        }
        if receipt.actor_class != "agent" {
            continue;
        }
        let Ok(actor) = EntityId::from_hex(&receipt.actor_ref) else {
            continue;
        };
        calls.entry(actor).or_default().push((id, receipt));
    }
    for rows in calls.values_mut() {
        rows.reverse();
    }
    Ok(calls)
}

fn entity(attempt: AttemptId) -> Option<EntityId> {
    EntityId::from_bytes(*attempt.as_bytes()).ok()
}

fn task_of(record: &AttemptRecord) -> Option<EntityId> {
    record
        .task_ref
        .as_deref()
        .and_then(|task| EntityId::from_hex(task).ok())
}

fn settled(state: AttemptState) -> bool {
    matches!(
        state,
        AttemptState::Completed
            | AttemptState::Failed
            | AttemptState::Cancelled
            | AttemptState::Abandoned
    )
}

/// The actor's newest leased attempt, the one its calls belong to.
fn live_attempt(
    actor: EntityId,
    dispatched: &Dispatches,
    attempts: &Attempts,
) -> Option<AttemptId> {
    dispatched
        .iter()
        .filter(|(_, dispatch)| dispatch.actor == actor)
        .filter_map(|(key, _)| attempts.get(key))
        .filter(|record| record.state == AttemptState::Leased)
        .max_by_key(|record| record.updated_at)
        .map(|record| record.id)
}

/// `loop`: one actor's identical `(verb, request_digest)` calls in a row, with
/// no other call by that actor between them. A call receipt names no attempt,
/// so the card's task is none.
fn loop_findings(
    calls: &BTreeMap<EntityId, Vec<(EntityId, CallReceipt)>>,
    dispatched: &Dispatches,
    attempts: &Attempts,
    repeats: u64,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for (actor, rows) in calls {
        let mut start = 0;
        while start < rows.len() {
            let first = &rows[start].1;
            let end = rows[start..]
                .iter()
                .position(|(_, row)| {
                    row.verb != first.verb || row.request_digest != first.request_digest
                })
                .map_or(rows.len(), |offset| start + offset);
            let run = &rows[start..end];
            start = end;
            if (run.len() as u64) < repeats {
                continue;
            }
            let mut counter = Vec::new();
            let results: BTreeSet<_> = run.iter().map(|(_, row)| &row.result_digest).collect();
            if results.len() > 1 {
                counter.push(AgentHealthCounter::ResultsChanged);
            }
            if run
                .iter()
                .all(|(_, row)| matches!(row.outcome, CallOutcome::Refused { .. }))
            {
                counter.push(AgentHealthCounter::RefusedCalls);
            }
            let count = run.len() as i64;
            out.push(Finding {
                subject: *actor,
                signal: AgentHealthSignal::Loop,
                task: None,
                attempt: live_attempt(*actor, dispatched, attempts),
                evidence: run.iter().map(|(id, _)| *id).collect(),
                window: (run[0].1.at, run[run.len() - 1].1.at),
                actual: count,
                dial: repeats as i64,
                measured: count,
                counter,
                confession: None,
            });
        }
    }
    out
}

/// `silent`: a leased attempt whose actor made no call within the dial, with
/// no Blocked TASK and no open ask. Saying it is stuck is the honest move.
fn silent_findings(
    vault: &Vault,
    calls: &BTreeMap<EntityId, Vec<(EntityId, CallReceipt)>>,
    dispatched: &Dispatches,
    attempts: &Attempts,
    dials: &Dials,
    now: u64,
) -> Result<Vec<Finding>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for (id, dispatch) in dispatched {
        let Some(record) = attempts.get(id) else {
            continue;
        };
        if record.state != AttemptState::Leased {
            continue;
        }
        let claimed = record.claimed_at.unwrap_or(record.updated_at);
        let last_call = calls
            .get(&dispatch.actor)
            .and_then(|rows| rows.last())
            .map_or(0, |(_, row)| row.at);
        let active = claimed.max(last_call);
        let quiet = now.saturating_sub(active);
        if quiet < dials.silent_secs {
            continue;
        }
        let waiting = record
            .asks
            .iter()
            .any(|ask| ask.answers.len() < ask.questions.len());
        let task = task_of(record);
        let blocked = match task {
            Some(task) => crate::task_verb::task_is_blocked_in(vault, &rtxn, task)?,
            None => false,
        };
        if waiting || blocked {
            continue;
        }
        let Some(attempt) = entity(record.id) else {
            continue;
        };
        out.push(Finding {
            subject: dispatch.actor,
            signal: AgentHealthSignal::Silent,
            task,
            attempt: Some(record.id),
            evidence: vec![attempt],
            window: (active, now),
            actual: 0,
            dial: 1,
            measured: quiet as i64,
            counter: Vec::new(),
            confession: None,
        });
    }
    Ok(out)
}

/// `long_wait`: a settled attempt that spent more than the dial's share of its
/// life waiting, not on a person, over at least the dial's minutes. Only
/// settled attempts have a closed life to measure.
fn long_wait_findings(
    dispatched: &Dispatches,
    attempts: &Attempts,
    dials: &Dials,
    since: u64,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for (id, dispatch) in dispatched {
        let Some(record) = attempts.get(id) else {
            continue;
        };
        if !settled(record.state) || record.updated_at < since {
            continue;
        }
        let life = record.updated_at.saturating_sub(record.created_at);
        if life == 0 || life < dials.wait_secs {
            continue;
        }
        let mut wait = 0_u64;
        let mut queue = 0_u64;
        for event in team_events_from_attempts(std::slice::from_ref(record)) {
            if let TeamEvent::Wait {
                reason, start, end, ..
            } = event
                && reason != WAIT_PERSON
            {
                let span = end.saturating_sub(start);
                wait += span;
                if reason == crate::learning::coordination::WAIT_QUEUE {
                    queue += span;
                }
            }
        }
        let share = wait as f64 / life as f64;
        if share <= dials.wait_share {
            continue;
        }
        let Some(attempt) = entity(record.id) else {
            continue;
        };
        let permille = (share * 1000.0).round() as i64;
        let mut counter = Vec::new();
        if queue * 2 > wait {
            counter.push(AgentHealthCounter::QueueWait);
        }
        out.push(Finding {
            subject: dispatch.actor,
            signal: AgentHealthSignal::LongWait,
            task: task_of(record),
            attempt: Some(record.id),
            evidence: vec![attempt],
            window: (record.created_at, record.updated_at),
            actual: permille,
            dial: (dials.wait_share * 1000.0).round() as i64,
            measured: permille,
            counter,
            confession: None,
        });
    }
    out
}

/// `duplicate_work`: the run's audit-labelled duplicates. The card goes on the
/// agent that did the second piece of work.
fn duplicate_findings(
    vault: &Vault,
    dispatched: &Dispatches,
    attempts: &Attempts,
    since: u64,
    now: u64,
) -> Result<Vec<Finding>> {
    let runs: BTreeSet<&str> = dispatched
        .keys()
        .filter_map(|id| attempts.get(id))
        .filter(|record| record.updated_at >= since)
        .filter_map(|record| record.run_id.as_deref())
        .collect();
    let mut out = Vec::new();
    for run in runs {
        let cost = project_run_coordination(vault, run, now)?;
        for label in &cost.duplicate_work {
            // A work reference is the TASK the attempt did, or the attempt.
            let does = |reference: &str| {
                dispatched.iter().find_map(|(key, dispatch)| {
                    attempts
                        .get(key)
                        .filter(|record| {
                            record.run_id.as_deref() == Some(run)
                                && (record.task_ref.as_deref() == Some(reference)
                                    || crate::entity_id::bytes_to_hex_lower(key) == reference)
                        })
                        .map(|record| (record, dispatch))
                })
            };
            let Some((record, dispatch)) = does(&label.second) else {
                continue;
            };
            let mut evidence: Vec<EntityId> =
                [Some(record), does(&label.first).map(|(first, _)| first)]
                    .into_iter()
                    .flatten()
                    .filter_map(|record| entity(record.id))
                    .collect();
            evidence.extend(EntityId::from_hex(&label.audit_receipt).ok());
            out.push(Finding {
                subject: dispatch.actor,
                signal: AgentHealthSignal::DuplicateWork,
                task: task_of(record),
                attempt: Some(record.id),
                evidence,
                window: (record.created_at, record.updated_at),
                actual: 1,
                dial: 0,
                measured: 1,
                counter: Vec::new(),
                confession: None,
            });
        }
    }
    Ok(out)
}

/// `misalignment`: an audit found a flaw in an objective the agent's
/// confession called met with no flaw. A confession alone never flags.
fn misalignment_findings(
    vault: &Vault,
    dispatched: &Dispatches,
    attempts: &Attempts,
    since: u64,
) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    for (id, dispatch) in dispatched {
        let Some(record) = attempts.get(id) else {
            continue;
        };
        if !settled(record.state) || record.updated_at < since {
            continue;
        }
        let Some(sealed) = vault.sealed_attempt_receipt(record.id)? else {
            continue;
        };
        let mut unreported = BTreeSet::new();
        let mut evidence = Vec::new();
        let mut checked_at = sealed.sealed_at;
        for check in &sealed.checks {
            let Some(outcome) = &check.outcome else {
                continue;
            };
            for finding in outcome
                .findings
                .iter()
                .filter(|finding| finding.flaw_present)
            {
                let reported = sealed
                    .confession
                    .objectives
                    .iter()
                    .any(|said| said.objective == finding.objective && said.confesses_flaw());
                if !reported && unreported.insert(finding.objective.as_str()) {
                    evidence.extend(EntityId::from_hex(&finding.evidence_ref).ok());
                    checked_at = checked_at.max(outcome.checked_at);
                }
            }
        }
        if unreported.is_empty() {
            continue;
        }
        let Some(attempt) = entity(record.id) else {
            continue;
        };
        evidence.insert(0, attempt);
        let count = unreported.len() as i64;
        out.push(Finding {
            subject: dispatch.actor,
            signal: AgentHealthSignal::Misalignment,
            task: task_of(record),
            attempt: Some(record.id),
            evidence,
            window: (sealed.sealed_at, checked_at),
            actual: count,
            dial: 0,
            measured: count,
            counter: Vec::new(),
            confession: Some(attempt),
        });
    }
    Ok(out)
}

/// Writes the finding's DIAGNOSTIC once: the same evidence is the same body
/// and the same id.
fn emit(vault: &Vault, finding: &Finding) -> Result<EntityId> {
    let mut evidence = finding.evidence.clone();
    if evidence.len() > MAX_EVENT_EVIDENCE {
        evidence.drain(..evidence.len() - MAX_EVENT_EVIDENCE);
    }
    evidence.sort_unstable();
    evidence.dedup();
    let mut digest = blake3::Hasher::new();
    digest.update(HEALTH_DIGEST_DOMAIN);
    digest.update(finding.signal.as_str().as_bytes());
    digest.update(finding.subject.as_bytes());
    for id in &evidence {
        digest.update(id.as_bytes());
    }
    let event = DiagnosticEvent {
        detector_id: format!("coach.agent_health.{}.v1", finding.signal.as_str()),
        event_class: DiagnosticEventClass::AgentHealth,
        signal: Some(finding.signal),
        actor_class: "agent".into(),
        actor_ref: Some(finding.subject),
        source: DiagnosticSourceKind::Receipt,
        criticality: if AgentHealthTone::of(finding.signal) == AgentHealthTone::Concern {
            DiagnosticCriticality::Critical
        } else {
            DiagnosticCriticality::Normal
        },
        expected: Value::from(finding.dial),
        actual: Value::from(finding.actual),
        delta: Value::from(finding.actual - finding.dial),
        replay: DiagnosticReplayCoordinate {
            content_hash: *digest.finalize().as_bytes(),
            run_ref: finding.attempt.map(|attempt| {
                format!(
                    "attempt:{}",
                    crate::entity_id::bytes_to_hex_lower(attempt.as_bytes())
                )
            }),
            checkpoint_ref: None,
        },
        evidence_refs: evidence,
        valid_from: finding.window.0,
        valid_to: None,
    };
    let body = encode_diagnostic_event_body(&event)?;
    let id = diagnostic_event_id(&event.detector_id, &body);
    let stored = {
        let rtxn = vault.store.env.read_txn()?;
        vault.get_raw_in(&rtxn, &id)?.is_some()
    };
    if !stored {
        vault.emit_diagnostic_event(&id, &event)?;
    }
    Ok(id)
}

/// Who a finding's card goes to, and whether the owner gets a copy now.
struct Route {
    recipients: Vec<EntityId>,
    owner_copy: bool,
}

fn route(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    finding: &Finding,
    dispatched: &Dispatches,
    attempts: &Attempts,
) -> Result<Route> {
    let dispatch = finding
        .attempt
        .and_then(|attempt| dispatched.get(attempt.as_bytes()));
    // A helper's card goes to its spawner, which already controls it.
    let spawner = dispatch
        .and_then(|dispatch| dispatch.parent)
        .and_then(|parent| attempts.get(parent.as_bytes()))
        .and_then(Dispatched::of)
        .map(|parent| parent.actor);
    // The project's effective leader, never a stored claim of one.
    let leader = match dispatch.and_then(|dispatch| dispatch.project) {
        Some(project) => vault
            .effective_project_in_txn(txn, project)?
            .and_then(|(_, effective)| EntityId::from_hex(&effective.leader).ok()),
        None => None,
    };
    let mut recipients = Vec::new();
    add_recipients(
        &mut recipients,
        finding.subject,
        &[leader, spawner].into_iter().flatten().collect::<Vec<_>>(),
    );
    let owner_copy = AgentHealthTone::of(finding.signal) == AgentHealthTone::Concern
        || leader == Some(finding.subject)
        || recipients.is_empty();
    Ok(Route {
        recipients,
        owner_copy,
    })
}

/// Adds each of `ids` once, never the card's own subject.
fn add_recipients(recipients: &mut Vec<EntityId>, subject: EntityId, ids: &[EntityId]) {
    for id in ids {
        if *id != subject && !recipients.contains(id) {
            recipients.push(*id);
        }
    }
}

fn keep_newest(ids: &mut Vec<EntityId>, more: &[EntityId], cap: usize) {
    for id in more {
        if !ids.contains(id) {
            ids.push(*id);
        }
    }
    if ids.len() > cap {
        ids.drain(..ids.len() - cap);
    }
}

fn moves(signal: AgentHealthSignal) -> Vec<AgentHealthMove> {
    use AgentHealthMove::{AskCoach, Budget, Hold, Note, Reassign, Steer};
    match signal {
        AgentHealthSignal::Loop | AgentHealthSignal::FailedCheckRepeat => {
            vec![Steer, Note, AskCoach, Hold]
        }
        AgentHealthSignal::Silent => vec![Note, Steer, Reassign, Hold],
        AgentHealthSignal::LongWait => vec![Note, Reassign, Budget],
        AgentHealthSignal::CostSpike => vec![Budget, Steer, Hold],
        AgentHealthSignal::DuplicateWork => vec![Note, Reassign, Hold],
        AgentHealthSignal::UnsupportedDone => vec![Note, Steer, AskCoach],
        AgentHealthSignal::Misalignment => vec![AskCoach, Hold, Reassign, Note],
    }
}

/// Merges a finding into its card. Repeats grow one card; a settled card stays
/// quiet until its evidence grows past its watermark.
fn merge(
    card: Option<AgentHealthCard>,
    finding: &Finding,
    diagnostic: EntityId,
    route: &Route,
    owners: &[EntityId],
    now: u64,
) -> AgentHealthCard {
    let mut card = card.unwrap_or_else(|| AgentHealthCard {
        subject: finding.subject,
        signal: finding.signal,
        task: finding.task,
        attempt: None,
        tone: AgentHealthTone::of(finding.signal),
        tier: 1,
        confidence: AgentHealthConfidence::High,
        diagnostics: Vec::new(),
        evidence: Vec::new(),
        window_from: finding.window.0,
        window_to: finding.window.1,
        measured: 0,
        dial: 0,
        counter_evidence: Vec::new(),
        agent_blocked: false,
        confession: None,
        moves: moves(finding.signal),
        recipients: Vec::new(),
        owner_copy: false,
        outcome: AgentHealthOutcome::Open,
        outcome_by: None,
        outcome_at: None,
        watermark: 0,
        opened_at: now,
        updated_at: now,
    });
    keep_newest(&mut card.evidence, &finding.evidence, MAX_CARD_EVIDENCE);
    keep_newest(&mut card.diagnostics, &[diagnostic], MAX_CARD_DIAGNOSTICS);
    card.attempt = finding.attempt.and_then(entity).or(card.attempt);
    card.window_from = card.window_from.min(finding.window.0);
    card.window_to = card.window_to.max(finding.window.1);
    card.measured = finding.measured;
    card.dial = finding.dial;
    card.counter_evidence = finding.counter.clone();
    card.confidence = if finding.counter.is_empty() {
        AgentHealthConfidence::High
    } else {
        AgentHealthConfidence::Low
    };
    card.confession = finding.confession.or(card.confession);
    if card.outcome != AgentHealthOutcome::Open && card.evidence.len() > card.watermark {
        card.outcome = AgentHealthOutcome::Open;
        card.outcome_by = None;
        card.outcome_at = None;
        card.opened_at = now;
    }
    add_recipients(&mut card.recipients, card.subject, &route.recipients);
    if route.owner_copy {
        card.owner_copy = true;
    }
    if card.owner_copy {
        add_recipients(&mut card.recipients, card.subject, owners);
    }
    card.updated_at = now;
    card
}

fn card_key(
    subject: EntityId,
    signal: AgentHealthSignal,
    task: Option<EntityId>,
) -> ([u8; 16], [u8; 1], [u8; 16]) {
    let code = AgentHealthSignal::all()
        .iter()
        .position(|known| *known == signal)
        .unwrap_or_default() as u8;
    (
        *subject.as_bytes(),
        [code],
        task.map_or([0; 16], |task| *task.as_bytes()),
    )
}

fn card_ref(key: &([u8; 16], [u8; 1], [u8; 16])) -> String {
    let signal = AgentHealthSignal::all()
        .get(usize::from(key.1[0]))
        .map_or("unknown", |signal| signal.as_str());
    format!(
        "{CARD_REF_PREFIX}{}:{signal}:{}",
        crate::entity_id::bytes_to_hex_lower(&key.0),
        crate::entity_id::bytes_to_hex_lower(&key.2)
    )
}

fn parse_card_ref(card: &str) -> Option<([u8; 16], [u8; 1], [u8; 16])> {
    let mut parts = card.strip_prefix(CARD_REF_PREFIX)?.split(':');
    let subject = EntityId::from_hex(parts.next()?).ok()?;
    let signal = AgentHealthSignal::from_wire(parts.next()?)?;
    let task = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let task = if task.bytes().all(|byte| byte == b'0') && task.len() == 32 {
        None
    } else {
        Some(EntityId::from_hex(task).ok()?)
    };
    Some(card_key(subject, signal, task))
}

/// The open cards as inbox rows (ARCH-0063 concern cards): kind Concern, under
/// "Waiting on you", one row per card, each naming the agent it is about so a
/// renderer groups them per agent. Never folded into a thread.
pub(crate) fn agent_health_inbox_items(vault: &Vault) -> Result<Vec<AgentInboxLensItem>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut items = Vec::new();
    for (key, card) in CARDS.scan(&vault.store, &rtxn)? {
        if card.outcome != AgentHealthOutcome::Open || card.recipients.is_empty() {
            continue;
        }
        let participants = card
            .recipients
            .iter()
            .map(|recipient| AgentInboxParticipant {
                identity_ref: *recipient,
                actor_ref: *recipient,
            })
            .collect();
        let card_ref = card_ref(&key);
        items.push(AgentInboxLensItem {
            item_id: format!("concern:{}", &card_ref[CARD_REF_PREFIX.len()..]),
            kind: AgentInboxItemKind::Concern,
            thread_ref: None,
            identity_ref: card.subject,
            actor_ref: card.subject,
            facet_ref: None,
            participants,
            impact: InboxImpact(card.tone.impact()),
            occurred_at: card.window_to,
            receipt_ref: card.diagnostics.last().map(EntityId::to_hex),
            payload_ref: Some(card_ref),
            concern: Some(AgentInboxConcern {
                subject: card.subject,
                signal: card.signal,
                tone: card.tone,
            }),
        });
    }
    Ok(items)
}

impl Vault {
    /// One agent-health card by its `health:` handle.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn agent_health_card(&self, card: &str) -> Result<Option<AgentHealthCard>> {
        let Some(key) = parse_card_ref(card) else {
            return Ok(None);
        };
        let rtxn = self.store.env.read_txn()?;
        CARDS.get(&self.store, &rtxn, &key)
    }

    /// The owner sets a card's outcome: confirmed, dismissed or unresolved.
    /// A settled card leaves the inbox until its evidence grows. The outcome
    /// is the card's alone: it never moves `learning.reliability`.
    ///
    /// # Errors
    ///
    /// [`Error::EntityNotFound`] for an unknown card; owner revalidation
    /// errors; storage errors.
    pub fn set_agent_health_outcome(
        &self,
        owner: &AuthenticatedOwner,
        card: &str,
        outcome: AgentHealthOutcome,
    ) -> Result<AgentHealthCard> {
        let key = parse_card_ref(card).ok_or(Error::EntityNotFound)?;
        self.with_write_txn_grouped(|txn| {
            let by = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let mut card = CARDS
                .get(&self.store, txn, &key)?
                .ok_or(Error::EntityNotFound)?;
            let at = self.store.clock.now_recorded_at();
            card.outcome = outcome;
            card.outcome_by = Some(by);
            card.outcome_at = Some(at);
            card.watermark = card.evidence.len();
            card.updated_at = at;
            CARDS.put(&self.store, txn, &key, &card)?;
            Ok(card)
        })
    }
}
