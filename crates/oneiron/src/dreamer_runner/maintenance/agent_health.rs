//! The Coach's agent-health review (OF-568, agent-mind §3): a closed-form T1
//! recipe on the gated maintenance lane, run on the Coach's timer wake. It
//! reads call receipts, attempt rows, run coordination and sealed attempt
//! receipts. Each finding is one `agent_health` DIAGNOSTIC, merged into one
//! card per actor, signal and task. Every dial resolves for the project and
//! task type of the attempt it judges (`learning_setting` scoped rows).
//!
//! It never stops an agent and never narrows a grant or scope: its output is
//! cards and proposed moves, and an agent-health event never feeds the auto
//! arm (`Vault::is_signed_tripwire`). It reads no diary. A card's recipient
//! settles it (`self.inbox.concern.outcome`), as the owner does through
//! `/v1/owner/inbox/concern/outcome`, and may ask the Coach for a proposal
//! (`self.inbox.concern.move`, `ask`).

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchInput, AgentDispatcher, SpendScope, SpendState,
    agent_dispatch_actor, decode_agent_dispatch_input,
};
use crate::agent_inbox_lens::{
    AgentInboxConcern, AgentInboxItemKind, AgentInboxLensItem, AgentInboxParticipant, InboxImpact,
};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::edge::EdgeKind;
use crate::learning::{TeamEvent, project_run_coordination, team_events_from_attempts};
use crate::learning_setting::{SettingSpec, setting_value_scoped_in_txn};
use crate::llm::run_admission::LeaseUnit;
use crate::llm::{DreamerTrapKind, OpenTrapWait, open_trap_waits};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::ports::EdgeDirection;
use crate::receipt::{CallOutcome, CallReceipt};
use crate::run_tree::{RunTree, RunTreeAdapter};
use crate::self_heal::{
    AgentHealthSignal, DiagnosticCriticality, DiagnosticEvent, DiagnosticEventClass,
    DiagnosticReplayCoordinate, DiagnosticSourceKind, diagnostic_event_id,
    encode_diagnostic_event_body,
};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};

mod ask;
mod check_repeat;
mod run_loop;
pub use ask::{
    AgentHealthCoachAnswer, AgentHealthCoachAsk, AgentHealthCoachDraft, AgentHealthCoachRoute,
    AgentHealthPadRead, COACH_AGENT_HEALTH_ASK_FACET, CoachHealthBrief, CoachHealthHost,
    ConcernMove, ConcernMoveOutcome, ConcernMoveRequest,
};

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

/// `failed_check_repeat`: the same tool run failing the same way, the canon
/// failure-ladder N.
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

/// `misalignment`: widen proposals one attempt raised that the board has not
/// approved.
pub const HEALTH_WIDEN_DENIALS: SettingSpec = SettingSpec {
    key: "health.widen.denials",
    min: 1.0,
    max: 100.0,
    seed: 3.0,
};

/// `cost_spike`: an attempt's own spend over this many times its task type's
/// p90, or the plan's expected spend while the type has too few runs.
pub const HEALTH_COST_SPIKE: SettingSpec = SettingSpec {
    key: "health.cost.spike",
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

/// The lowest card impact that still makes a card: struggling 100, off
/// course 150, concern 200, so a concern always does. A finding below it
/// writes its DIAGNOSTIC and no card.
pub const HEALTH_CARD_FLOOR: SettingSpec = SettingSpec {
    key: "health.card.floor",
    min: 0.0,
    max: 200.0,
    seed: 0.0,
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
/// `cost_spike` needs this many settled runs of a task type for its p90.
const COST_MIN_RUNS: usize = 10;
/// The newest settled runs of a task type its p90 is taken over.
const COST_HISTORY: usize = 100;
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
    /// Too few runs of the task type for a p90: the spend was held against
    /// the plan's expected spend.
    FewRuns,
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
    /// The newest ask of the Coach (`ask_coach`), and its answer once drafted.
    #[serde(default)]
    pub coach: Option<AgentHealthCoachAsk>,
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
    /// The agent said it was stuck: a Blocked TASK, or a blocked report since
    /// its attempt began.
    blocked: bool,
}

/// The working set's attempts, and its agent dispatches, by attempt bytes.
type Attempts = BTreeMap<[u8; 16], AttemptRecord>;
type Dispatches = BTreeMap<[u8; 16], Dispatched>;
/// The open trap waits, by attempt bytes.
type Traps = BTreeMap<[u8; 16], Vec<OpenTrapWait>>;

/// The dials in force for one project and task type.
struct Dials {
    review: bool,
    loop_repeats: u64,
    check_fails: u64,
    wait_share: f64,
    wait_secs: u64,
    silent_secs: u64,
    widen_denials: u64,
    cost_spike: f64,
    ttl_secs: u64,
    card_floor: f64,
}

/// The dials for each project and task type the review meets (agent-mind
/// §3.7): the narrowest owner pin (project, then type, then vault), else the
/// vault fit, else the narrowest seed, else the catalog seed. A finding with
/// no dispatch behind it reads the vault's.
struct DialBook {
    vault: Dials,
    scoped: BTreeMap<Option<EntityId>, BTreeMap<String, Dials>>,
}

impl DialBook {
    fn read(vault: &Vault, dispatched: &Dispatches) -> Result<Self> {
        let rtxn = vault.store.env.read_txn()?;
        let mut book = Self {
            vault: read_dials(vault, &rtxn, None, None)?,
            scoped: BTreeMap::new(),
        };
        for dispatch in dispatched.values() {
            let types = book.scoped.entry(dispatch.project).or_default();
            if !types.contains_key(&dispatch.type_node) {
                let dials = read_dials(vault, &rtxn, dispatch.project, Some(&dispatch.type_node))?;
                types.insert(dispatch.type_node.clone(), dials);
            }
        }
        Ok(book)
    }

    /// One dispatch's dials; the vault's for none.
    fn of(&self, dispatch: Option<&Dispatched>) -> &Dials {
        dispatch
            .and_then(|dispatch| {
                self.scoped
                    .get(&dispatch.project)?
                    .get(&dispatch.type_node)
            })
            .unwrap_or(&self.vault)
    }

    /// The dials of an attempt's dispatch.
    fn for_attempt(&self, dispatched: &Dispatches, attempt: Option<AttemptId>) -> &Dials {
        self.of(attempt.and_then(|attempt| dispatched.get(attempt.as_bytes())))
    }

    /// Whether any scope the review meets is reviewed at all.
    fn any_review(&self) -> bool {
        self.vault.review
            || self
                .scoped
                .values()
                .flat_map(BTreeMap::values)
                .any(|dials| dials.review)
    }
}

/// The dials one project and task type resolve to. A type row matches its
/// node at any tree version.
fn read_dials(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    project: Option<EntityId>,
    type_node: Option<&str>,
) -> Result<Dials> {
    let type_ref = type_node.map(|node_id| crate::learning::TypeRef {
        node_id: node_id.to_owned(),
        tree_version: 0,
    });
    let value = |spec: &SettingSpec| {
        setting_value_scoped_in_txn(&vault.store, rtxn, spec, project, type_ref.as_ref())
    };
    Ok(Dials {
        review: value(&HEALTH_REVIEW)? >= 0.5,
        loop_repeats: value(&HEALTH_LOOP_REPEATS)?.round() as u64,
        check_fails: value(&HEALTH_CHECK_FAILS)?.round() as u64,
        wait_share: value(&HEALTH_WAIT_SHARE)?,
        wait_secs: (value(&HEALTH_WAIT_MINUTES)? * 60.0).round() as u64,
        silent_secs: (value(&HEALTH_SILENT_MINUTES)? * 60.0).round() as u64,
        widen_denials: value(&HEALTH_WIDEN_DENIALS)?.round() as u64,
        cost_spike: value(&HEALTH_COST_SPIKE)?,
        ttl_secs: (value(&HEALTH_ESCALATE_TTL_HOURS)? * 3600.0).round() as u64,
        card_floor: value(&HEALTH_CARD_FLOOR)?,
    })
}

/// One review: detect, emit, merge, escalate. Returns the cards it touched.
/// Each dial is read for the project and task type of the attempt it judges.
pub(super) fn run(vault: &Vault, now: u64) -> Result<u64> {
    let attempts: Attempts = AttemptQueue::new(vault)
        .list()?
        .into_iter()
        .map(|record| (*record.id.as_bytes(), record))
        .collect();
    let dispatched: Dispatches = attempts
        .iter()
        .filter_map(|(key, record)| Dispatched::of(record).map(|dispatch| (*key, dispatch)))
        .collect();
    let book = DialBook::read(vault, &dispatched)?;
    if !book.any_review() {
        return Ok(0);
    }
    let since = now.saturating_sub(LOOKBACK_SECS);
    let calls = agent_calls(vault, since)?;

    let mut traps = Traps::new();
    for wait in open_trap_waits(vault)? {
        traps
            .entry(*wait.attempt.as_bytes())
            .or_default()
            .push(wait);
    }

    let mut findings = loop_findings(&calls, &dispatched, &attempts, &book);
    findings.extend(run_loop::run_loop_findings(
        vault,
        &dispatched,
        &attempts,
        &book,
        since,
    )?);
    findings.extend(check_repeat::check_repeat_findings(
        vault,
        &calls,
        &dispatched,
        &attempts,
        &book,
        since,
    )?);
    findings.extend(silent_findings(
        vault,
        &calls,
        &dispatched,
        &attempts,
        &traps,
        &book,
        now,
    )?);
    findings.extend(long_wait_findings(
        &dispatched,
        &attempts,
        &traps,
        &book,
        since,
        now,
    ));
    findings.extend(duplicate_findings(
        vault,
        &dispatched,
        &attempts,
        since,
        now,
    )?);
    findings.extend(misalignment_findings(vault, &dispatched, &attempts, since)?);
    findings.extend(widen_denial_findings(vault, &dispatched, &attempts, &book, since)?);
    findings.extend(unsupported_done_findings(vault, &dispatched, &attempts, since)?);
    findings.extend(cost_spike_findings(vault, &dispatched, &attempts, &book, since, now)?);
    // A project or task type whose review is off keeps its findings unsaid.
    findings.retain(|finding| book.for_attempt(&dispatched, finding.attempt).review);
    // What each agent said itself, for its card.
    for finding in &mut findings {
        let began = finding
            .attempt
            .and_then(|attempt| attempts.get(attempt.as_bytes()))
            .map_or(finding.window.0, |record| {
                record.claimed_at.unwrap_or(record.created_at)
            });
        finding.blocked = said_blocked(vault, finding.subject, finding.task, began)?;
    }

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
            let floor = book.for_attempt(&dispatched, finding.attempt).card_floor;
            if f64::from(AgentHealthTone::of(finding.signal).impact()) < floor {
                continue;
            }
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
                && now
                    >= card.opened_at.saturating_add(
                        book.of(card.attempt.and_then(|attempt| dispatched.get(attempt.as_bytes())))
                            .ttl_secs,
                    )
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

/// An agent-dispatch attempt's actor, project, parent, task type and plan.
struct Dispatched {
    actor: EntityId,
    project: Option<EntityId>,
    parent: Option<AttemptId>,
    /// The task type's node (OF-543), across tree versions.
    type_node: String,
    /// The launch plan's expected spend, and its unit.
    expected: Option<(LeaseUnit, u64)>,
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
            type_node: input.type_ref.node_id.clone(),
            expected: input
                .launch
                .as_ref()
                .map(|launch| (launch.unit.clone(), launch.expected.units)),
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
/// so the card's task is none. An agent run's own calls leave no receipt and
/// are judged per attempt (`run_loop`).
fn loop_findings(
    calls: &BTreeMap<EntityId, Vec<(EntityId, CallReceipt)>>,
    dispatched: &Dispatches,
    attempts: &Attempts,
    book: &DialBook,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for (actor, rows) in calls {
        let attempt = live_attempt(*actor, dispatched, attempts);
        let repeats = book.for_attempt(dispatched, attempt).loop_repeats;
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
                attempt,
                evidence: run.iter().map(|(id, _)| *id).collect(),
                window: (run[0].1.at, run[run.len() - 1].1.at),
                actual: count,
                dial: repeats as i64,
                measured: count,
                counter,
                confession: None,
                blocked: false,
            });
        }
    }
    out
}

/// `silent`: a leased attempt whose actor made no call within the dial, with
/// no open wait (an ask, a trap, a park) and no word that it is stuck (a
/// Blocked TASK or a blocked report). Saying it is stuck is the honest move.
fn silent_findings(
    vault: &Vault,
    calls: &BTreeMap<EntityId, Vec<(EntityId, CallReceipt)>>,
    dispatched: &Dispatches,
    attempts: &Attempts,
    traps: &Traps,
    book: &DialBook,
    now: u64,
) -> Result<Vec<Finding>> {
    let runner = DreamerRunnerStore::new(vault);
    let mut out = Vec::new();
    for (id, dispatch) in dispatched {
        let Some(record) = attempts.get(id) else {
            continue;
        };
        if record.state != AttemptState::Leased {
            continue;
        }
        let dials = book.of(Some(dispatch));
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
            .any(|ask| ask.answers.len() < ask.questions.len())
            || traps.contains_key(id)
            || runner.parked_attempt(record.id)?.is_some();
        let task = task_of(record);
        if waiting || said_blocked(vault, dispatch.actor, task, claimed)? {
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
            blocked: false,
        });
    }
    Ok(out)
}

/// `long_wait`: an attempt that spent more than the dial's share of its life
/// waiting, not on a person, over at least the dial's minutes. A settled
/// attempt's life is closed. A live one's runs to now, and its open trap
/// waits on a peer or on budget count to now; a wait for a person's answer
/// or consent does not.
fn long_wait_findings(
    dispatched: &Dispatches,
    attempts: &Attempts,
    traps: &Traps,
    book: &DialBook,
    since: u64,
    now: u64,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for (id, dispatch) in dispatched {
        let Some(record) = attempts.get(id) else {
            continue;
        };
        let live = matches!(record.state, AttemptState::Leased | AttemptState::Paused);
        if !live && (!settled(record.state) || record.updated_at < since) {
            continue;
        }
        let dials = book.of(Some(dispatch));
        let end = if live { now } else { record.updated_at };
        let life = end.saturating_sub(record.created_at);
        if life == 0 || life < dials.wait_secs {
            continue;
        }
        let mut spans = Vec::new();
        let mut queue = 0_u64;
        for event in team_events_from_attempts(std::slice::from_ref(record)) {
            if let TeamEvent::Wait {
                reason, start, end, ..
            } = event
                && reason != WAIT_PERSON
            {
                if reason == crate::learning::coordination::WAIT_QUEUE {
                    queue += end.saturating_sub(start);
                }
                spans.push((start, end));
            }
        }
        let Some(attempt) = entity(record.id) else {
            continue;
        };
        let mut evidence = vec![attempt];
        if live {
            for trap in traps.get(id).into_iter().flatten() {
                if matches!(
                    trap.kind,
                    DreamerTrapKind::PeerResult | DreamerTrapKind::Budget
                ) {
                    spans.push((trap.opened_at_ms / 1000, now));
                    evidence.push(trap.anchor);
                }
            }
        }
        let wait = covered(spans);
        let share = wait as f64 / life as f64;
        if share <= dials.wait_share {
            continue;
        }
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
            evidence,
            window: (record.created_at, end),
            // A live share moves on every review; the DIAGNOSTIC carries it in
            // tenths, so it is written again only when it crosses one.
            actual: if live { permille / 100 * 100 } else { permille },
            dial: (dials.wait_share * 1000.0).round() as i64,
            measured: permille,
            counter,
            confession: None,
            blocked: false,
        });
    }
    out
}

/// Seconds covered by the union of `spans`.
fn covered(mut spans: Vec<(u64, u64)>) -> u64 {
    spans.sort_unstable();
    let mut total = 0;
    let mut reach = 0;
    for (start, end) in spans {
        let start = start.max(reach);
        if end > start {
            total += end - start;
            reach = end;
        }
    }
    total
}

/// `cost_spike`: an attempt's own spend over the dial times the p90 of its
/// task type's settled runs in the same unit, from at least
/// [`COST_MIN_RUNS`] of them. With fewer, it is held against the plan's
/// expected spend, at low confidence. Own spend is the launch scope's spend
/// less what its settled children spent. Retries share one scope, so a scope
/// counts once, on its newest attempt.
fn cost_spike_findings(
    vault: &Vault,
    dispatched: &Dispatches,
    attempts: &Attempts,
    book: &DialBook,
    since: u64,
    now: u64,
) -> Result<Vec<Finding>> {
    let dispatcher = AgentDispatcher::new(vault);
    let mut scopes: BTreeMap<String, ([u8; 16], SpendScope)> = BTreeMap::new();
    for key in dispatched.keys() {
        let Some(record) = attempts.get(key) else {
            continue;
        };
        let Some(scope_id) = dispatcher.spend_scope_for_attempt(record.id)? else {
            continue;
        };
        let name = scope_id.to_string();
        let newer = scopes
            .get(&name)
            .and_then(|(held, _)| attempts.get(held))
            .is_none_or(|held| held.updated_at <= record.updated_at);
        if newer && let Some(scope) = dispatcher.read_spend_scope(&scope_id)? {
            scopes.insert(name, (*key, scope));
        }
    }
    let mut children: BTreeMap<String, u64> = BTreeMap::new();
    for (_, scope) in scopes.values() {
        if scope.state == SpendState::Closed
            && let Some(parent) = &scope.parent
        {
            *children.entry(parent.to_string()).or_default() += scope.spent_units;
        }
    }
    let own = |name: &str, scope: &SpendScope| {
        scope
            .spent_units
            .saturating_sub(children.get(name).copied().unwrap_or(0))
    };
    let mut history: BTreeMap<(&str, &LeaseUnit), Vec<(u64, &str, u64)>> = BTreeMap::new();
    for (name, (key, scope)) in &scopes {
        if let (Some(record), Some(dispatch)) = (attempts.get(key), dispatched.get(key))
            && settled(record.state)
            && scope.state == SpendState::Closed
        {
            history
                .entry((dispatch.type_node.as_str(), &scope.unit))
                .or_default()
                .push((record.updated_at, name.as_str(), own(name, scope)));
        }
    }
    for runs in history.values_mut() {
        runs.sort_unstable();
        if runs.len() > COST_HISTORY {
            runs.drain(..runs.len() - COST_HISTORY);
        }
    }
    let mut out = Vec::new();
    for (name, (key, scope)) in &scopes {
        let (Some(record), Some(dispatch)) = (attempts.get(key), dispatched.get(key)) else {
            continue;
        };
        let dials = book.of(Some(dispatch));
        let live = record.state == AttemptState::Leased;
        if !live && (!settled(record.state) || record.updated_at < since) {
            continue;
        }
        let spent = own(name, scope);
        let runs: Vec<u64> = history
            .get(&(dispatch.type_node.as_str(), &scope.unit))
            .into_iter()
            .flatten()
            .filter(|(_, run, _)| *run != name.as_str())
            .map(|(_, _, spent)| *spent)
            .collect();
        let (baseline, counter) = if runs.len() >= COST_MIN_RUNS {
            (p90(runs), Vec::new())
        } else {
            match &dispatch.expected {
                Some((unit, units)) if *unit == scope.unit => {
                    (*units, vec![AgentHealthCounter::FewRuns])
                }
                _ => continue,
            }
        };
        if baseline == 0 || spent == 0 {
            continue;
        }
        let ratio = spent as f64 / baseline as f64;
        if ratio <= dials.cost_spike {
            continue;
        }
        let Some(attempt) = entity(record.id) else {
            continue;
        };
        let permille = (ratio * 1000.0).round() as i64;
        out.push(Finding {
            subject: dispatch.actor,
            signal: AgentHealthSignal::CostSpike,
            task: task_of(record),
            attempt: Some(record.id),
            evidence: vec![attempt],
            window: (
                record.created_at,
                if live { now } else { record.updated_at },
            ),
            // A live ratio moves on every review; the DIAGNOSTIC carries it in
            // halves, so it is written again only when it crosses one.
            actual: if live { permille / 500 * 500 } else { permille },
            dial: (dials.cost_spike * 1000.0).round() as i64,
            measured: permille,
            counter,
            confession: None,
            blocked: false,
        });
    }
    Ok(out)
}

/// The 90th percentile, by nearest rank, of `values` (not empty).
fn p90(mut values: Vec<u64>) -> u64 {
    values.sort_unstable();
    let rank = (values.len() * 9).div_ceil(10).max(1);
    values[rank - 1]
}

/// Whether the agent said it was stuck: its TASK is Blocked, or it filed a
/// blocked report (`self.report_blocked`) at or after `since`.
fn said_blocked(
    vault: &Vault,
    actor: EntityId,
    task: Option<EntityId>,
    since: u64,
) -> Result<bool> {
    let recent = {
        let rtxn = vault.store.env.read_txn()?;
        if let Some(task) = task
            && crate::task_verb::task_is_blocked_in(vault, &rtxn, task)?
        {
            return Ok(true);
        }
        let mut recent = Vec::new();
        for id in vault.filtered_edge_peers(
            &rtxn,
            EdgeDirection::In,
            &actor,
            EdgeKind::AuthoredBy,
            Some(crate::registry::ENTITY_TYPE_MESSAGE),
        )? {
            let at = vault
                .get_raw_in(&rtxn, &id)?
                .as_deref()
                .and_then(crate::batch::EntityMetadataHeader::parse)
                .map_or(0, |header| unix_secs(header.occurred_start));
            if at >= since {
                recent.push(id);
            }
        }
        recent
    };
    // The report reader opens its own snapshot.
    for id in recent {
        if crate::code_run::blocked::read_blocked_receipt(vault, &id)?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A stored time in seconds, whether it was written in seconds or in
/// milliseconds.
const fn unix_secs(at: u64) -> u64 {
    if at >= 100_000_000_000 { at / 1000 } else { at }
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
                blocked: false,
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
            blocked: false,
        });
    }
    Ok(out)
}

/// `misalignment`: one attempt raised at least the dial's widen proposals
/// that the board has not approved, pending or refused alike.
fn widen_denial_findings(
    vault: &Vault,
    dispatched: &Dispatches,
    attempts: &Attempts,
    book: &DialBook,
    since: u64,
) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    for (id, denials) in crate::agent_dispatch::unlanded_widens_by_parent(vault)? {
        let (Some(dispatch), Some(record)) = (dispatched.get(&id), attempts.get(&id)) else {
            continue;
        };
        let dials = book.of(Some(dispatch));
        if denials < dials.widen_denials {
            continue;
        }
        if settled(record.state) && record.updated_at < since {
            continue;
        }
        let Some(attempt) = entity(record.id) else {
            continue;
        };
        let count = denials as i64;
        out.push(Finding {
            subject: dispatch.actor,
            signal: AgentHealthSignal::Misalignment,
            task: task_of(record),
            attempt: Some(record.id),
            evidence: vec![attempt],
            window: (record.claimed_at.unwrap_or(record.created_at), record.updated_at),
            actual: count,
            dial: dials.widen_denials as i64,
            measured: count,
            counter: Vec::new(),
            confession: None,
            blocked: false,
        });
    }
    Ok(out)
}

/// `unsupported_done`: a Completed attempt whose TASK settled Done while an
/// evidence ref its done-means names does not resolve to a live entity.
/// Missing evidence, not deception: any one flags.
fn unsupported_done_findings(
    vault: &Vault,
    dispatched: &Dispatches,
    attempts: &Attempts,
    since: u64,
) -> Result<Vec<Finding>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for (id, dispatch) in dispatched {
        let Some(record) = attempts.get(id) else {
            continue;
        };
        if record.state != AttemptState::Completed || record.updated_at < since {
            continue;
        }
        let (Some(task), Some(attempt)) = (task_of(record), entity(record.id)) else {
            continue;
        };
        let Some(needed) = crate::task_verb::done_task_evidence_in(vault, &rtxn, task)? else {
            continue;
        };
        let mut missing = BTreeSet::new();
        for evidence in needed {
            if !crate::vault::live_entity_row_in_txn(&vault.store, &rtxn, &evidence)?.is_live() {
                missing.insert(evidence);
            }
        }
        if missing.is_empty() {
            continue;
        }
        let count = missing.len() as i64;
        out.push(Finding {
            subject: dispatch.actor,
            signal: AgentHealthSignal::UnsupportedDone,
            task: Some(task),
            attempt: Some(record.id),
            evidence: vec![attempt, task],
            window: (record.claimed_at.unwrap_or(record.created_at), record.updated_at),
            actual: count,
            dial: 0,
            measured: count,
            counter: Vec::new(),
            confession: None,
            blocked: false,
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
        coach: None,
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
    card.agent_blocked = finding.blocked;
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

/// Every card in `txn`, concern first and newest first within a tone, as
/// [`Vault::agent_health_cards_between`] orders them: the weave report reads
/// them in its own snapshot (OF-568).
pub(crate) fn agent_health_cards_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<AgentHealthCard>> {
    let mut cards: Vec<AgentHealthCard> = CARDS
        .scan(&vault.store, txn)?
        .into_iter()
        .map(|(_, card)| card)
        .collect();
    cards.sort_by(|left, right| {
        right
            .tone
            .impact()
            .cmp(&left.tone.impact())
            .then(right.updated_at.cmp(&left.updated_at))
    });
    Ok(cards)
}

/// One card by its `health:` handle in `txn`: a saved weave period rechecks
/// the card it carries against the current one (OF-568).
pub(crate) fn agent_health_card_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    card: &str,
) -> Result<Option<AgentHealthCard>> {
    let Some(key) = parse_card_ref(card) else {
        return Ok(None);
    };
    CARDS.get(&vault.store, txn, &key)
}

/// What a card now says: the answer to a settle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConcernCardSummary {
    /// The card's `health:` handle.
    pub card: String,
    /// The agent the card is about, as 32 hex.
    pub agent: String,
    pub signal: String,
    pub tone: String,
    pub outcome: String,
    pub evidence: usize,
}

impl ConcernCardSummary {
    #[must_use]
    pub fn of(card: &AgentHealthCard) -> Self {
        Self {
            card: card.card_ref(),
            agent: card.subject.to_hex(),
            signal: card.signal.as_str().to_owned(),
            tone: card.tone.as_str().to_owned(),
            outcome: card.outcome.as_str().to_owned(),
            evidence: card.evidence.len(),
        }
    }
}

/// The outcome a card's reader sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConcernOutcome {
    Confirmed,
    Dismissed,
    Unresolved,
}

impl From<ConcernOutcome> for AgentHealthOutcome {
    fn from(outcome: ConcernOutcome) -> Self {
        match outcome {
            ConcernOutcome::Confirmed => Self::Confirmed,
            ConcernOutcome::Dismissed => Self::Dismissed,
            ConcernOutcome::Unresolved => Self::Unresolved,
        }
    }
}

/// `self.inbox.concern`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConcernCardRequest {
    /// The card's `health:` handle: the concern row's `payload_ref`.
    pub card: String,
}

/// `self.inbox.concern.outcome`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConcernOutcomeRequest {
    /// The card's `health:` handle: the concern row's `payload_ref`.
    pub card: String,
    pub outcome: ConcernOutcome,
}

/// One card as its reader sees it, with the ARCH-0066 run-tree diagram.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentHealthCardView {
    /// The card's `health:` handle.
    pub card: String,
    pub body: AgentHealthCard,
    /// The run of the card's newest attempt, when it has one.
    pub run_tree: Option<AgentHealthRunTree>,
}

/// The run a card's attempt is in, with that attempt's node marked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentHealthRunTree {
    pub run_id: String,
    pub tree: RunTree,
    /// The node the card is about: its attempt, as 32 hex.
    pub marked: String,
}

/// Whether `reader` sees and settles `card`: one of its recipients (its
/// leader, its spawner, an owner with a copy) or a live vault owner. The
/// agent a card is about never settles it.
fn may_read(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    card: &AgentHealthCard,
    reader: EntityId,
) -> Result<bool> {
    if reader == card.subject {
        return Ok(false);
    }
    Ok(card.recipients.contains(&reader)
        || crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &reader)?)
}

/// Sets a card's outcome. A settled card leaves the inbox until its evidence
/// grows past the watermark set here.
fn settle(card: &mut AgentHealthCard, by: EntityId, outcome: AgentHealthOutcome, at: u64) {
    card.outcome = outcome;
    card.outcome_by = Some(by);
    card.outcome_at = Some(at);
    card.watermark = card.evidence.len();
    card.updated_at = at;
}

fn forbidden() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        "only a card's recipient or a vault owner reads or settles a concern card",
        &["Act on the cards your inbox shows: their payload_ref is the card."],
    )
}

fn card_view(
    vault: &Vault,
    key: &([u8; 16], [u8; 1], [u8; 16]),
    card: AgentHealthCard,
) -> Result<AgentHealthCardView> {
    let mut run_tree = None;
    if let Some(attempt) = card.attempt {
        let attempt = AttemptId::from_bytes(attempt.as_bytes())?;
        if let Some(run_id) = AttemptQueue::new(vault)
            .get(attempt)?
            .and_then(|record| record.run_id)
        {
            run_tree = Some(AgentHealthRunTree {
                tree: RunTreeAdapter::new(vault).read_run(&run_id)?,
                marked: crate::entity_id::bytes_to_hex_lower(attempt.as_bytes()),
                run_id,
            });
        }
    }
    Ok(AgentHealthCardView {
        card: card_ref(key),
        body: card,
        run_tree,
    })
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

    /// One card with its run-tree diagram, for the owner.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn agent_health_card_view(&self, card: &str) -> Result<Option<AgentHealthCardView>> {
        let Some(key) = parse_card_ref(card) else {
            return Ok(None);
        };
        let stored = {
            let rtxn = self.store.env.read_txn()?;
            CARDS.get(&self.store, &rtxn, &key)?
        };
        stored
            .map(|stored| card_view(self, &key, stored))
            .transpose()
    }

    /// The cards a digest period carries (agent-mind §3.5: a card that does
    /// not go up to the owner's inbox goes into the owner's digest and the
    /// weave report): each card opened, updated or settled in `[from, to)`,
    /// in impact order (concern first), newest first within a tone.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn agent_health_cards_between(&self, from: u64, to: u64) -> Result<Vec<AgentHealthCard>> {
        let rtxn = self.store.env.read_txn()?;
        let mut cards: Vec<AgentHealthCard> = CARDS
            .scan(&self.store, &rtxn)?
            .into_iter()
            .map(|(_, card)| card)
            .filter(|card| {
                let touched = |at: u64| at >= from && at < to;
                touched(card.opened_at)
                    || touched(card.updated_at)
                    || card.outcome_at.is_some_and(touched)
            })
            .collect();
        cards.sort_by(|left, right| {
            right
                .tone
                .impact()
                .cmp(&left.tone.impact())
                .then(right.updated_at.cmp(&left.updated_at))
        });
        Ok(cards)
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
            settle(&mut card, by, outcome, self.store.clock.now_recorded_at());
            CARDS.put(&self.store, txn, &key, &card)?;
            Ok(card)
        })
    }
}

impl Memory<'_> {
    /// `self.inbox.concern`: one agent-health card with its run-tree diagram,
    /// for one of its recipients or a vault owner.
    pub fn concern_card(&self, input: &ConcernCardRequest) -> MemoryResult<AgentHealthCardView> {
        crate::memory::verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let key = parse_card_ref(&input.card).ok_or_else(|| {
            MemoryError::bad_request("card is a health: handle from a concern row")
        })?;
        let card = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            let card = CARDS
                .get(&self.vault().store, &txn, &key)?
                .ok_or_else(|| MemoryError::not_found("no such concern card"))?;
            if !may_read(self.vault(), &txn, &card, self.actor())? {
                return Err(forbidden());
            }
            card
        };
        Ok(card_view(self.vault(), &key, card)?)
    }

    /// `self.inbox.concern.outcome`: a card's recipient (its leader or
    /// spawner) or a vault owner marks it confirmed, dismissed or unresolved,
    /// as the owner's route does. It never moves `learning.reliability`.
    pub fn concern_outcome(
        &self,
        input: &ConcernOutcomeRequest,
    ) -> MemoryResult<ConcernCardSummary> {
        let key = parse_card_ref(&input.card).ok_or_else(|| {
            MemoryError::bad_request("card is a health: handle from a concern row")
        })?;
        let at = self.vault().store.clock.now_recorded_at();
        self.with_verified_actor_write_txn(|txn| {
            let mut card = CARDS
                .get(&self.vault().store, txn, &key)?
                .ok_or_else(|| MemoryError::not_found("no such concern card"))?;
            if !may_read(self.vault(), txn, &card, self.actor())? {
                return Err(forbidden());
            }
            settle(&mut card, self.actor(), input.outcome.into(), at);
            CARDS.put(&self.vault().store, txn, &key, &card)?;
            Ok(ConcernCardSummary::of(&card))
        })
    }
}
