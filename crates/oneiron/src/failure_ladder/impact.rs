//! The self-healing loop's human residue, ordered by impact (OF-418 L4; ARCH-0066 §6): one
//! parked run blocking a task chain sits above fifty copies of a cosmetic complaint.
//!
//! A residue row is one source a Coach proposal still waiting in the owner's tray was filed
//! for: a failure-ladder case, a blocked report or a model finding's issue. The tray is read
//! whole, every page to its last row, in one snapshot. Each row carries its pending
//! proposals, the attempt and TASK its records bind it to, every TASK that waits on it
//! through recorded `blocked_by` edges with each edge and state read, and, for every part no
//! record proves, a marker that says why that part scores nothing. Nothing is stored and
//! nothing is cut: the order is computed at read time under [`HealImpactPolicy`], beside the
//! grouped failure counts, which stay as they are. A worker's unfiled backlog is not
//! residue, and complaint counts and taxonomy never enter the order.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptState};
use crate::batch::EntityMetadataHeader;
use crate::claim::ClaimBody;
use crate::code_run::blocked::read_blocked_receipt;
use crate::dreamer_runner::maintenance::coach_diagnostic::{
    COACH_DIAGNOSTIC_PROPOSAL_PREDICATE, COACH_ISSUE_RESOLUTION_PREDICATE, ProducerTarget,
};
use crate::dreamer_runner::maintenance::coach_heal::{
    COACH_HEAL_PROPOSAL_PREDICATE, COACH_ISSUE_PROPOSAL_PREDICATE,
};
use crate::dreamer_runner::{DreamerParkCause, DreamerRunnerStore};
use crate::edge::EdgeKind;
use crate::entity_id::bytes_to_hex_lower;
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::self_heal::{blocked_reports, issue_evidence, issue_work};
use crate::task_verb::{TaskTerminalDisposition, task_impact_facts_in_txn};
use crate::{EntityId, Error, Result, Vault};

use super::healer_case_in_txn;

/// The Coach's proposal predicates whose pending claims are the human residue: a case's
/// heal, a blocked report's heal, a model issue's heal or question, and a model issue's
/// resolution.
const COACH_PROPOSALS: [&str; 4] = [
    COACH_HEAL_PROPOSAL_PREDICATE,
    COACH_ISSUE_PROPOSAL_PREDICATE,
    COACH_DIAGNOSTIC_PROPOSAL_PREDICATE,
    COACH_ISSUE_RESOLUTION_PREDICATE,
];

/// The one hook that orders the human residue (OF-418 L4; ARCH-0066 §6).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HealImpactPolicy {
    /// Descending by [`HealImpactScore`]: a proved unfinished chain blocked by a non-success
    /// source first, then more distinct unfinished TASKs waiting on it, then a parked or
    /// STUCK source. Ties go to the oldest source time, a source with none after every one
    /// that has one, then to the source ref, ascending. Only identical source refs share a
    /// row; how many proposals or complaints a source drew, and their taxonomy, never count.
    #[default]
    DependencyFirst,
}

impl HealImpactPolicy {
    /// Puts `rows` in this policy's order.
    pub fn order(self, rows: &mut [HealResidue]) {
        match self {
            Self::DependencyFirst => rows.sort_by(|left, right| {
                right
                    .score
                    .key()
                    .cmp(&left.score.key())
                    .then_with(|| oldest_first(left.source_time, right.source_time))
                    .then_with(|| left.source.cmp(&right.source))
            }),
        }
    }
}

/// What a residue row's records prove of its impact. Unknown impact proves nothing and
/// scores zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HealImpactScore {
    /// The source is no success, and at least one unfinished TASK waits on it through a
    /// recorded `blocked_by` edge.
    pub chain: bool,
    /// The distinct unfinished TASKs that wait on it, directly or through other unfinished
    /// TASKs.
    pub dependents: u64,
    /// Its attempt holds a parked row, or its TASK reports STUCK.
    pub parked_or_stuck: bool,
}

impl HealImpactScore {
    /// The score's keys, in the order the policy compares them.
    #[must_use]
    pub const fn key(self) -> (bool, u64, bool) {
        (self.chain, self.dependents, self.parked_or_stuck)
    }
}

/// What a residue row is about: the one source its pending proposals were filed for. Ids of
/// different substrates are never one source.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HealSourceRef {
    /// A failure-ladder case, by its lowercase-hex case ref, which names no entity.
    Case(String),
    /// A blocked report, by its receipt.
    Report(EntityId),
    /// A model finding's issue, by its id.
    Issue(EntityId),
    /// A pending claim no record proves a Coach source for, by the claim; its marker says
    /// why.
    Unproved(EntityId),
}

impl HealSourceRef {
    /// `case`, `report`, `issue` or `unproved`.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Case(_) => "case",
            Self::Report(_) => "report",
            Self::Issue(_) => "issue",
            Self::Unproved(_) => "unproved",
        }
    }

    /// The source's id as lowercase hex: the case ref, the receipt, the issue, or the
    /// unproved claim.
    #[must_use]
    pub fn id(&self) -> String {
        match self {
            Self::Case(case_ref) => case_ref.clone(),
            Self::Report(id) | Self::Issue(id) | Self::Unproved(id) => id.to_hex(),
        }
    }
}

/// One Coach proposal of a residue row, waiting in the owner's tray.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealPendingProposal {
    /// The proposed claim.
    pub claim: EntityId,
    /// The gate decision that holds it for consent.
    pub decision: [u8; 16],
    /// Its predicate; `None` when its live body is gone.
    pub predicate: Option<String>,
    /// When it entered the tray.
    pub proposed_at: u64,
}

/// One attempt a residue row's source names, as its row stands now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealAttemptFact {
    /// The attempt.
    pub attempt: AttemptId,
    /// Its current state.
    pub state: AttemptState,
    /// When its row last changed.
    pub updated_at: u64,
    /// The TASK its row names.
    pub task_ref: Option<String>,
    /// When it parked, and why, while a parked row holds it.
    pub parked: Option<(u64, DreamerParkCause)>,
}

/// A TASK as its own row reads now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealTaskState {
    /// No terminal record: still to finish.
    Unfinished,
    /// Settled with this disposition; only `Completed` is a success.
    Settled(TaskTerminalDisposition),
    /// No typed TASK row reads at the ref: unknown, and never a success.
    Unknown,
}

impl HealTaskState {
    /// `unfinished`, the disposition's own token, or `unknown`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unfinished => "unfinished",
            Self::Settled(disposition) => disposition.as_str(),
            Self::Unknown => "unknown",
        }
    }
}

/// One recorded `blocked_by` edge a residue row's walk read: `dependent` waits on `blocker`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealDependencyEdge {
    /// The TASK that waits.
    pub dependent: EntityId,
    /// The TASK it waits on.
    pub blocker: EntityId,
    /// When the edge was recorded.
    pub recorded_at: u64,
    /// The waiting TASK's state: only an unfinished one counts, and the walk goes on only
    /// through it.
    pub dependent_state: HealTaskState,
    /// The state of the TASK it waits on.
    pub blocker_state: HealTaskState,
}

/// One part of a residue row no record proves, which therefore scores nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealUnknown {
    /// What is unproved: `claim_body_missing`, `source_unproved`, `source_row_missing`,
    /// `no_attempt`, `attempt_missing`, `park_unreadable`, `no_task`, `task_missing`,
    /// `dependent_unknown` or `edges_unreadable`.
    pub marker: &'static str,
    /// The id it concerns, as lowercase hex.
    pub about: String,
    /// Why it scores nothing, in the engine's words.
    pub explanation: &'static str,
}

/// One source of the human residue (OF-418 L4) and what its records prove of its impact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealResidue {
    /// The source its pending proposals were filed for.
    pub source: HealSourceRef,
    /// Every pending Coach proposal filed for it, in tray order.
    pub proposals: Vec<HealPendingProposal>,
    /// The attempt its records name, as its row stands now.
    pub attempts: Vec<HealAttemptFact>,
    /// The TASK its records bind it to, and that TASK's state.
    pub task: Option<(EntityId, HealTaskState)>,
    /// When that TASK reported STUCK and what it waits on, while it does.
    pub stuck: Option<(u64, Vec<EntityId>)>,
    /// Every distinct unfinished TASK that waits on it, in walk order.
    pub dependents: Vec<EntityId>,
    /// Every recorded `blocked_by` edge the walk read, each once.
    pub edges: Vec<HealDependencyEdge>,
    /// The source's own time: a case's failed attempt's last change, a report's receipt
    /// time, an issue's filing time. `None` when no record gives one.
    pub source_time: Option<u64>,
    /// What its records prove of its impact.
    pub score: HealImpactScore,
    /// Every part no record proves.
    pub unknown: Vec<HealUnknown>,
}

impl HealResidue {
    fn empty(source: HealSourceRef) -> Self {
        Self {
            source,
            proposals: Vec::new(),
            attempts: Vec::new(),
            task: None,
            stuck: None,
            dependents: Vec::new(),
            edges: Vec::new(),
            source_time: None,
            score: HealImpactScore::default(),
            unknown: Vec::new(),
        }
    }

    /// Marks the part `about` names unproved for `gap`, once.
    fn mark(&mut self, gap: Gap, about: String) {
        let (marker, explanation) = gap.parts();
        if !self
            .unknown
            .iter()
            .any(|unknown| unknown.marker == marker && unknown.about == about)
        {
            self.unknown.push(HealUnknown {
                marker,
                about,
                explanation,
            });
        }
    }

    /// What the row's read records prove.
    fn proved_score(&self) -> HealImpactScore {
        HealImpactScore {
            chain: !self.dependents.is_empty(),
            dependents: self.dependents.len() as u64,
            parked_or_stuck: self.stuck.is_some()
                || self.attempts.iter().any(|attempt| attempt.parked.is_some()),
        }
    }
}

/// Why a part of a residue row is unproved.
#[derive(Clone, Copy)]
enum Gap {
    ClaimBodyMissing,
    SourceUnproved,
    SourceRowMissing,
    NoAttempt,
    AttemptMissing,
    ParkUnreadable,
    NoTask,
    TaskMissing,
    DependentUnknown,
    EdgesUnreadable,
}

impl Gap {
    /// The gap's marker and its explanation.
    const fn parts(self) -> (&'static str, &'static str) {
        match self {
            Self::ClaimBodyMissing => (
                "claim_body_missing",
                "The pending claim's live body is gone, so no record says which source it \
                 was filed for.",
            ),
            Self::SourceUnproved => (
                "source_unproved",
                "No settled marker or resolution record names this claim as the Coach's \
                 proposal for the source its body cites.",
            ),
            Self::SourceRowMissing => (
                "source_row_missing",
                "The case, report or issue the proposal was filed for has no readable row.",
            ),
            Self::NoAttempt => (
                "no_attempt",
                "No recorded link binds the source to an attempt; a retrieval run is never \
                 read as a task.",
            ),
            Self::AttemptMissing => (
                "attempt_missing",
                "The attempt the source names has no stored row.",
            ),
            Self::ParkUnreadable => (
                "park_unreadable",
                "The attempt's parked row could not be read, so no park is proved.",
            ),
            Self::NoTask => (
                "no_task",
                "No record binds the source to a TASK, so no dependency is proved.",
            ),
            Self::TaskMissing => (
                "task_missing",
                "The source's TASK has no typed TASK row: it counts as no success, as \
                 readiness counts it.",
            ),
            Self::DependentUnknown => (
                "dependent_unknown",
                "A recorded edge names a waiting TASK with no typed TASK row; it is not \
                 counted.",
            ),
            Self::EdgesUnreadable => (
                "edges_unreadable",
                "This TASK's recorded blocked_by edges could not be read, so what waits on \
                 it is not counted.",
            ),
        }
    }
}

impl Vault {
    /// The Coach's proposals still waiting for the owner, one row per source they were
    /// filed for, in [`HealImpactPolicy::DependencyFirst`] order (OF-418 L4). One read
    /// snapshot (a report's receipt, which never changes, is read through its own reader);
    /// every tray row and every recorded edge is read, with no count, depth or age bound. A
    /// row whose source, attempt, TASK or edges no record proves stays listed, that part
    /// scoring nothing, with a marker that says why. Writes nothing.
    ///
    /// # Errors
    /// Only a store failure fails the read.
    pub fn healer_residue_by_impact(&self) -> Result<Vec<HealResidue>> {
        let txn = self.store.env.read_txn()?;
        let mut rows: BTreeMap<HealSourceRef, HealResidue> = BTreeMap::new();
        for pending in self.pending_heal_refs_in_txn(&txn, &COACH_PROPOSALS)? {
            let (source, gap) = match pending.body.as_ref() {
                None => (
                    HealSourceRef::Unproved(pending.claim),
                    Some(Gap::ClaimBodyMissing),
                ),
                Some(body) => match proved_source(self, &txn, pending.claim, body)? {
                    Some(source) => (source, None),
                    None => (
                        HealSourceRef::Unproved(pending.claim),
                        Some(Gap::SourceUnproved),
                    ),
                },
            };
            let row = rows
                .entry(source.clone())
                .or_insert_with(|| HealResidue::empty(source));
            if let Some(gap) = gap {
                row.mark(gap, pending.claim.to_hex());
            }
            row.proposals.push(HealPendingProposal {
                claim: pending.claim,
                decision: pending.decision.as_bytes(),
                predicate: pending.body.map(|body| body.predicate),
                proposed_at: pending.created_at,
            });
        }
        let mut residue = Vec::with_capacity(rows.len());
        for mut row in rows.into_values() {
            read_impact(self, &txn, &mut row)?;
            row.score = row.proved_score();
            residue.push(row);
        }
        HealImpactPolicy::default().order(&mut residue);
        Ok(residue)
    }
}

/// `read`'s value, or `None` when it failed for any reason but the store: the caller marks
/// that part unproved. Only a store failure fails the residue read.
fn soft<T>(read: Result<T>) -> Result<Option<T>> {
    match read {
        Ok(value) => Ok(Some(value)),
        Err(error @ (Error::Storage(_) | Error::Io(_) | Error::Store(_) | Error::MapFull)) => {
            Err(error)
        }
        Err(_) => Ok(None),
    }
}

/// Known times ascending, then every missing one.
fn oldest_first(left: Option<u64>, right: Option<u64>) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.cmp(&right),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// The source `claim` was filed for, as the Coach's own records prove it: the settled marker
/// of the case, report or issue its body cites names this claim, or, for a resolution, the
/// issue's evidence records proposing it. `None` when no record proves one.
fn proved_source(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim: EntityId,
    body: &ClaimBody,
) -> Result<Option<HealSourceRef>> {
    let predicate = body.predicate.as_str();
    let field = match predicate {
        COACH_HEAL_PROPOSAL_PREDICATE => "case",
        COACH_ISSUE_PROPOSAL_PREDICATE => "receipt",
        _ => "issue",
    };
    let Some(key) = body
        .value
        .as_str()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
        .and_then(|value| EntityId::from_hex(value.get(field)?.as_str()?).ok())
    else {
        return Ok(None);
    };
    let proved = if predicate == COACH_ISSUE_RESOLUTION_PREDICATE {
        soft(issue_evidence::resolution_proposed_in_txn(
            vault, txn, key, claim,
        ))? == Some(true)
    } else {
        soft(blocked_reports::settled_in_txn(vault, txn, &key))?
            .flatten()
            .is_some_and(|settled| settled.proposal == claim)
    };
    Ok(proved.then(|| match predicate {
        COACH_HEAL_PROPOSAL_PREDICATE => HealSourceRef::Case(key.to_hex()),
        COACH_ISSUE_PROPOSAL_PREDICATE => HealSourceRef::Report(key),
        _ => HealSourceRef::Issue(key),
    }))
}

/// Reads what `row`'s source binds it to: its attempt as it stands, with any park, its TASK
/// with any STUCK report, and, while that TASK is no success, every unfinished TASK that
/// waits on it. An unproved source reads nothing.
fn read_impact(vault: &Vault, txn: &heed::RoTxn<'_>, row: &mut HealResidue) -> Result<()> {
    let (attempt, mut task_ref) = source_binding(vault, txn, row)?;
    if let Some(attempt) = attempt {
        let hex = bytes_to_hex_lower(attempt.as_bytes());
        match soft(AttemptQueue::new(vault).get_in_txn(txn, attempt))?.flatten() {
            Some(record) => {
                if matches!(row.source, HealSourceRef::Case(_)) {
                    row.source_time = Some(record.updated_at);
                }
                let store = DreamerRunnerStore::new(vault);
                let parked = match soft(store.parked_attempt_in_txn(txn, attempt))? {
                    Some(parked) => parked.map(|park| (park.parked_at, park.cause)),
                    None => {
                        row.mark(Gap::ParkUnreadable, hex);
                        None
                    }
                };
                task_ref = task_ref.or_else(|| record.task_ref.clone());
                row.attempts.push(HealAttemptFact {
                    attempt,
                    state: record.state,
                    updated_at: record.updated_at,
                    task_ref: record.task_ref,
                    parked,
                });
            }
            None => row.mark(Gap::AttemptMissing, hex),
        }
    }
    if matches!(row.source, HealSourceRef::Unproved(_)) {
        return Ok(());
    }
    let Some(task) = task_ref
        .as_deref()
        .and_then(|hex| EntityId::from_hex(hex).ok())
    else {
        let about = task_ref.unwrap_or_else(|| row.source.id());
        row.mark(Gap::NoTask, about);
        return Ok(());
    };
    let (state, stuck) = task_facts(vault, txn, task)?;
    if state == HealTaskState::Unknown {
        row.mark(Gap::TaskMissing, task.to_hex());
    }
    row.task = Some((task, state));
    row.stuck = stuck;
    if state != HealTaskState::Settled(TaskTerminalDisposition::Completed) {
        walk_dependents(vault, txn, task, state, row)?;
    }
    Ok(())
}

/// The attempt `row`'s source names and the TASK its own row names, if any: a case's failed
/// attempt and TASK; a report's host-stamped attempt; a model issue's attempt only where
/// its recorded links prove a skill producer. Sets the source's time where its own row gives
/// it, and marks what it cannot read.
fn source_binding(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &mut HealResidue,
) -> Result<(Option<AttemptId>, Option<String>)> {
    let about = row.source.id();
    let attempt = match row.source.clone() {
        HealSourceRef::Case(case_ref) => {
            match soft(healer_case_in_txn(vault, txn, &case_ref))?.flatten() {
                Some(case) => return Ok((Some(case.failing_attempt_id), case.task_ref)),
                None => {
                    row.mark(Gap::SourceRowMissing, about);
                    return Ok((None, None));
                }
            }
        }
        HealSourceRef::Report(receipt) => {
            row.source_time = soft(vault.get_raw_in(txn, &receipt))?
                .flatten()
                .and_then(|raw| EntityMetadataHeader::parse(&raw))
                .map(|header| header.learned_at);
            match soft(read_blocked_receipt(vault, &receipt))?.flatten() {
                Some(report) => report
                    .attempt
                    .as_deref()
                    .and_then(|hex| EntityId::from_hex(hex).ok())
                    .and_then(|id| AttemptId::from_bytes(id.as_bytes()).ok()),
                None => {
                    row.mark(Gap::SourceRowMissing, about);
                    return Ok((None, None));
                }
            }
        }
        HealSourceRef::Issue(issue_id) => {
            match soft(issue_work::issue_in_txn(vault, txn, &issue_id))?.flatten() {
                Some(issue) => {
                    row.source_time = Some(issue.raised_at);
                    match issue.producer {
                        ProducerTarget::Skill { attempt, .. } => {
                            AttemptId::from_bytes(attempt.as_bytes()).ok()
                        }
                        ProducerTarget::PolicyManifest { .. }
                        | ProducerTarget::Config { .. }
                        | ProducerTarget::Unknown => None,
                    }
                }
                None => {
                    row.mark(Gap::SourceRowMissing, about);
                    return Ok((None, None));
                }
            }
        }
        HealSourceRef::Unproved(_) => return Ok((None, None)),
    };
    if attempt.is_none() {
        row.mark(Gap::NoAttempt, about);
    }
    Ok((attempt, None))
}

/// A TASK's state and STUCK report as its row reads at `txn`. A row that is no typed TASK,
/// or does not decode, is unknown.
fn task_facts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
) -> Result<(HealTaskState, Option<(u64, Vec<EntityId>)>)> {
    Ok(
        match soft(task_impact_facts_in_txn(vault, txn, task))?.flatten() {
            Some(facts) => (
                facts
                    .terminal
                    .map_or(HealTaskState::Unfinished, HealTaskState::Settled),
                facts.stuck,
            ),
            None => (HealTaskState::Unknown, None),
        },
    )
}

/// Walks every unfinished TASK that waits on `source` through recorded `blocked_by` edges,
/// transitively, each once, recording every edge read and every TASK each one waits on. A
/// finished TASK ends its branch, recorded but not counted; an unknown one is marked. The
/// CODE plane's `blocks` edges are never read.
fn walk_dependents(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: EntityId,
    source_state: HealTaskState,
    row: &mut HealResidue,
) -> Result<()> {
    let mut visited = BTreeSet::from([source]);
    let mut recorded = BTreeSet::new();
    let mut frontier = vec![(source, source_state)];
    while let Some((blocker, blocker_state)) = frontier.pop() {
        let Some(waiting) = soft(blocked_by(vault, txn, blocker, EdgeDirection::In))? else {
            row.mark(Gap::EdgesUnreadable, blocker.to_hex());
            continue;
        };
        for (dependent, recorded_at) in waiting {
            let (dependent_state, _) = task_facts(vault, txn, dependent)?;
            if recorded.insert((dependent, blocker)) {
                row.edges.push(HealDependencyEdge {
                    dependent,
                    blocker,
                    recorded_at,
                    dependent_state,
                    blocker_state,
                });
            }
            match dependent_state {
                HealTaskState::Unfinished if visited.insert(dependent) => {
                    row.dependents.push(dependent);
                    frontier.push((dependent, dependent_state));
                    other_blockers(vault, txn, dependent, &mut recorded, row)?;
                }
                HealTaskState::Unknown => row.mark(Gap::DependentUnknown, dependent.to_hex()),
                HealTaskState::Unfinished | HealTaskState::Settled(_) => {}
            }
        }
    }
    Ok(())
}

/// Records every TASK the unfinished `dependent` waits on that no edge read yet named, with
/// its state: a missing one is unknown, never a success.
fn other_blockers(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    dependent: EntityId,
    recorded: &mut BTreeSet<(EntityId, EntityId)>,
    row: &mut HealResidue,
) -> Result<()> {
    let Some(waits_on) = soft(blocked_by(vault, txn, dependent, EdgeDirection::Out))? else {
        row.mark(Gap::EdgesUnreadable, dependent.to_hex());
        return Ok(());
    };
    for (blocker, recorded_at) in waits_on {
        if recorded.insert((dependent, blocker)) {
            let (blocker_state, _) = task_facts(vault, txn, blocker)?;
            row.edges.push(HealDependencyEdge {
                dependent,
                blocker,
                recorded_at,
                dependent_state: HealTaskState::Unfinished,
                blocker_state,
            });
        }
    }
    Ok(())
}

/// The TASKs at the other end of `task`'s recorded `blocked_by` edges in `direction`, with
/// each edge's time: `In` reads what waits on it, `Out` what it waits on. Every edge is read.
fn blocked_by(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
    direction: EdgeDirection,
) -> Result<Vec<(EntityId, u64)>> {
    let mut edges = Vec::new();
    for edge in vault
        .store
        .port_edges(txn, &task, direction, Some(EdgeKind::BlockedBy), None)?
    {
        let edge = edge?;
        edges.push((edge.target, edge.created_at));
    }
    Ok(edges)
}
