//! Full goal revision proposals (LEARNING-01; ARCH-0053, "The ruler-change
//! proposal"). The vault owner, or an agent whose live owner Grant lists
//! `vault.projects.goal.propose` and that sits in the project, proposes a
//! whole goal record against the goal claim and generation in force, with
//! its reasons and evidence. The engine stores it with the diff against that
//! base. Nothing here writes the goal: only the human goal-intake interview
//! does, and a proposer never approves its own proposal. A vault owner
//! dismisses a proposal with a reason; the row stays as history. An agent's
//! proposals carry a rate (LEARN-GOAL-RATE = A); the owner's do not.

mod diff;

use serde::{Deserialize, Serialize};

pub use diff::{
    GoalAxisChange, GoalAxisChanges, GoalBudgetChange, GoalPreferenceChange, GoalPreferenceChanges,
    GoalRecordDiff, GoalTextChange,
};

use super::GoalRecord;
use crate::authority::{NoStanding, PACT_STANDING_LAPSED, principal_standing_or_lapse_in_txn};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::federation::SubstrateRead;
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE,
    MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};
use crate::side_table::{self, Named, SideTable};
use crate::skill_optimize::ProjectGoalRevisionProposal;
use crate::workspace_roster::spend_scope::SpendScopeId;
use crate::{EntityId, Vault};

/// The verb a Grant lists to propose: the row's own name.
const PROPOSE_VERB: &str = "vault.projects.goal.propose";

/// Why an agent with no conferring Grant is refused.
const NO_GRANT: &str = "no live Grant from a live owner names this agent and lists the verb";

/// The rate an agent's proposals carry. Canon asks for one ("Proposals
/// carry a rate and a budget, or a hard target turns them into spam",
/// ARCH-0053) and names no number: Engine's built default, not ruled
/// (LEARN-GOAL-RATE = A). Each agent's row records the terms it was
/// admitted under, so a later policy key replaces them without a migration.
const AGENT_PROPOSAL_RATE: ProjectGoalProposalRate = ProjectGoalProposalRate {
    open_per_base: 1,
    per_window: 4,
    window_secs: 7 * 86_400,
};

/// The bound on each reason text and each receipt reference, in bytes once
/// trimmed: the optimizer's rationale bound.
const TEXT_MAX_BYTES: usize = 1_024;

/// The bound on each list a proposal carries.
const LIST_MAX: usize = 32;

/// Every full proposal. Key: id16 (project) + id16 (proposal).
const PROPOSALS: SideTable<(EntityId, EntityId), ProjectGoalProposal, Named> =
    SideTable::new(&side_table::PROJECT_GOAL_PROPOSAL);

/// The goal a proposal revises: the goal claim in force and the goal
/// generation it was read at. Either one moving makes the base stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalBase {
    pub goal_claim: EntityId,
    pub generation: u64,
}

/// Who proposed, as the engine admitted it: never a field of the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProjectGoalProposer {
    /// The live vault owner.
    Owner { person: EntityId },
    /// An agent, on the live owner Grant that listed the verb when it
    /// proposed.
    Agent { agent: EntityId, grant: EntityId },
}

impl ProjectGoalProposer {
    /// The actor the rate counts, whichever Grant admitted it.
    fn principal(&self) -> EntityId {
        match self {
            Self::Owner { person } => *person,
            Self::Agent { agent, .. } => *agent,
        }
    }
}

/// The rate a proposal was admitted under: at most `open_per_base` open
/// proposals of one proposer on one goal base, and at most `per_window` of
/// its proposals for one project in any `window_secs` (the vault clock's
/// seconds), dismissed ones counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalProposalRate {
    pub open_per_base: u32,
    pub per_window: u32,
    pub window_secs: u64,
}

/// The proposal's argument (ARCH-0053): why, its merits and demerits, and
/// the sacrifice, what is given up if the goal moves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalProposalReasons {
    pub reason: String,
    pub merits: Vec<String>,
    pub demerits: Vec<String>,
    pub sacrifice: String,
}

/// imp@k against the target over N cycles, by the receipts that show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalProposalImprovement {
    pub k: u32,
    pub cycles: u32,
    pub receipts: Vec<String>,
}

/// The proposal's evidence shape (ARCH-0053): the attractor case, imp@k
/// against the target over N cycles, and the cost spent. These are
/// references the human and the judge read; the door stores them and
/// scores nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalProposalEvidence {
    /// The eval case the target pulls toward.
    pub attractor_case: EntityId,
    pub improvement: ProjectGoalProposalImprovement,
    /// The spend scopes the evidence was paid from.
    pub cost_spent: Vec<SpendScopeId>,
}

/// `vault.projects.goal.propose`'s input. Who proposes and when come from
/// the engine; the diff is computed against the goal in force.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalProposeRequest {
    pub project_ref: EntityId,
    /// The goal the proposal revises, as the proposer read it.
    pub base: ProjectGoalBase,
    /// The whole goal record proposed, valid as the interview would write it.
    pub proposed: GoalRecord,
    pub reasons: ProjectGoalProposalReasons,
    pub evidence: ProjectGoalProposalEvidence,
}

/// A vault owner's outcome for a proposal: dismissed, with the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalProposalDismissal {
    pub person: EntityId,
    pub reason: String,
    pub at: u64,
}

/// One stored proposal. Only the dismissal is ever written after it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalProposal {
    pub id: EntityId,
    pub project: EntityId,
    pub base: ProjectGoalBase,
    pub proposed: GoalRecord,
    pub proposer: ProjectGoalProposer,
    pub reasons: ProjectGoalProposalReasons,
    pub evidence: ProjectGoalProposalEvidence,
    /// What `proposed` changes against `base`, computed when it was stored.
    pub diff: GoalRecordDiff,
    pub created_at: u64,
    /// The rate this proposal was admitted under; none for the owner's.
    pub rate: Option<ProjectGoalProposalRate>,
    pub dismissal: Option<ProjectGoalProposalDismissal>,
}

/// Where a proposal stands now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectGoalProposalStatus {
    /// On the goal in force and not dismissed: the interview shows it.
    Open,
    /// A vault owner dismissed it.
    Dismissed,
    /// The goal moved since; history only.
    Superseded,
}

/// A proposal with where it stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalProposalView {
    pub proposal: ProjectGoalProposal,
    pub status: ProjectGoalProposalStatus,
}

/// `vault.projects.goal.revisions`: the goal in force, the learned
/// preferences proposed under it, and every full proposal with its status,
/// oldest first. Full proposals carry goal records, so only a caller that
/// may read the goal gets them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalRevisionsView {
    pub project_ref: EntityId,
    pub base: Option<ProjectGoalBase>,
    pub preferences: Vec<ProjectGoalRevisionProposal>,
    pub proposals: Vec<ProjectGoalProposalView>,
}

impl ProjectGoalProposal {
    /// This proposal with its status against `base`, the goal in force.
    pub(crate) fn view(self, base: Option<&ProjectGoalBase>) -> ProjectGoalProposalView {
        let status = if self.dismissal.is_some() {
            ProjectGoalProposalStatus::Dismissed
        } else if base == Some(&self.base) {
            ProjectGoalProposalStatus::Open
        } else {
            ProjectGoalProposalStatus::Superseded
        };
        ProjectGoalProposalView {
            proposal: self,
            status,
        }
    }
}

/// `vault.projects.goal.propose` on the caller's handle: the stored
/// proposal. An identical repeat by the same proposer returns the first row
/// and counts nothing.
///
/// One writer admits the caller (the live vault owner, or an agent whose
/// live owner Grant lists the verb); checks that an agent sits in the
/// project (a seat, its leader or its board) and reads the goal it revises;
/// that the base is the goal in force; the record, reasons and evidence;
/// then an agent's rate; then stores the row. The owner passes the seat
/// check and the rate on its own vault (LEARN-GOAL-RATE). It never writes
/// the goal.
///
/// # Errors
///
/// FORBIDDEN for a caller that is not admitted, or an agent that sits in no
/// seat of the project or reads no goal; INVALID_STATE for a project with no
/// goal, a stale base, or an agent past its rate; BAD_REQUEST for an invalid
/// or unchanged record or an unbounded argument; storage errors.
pub fn project_goal_propose(
    memory: &Memory<'_>,
    input: ProjectGoalProposeRequest,
) -> MemoryResult<ProjectGoalProposalView> {
    let vault = memory.vault();
    let at = vault.now_recorded_at();
    vault.try_with_write_txn_grouped(|txn| {
        let proposer = admit_proposer_in_txn(memory, txn)?;
        if let ProjectGoalProposer::Agent { agent, .. } = proposer {
            require_project_member_in_txn(vault, txn, input.project_ref, agent)?;
            if !vault.substrate_read_granted_in_txn(txn, agent, SubstrateRead::Goal)? {
                return Err(refused(
                    "the agent reads no goal: it holds no Steward grant naming `read` over the whole vault",
                ));
            }
        }
        let Some((base, record)) = goal_in_force_in_txn(vault, txn, input.project_ref)? else {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "the project has no goal in force to revise",
                &["The goal-intake interview writes a project's first goal."],
            ));
        };
        if input.base != base {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "the proposal's base is not the goal in force: the goal moved since it was read",
                &["Read the goal again and propose against it."],
            ));
        }
        check_proposed(&input.proposed, &record)?;
        check_reasons(&input.reasons)?;
        check_evidence(&input.evidence)?;
        let principal = proposer.principal();
        let mine: Vec<ProjectGoalProposal> =
            project_goal_proposals_in_txn(vault, txn, input.project_ref)?
                .into_iter()
                .filter(|row| row.proposer.principal() == principal)
                .collect();
        if let Some(first) = mine.iter().find(|row| {
            row.base == base
                && row.proposed == input.proposed
                && row.reasons == input.reasons
                && row.evidence == input.evidence
        }) {
            return Ok(first.clone().view(Some(&base)));
        }
        let rate = match proposer {
            ProjectGoalProposer::Owner { .. } => None,
            ProjectGoalProposer::Agent { .. } => {
                check_rate(&AGENT_PROPOSAL_RATE, &mine, &base, at)?;
                Some(AGENT_PROPOSAL_RATE)
            }
        };
        let proposal = ProjectGoalProposal {
            id: vault.store.clock.entity_id()?,
            project: input.project_ref,
            base,
            diff: GoalRecordDiff::between(&record, &input.proposed),
            proposed: input.proposed,
            proposer,
            reasons: input.reasons,
            evidence: input.evidence,
            created_at: at,
            rate,
            dismissal: None,
        };
        PROPOSALS.put(
            &vault.store,
            txn,
            &(proposal.project, proposal.id),
            &proposal,
        )?;
        Ok(proposal.view(Some(&base)))
    })
}

/// The proposer a proposal names, in `txn`: the vault owner while a live
/// person, or an agent on the live owner Grant that lists the verb. The
/// caller's actor binding and any credential it presented are checked first.
fn admit_proposer_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
) -> MemoryResult<ProjectGoalProposer> {
    if let Some(person) = live_owner_caller_in_txn(memory, txn)? {
        return Ok(ProjectGoalProposer::Owner { person });
    }
    if memory.actor_class() != EdgeActorClass::Agent {
        return Err(refused(
            "the caller is neither the vault owner nor an agent",
        ));
    }
    match principal_standing_or_lapse_in_txn(
        memory.vault(),
        txn,
        memory.actor(),
        EdgeActorClass::Agent,
        PROPOSE_VERB,
    )? {
        Ok(standing) => Ok(ProjectGoalProposer::Agent {
            agent: memory.actor(),
            grant: standing.grant.ok_or_else(|| refused(NO_GRANT))?,
        }),
        Err(NoStanding::PactStandingLapsed) => Err(refused(PACT_STANDING_LAPSED)),
        Err(NoStanding::NotStanding) => Err(refused(NO_GRANT)),
    }
}

/// The caller, in `txn`, when it is the live vault owner: its actor binding
/// and any credential it presented checked first. `None` for any other
/// caller; a dead credential or a dead owner is refused.
fn live_owner_caller_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
) -> MemoryResult<Option<EntityId>> {
    let vault = memory.vault();
    crate::memory::verify_actor_binding_in_txn(vault, txn, memory.actor(), memory.actor_class())?;
    if let Some(slip) = memory.presented_credential()
        && !vault.capability_slip_is_live_in_txn(txn, slip)?
    {
        return Err(refused("the caller's credential is no longer live"));
    }
    if !crate::memory::actor_is_vault_owner_in_txn(
        vault,
        txn,
        memory.actor(),
        memory.actor_class(),
    )? {
        return Ok(None);
    }
    if !crate::consent::person_is_live_in_txn(vault, txn, &memory.actor())? {
        return Err(refused("the vault owner is not a live person"));
    }
    Ok(Some(memory.actor()))
}

/// Whether the caller, in `txn`, reads full proposals: the live vault owner,
/// or a holder of a Steward grant naming `read` over the whole vault, as an
/// agent reads the goal itself (untangle 6.6d). A full proposal carries a
/// goal record and its diff the goal in force.
pub(crate) fn reads_goal_proposals_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
) -> MemoryResult<bool> {
    if live_owner_caller_in_txn(memory, txn)?.is_some() {
        return Ok(true);
    }
    Ok(memory
        .vault()
        .substrate_read_granted_in_txn(txn, memory.actor(), SubstrateRead::Goal)?)
}

/// Refuses an actor that sits in no seat of `project`'s folded authority and
/// is neither its leader nor on its board, as the goal revisions read does.
fn require_project_member_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: EntityId,
    actor: EntityId,
) -> MemoryResult<()> {
    let (_, effective) = vault
        .effective_project_in_txn(txn, project)?
        .ok_or(crate::Error::EntityNotFound)?;
    let actor = actor.to_hex();
    if effective.seats(&actor) || effective.leader == actor || effective.board.contains(&actor) {
        return Ok(());
    }
    Err(refused(
        "the caller sits in no seat of the project and is neither its leader nor on its board",
    ))
}

/// The goal in force for `project` and its record, in `txn`; `None` before
/// the first interview commits. The engine's own read, for the writer's
/// base check and diff: callers are admitted before it.
fn goal_in_force_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: EntityId,
) -> crate::Result<Option<(ProjectGoalBase, GoalRecord)>> {
    let Some((goal_claim, record)) = vault.project_intake_goal_in_txn(txn, project)? else {
        return Ok(None);
    };
    let generation = super::interview::generation(&vault.store, txn, project)?;
    Ok(Some((
        ProjectGoalBase {
            goal_claim,
            generation,
        },
        record,
    )))
}

/// The goal in force for `project` as a base, in `txn`.
pub(crate) fn project_goal_base_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: EntityId,
) -> crate::Result<Option<ProjectGoalBase>> {
    Ok(goal_in_force_in_txn(vault, txn, project)?.map(|(base, _)| base))
}

/// Every full proposal for `project`, oldest first, in `txn`.
pub(crate) fn project_goal_proposals_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: EntityId,
) -> crate::Result<Vec<ProjectGoalProposal>> {
    let mut rows: Vec<ProjectGoalProposal> = PROPOSALS
        .scan_from(&vault.store, txn, project.as_bytes())?
        .into_iter()
        .map(|(_, row)| row)
        .collect();
    rows.sort_by_key(|row| (row.created_at, row.id));
    Ok(rows)
}

/// A vault owner dismisses the full proposal `proposal` of `project` with
/// `reason`: the interview no longer shows it, and the row stays as history
/// with the outcome. The owner is revalidated in the write; a proposal
/// already dismissed keeps its first outcome and returns `false`.
///
/// # Errors
///
/// An owner that no longer revalidates, a blank or unbounded reason, no
/// such proposal, storage errors.
pub(crate) fn dismiss_project_goal_proposal(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    project: EntityId,
    proposal: EntityId,
    reason: &str,
    at: u64,
) -> MemoryResult<bool> {
    let reason = bounded_text("the dismissal's reason", reason)?;
    vault.try_with_write_txn_grouped(|txn| {
        let person = owner.revalidate_in_txn(vault, txn)?;
        let Some(mut row) = PROPOSALS.get(&vault.store, txn, &(project, proposal))? else {
            return Err(MemoryError::new(
                MEMORY_CODE_NOT_FOUND,
                "no goal proposal with that id for that project",
                &["List the project's goal revisions for the proposal's id."],
            ));
        };
        if row.dismissal.is_some() {
            return Ok(false);
        }
        row.dismissal = Some(ProjectGoalProposalDismissal { person, reason, at });
        PROPOSALS.put(&vault.store, txn, &(project, proposal), &row)?;
        Ok(true)
    })
}

/// Refuses a proposal past `rate`, given the proposer's own `rows` for the
/// project: an open proposal of its own already on `base`, or a full window
/// ending at `at`.
fn check_rate(
    rate: &ProjectGoalProposalRate,
    rows: &[ProjectGoalProposal],
    base: &ProjectGoalBase,
    at: u64,
) -> MemoryResult<()> {
    let open = rows
        .iter()
        .filter(|row| row.base == *base && row.dismissal.is_none())
        .count();
    if open >= usize::try_from(rate.open_per_base).unwrap_or(usize::MAX) {
        return Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "this agent already has an open proposal on the goal in force",
            &["Wait for the owner's outcome, or for the goal to move."],
        ));
    }
    let since = at.saturating_sub(rate.window_secs);
    let recent = rows.iter().filter(|row| row.created_at > since).count();
    if recent >= usize::try_from(rate.per_window).unwrap_or(usize::MAX) {
        return Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            format!(
                "an agent stores at most {} proposals for a project in {} seconds",
                rate.per_window, rate.window_secs
            ),
            &["Propose again once the window has room."],
        ));
    }
    Ok(())
}

/// A proposed record the interview could write, and not the one in force.
fn check_proposed(proposed: &GoalRecord, in_force: &GoalRecord) -> MemoryResult<()> {
    if proposed.validate().is_err() {
        return Err(bad_request(
            "the proposed goal record is not one the interview could write: a goal, a why, at least one primary, floor and cost axis (human_minutes among the costs), unique axis names, and an exploration slice within its spend",
        ));
    }
    if proposed == in_force {
        return Err(bad_request("the proposed goal record is the goal in force"));
    }
    Ok(())
}

fn check_reasons(reasons: &ProjectGoalProposalReasons) -> MemoryResult<()> {
    bounded_text("the reason", &reasons.reason)?;
    bounded_text("the sacrifice", &reasons.sacrifice)?;
    bounded_list("the merits", &reasons.merits)?;
    bounded_list("the demerits", &reasons.demerits)?;
    Ok(())
}

fn check_evidence(evidence: &ProjectGoalProposalEvidence) -> MemoryResult<()> {
    let improvement = &evidence.improvement;
    if improvement.k == 0 || improvement.cycles == 0 {
        return Err(bad_request(
            "imp@k names a k and a number of cycles above zero",
        ));
    }
    bounded_list("the improvement's receipts", &improvement.receipts)?;
    if evidence.cost_spent.len() > LIST_MAX {
        return Err(bad_request(&format!(
            "the cost spent names at most {LIST_MAX} spend scopes"
        )));
    }
    Ok(())
}

/// `text` trimmed, refused when blank or over [`TEXT_MAX_BYTES`].
fn bounded_text(what: &str, text: &str) -> MemoryResult<String> {
    let text = text.trim();
    if text.is_empty() || text.len() > TEXT_MAX_BYTES {
        return Err(bad_request(&format!(
            "{what} is a text of 1 to {TEXT_MAX_BYTES} bytes once trimmed"
        )));
    }
    Ok(text.to_owned())
}

/// One to [`LIST_MAX`] texts, each bounded.
fn bounded_list(what: &str, items: &[String]) -> MemoryResult<()> {
    if items.is_empty() || items.len() > LIST_MAX {
        return Err(bad_request(&format!("{what} are 1 to {LIST_MAX} entries")));
    }
    for item in items {
        bounded_text(what, item)?;
    }
    Ok(())
}

fn bad_request(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_BAD_REQUEST,
        format!("{PROPOSE_VERB}: {why}"),
        &["Send a complete, bounded proposal."],
    )
}

/// The verb's refusal of a caller it does not admit.
fn refused(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "{PROPOSE_VERB} takes the vault owner, or an agent on its own live owner Grant that lists it, seated in the project: {why}"
        ),
        &[
            "Call as the owner, or have the owner grant this agent the verb by name and seat it in the project.",
        ],
    )
}
