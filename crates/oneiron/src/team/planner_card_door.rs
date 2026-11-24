//! `vault.planner.card` (design pass 32 section 5, row 12; ARCH-0079
//! #planner): the planner card of one project and task type, as a read door.
//!
//! The door answers what the planner's deterministic floor reads at spawn:
//! the project's payoff rows (else the vault's) and every admitted pattern
//! skill's estimate, own runs, borrowed cell and UNTESTED mark, ranked by
//! the shared selector ranking. It calls the pure read
//! ([`super::payoff::planner_card_in_txn`]) in one snapshot and never runs
//! the planner ladder, whose model rungs load packs and can reserve trial
//! spend. Beside the card it answers a `digest` of the whole answer, so a
//! session can prove which card it read before it admits an arm.
//!
//! The caller is the vault owner under their own proof, or an agent whose
//! own live Grant from a live owner lists the verb
//! ([`crate::memory::verb_grant_caller`]), judged at each call.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::learning::doors::{LearningCellKey, MeasuredLearningEstimate};
use crate::memory::{Memory, MemoryResult};
use crate::receipt::task_type_ref::TypeRef;
use crate::skill::skill_loadable;

use super::pattern::{TeamPattern, pattern_skills_in_txn};
use super::payoff::{PatternCardEntry, PayoffRow, PlannerCard, planner_card_in_txn};

/// The verb's registered name.
pub const PLANNER_CARD_VERB: &str = "vault.planner.card";

/// The most executor models one card names.
pub const PLANNER_CARD_MODELS_MAX: usize = 32;

/// `vault.planner.card`'s input: the project and the task type the card is
/// for, and the executor models whose mix keys the pattern cells.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlannerCardRequest {
    /// The project (a lane's family) as an entity id.
    pub project_ref: String,
    /// The task type; the project's recorded tree at its version must hold it.
    pub type_ref: TypeRef,
    /// The executor models, as the planner names a seat's model; empty reads
    /// the mix `unknown`.
    #[serde(default)]
    pub models: Vec<String>,
}

/// One payoff row on the card.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannerCardPayoffRow {
    /// The receipts' frozen project; absent is the vault's runs.
    pub project_ref: Option<String>,
    pub type_ref: TypeRef,
    pub pattern: TeamPattern,
    pub pattern_skill: Option<String>,
    pub models: String,
    pub shape: String,
    pub decided_by: String,
    pub teams: u64,
    pub wins: u64,
    pub losses: u64,
    pub mean_spend: Option<f64>,
    pub mean_elapsed_secs: f64,
    pub mean_calls: Option<f64>,
    pub mean_coverage: Option<f64>,
    pub confessions: u64,
    pub wait_by_reason: BTreeMap<String, u64>,
    pub mean_reuse_delay_secs: Option<f64>,
    pub duplicate_work: u64,
}

impl From<PayoffRow> for PlannerCardPayoffRow {
    fn from(row: PayoffRow) -> Self {
        Self {
            project_ref: row.project.map(|project| project.to_hex()),
            type_ref: row.type_ref,
            pattern: row.pattern,
            pattern_skill: row.pattern_skill.map(|skill| skill.to_hex()),
            models: row.models,
            shape: row.shape,
            decided_by: row.decided_by,
            teams: row.teams,
            wins: row.wins,
            losses: row.losses,
            mean_spend: row.mean_spend,
            mean_elapsed_secs: row.mean_elapsed_secs,
            mean_calls: row.mean_calls,
            mean_coverage: row.mean_coverage,
            confessions: row.confessions,
            wait_by_reason: row.wait_by_reason,
            mean_reuse_delay_secs: row.mean_reuse_delay_secs,
            duplicate_work: row.duplicate_work,
        }
    }
}

/// One candidate pattern on the card, as the planner ranks it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannerCardPattern {
    pub skill: String,
    /// The pattern the skill teaches; absent when its binding is gone.
    pub pattern: Option<TeamPattern>,
    /// The binding's plain line: "for tasks like X, Y usually works".
    pub works_well_for: Option<String>,
    /// The estimate in force, with its UNTESTED mark.
    pub estimate: MeasuredLearningEstimate,
    /// Whether the estimate rests on the cell's own runs.
    pub own: bool,
    /// The cell a borrowed prior came from.
    pub borrowed_from: Option<LearningCellKey>,
    /// Mean plus the exploration bonus; the card lists the highest first.
    pub score: f64,
}

impl From<PatternCardEntry> for PlannerCardPattern {
    fn from(entry: PatternCardEntry) -> Self {
        let (pattern, works_well_for) = match entry.binding {
            Some(binding) => (Some(binding.pattern), Some(binding.works_well_for)),
            None => (None, None),
        };
        Self {
            skill: entry.skill.to_hex(),
            pattern,
            works_well_for,
            estimate: entry.read.estimate.into(),
            own: entry.read.own,
            borrowed_from: entry.read.borrowed_from.map(LearningCellKey::from),
            score: entry.score,
        }
    }
}

/// `vault.planner.card`'s answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannerCardView {
    pub project_ref: String,
    pub type_ref: TypeRef,
    pub executor_mix: String,
    /// The project's own payoff rows, else the vault's (each row names its
    /// scope).
    pub rows: Vec<PlannerCardPayoffRow>,
    /// Highest score first; ties by skill id.
    pub patterns: Vec<PlannerCardPattern>,
    /// sha256, lower hex, of this answer's JSON with this field empty: one
    /// card answers one digest.
    pub digest: String,
}

impl PlannerCardView {
    fn of(project: EntityId, card: PlannerCard) -> Result<Self> {
        let mut view = Self {
            project_ref: project.to_hex(),
            type_ref: card.type_ref,
            executor_mix: card.executor_mix,
            rows: card.rows.into_iter().map(Into::into).collect(),
            patterns: card.patterns.into_iter().map(Into::into).collect(),
            digest: String::new(),
        };
        let bytes = serde_json::to_vec(&view)
            .map_err(|_| Error::InvalidClaimBody("the planner card does not encode"))?;
        view.digest = format!("{:x}", Sha256::digest(&bytes));
        Ok(view)
    }
}

/// The planner card `input` names, read in one snapshot. It writes nothing.
///
/// # Errors
///
/// A malformed project id, type stamp or model list; a type stamp the
/// project's recorded task-type tree does not hold; storage errors.
pub fn planner_card_view(vault: &Vault, input: &PlannerCardRequest) -> Result<PlannerCardView> {
    let project = EntityId::from_hex(&input.project_ref)
        .map_err(|_| Error::InvalidClaimBody("the planner card's project_ref is an entity id"))?;
    if input.models.len() > PLANNER_CARD_MODELS_MAX {
        return Err(Error::InvalidClaimBody(
            "the planner card names at most 32 executor models",
        ));
    }
    input.type_ref.validate()?;
    let tree = crate::task_type::type_tree_at(vault, Some(project), input.type_ref.tree_version)?
        .filter(|tree| tree.contains(&input.type_ref))
        .ok_or(Error::InvalidClaimBody(
            "the planner card's type_ref must name a node of the project's recorded task-type tree",
        ))?;
    let parents = tree.ancestors(&input.type_ref);
    let txn = vault.store.env.read_txn()?;
    // The candidates the planner reads at spawn: every bound pattern skill
    // whose skill record is loadable.
    let mut candidates = Vec::new();
    for binding in pattern_skills_in_txn(vault, &txn)? {
        if vault
            .get_skill_record_in_txn(&txn, &binding.skill)?
            .is_some_and(|record| skill_loadable(&record))
        {
            candidates.push(binding.skill);
        }
    }
    let card = planner_card_in_txn(
        vault,
        &txn,
        Some(project),
        &input.type_ref,
        &parents,
        &input.models,
        &candidates,
    )?;
    drop(txn);
    PlannerCardView::of(project, card)
}

/// `vault.planner.card` for the owner under `owner`'s proof.
///
/// # Errors
///
/// An owner proof that no longer holds; as [`planner_card_view`].
pub fn planner_card_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &PlannerCardRequest,
) -> Result<PlannerCardView> {
    owner.revalidate(vault)?;
    planner_card_view(vault, input)
}

/// `vault.planner.card` for this handle's caller: the owner under `owner`,
/// or an agent whose own live Grant lists the verb.
///
/// # Errors
///
/// `forbidden` for a caller the verb does not admit; as
/// [`planner_card_view`].
pub fn planner_card_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    input: &PlannerCardRequest,
) -> MemoryResult<PlannerCardView> {
    memory.verb_grant_caller_admits(owner, PLANNER_CARD_VERB)?;
    Ok(planner_card_view(memory.vault(), input)?)
}

/// `vault.planner.card` on a bound handle: the embedded owner reads under
/// its own proof, any other caller under its own Grant.
///
/// # Errors
///
/// As [`planner_card_as`].
pub fn planner_card_embedded(
    memory: &Memory<'_>,
    input: &PlannerCardRequest,
) -> MemoryResult<PlannerCardView> {
    let owner = memory.embedded_owner(PLANNER_CARD_VERB).ok();
    planner_card_as(memory, owner.as_ref(), input)
}
