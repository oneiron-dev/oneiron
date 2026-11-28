//! `vault.planner.card` (design pass 32 r2, sections 5.1 and 5.4; ARCH-0079
//! #planner): the planner card of one project and task type, as a read door.
//!
//! The door answers one snapshot in three labelled parts:
//! - `lane_arms`: when a GPU line seats the project as a family, the
//!   family's own arms on that line, its room this period, its refusals and
//!   its forecast scores, from the line's own rows ([`lane_arms`]);
//! - `payoff_rows`: the project's payoff rows, else the vault's, each marked
//!   `scope: project` or `scope: vault_prior`, so a vault row is never shown
//!   as the lane's result;
//! - `coordination_patterns`: every admitted pattern skill's estimate, own
//!   runs, borrowed cell and UNTESTED mark, ranked by the shared selector
//!   ranking. Lane arms do not train these cells (section 3.6), and the card
//!   says so.
//!
//! It calls the pure reads ([`super::payoff::planner_card_in_txn`]) in one
//! snapshot and never runs the planner ladder, whose model rungs load packs
//! and can reserve trial spend. Beside the card it answers a `digest` of the
//! whole answer, so a session can prove which card it read before it admits
//! an arm (`vault.arms.admit` stores it on the arm).
//!
//! The caller is the vault owner under their own proof, or an agent whose
//! own live Grant from a live owner lists the verb
//! ([`crate::memory::verb_grant_caller`]), judged at each call in the
//! snapshot the card is read in. When a line seats the project, the Grant
//! must also reach the line's project and hold a role on the line (lead,
//! reviewer or planner; section 5.1): a Grant of another line is refused
//! `not_this_line`. A host that collects producers is handed every row the
//! card was read from ([`super::payoff::planner_card_sources_in_txn`]), so
//! an answer derived from a row its destination may not see is withheld
//! there.

use std::collections::BTreeMap;

use oneiron_contracts::fingerprint::ContentHash;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gpu_line::{GpuLine, LineRole, doors_caller};
use crate::learning::doors::{LearningCellKey, MeasuredLearningEstimate};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::receipt::task_type_ref::TypeRef;
use crate::skill::skill_loadable;

use super::pattern::{TeamPattern, pattern_skills_in_txn};
use super::payoff::{
    PatternCardEntry, PayoffRow, PlannerCard, planner_card_in_txn, planner_card_sources_in_txn,
};

mod lane_arms;

use lane_arms::family_line_in_txn;
pub use lane_arms::{
    PLANNER_CARD_ARMS_PAGE, PlannerCardArm, PlannerCardBucket, PlannerCardLaneArms, PlannerCardRoom,
};

/// The verb's registered name.
pub const PLANNER_CARD_VERB: &str = "vault.planner.card";

/// The most executor models one card names.
pub const PLANNER_CARD_MODELS_MAX: usize = 32;

/// `vault.planner.card`'s input: the project and the task type the card is
/// for, the executor models whose mix keys the pattern cells, and the page
/// of the lane arms to read.
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
    /// The `lane_arms.next_cursor` an earlier card answered: the lane arms
    /// after it. Absent reads the newest page.
    #[serde(default)]
    pub cursor: Option<String>,
}

impl PlannerCardRequest {
    /// The project the card is for.
    fn project(&self) -> Result<EntityId> {
        EntityId::from_hex(&self.project_ref)
            .map_err(|_| Error::InvalidClaimBody("the planner card's project_ref is an entity id"))
    }
}

/// Whose runs a payoff row counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayoffScope {
    /// The card's own project's runs.
    Project,
    /// The vault's runs, read because the project has none: a prior, never
    /// the project's or the lane's result.
    VaultPrior,
}

/// One payoff row on the card.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannerCardPayoffRow {
    /// `project` only for a row of the card's own project's receipts.
    pub scope: PayoffScope,
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

impl PlannerCardPayoffRow {
    /// `row` on the card of `project`.
    fn of(row: PayoffRow, project: EntityId) -> Self {
        Self {
            scope: if row.project == Some(project) {
                PayoffScope::Project
            } else {
                PayoffScope::VaultPrior
            },
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
    /// The family's arms on the GPU line that seats the project, and its
    /// room, refusals and forecast scores there; `None` when no line ever
    /// seated it.
    pub lane_arms: Option<PlannerCardLaneArms>,
    /// The project's own payoff rows, else the vault's; each row names its
    /// scope.
    pub payoff_rows: Vec<PlannerCardPayoffRow>,
    /// Highest score first; ties by skill id.
    pub coordination_patterns: Vec<PlannerCardPattern>,
    /// Always `false`: an arm's rung receipt is a width-one market receipt,
    /// below the pattern's floor, so lane arms never train these cells
    /// (design pass 32 r2, section 3.6).
    pub lane_arms_train_patterns: bool,
    /// The content hash (BLAKE3, lower hex) of the card's JSON as the engine
    /// read it, with this field empty: one card answers one digest. It names
    /// the engine's card, so a verb hook that rewrites the view on its way
    /// out leaves it naming the card the door read.
    pub digest: String,
}

impl PlannerCardView {
    fn of(
        project: EntityId,
        card: PlannerCard,
        lane_arms: Option<PlannerCardLaneArms>,
    ) -> Result<Self> {
        let mut view = Self {
            project_ref: project.to_hex(),
            type_ref: card.type_ref,
            executor_mix: card.executor_mix,
            lane_arms,
            payoff_rows: card
                .rows
                .into_iter()
                .map(|row| PlannerCardPayoffRow::of(row, project))
                .collect(),
            coordination_patterns: card.patterns.into_iter().map(Into::into).collect(),
            lane_arms_train_patterns: false,
            digest: String::new(),
        };
        let bytes = serde_json::to_vec(&view)
            .map_err(|_| Error::InvalidClaimBody("the planner card does not encode"))?;
        view.digest = ContentHash::of(&bytes).to_hex();
        Ok(view)
    }
}

/// The planner card `input` names in the caller's snapshot `txn`, for
/// `project` and the line that seats it, at `now_ms`, beside every row the
/// card was read from ([`planner_card_sources_in_txn`]). It writes nothing.
fn planner_card_read_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    input: &PlannerCardRequest,
    project: EntityId,
    line: Option<&GpuLine>,
    now_ms: u64,
) -> Result<(PlannerCardView, Vec<EntityId>)> {
    if input.models.len() > PLANNER_CARD_MODELS_MAX {
        return Err(Error::InvalidClaimBody(
            "the planner card names at most 32 executor models",
        ));
    }
    input.type_ref.validate()?;
    let tree = crate::task_type::type_tree_at_in_txn(
        vault,
        txn,
        Some(project),
        input.type_ref.tree_version,
    )?
    .filter(|tree| tree.contains(&input.type_ref))
    .ok_or(Error::InvalidClaimBody(
        "the planner card's type_ref must name a node of the project's recorded task-type tree",
    ))?;
    let parents = tree.ancestors(&input.type_ref);
    // The candidates the planner reads at spawn: every bound pattern skill
    // whose skill record is loadable.
    let mut candidates = Vec::new();
    for binding in pattern_skills_in_txn(vault, txn)? {
        if vault
            .get_skill_record_in_txn(txn, &binding.skill)?
            .is_some_and(|record| skill_loadable(&record))
        {
            candidates.push(binding.skill);
        }
    }
    let card = planner_card_in_txn(
        vault,
        txn,
        Some(project),
        &input.type_ref,
        &parents,
        &input.models,
        &candidates,
    )?;
    let sources = planner_card_sources_in_txn(vault, txn, &card)?;
    let lane_arms = line
        .map(|line| {
            lane_arms::lane_arms_in_txn(vault, txn, line, project, input.cursor.as_deref(), now_ms)
        })
        .transpose()?;
    Ok((PlannerCardView::of(project, card, lane_arms)?, sources))
}

/// `vault.planner.card` for the owner under `owner`'s proof at `now_ms`,
/// judged in the card's own snapshot. The owner reads every line.
///
/// # Errors
///
/// An owner proof that no longer holds; a malformed project id, type stamp,
/// model list or cursor; a type stamp the project's recorded task-type tree
/// does not hold; storage errors.
pub fn planner_card_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &PlannerCardRequest,
    now_ms: u64,
) -> Result<PlannerCardView> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    let project = input.project()?;
    let line = family_line_in_txn(vault, &txn, project, now_ms)?;
    Ok(planner_card_read_in_txn(vault, &txn, input, project, line.as_ref(), now_ms)?.0)
}

/// `vault.planner.card` for this handle's caller at `now_ms`: the owner
/// under `owner`, or an agent whose own live Grant lists the verb, judged in
/// the snapshot the card is read in. When a GPU line seats the project, that
/// Grant must also reach the line's project and hold a role on the line
/// (section 5.1). That snapshot judges at the store's clock and refreshes
/// none, so the door commits no write (T24), as the GPU job caller's reads
/// judge. The rows the card was read from go to the handle's producer
/// listing.
///
/// # Errors
///
/// `forbidden` for a caller the verb does not admit, and `not_this_line`
/// for a Grant with no role on the project's line; as
/// [`planner_card_as_owner`].
pub fn planner_card_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    input: &PlannerCardRequest,
    now_ms: u64,
) -> MemoryResult<PlannerCardView> {
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    memory.verb_grant_caller_admits_in_txn(&txn, owner, PLANNER_CARD_VERB)?;
    let project = input.project()?;
    let line = family_line_in_txn(vault, &txn, project, now_ms)?;
    if let Some(line) = &line {
        match doors_caller::admit_in_txn(memory, &txn, owner, PLANNER_CARD_VERB, line.project) {
            Ok(caller) => caller.require_role(line, &LINE_READ_ROLES, PLANNER_CARD_VERB)?,
            // The verb check above admitted the caller, so a refusal here is
            // its Grant not reaching the line's project: no role on this line.
            Err(error) if error.code == MEMORY_CODE_FORBIDDEN => return Err(not_this_line()),
            Err(error) => return Err(error),
        }
    }
    let (view, sources) =
        planner_card_read_in_txn(vault, &txn, input, project, line.as_ref(), now_ms)?;
    drop(txn);
    memory.produced_from(sources);
    Ok(view)
}

/// `vault.planner.card` on a bound handle, at the vault's clock: the
/// embedded owner reads under its own proof, any other caller under its own
/// Grant.
///
/// # Errors
///
/// As [`planner_card_as`].
pub fn planner_card_embedded(
    memory: &Memory<'_>,
    input: &PlannerCardRequest,
) -> MemoryResult<PlannerCardView> {
    let owner = memory.embedded_owner(PLANNER_CARD_VERB).ok();
    let now_ms = memory.vault().now_recorded_ms();
    planner_card_as(memory, owner.as_ref(), input, now_ms)
}

/// The refusal of a Grant that admits the verb but does not reach the line's
/// project, as the role check words a Grant with no role on the line.
fn not_this_line() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{PLANNER_CARD_VERB}: not_this_line: the Grant does not reach this line's project"),
        &["Ask the owner to widen the Grant to the line's project and name it in a role list."],
    )
}

/// The roles that read a line's card: any of the three.
const LINE_READ_ROLES: [LineRole; 3] = [LineRole::Lead, LineRole::Reviewer, LineRole::Planner];
