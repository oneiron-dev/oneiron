//! The team receipt contract (ARCH-0079 #scoring): one receipt per team run,
//! the input of the payoff table and of the pattern skills' measured payoff.
//!
//! It names the task type, the pattern and its skill, the converge/diverge
//! setting, the model ids, the team shape, who decided, coverage and the
//! confession count. A confession is control evidence, never a payoff feature.
//! The receipt is written once; its anchored outcome settles later and is
//! the only thing that moves the pattern skill's `learning.reliability`.
//!
//! Beside the receipt its row keeps, apart, the entity rows its facts and
//! its outcome were read from, as the writer that assembled each named them
//! (FIX 7103). A writer that names none leaves them unknown.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::agent_dispatch::{
    CoordinationPattern, load_team_type_tree_at_in_txn, load_team_type_tree_in_txn,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::learning::{Anchor, EvidenceSource, LearningEvidence, Observation, TypeRef};
use crate::side_table::{self, Named, SideTable};
use crate::skill_optimize::union_source_rows;
use crate::task_type::TypeTree;

use super::pattern::{TeamAxis, TeamPattern, model_mix, pattern_cell};

/// Team receipts. Key: team reference (the run id).
const TEAM_RECEIPT: SideTable<String, StoredTeamReceipt, Named> =
    SideTable::new(&side_table::TEAM_RECEIPT);

/// A team receipt with the entity rows it was read from (FIX 7103); `None`
/// is unknown.
pub type SourcedTeamReceipt = (TeamReceipt, Option<Vec<EntityId>>);

/// One stored team receipt: the receipt, and the entity rows its facts and
/// its outcome were read from, kept apart so a replaced outcome takes only
/// its own. `None` is unknown, never an empty set.
#[derive(Debug, Serialize, Deserialize)]
struct StoredTeamReceipt {
    receipt: TeamReceipt,
    fact_sources: Option<Vec<EntityId>>,
    /// `None` too while the receipt has no outcome.
    outcome_sources: Option<Vec<EntityId>>,
}

impl StoredTeamReceipt {
    /// The receipt with every row it was read from: its facts' and, once it
    /// has an outcome, the outcome's. Unknown when either is.
    fn sourced(self) -> SourcedTeamReceipt {
        let settled = self.receipt.outcome.is_some();
        let outcome = settled.then_some(self.outcome_sources);
        let rows = union_source_rows(std::iter::once(self.fact_sources).chain(outcome));
        (self.receipt, rows)
    }
}

/// Longest reference or model id kept.
const MAX_REF_BYTES: usize = 256;

/// The pattern skill revision a team ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PatternSkillRef {
    pub skill: EntityId,
    pub version: String,
}

/// How many agents, in which roles.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamShape {
    pub width: u32,
    /// Role name to head count, such as `lead`, `member`, `critic`.
    pub roles: BTreeMap<String, u32>,
}

impl TeamShape {
    /// A stable signature for grouping: `width` then `role:count` pairs.
    #[must_use]
    pub fn signature(&self) -> String {
        let roles: Vec<String> = self
            .roles
            .iter()
            .map(|(role, n)| format!("{role}:{n}"))
            .collect();
        format!("{}|{}", self.width, roles.join(","))
    }
}

/// Who decided the team's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DecidedBy {
    Leader {
        actor: EntityId,
    },
    Chair {
        actor: EntityId,
    },
    Vote {
        tally: BTreeMap<String, u32>,
    },
    /// A rule signed before the work: a test suite, a holdout, a pinned judge.
    Referee {
        rule: String,
        signed_at: u64,
    },
}

impl DecidedBy {
    /// The decider kind token.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Leader { .. } => "leader",
            Self::Chair { .. } => "chair",
            Self::Vote { .. } => "vote",
            Self::Referee { .. } => "referee",
        }
    }
}

/// How much of the campaign's cell grid the team's outputs covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    pub cells_filled: u32,
    pub cells_total: u32,
}

/// The anchored outcome that settles a team run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TeamOutcome {
    /// The receipt the outcome rests on.
    pub receipt: String,
    pub anchor: Anchor,
    pub success: bool,
    pub at: u64,
    /// The critics whose persisted reviews of the team's deliverable the
    /// outcome settled (OF-420), as the settler read them. `None` is unknown
    /// (a settler that read none); empty, no critic reviewed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critics: Option<Vec<TeamCritic>>,
}

/// One critique of a team's deliverable that the team's outcome settled
/// (OF-420): the review holding it and the critic that gave it, named as
/// the critique's reliability cell names that critic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamCritic {
    /// The review's verdict claim.
    pub review: EntityId,
    pub artifact_id: String,
    /// The lens's stored skill.
    pub lens: EntityId,
    /// The critic's executor at revision: `model@revision`, or a person's
    /// own id.
    pub executor: String,
    /// What the critique said of the deliverable.
    pub verdict: crate::critic::CritiqueVerdict,
}

/// One team run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TeamReceipt {
    pub team_ref: String,
    pub project: Option<EntityId>,
    /// Required: missing is invalid, never untyped; unsure is the root.
    pub type_ref: TypeRef,
    pub pattern: TeamPattern,
    pub pattern_skill: Option<PatternSkillRef>,
    pub axis: TeamAxis,
    /// Model ids at revision the team ran on; empty when none was recorded.
    pub models: Vec<String>,
    pub shape: TeamShape,
    pub decided_by: DecidedBy,
    pub coverage: Option<Coverage>,
    /// Confessions on the team's attempts. Control evidence only. `None`:
    /// the host could not count them in full.
    pub confessions: Option<u32>,
    /// Spend against the hard cap stated before launch, in the cap's unit.
    pub spend: Option<f64>,
    pub spend_cap: Option<f64>,
    pub elapsed_secs: u64,
    /// The team's calls. `None`: the host could not count them in full.
    pub calls: Option<u64>,
    pub outcome: Option<TeamOutcome>,
    pub at: u64,
}

fn bounded(text: &str, what: &'static str) -> Result<()> {
    if text.is_empty() || text.len() > MAX_REF_BYTES || text.contains('\0') {
        return Err(Error::InvalidClaimBody(what));
    }
    Ok(())
}

impl TeamReceipt {
    /// Whether the team ran below its pattern's floor: fewer agents than the
    /// pattern needs to mean anything, such as a one-branch market. The
    /// receipt still records what ran, at its real width.
    #[must_use]
    pub const fn below_floor(&self) -> bool {
        !CoordinationPattern::from_team(self.pattern).admits_width(self.shape.width)
    }

    /// The contract's structural checks.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidClaimBody`] naming the broken rule.
    pub fn validate(&self) -> Result<()> {
        bounded(
            &self.team_ref,
            "a team reference is 1..=256 bytes without NUL",
        )?;
        self.type_ref.validate()?;
        // No count cap on models or roles (ARCH-0079: width has no count
        // cap), so a very wide team still records its receipt. No model
        // recorded is unknown, never a refusal (FIX 10192).
        for model in &self.models {
            bounded(model, "a model id is 1..=256 bytes without NUL")?;
        }
        if self.shape.width == 0 {
            return Err(Error::InvalidClaimBody("a team has at least one agent"));
        }
        if self.decided_by.kind() != self.pattern.decider_kind() {
            return Err(Error::InvalidClaimBody(
                "who decided must match the pattern's decider",
            ));
        }
        if let DecidedBy::Referee { rule, .. } = &self.decided_by {
            bounded(
                rule,
                "a referee rule reference is 1..=256 bytes without NUL",
            )?;
        }
        if let Some(skill) = &self.pattern_skill {
            bounded(&skill.version, "a pattern skill version is 1..=256 bytes")?;
        }
        if let Some(coverage) = self.coverage
            && coverage.cells_filled > coverage.cells_total
        {
            return Err(Error::InvalidClaimBody(
                "coverage cannot fill more cells than exist",
            ));
        }
        for value in [self.spend, self.spend_cap].into_iter().flatten() {
            if !value.is_finite() || value < 0.0 {
                return Err(Error::InvalidClaimBody("spend is finite and non-negative"));
            }
        }
        Ok(())
    }

    /// The team's executor mix, the executor key of its pattern skill cell.
    #[must_use]
    pub fn executor_mix(&self) -> String {
        model_mix(&self.models)
    }

    /// The one critic the settled outcome names (OF-420), the value the
    /// TrustedCritic decision reads: `<lens skill hex>@<model>`, the
    /// executor's final `@revision` stripped as the winning model's is. None
    /// when the outcome names no critic or more than one: a panel is not one
    /// critic's win.
    #[must_use]
    pub fn trusted_critic(&self) -> Option<String> {
        let critics: std::collections::BTreeSet<String> = self
            .outcome
            .as_ref()?
            .critics
            .as_ref()?
            .iter()
            .map(|critic| {
                let executor = critic.executor.as_str();
                let model = executor
                    .rsplit_once('@')
                    .map_or(executor, |(model, _)| model);
                format!("{}@{model}", critic.lens.to_hex())
            })
            .collect();
        let mut critics = critics.into_iter();
        match (critics.next(), critics.next()) {
            (Some(critic), None) => Some(critic),
            _ => None,
        }
    }
}

/// Records one team receipt. A receipt is written once; settling its outcome
/// is [`settle_team_outcome`].
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] for a malformed receipt or one that already
/// exists; storage errors.
pub fn record_team_receipt(vault: &Vault, receipt: &TeamReceipt) -> Result<()> {
    record_team_receipt_sourced(vault, receipt, None, None)
}

/// [`record_team_receipt`], keeping the entity rows the receipt's facts and
/// its outcome were read from (FIX 7103). `None` is unknown: the caller
/// names a set only when it covers every fact. Outcome sources are kept only
/// with an outcome. The sources ride in the receipt's own row and never
/// fail its write.
///
/// # Errors
///
/// As [`record_team_receipt`].
pub fn record_team_receipt_sourced(
    vault: &Vault,
    receipt: &TeamReceipt,
    fact_sources: Option<Vec<EntityId>>,
    outcome_sources: Option<Vec<EntityId>>,
) -> Result<()> {
    receipt.validate()?;
    // The stamp names a node of the tree in force for its project, at that
    // tree's version: an unknown node is invalid, never untyped.
    crate::task_type::validate_type_ref(vault, receipt.project, &receipt.type_ref)?;
    let stored = StoredTeamReceipt {
        receipt: receipt.clone(),
        fact_sources,
        outcome_sources: receipt.outcome.as_ref().and(outcome_sources),
    };
    vault.with_write_txn_grouped(|wtxn| {
        if TEAM_RECEIPT.contains(&vault.store, wtxn, &receipt.team_ref)? {
            return Err(Error::InvalidClaimBody("a team receipt is written once"));
        }
        TEAM_RECEIPT.put(&vault.store, wtxn, &receipt.team_ref, &stored)?;
        if let (Some(outcome), Some(skill)) = (&receipt.outcome, &receipt.pattern_skill) {
            feed_pattern_payoff_in_txn(vault, wtxn, receipt, skill.skill, outcome)?;
        }
        Ok(())
    })
}

/// Settles a team run's anchored outcome and feeds its pattern skill's
/// payoff. Settling again with the same receipt replaces the outcome.
///
/// # Errors
///
/// [`Error::EntityNotFound`] for an unknown team; the evidence door's errors
/// (an unanchored source is refused there by name); storage errors.
pub fn settle_team_outcome(
    vault: &Vault,
    team_ref: &str,
    outcome: &TeamOutcome,
) -> Result<TeamReceipt> {
    vault.with_write_txn_grouped(|wtxn| settle_team_outcome_in_txn(vault, wtxn, team_ref, outcome))
}

/// [`settle_team_outcome`] in the caller's transaction, so the source of the
/// anchor, the outcome and its learning evidence land together.
///
/// # Errors
///
/// As [`settle_team_outcome`].
pub(crate) fn settle_team_outcome_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    team_ref: &str,
    outcome: &TeamOutcome,
) -> Result<TeamReceipt> {
    settle_team_outcome_sourced_in_txn(vault, wtxn, team_ref, outcome, None)
}

/// [`settle_team_outcome_in_txn`], keeping the entity rows the outcome was
/// read from (FIX 7103); `None` is unknown. A replaced outcome's sources go
/// with it, and the receipt's fact sources stay as they are.
///
/// # Errors
///
/// As [`settle_team_outcome`].
pub(crate) fn settle_team_outcome_sourced_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    team_ref: &str,
    outcome: &TeamOutcome,
    outcome_sources: Option<Vec<EntityId>>,
) -> Result<TeamReceipt> {
    bounded(
        &outcome.receipt,
        "an outcome receipt is 1..=256 bytes without NUL",
    )?;
    let mut stored = TEAM_RECEIPT
        .get(&vault.store, wtxn, &team_ref.to_owned())?
        .ok_or(Error::EntityNotFound)?;
    stored.receipt.outcome = Some(outcome.clone());
    stored.outcome_sources = outcome_sources;
    TEAM_RECEIPT.put(&vault.store, wtxn, &stored.receipt.team_ref, &stored)?;
    if let Some(skill) = &stored.receipt.pattern_skill {
        feed_pattern_payoff_in_txn(vault, wtxn, &stored.receipt, skill.skill, outcome)?;
    }
    Ok(stored.receipt)
}

/// Whether a team's outcome teaches its pattern skill's cell: a team that
/// ran below its pattern's floor did not run that pattern, so its outcome
/// stays on its receipt and teaches no pattern prior.
const fn teaches_pattern(receipt: &TeamReceipt) -> bool {
    !receipt.below_floor()
}

fn feed_pattern_payoff_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    receipt: &TeamReceipt,
    skill: EntityId,
    outcome: &TeamOutcome,
) -> Result<()> {
    if !teaches_pattern(receipt) {
        return Ok(());
    }
    let cell = pattern_cell(
        skill,
        &receipt.executor_mix(),
        receipt.project,
        &receipt.type_ref,
    );
    // The planner card read this cell with parent/carried backoff; its first
    // own result keeps that borrowed prior (ARCH-0053 `#executor-swaps`).
    let parents = capture_parents_in_txn(vault, wtxn, receipt.project, &receipt.type_ref)?;
    let evidence = LearningEvidence {
        receipt: outcome.receipt.clone(),
        at: outcome.at,
        source: EvidenceSource::Anchored(outcome.anchor),
        observation: Observation::Success(outcome.success),
        weight: 1.0,
        judge: None,
        on_judge_model: false,
        outcome_label: None,
        pack_attribution: None,
        goal_revision: None,
        measurement_version: None,
    };
    crate::learning::prior::capture_borrowed_prior_in_txn(
        vault,
        wtxn,
        &cell,
        &parents,
        evidence.observation.form(),
    )?;
    crate::learning::record_evidence_in_txn(vault, wtxn, &cell, &evidence, outcome.at)?;
    Ok(())
}

/// The parents a cell's first own result keeps its borrowed prior through
/// (FIX 9889): the stamp's chain in the tree it was placed in, the chain the
/// owner's spawn read backs off through. A placed tree no longer kept, or
/// one that does not read, borrows through `project`'s tree in force
/// instead, so an outcome's write never fails on it.
///
/// # Errors
///
/// Storage errors reading the tree in force.
pub(crate) fn capture_parents_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: Option<EntityId>,
    type_ref: &TypeRef,
) -> Result<Vec<TypeRef>> {
    Ok(match stamp_ancestry_in_txn(vault, txn, project, type_ref) {
        (parents, None) => parents,
        (_, Some(_)) => {
            let tree = load_team_type_tree_in_txn(vault, txn, project)?;
            TypeTree::from(tree).ancestors(type_ref)
        }
    })
}

/// The parent chain of `receipt`'s stamp in the tree it was placed in: its
/// project's kept tree at the stamp's version, read in `txn`. Settlement and
/// the owner's spawn read take learning parents from this one chain. The
/// reason is given when there is none: no kept tree is at that version, or
/// the kept tree does not read.
pub(super) fn placed_ancestry_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt: &TeamReceipt,
) -> (Vec<TypeRef>, Option<String>) {
    stamp_ancestry_in_txn(vault, txn, receipt.project, &receipt.type_ref)
}

/// [`placed_ancestry_in_txn`] for a stamp placed in `project`'s tree.
fn stamp_ancestry_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: Option<EntityId>,
    type_ref: &TypeRef,
) -> (Vec<TypeRef>, Option<String>) {
    let version = type_ref.tree_version;
    match load_team_type_tree_at_in_txn(vault, txn, project, version) {
        Ok(Some(tree)) => (TypeTree::from(tree).ancestors(type_ref), None),
        Ok(None) => (
            Vec::new(),
            Some(format!("no kept task-type tree is at version {version}")),
        ),
        Err(error) => (
            Vec::new(),
            Some(format!(
                "the kept task-type tree at version {version} does not read: {error}"
            )),
        ),
    }
}

/// One team's receipt.
///
/// # Errors
///
/// Storage errors.
pub fn team_receipt(vault: &Vault, team_ref: &str) -> Result<Option<TeamReceipt>> {
    let rtxn = vault.store.env.read_txn()?;
    team_receipt_in_txn(vault, &rtxn, team_ref)
}

/// [`team_receipt`] in the caller's snapshot.
pub(super) fn team_receipt_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    team_ref: &str,
) -> Result<Option<TeamReceipt>> {
    Ok(TEAM_RECEIPT
        .get(&vault.store, txn, &team_ref.to_owned())?
        .map(|stored| stored.receipt))
}

/// Which team receipts a scan keeps (FIX 6038).
#[derive(Debug, Clone, Copy)]
pub(crate) enum ReceiptScan<'a> {
    /// Every scope's receipts, only those of one task type when one is
    /// named: an inventory.
    AllScopes(Option<&'a TypeRef>),
    /// One scope's receipts of one task type: a project's (`None`, the
    /// vault's) own runs, as its learning cells key them.
    Scoped(Option<EntityId>, &'a TypeRef),
}

impl ReceiptScan<'_> {
    fn keeps(self, receipt: &TeamReceipt) -> bool {
        match self {
            Self::AllScopes(type_ref) => type_ref.is_none_or(|t| receipt.type_ref == *t),
            Self::Scoped(project, type_ref) => {
                receipt.project == project && receipt.type_ref == *type_ref
            }
        }
    }
}

/// Every team receipt of every scope, optionally only those of one task
/// type: an inventory.
///
/// # Errors
///
/// Storage errors.
pub fn team_receipts(vault: &Vault, type_ref: Option<&TypeRef>) -> Result<Vec<TeamReceipt>> {
    let rtxn = vault.store.env.read_txn()?;
    team_receipts_in_txn(vault, &rtxn, ReceiptScan::AllScopes(type_ref))
}

/// The receipts `scan` keeps, in the caller's snapshot.
pub(crate) fn team_receipts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scan: ReceiptScan<'_>,
) -> Result<Vec<TeamReceipt>> {
    Ok(stored_receipts_in_txn(vault, txn, scan)?
        .into_iter()
        .map(|stored| stored.receipt)
        .collect())
}

/// [`team_receipts`], each receipt with the entity rows it was read from
/// (FIX 7103): its facts' and, once settled, its outcome's. `None` is
/// unknown: a receipt or outcome whose writer named no sources.
///
/// # Errors
///
/// Storage errors.
pub fn team_receipts_sourced(
    vault: &Vault,
    type_ref: Option<&TypeRef>,
) -> Result<Vec<SourcedTeamReceipt>> {
    let rtxn = vault.store.env.read_txn()?;
    let scan = ReceiptScan::AllScopes(type_ref);
    Ok(stored_receipts_in_txn(vault, &rtxn, scan)?
        .into_iter()
        .map(StoredTeamReceipt::sourced)
        .collect())
}

/// The stored receipts [`team_receipts_in_txn`] reads, in its order.
fn stored_receipts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scan: ReceiptScan<'_>,
) -> Result<Vec<StoredTeamReceipt>> {
    let mut rows: Vec<StoredTeamReceipt> = TEAM_RECEIPT
        .scan(&vault.store, txn)?
        .into_iter()
        .map(|(_, row)| row)
        .filter(|row| scan.keeps(&row.receipt))
        .collect();
    rows.sort_by(|a, b| {
        let (a, b) = (&a.receipt, &b.receipt);
        a.at.cmp(&b.at).then_with(|| a.team_ref.cmp(&b.team_ref))
    });
    Ok(rows)
}
