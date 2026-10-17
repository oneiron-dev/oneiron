//! The team receipt contract (ARCH-0079 #scoring): one receipt per team run,
//! the input of the payoff table and of the pattern skills' measured payoff.
//!
//! It names the task type, the pattern and its skill, the converge/diverge
//! setting, the model ids, the team shape, who decided, coverage and the
//! confession count. A confession is control evidence, never a payoff feature.
//! The receipt is written once; its anchored outcome settles later and is
//! the only thing that moves the pattern skill's `learning.reliability`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::learning::{Anchor, EvidenceSource, LearningEvidence, Observation, TypeRef};
use crate::side_table::{self, Named, SideTable};

use super::pattern::{TeamAxis, TeamPattern, model_mix, pattern_cell};

/// Team receipts. Key: team reference (the run id).
const TEAM_RECEIPT: SideTable<String, TeamReceipt, Named> =
    SideTable::new(&side_table::TEAM_RECEIPT);

/// Longest reference or model id kept.
const MAX_REF_BYTES: usize = 256;

/// Most model ids or roles one receipt names.
const MAX_LIST: usize = 256;

/// The pattern skill revision a team ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Model ids at revision the team ran on.
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
        if self.models.is_empty() || self.models.len() > MAX_LIST {
            return Err(Error::InvalidClaimBody(
                "a team receipt names 1..=256 model ids",
            ));
        }
        for model in &self.models {
            bounded(model, "a model id is 1..=256 bytes without NUL")?;
        }
        if self.shape.width == 0 || self.shape.roles.len() > MAX_LIST {
            return Err(Error::InvalidClaimBody(
                "a team has at least one agent and at most 256 roles",
            ));
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
}

/// Records one team receipt. A receipt is written once; settling its outcome
/// is [`settle_team_outcome`].
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] for a malformed receipt or one that already
/// exists; storage errors.
pub fn record_team_receipt(vault: &Vault, receipt: &TeamReceipt) -> Result<()> {
    receipt.validate()?;
    // The stamp names a node of the tree in force for its project, at that
    // tree's version: an unknown node is invalid, never untyped.
    crate::task_type::validate_type_ref(vault, receipt.project, &receipt.type_ref)?;
    vault.with_write_txn_grouped(|wtxn| {
        if TEAM_RECEIPT.contains(&vault.store, wtxn, &receipt.team_ref)? {
            return Err(Error::InvalidClaimBody("a team receipt is written once"));
        }
        TEAM_RECEIPT.put(&vault.store, wtxn, &receipt.team_ref, receipt)?;
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
    bounded(
        &outcome.receipt,
        "an outcome receipt is 1..=256 bytes without NUL",
    )?;
    let mut receipt = TEAM_RECEIPT
        .get(&vault.store, wtxn, &team_ref.to_owned())?
        .ok_or(Error::EntityNotFound)?;
    receipt.outcome = Some(outcome.clone());
    TEAM_RECEIPT.put(&vault.store, wtxn, &receipt.team_ref, &receipt)?;
    if let Some(skill) = &receipt.pattern_skill {
        feed_pattern_payoff_in_txn(vault, wtxn, &receipt, skill.skill, outcome)?;
    }
    Ok(receipt)
}

fn feed_pattern_payoff_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    receipt: &TeamReceipt,
    skill: EntityId,
    outcome: &TeamOutcome,
) -> Result<()> {
    let cell = pattern_cell(skill, &receipt.executor_mix(), &receipt.type_ref);
    // The planner card read this cell with parent/carried backoff; its first
    // own result keeps that borrowed prior (ARCH-0053 `#executor-swaps`).
    let tree = crate::agent_dispatch::load_team_type_tree_in_txn(vault, wtxn, receipt.project)?;
    let parents = crate::task_type::TypeTree::from(tree).ancestors(&receipt.type_ref);
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
    TEAM_RECEIPT.get(&vault.store, txn, &team_ref.to_owned())
}

/// Every team receipt, optionally only those of one task type.
///
/// # Errors
///
/// Storage errors.
pub fn team_receipts(vault: &Vault, type_ref: Option<&TypeRef>) -> Result<Vec<TeamReceipt>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut rows: Vec<TeamReceipt> = TEAM_RECEIPT
        .scan(&vault.store, &rtxn)?
        .into_iter()
        .map(|(_, row)| row)
        .filter(|row| type_ref.is_none_or(|t| row.type_ref == *t))
        .collect();
    rows.sort_by(|a, b| a.at.cmp(&b.at).then_with(|| a.team_ref.cmp(&b.team_ref)));
    Ok(rows)
}
