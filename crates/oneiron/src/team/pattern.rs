//! Coordination patterns as skills (ARCH-0079 #coordination-patterns).
//!
//! A pattern is a role workflow skill, scored and revised like any skill.
//! Patterns differ by who decides; whether the team converges on one answer
//! or diverges into many is a separate setting of the same pattern. This
//! module names the patterns, binds a pattern skill to the pattern it teaches,
//! and carries each pattern skill's `works well for` line, which the planner
//! reads as the skill's prior for matching task types until receipts outweigh
//! it. The skill content itself ships through the hub.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::learning::{
    EstimateValue, LearningCell, LearningPredicate, Prior, PriorOrigin, TypeRef, put_cell_prior,
};
use crate::side_table::{self, Named, SideTable};
use crate::skill::SkillRole;

/// Pattern skills, by skill entity.
const PATTERN_SKILL: SideTable<EntityId, PatternSkill, Named> =
    SideTable::new(&side_table::TEAM_PATTERN_SKILL);

/// The axis a pattern skill's payoff is measured on.
pub const PAYOFF_AXIS: &str = "payoff";

/// The weight in runs a `works well for` line counts as: a weak prior that
/// a few receipts outweigh.
pub const WORKS_WELL_FOR_PRIOR_RUNS: f64 = 2.0;

/// The prior mean a `works well for` line asserts for a matching task type.
pub const WORKS_WELL_FOR_PRIOR_MEAN: f64 = 0.65;

/// Longest `works well for` line kept.
const MAX_LINE_BYTES: usize = 512;

/// Who decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamPattern {
    /// The leader alone, after advice. The default.
    CeoDecides,
    /// A few members deliberate; the chair decides (Council Mode).
    Committee,
    /// Members vote first; debate only on request.
    Vote,
    /// A referee: a rule signed before the work.
    Market,
    /// Roles rotate by turn inside the leader's patch. Optional; starts untested.
    Rotation,
}

impl TeamPattern {
    /// The pinned wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CeoDecides => "ceo_decides",
            Self::Committee => "committee",
            Self::Vote => "vote",
            Self::Market => "market",
            Self::Rotation => "rotation",
        }
    }

    /// The decider kind a receipt under this pattern must name.
    #[must_use]
    pub const fn decider_kind(self) -> &'static str {
        match self {
            Self::CeoDecides | Self::Rotation => "leader",
            Self::Committee => "chair",
            Self::Vote => "vote",
            Self::Market => "referee",
        }
    }
}

/// Converge on one answer, or diverge into many: a setting of any pattern.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TeamAxis {
    Converge,
    Diverge,
}

/// A skill bound to the pattern it teaches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatternSkill {
    pub skill: EntityId,
    pub pattern: TeamPattern,
    /// The pattern's default setting; a team may run it either way.
    pub default_axis: TeamAxis,
    /// The plain line: "for tasks like X, Y usually works".
    pub works_well_for: String,
    /// The task-type nodes the line names; each gets the weak prior.
    pub works_well_for_types: Vec<String>,
    pub at: u64,
}

/// Binds `skill` to `pattern` and seeds a weak `model` prior on each task
/// type its `works well for` line names, for every executor mix the caller
/// lists. Rebinding replaces the row.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] for a skill that is not a workflow skill, an
/// over-long line or a malformed type node; storage errors.
pub fn register_pattern_skill(
    vault: &Vault,
    binding: &PatternSkill,
    tree_version: u32,
    executors: &[String],
    now: u64,
) -> Result<()> {
    let record = vault
        .get_skill_record(&binding.skill)?
        .ok_or(Error::EntityNotFound)?;
    if record.role != SkillRole::Workflow {
        return Err(Error::InvalidClaimBody(
            "a coordination pattern is a workflow skill",
        ));
    }
    if binding.works_well_for.len() > MAX_LINE_BYTES {
        return Err(Error::InvalidClaimBody(
            "a works-well-for line is a sentence, not a document",
        ));
    }
    let nodes: BTreeSet<&str> = binding
        .works_well_for_types
        .iter()
        .map(String::as_str)
        .collect();
    for node in &nodes {
        TypeRef {
            node_id: (*node).to_owned(),
            tree_version,
        }
        .validate()?;
    }
    vault.with_write_txn_grouped(|wtxn| {
        PATTERN_SKILL.put(&vault.store, wtxn, &binding.skill, binding)?;
        Ok(())
    })?;
    for node in nodes {
        for executor in executors {
            let cell = pattern_cell(
                binding.skill,
                executor,
                &TypeRef {
                    node_id: node.to_owned(),
                    tree_version,
                },
            );
            let prior = Prior {
                origin: PriorOrigin::Model,
                value: EstimateValue::Beta {
                    alpha: WORKS_WELL_FOR_PRIOR_MEAN,
                    beta: 1.0 - WORKS_WELL_FOR_PRIOR_MEAN,
                },
                weight_runs: WORKS_WELL_FOR_PRIOR_RUNS,
                from: Some(format!("works well for: {}", binding.works_well_for)),
            };
            put_cell_prior(vault, &cell, &prior, now)?;
        }
    }
    Ok(())
}

/// [`register_pattern_skill`]'s binding inside the caller's write
/// transaction, with no executor priors: the first-open seed binds each
/// shipped pattern skill in the transaction that admits it (OF-540), so the
/// skill must be read on that same transaction.
///
/// # Errors
///
/// As [`register_pattern_skill`].
pub(crate) fn bind_pattern_skill_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    binding: &PatternSkill,
    tree_version: u32,
) -> Result<()> {
    let record = vault
        .get_skill_record_in_txn(wtxn, &binding.skill)?
        .ok_or(Error::EntityNotFound)?;
    if record.role != SkillRole::Workflow {
        return Err(Error::InvalidClaimBody(
            "a coordination pattern is a workflow skill",
        ));
    }
    if binding.works_well_for.len() > MAX_LINE_BYTES {
        return Err(Error::InvalidClaimBody(
            "a works-well-for line is a sentence, not a document",
        ));
    }
    for node in &binding.works_well_for_types {
        TypeRef {
            node_id: node.clone(),
            tree_version,
        }
        .validate()?;
    }
    PATTERN_SKILL.put(&vault.store, wtxn, &binding.skill, binding)?;
    Ok(())
}

/// The pattern binding of `skill`, if it teaches one.
///
/// # Errors
///
/// Storage errors.
pub fn pattern_skill(vault: &Vault, skill: &EntityId) -> Result<Option<PatternSkill>> {
    let rtxn = vault.store.env.read_txn()?;
    PATTERN_SKILL.get(&vault.store, &rtxn, skill)
}

/// Every bound pattern skill.
///
/// # Errors
///
/// Storage errors.
pub fn pattern_skills(vault: &Vault) -> Result<Vec<PatternSkill>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(PATTERN_SKILL
        .scan(&vault.store, &rtxn)?
        .into_iter()
        .map(|(_, row)| row)
        .collect())
}

/// The `learning.reliability` cell a pattern skill's payoff lives in.
#[must_use]
pub fn pattern_cell(skill: EntityId, executor: &str, type_ref: &TypeRef) -> LearningCell {
    LearningCell::new(LearningPredicate::Reliability, skill)
        .executor(executor)
        .type_ref(type_ref.clone())
        .axis(PAYOFF_AXIS)
}

/// A team's executor mix: its sorted, distinct model ids joined by `+`, or
/// their digest when the join would not fit a cell qualifier.
#[must_use]
pub fn model_mix(models: &[String]) -> String {
    let set: BTreeSet<&str> = models.iter().map(String::as_str).collect();
    let joined = set.into_iter().collect::<Vec<_>>().join("+");
    if joined.is_empty() {
        return "unknown".to_owned();
    }
    if joined.len() <= 256 {
        return joined;
    }
    format!(
        "mix#{}",
        &crate::entity_id::bytes_to_hex_lower(blake3::hash(joined.as_bytes()).as_bytes())[..32]
    )
}
