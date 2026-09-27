//! Typed turn-one self projection shared by the prefix and mid-run describe call.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::Scope;
use crate::llm::BudgetRead;
use crate::skill_reliability::{skill_reliability_posterior, skill_reliability_prior};
use crate::{Vault, skill::SkillContentHash};

use super::SessionReadSet;

/// A class verdict is a dated description, not authorization. Execution rechecks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassVerdict {
    Allow,
    Deny,
    WouldAsk,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClassLimit {
    pub class: String,
    pub verdict: ClassVerdict,
}

/// Host-resolved communication restrictions. The six-axis scope is a ceiling,
/// not a grant minted by this projection.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CommunicationLimits {
    pub scope: Scope,
    pub recipients: Vec<EntityId>,
    pub max_messages: Option<u64>,
}

/// Inputs must be the effective, already-authorized run/session reads. In
/// particular, this renderer cannot decide which classes or worlds are visible.
pub struct SelfBriefInput<'a> {
    pub self_ref: EntityId,
    pub principal: EntityId,
    pub cast: &'a [EntityId],
    pub grant_revision: u64,
    pub effective_scope: &'a Scope,
    pub communication: &'a CommunicationLimits,
    pub classes: &'a [ClassLimit],
    pub budget_lease_id: &'a str,
    pub budget: &'a BudgetRead,
    pub clock_ms: u64,
    pub skill_index: &'a [EntityId],
    pub read_set: &'a SessionReadSet,
    pub working_set: &'a [EntityId],
}

/// A skill index row is resolved from the skill record and reliability claim;
/// the mutable confidence cache is never an authority for this number.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct BriefSkillRow {
    pub id: EntityId,
    pub hash: Option<String>,
    pub reliability: f32,
    pub loaded_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SelfBrief {
    pub self_ref: EntityId,
    pub principal: EntityId,
    pub cast: Vec<EntityId>,
    pub grant_revision: u64,
    pub effective_scope: Scope,
    pub communication: CommunicationLimits,
    pub classes: Vec<ClassLimit>,
    pub budget_lease_id: String,
    pub budget: BudgetRead,
    pub clock_ms: u64,
    pub skills: Vec<BriefSkillRow>,
    pub working_set: Vec<EntityId>,
}

impl SelfBrief {
    /// Read reliability for the skill index at assembly time. Missing records
    /// and malformed claims fail closed instead of inventing a reliability.
    pub fn describe(vault: &Vault, input: SelfBriefInput<'_>) -> Result<Self> {
        let mut skills = Vec::with_capacity(input.skill_index.len());
        for id in input.skill_index {
            let record = vault
                .get_skill_record(id)?
                .ok_or(crate::Error::EntityNotFound)?;
            let posterior = match skill_reliability_posterior(vault, id)? {
                Some(posterior) => posterior,
                None => skill_reliability_prior(vault, id)?,
            };
            let hash = record.content_hash.map(|h: SkillContentHash| h.to_hex());
            let loaded_hash = input
                .read_set
                .loaded_skills()
                .any(|(loaded_id, version)| loaded_id == id.to_hex() && version == record.version)
                .then(|| hash.clone())
                .flatten();
            skills.push(BriefSkillRow {
                id: *id,
                hash,
                reliability: posterior.mean(),
                loaded_hash,
            });
        }
        Ok(Self {
            self_ref: input.self_ref,
            principal: input.principal,
            cast: input.cast.to_vec(),
            grant_revision: input.grant_revision,
            effective_scope: input.effective_scope.clone(),
            communication: input.communication.clone(),
            classes: input.classes.to_vec(),
            budget_lease_id: input.budget_lease_id.to_owned(),
            budget: input.budget.clone(),
            clock_ms: input.clock_ms,
            skills,
            working_set: input.working_set.to_vec(),
        })
    }

    /// Single renderer used at session open, keyframe rebuild and describe(self).
    #[must_use]
    pub fn render(&self) -> String {
        // All text comes from typed fields and JSON escaping; never parse this
        // rendered text back into authority or state.
        let mut identity = serde_json::to_value(self).expect("typed self brief JSON");
        let skills = identity
            .as_object_mut()
            .expect("self brief is a struct")
            .remove("skills")
            .expect("self brief always carries skill index rows");
        // JSON escapes quotes, but not XML delimiters. Encode those as JSON
        // unicode escapes so a class or label cannot close either block.
        let safe = |value: &serde_json::Value| {
            value
                .to_string()
                .replace('&', "\\u0026")
                .replace('<', "\\u003c")
                .replace('>', "\\u003e")
        };
        format!(
            "<skills>{}</skills>\n<identity>{}</identity>",
            safe(&skills),
            safe(&identity)
        )
    }
}

/// The cached prefix is replaced only at turn one or an epoch fold. A mid-run
/// call returns an append-only tail update without touching the prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BriefPlacement {
    TurnOne,
    Fold,
    MidRun,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PlacedSelfBrief {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tail: Option<String>,
}

impl PlacedSelfBrief {
    #[must_use]
    pub fn assemble(brief: &SelfBrief, placement: BriefPlacement) -> Self {
        let text = brief.render();
        match placement {
            BriefPlacement::TurnOne | BriefPlacement::Fold => Self {
                prefix: Some(text),
                tail: None,
            },
            BriefPlacement::MidRun => Self {
                prefix: None,
                tail: Some(text),
            },
        }
    }
}

/// Host-owned run snapshot. Only the host that resolved the grant and budget
/// can create this state; an HTTP request never supplies any authority fields.
#[derive(Debug, Clone)]
pub struct SelfBriefState {
    pub self_ref: EntityId,
    pub principal: EntityId,
    pub cast: Vec<EntityId>,
    pub grant_revision: u64,
    pub effective_scope: Scope,
    pub communication: CommunicationLimits,
    pub classes: Vec<ClassLimit>,
    pub budget_lease_id: String,
    pub budget: BudgetRead,
    pub clock_ms: u64,
    pub skill_index: Vec<EntityId>,
    pub working_set: Vec<EntityId>,
}

impl SelfBriefState {
    /// Resolve skill records and claims afresh for each render, against the
    /// session's read set rather than a previously rendered prompt.
    pub fn describe(&self, vault: &Vault, read_set: &SessionReadSet) -> Result<SelfBrief> {
        SelfBrief::describe(
            vault,
            SelfBriefInput {
                self_ref: self.self_ref,
                principal: self.principal,
                cast: &self.cast,
                grant_revision: self.grant_revision,
                effective_scope: &self.effective_scope,
                communication: &self.communication,
                classes: &self.classes,
                budget_lease_id: &self.budget_lease_id,
                budget: &self.budget,
                clock_ms: self.clock_ms,
                skill_index: &self.skill_index,
                read_set,
                working_set: &self.working_set,
            },
        )
    }
}

/// Per-run prefix custody. `describe_self` appends to the tail, leaving the
/// cached bytes untouched until `fold` deliberately replaces the prefix.
#[derive(Debug, Clone, Default)]
pub struct SelfBriefSession {
    cached_prefix: Option<String>,
}

impl SelfBriefSession {
    pub fn turn_one(
        &mut self,
        vault: &Vault,
        state: &SelfBriefState,
        read_set: &SessionReadSet,
    ) -> Result<PlacedSelfBrief> {
        self.cached_prefix = Some(state.describe(vault, read_set)?.render());
        Ok(PlacedSelfBrief {
            prefix: self.cached_prefix.clone(),
            tail: None,
        })
    }

    pub fn fold(
        &mut self,
        vault: &Vault,
        state: &SelfBriefState,
        read_set: &SessionReadSet,
    ) -> Result<PlacedSelfBrief> {
        if self.cached_prefix.is_none() {
            return Err(crate::Error::InvariantViolation(
                "self brief fold before turn one",
            ));
        }
        self.cached_prefix = Some(state.describe(vault, read_set)?.render());
        Ok(PlacedSelfBrief {
            prefix: self.cached_prefix.clone(),
            tail: None,
        })
    }

    pub fn describe_self(
        &self,
        vault: &Vault,
        state: &SelfBriefState,
        read_set: &SessionReadSet,
    ) -> Result<PlacedSelfBrief> {
        if self.cached_prefix.is_none() {
            return Err(crate::Error::InvariantViolation(
                "self brief describe before turn one",
            ));
        }
        Ok(PlacedSelfBrief {
            prefix: None,
            tail: Some(state.describe(vault, read_set)?.render()),
        })
    }

    #[must_use]
    pub fn cached_prefix(&self) -> Option<&str> {
        self.cached_prefix.as_deref()
    }
}

#[cfg(test)]
mod tests;
