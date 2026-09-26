//! Human-authenticated project goal intake; proposals never write this record.
use super::{ProjectRecord, encode, invalid};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ClaimSubject};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};
use crate::{EntityId, TimeRange, Vault};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const PREDICATE: &str = "project.goal_intake";
#[cfg(test)]
mod tests;

/// A named observation that can be checked against receipts or a held-out trial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalAxis {
    pub name: String,
    pub measure: String,
    pub bound: String,
}

/// One tradeoff the human actually chose; the loop may propose, not invent, these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalPreference {
    pub prefer: String,
    pub over: String,
    pub reason: String,
}

/// A goal's soft exploration share, not a grant or a vault budget lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalExplorationBudget {
    pub max_spend: u64,
    pub exploration_slice: u64,
    pub human_minutes: u64,
}

/// Typed data for a project's admission target; never an agent prompt or authority grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalRecord {
    pub goal: String,
    pub why: String,
    pub primary_axes: Vec<GoalAxis>,
    pub floor_axes: Vec<GoalAxis>,
    pub cost_axes: Vec<GoalAxis>,
    pub preferences: Vec<GoalPreference>,
    pub exploration_budget: GoalExplorationBudget,
}

impl GoalRecord {
    /// Reject incomplete interview drafts before they enter the write gate.
    pub fn validate(&self) -> Result<()> {
        if self.goal.trim().is_empty()
            || self.why.trim().is_empty()
            || self.goal.len() > 4096
            || self.why.len() > 4096
            || self.primary_axes.is_empty()
            || self.floor_axes.is_empty()
            || self.cost_axes.is_empty()
            || self.exploration_budget.exploration_slice > self.exploration_budget.max_spend
        {
            return Err(invalid());
        }
        let mut names = BTreeSet::new();
        for axis in self
            .primary_axes
            .iter()
            .chain(&self.floor_axes)
            .chain(&self.cost_axes)
        {
            if axis.name.trim().is_empty()
                || axis.measure.trim().is_empty()
                || axis.bound.trim().is_empty()
                || axis.name.len() > 128
                || axis.measure.len() > 1024
                || axis.bound.len() > 1024
                || !names.insert(axis.name.as_str())
            {
                return Err(invalid());
            }
        }
        if !self
            .cost_axes
            .iter()
            .any(|axis| axis.name == "human_minutes")
            || self.preferences.iter().any(|p| {
                p.prefer.trim().is_empty()
                    || p.over.trim().is_empty()
                    || p.reason.trim().is_empty()
                    || p.prefer == p.over
                    || p.prefer.len() > 1024
                    || p.over.len() > 1024
                    || p.reason.len() > 1024
            })
            || self.preferences.len() > 64
            || names.len() > 32
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl Vault {
    /// Commit an interview answered by an authenticated human. A loop proposal
    /// has no `AuthenticatedOwner` and cannot call this door on its own.
    /// Replaces the project pointer and supersedes the prior goal atomically.
    pub fn write_project_goal_from_intake(
        &self,
        owner: &AuthenticatedOwner,
        project_id: EntityId,
        record: &GoalRecord,
        now: u64,
    ) -> Result<EntityId> {
        record.validate()?;
        let id = EntityId::now();
        let envelope = WriteEnvelope::new(
            WriteActor::new(owner.actor(), EdgeActorClass::Human),
            ClaimSource::UserStated,
            WriteProvenance::new(Value::Map(vec![
                (Value::from("op"), Value::from("goal.intake")),
                (
                    Value::from("authentication"),
                    Value::from(format!("{:?}", owner.decision_id())),
                ),
            ]))?,
            ClaimApprovalStatus::Approved,
        );
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let mut project: ProjectRecord =
                super::record(&self.store, txn, project_id, self.project_type_byte()?)?
                    .ok_or_else(invalid)?;
            let previous = project
                .goal
                .as_deref()
                .map(EntityId::from_hex)
                .transpose()?;
            self.batch_in()
                .claim_candidate(
                    &id,
                    ClaimCandidate::new(
                        PREDICATE,
                        ClaimSubject::Entity(project_id),
                        Value::Binary(encode(record)?),
                        1.0,
                    ),
                    &envelope,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                )
                .apply(txn)?;
            project.goal = Some(id.to_hex());
            self.batch_in()
                .put(
                    &project_id,
                    self.project_type_byte()?,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &encode(&project)?,
                )
                .apply(txn)?;
            if let Some(old) = previous
                && self.get_claim_in_txn(txn, &old)?.is_some()
            {
                self.supersede_claim_in_txn(txn, &id, &old, now)?;
            }
            Ok(())
        })?;
        Ok(id)
    }

    /// Read the project's current goal, never the leader's instructions.
    pub fn project_goal_record(&self, project_id: EntityId) -> Result<Option<GoalRecord>> {
        let Some(project) = self.project(project_id)? else {
            return Ok(None);
        };
        let Some(id) = project.goal else {
            return Ok(None);
        };
        let id = EntityId::from_hex(&id).map_err(|_| invalid())?;
        let claim = self.get_claim(&id)?.ok_or_else(invalid)?;
        if claim.predicate != PREDICATE
            || claim.subject != ClaimSubject::Entity(project_id)
            || claim.source != Some(ClaimSource::UserStated)
            || claim.approval != ClaimApprovalStatus::Approved
            || claim.lifecycle != ClaimLifecycleStatus::Active
        {
            return Err(invalid());
        }
        let Value::Binary(bytes) = claim.value else {
            return Err(invalid());
        };
        let record: GoalRecord = super::decode(&bytes)?;
        record.validate()?;
        Ok(Some(record))
    }
}
