//! Human-authenticated project goal intake; proposals never write this record.
use super::{ProjectRecord, encode, invalid};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};
use crate::{EntityId, TimeRange, Vault};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub(crate) const PREDICATE: &str = "project.goal_intake";
mod admission;
mod interview;
mod limits;
pub(crate) use admission::{
    admitted_claim_of_project, guard_claim_put, guard_goal_delete, guard_pointer_put,
    precheck_delete as precheck_goal_delete, retire_for_delete as retire_goal_for_delete,
};
pub use interview::GoalInterviewTurns;
pub(crate) use limits::GoalLimits;

fn decode_goal_claim(body: &ClaimBody, project: EntityId) -> Result<GoalRecord> {
    if body.predicate != PREDICATE
        || body.subject != ClaimSubject::Entity(project)
        || body.source != Some(ClaimSource::UserStated)
        || body.approval != ClaimApprovalStatus::Approved
        || body.lifecycle != ClaimLifecycleStatus::Active
    {
        return Err(invalid());
    }
    let Value::Binary(bytes) = &body.value else {
        return Err(invalid());
    };
    let record: GoalRecord = super::decode(bytes)?;
    record.validate()?;
    Ok(record)
}
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
    fn validate(&self) -> Result<()> {
        if self.goal.trim().is_empty()
            || self.why.trim().is_empty()
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
            })
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn validate_limits(&self, limits: GoalLimits) -> Result<()> {
        let len = |s: &str| u64::try_from(s.len()).unwrap_or(u64::MAX);
        if len(&self.goal) > limits.goal_bytes
            || len(&self.why) > limits.why_bytes
            || u64::try_from(self.primary_axes.len() + self.floor_axes.len() + self.cost_axes.len())
                .unwrap_or(u64::MAX)
                > limits.axes
            || u64::try_from(self.preferences.len()).unwrap_or(u64::MAX) > limits.preferences
            || self
                .primary_axes
                .iter()
                .chain(&self.floor_axes)
                .chain(&self.cost_axes)
                .any(|axis| {
                    len(&axis.name) > limits.axis_name_bytes
                        || len(&axis.measure) > limits.axis_detail_bytes
                        || len(&axis.bound) > limits.axis_detail_bytes
                })
            || self.preferences.iter().any(|pref| {
                len(&pref.prefer) > limits.axis_detail_bytes
                    || len(&pref.over) > limits.axis_detail_bytes
                    || len(&pref.reason) > limits.axis_detail_bytes
            })
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
    #[cfg(test)]
    pub(crate) fn write_project_goal_from_intake(
        &self,
        owner: &AuthenticatedOwner,
        project_id: EntityId,
        record: &GoalRecord,
        now: u64,
    ) -> Result<EntityId> {
        self.with_write_txn(|txn| {
            self.write_project_goal_in_txn(txn, owner, project_id, record, now)
        })
    }

    pub(super) fn write_project_goal_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        project_id: EntityId,
        record: &GoalRecord,
        now: u64,
    ) -> Result<EntityId> {
        owner.revalidate_in_txn(self, txn)?;
        record.validate()?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
        if policy.diagnostics().loaded_manifest_forces_fail_closed() {
            return Err(invalid());
        }
        record.validate_limits(policy.goal_limits())?;
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

        let mut project: ProjectRecord =
            super::record(&self.store, txn, project_id, self.project_type_byte()?)?
                .ok_or_else(invalid)?;
        let previous = project
            .goal
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()?;
        admission::arm_birth(&self.store, txn, id, project_id, record)?;
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
        admission::seal_claim(&self.store, txn, id)?;
        project.goal = Some(id.to_hex());
        let project_bytes = encode(&project)?;
        admission::arm_pointer(&self.store, txn, project_id, previous, id, &project_bytes)?;
        self.batch_in()
            .put(
                &project_id,
                self.project_type_byte()?,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &project_bytes,
            )
            .apply(txn)?;
        admission::disarm_pointer(&self.store, txn, project_id)?;
        if let Some(old) = previous {
            let prior = admission::trusted_active_claim(&self.store, txn, old, project_id)?;
            admission::arm_supersession(&self.store, txn, old, &prior, now)?;
            self.supersede_claim_in_txn(txn, &id, &old, now)?;
            admission::seal_claim(&self.store, txn, old)?;
        }
        Ok(id)
    }

    /// Read the project's current goal, never the leader's instructions.
    pub fn project_intake_goal(&self, project_id: EntityId) -> Result<Option<GoalRecord>> {
        let txn = self.store.env.read_txn()?;
        let Some(project): Option<ProjectRecord> =
            super::record(&self.store, &txn, project_id, self.project_type_byte()?)?
        else {
            return Ok(None);
        };
        let Some(id) = project.goal else {
            return Ok(None);
        };
        let id = EntityId::from_hex(&id).map_err(|_| invalid())?;
        let claim = admission::trusted_active_claim(&self.store, &txn, id, project_id)?;
        let record = decode_goal_claim(&claim, project_id)?;
        Ok(Some(record))
    }
}
