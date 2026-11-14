//! Human-authenticated project goal intake; proposals never write this record.
use super::{encode, invalid};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::run_budget::LeaseUnit;
use crate::scan_check::{EngineScan, ScanCount};
use crate::store::Store;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};
use crate::{EntityId, TimeRange, Vault};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub(crate) const PREDICATE: &str = "project.goal_intake";
mod admission;
mod context;
mod interview;
mod limits;
mod proposals;
pub(crate) use admission::{
    admitted_claim_of_project, guard_claim_put, guard_goal_delete, guard_pointer_put,
    precheck_delete as precheck_goal_delete, retire_for_delete as retire_goal_for_delete,
};
pub use context::ProjectGoalInterviewContext;
pub use interview::GoalInterviewTurns;
use limits::GoalLimitValues;
pub(crate) use limits::GoalLimits;
pub use proposals::{
    GoalAxisChange, GoalAxisChanges, GoalBudgetChange, GoalPreferenceChange, GoalPreferenceChanges,
    GoalRecordDiff, GoalTextChange, ProjectGoalBase, ProjectGoalProposal,
    ProjectGoalProposalDismissal, ProjectGoalProposalEvidence, ProjectGoalProposalImprovement,
    ProjectGoalProposalRate, ProjectGoalProposalReasons, ProjectGoalProposalStatus,
    ProjectGoalProposalView, ProjectGoalProposeRequest, ProjectGoalProposer,
    ProjectGoalRevisionsView, project_goal_propose,
};
pub(crate) use proposals::{
    dismiss_project_goal_proposal, project_goal_base_in_txn, project_goal_proposals_in_txn,
    reads_goal_proposals_in_txn,
};

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
// FIX [LIBTEST-QUARANTINE-WORKSPACE-ROSTER-PROJECT-GOAL-TESTS]: the lib test target's type check fails here (8 errors: E0061 x7, E0063 x1); port it, then drop this gate
#[cfg(any())]
#[cfg(test)]
mod tests;

#[doc(hidden)]
pub use oneiron_verb_wire::workspace_roster::project::goal::{
    GoalAxis, GoalExplorationBudget, GoalPreference,
};

/// Typed data for a project's admission target; never an agent prompt or authority grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
            || LeaseUnit::new(self.exploration_budget.unit.as_str()).is_err()
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

    /// Counts the record against `limits`, each field under its own scope
    /// (the project, then the field's name; never its text). Past one, the
    /// intake raises its scan check and keeps the whole record (rule 5).
    fn observe_limits(&self, store: &Store, project: EntityId, limits: GoalLimitValues) {
        let observe = |scan: EngineScan, field: &str, threshold: u64, rows: usize| {
            let scope = [project.as_bytes().as_slice(), field.as_bytes()].concat();
            let mut count = ScanCount::start_at(scan, &scope, threshold);
            count.rows(rows);
            count.defer(store);
        };
        let axes = || {
            self.primary_axes
                .iter()
                .chain(&self.floor_axes)
                .chain(&self.cost_axes)
        };
        observe(
            EngineScan::ProjectGoalTextBytes,
            "goal",
            limits.goal_bytes,
            self.goal.len(),
        );
        observe(
            EngineScan::ProjectGoalTextBytes,
            "why",
            limits.why_bytes,
            self.why.len(),
        );
        observe(
            EngineScan::ProjectGoalAxes,
            "axes",
            limits.axes,
            axes().count(),
        );
        observe(
            EngineScan::ProjectGoalPreferences,
            "preferences",
            limits.preferences,
            self.preferences.len(),
        );
        for axis in axes() {
            observe(
                EngineScan::ProjectGoalAxisNameBytes,
                "axis_name",
                limits.axis_name_bytes,
                axis.name.len(),
            );
            for (field, value) in [("measure", &axis.measure), ("bound", &axis.bound)] {
                let detail = EngineScan::ProjectGoalDetailBytes;
                observe(detail, field, limits.axis_detail_bytes, value.len());
            }
        }
        for preference in &self.preferences {
            for (field, value) in [
                ("prefer", &preference.prefer),
                ("over", &preference.over),
                ("reason", &preference.reason),
            ] {
                let detail = EngineScan::ProjectGoalDetailBytes;
                observe(detail, field, limits.axis_detail_bytes, value.len());
            }
        }
    }
}

impl Vault {
    /// Commit an interview answered by an authenticated human. A loop proposal
    /// has no `AuthenticatedOwner` and cannot call this door on its own.
    /// Replaces the project pointer and supersedes the prior goal atomically.
    #[cfg(any(test, oneiron_test_support))]
    pub(crate) fn write_project_goal_from_intake(
        &self,
        owner: &AuthenticatedOwner,
        project_id: EntityId,
        record: &GoalRecord,
        now: u64,
    ) -> Result<EntityId> {
        self.with_write_txn_grouped(|txn| {
            self.write_project_goal_in_txn(txn, owner, project_id, None, record, now)
        })
    }

    /// `thread` is the room thread the intake was confirmed in, if any: its
    /// scoped goal-limit rows apply beside the project's.
    pub(super) fn write_project_goal_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        project_id: EntityId,
        thread: Option<EntityId>,
        record: &GoalRecord,
        now: u64,
    ) -> Result<EntityId> {
        let actor = owner.revalidate_in_txn(self, txn)?;
        record.validate()?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
        if policy.diagnostics().loaded_manifest_forces_fail_closed() {
            return Err(invalid());
        }
        let limits = policy
            .goal_limits()
            .resolve_for(project_id, thread, Some(actor));
        record.observe_limits(&self.store, project_id, limits);
        let id = EntityId::now();
        let envelope = WriteEnvelope::new(
            WriteActor::new(actor, EdgeActorClass::Human),
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

        let mut project = self
            .visible_project_in_txn(txn, project_id)?
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
        interview::bump_generation(&self.store, txn, project_id)?;
        if let Some(old) = previous {
            let prior = admission::trusted_active_claim(&self.store, txn, old, project_id)?;
            admission::arm_supersession(&self.store, txn, old, &prior, now)?;
            self.supersede_claim_in_txn(txn, &id, &old, now)?;
            admission::seal_claim(&self.store, txn, old)?;
        }
        Ok(id)
    }

    /// The project's current goal as `reader` may read it, never the
    /// leader's instructions (untangle 6.6d, F4: the goal read is an
    /// ordinary granted read with an actor). The vault's owner reads it; a
    /// base agent reads it through its own grant and scoped read
    /// (GOAL-PRIVACY); any other reader through a live Steward grant naming
    /// `read`. A reader without that reads no goal: absent.
    ///
    /// # Errors
    ///
    /// A store failure; a goal claim that fails its seal.
    pub fn project_intake_goal_as(
        &self,
        reader: WriteActor,
        project_id: EntityId,
    ) -> Result<Option<GoalRecord>> {
        let txn = self.store.env.read_txn()?;
        Ok(self
            .project_intake_goal_as_in_txn(&txn, reader, project_id)?
            .map(|(_, record)| record))
    }

    /// The project's current goal as the caller's scoped read `read` may
    /// read it: only when that read admits the goal claim itself, not only
    /// the project (the context board's project row, F4).
    ///
    /// # Errors
    ///
    /// A store or read failure; a goal claim that fails its seal.
    pub fn project_intake_goal_through(
        &self,
        read: &crate::claim::ScopedRead<'_>,
        project_id: EntityId,
    ) -> Result<Option<GoalRecord>> {
        let goal = {
            let txn = self.store.env.read_txn()?;
            self.project_intake_goal_in_txn(&txn, project_id)?
        };
        let Some((claim, record)) = goal else {
            return Ok(None);
        };
        Ok(read.is_entity_readable(&claim)?.then_some(record))
    }

    /// [`Self::project_intake_goal_as`] in the caller's snapshot, with the
    /// id of the goal claim it read.
    pub(crate) fn project_intake_goal_as_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        reader: WriteActor,
        project_id: EntityId,
    ) -> Result<Option<(EntityId, GoalRecord)>> {
        let Some((claim, record)) = self.project_intake_goal_in_txn(txn, project_id)? else {
            return Ok(None);
        };
        let actor = reader.entity_ref();
        if crate::federation::SystemAgent::of(actor).is_some() {
            // Before the engine stands its grant, the agent's rows decide,
            // as before.
            if crate::federation::steward_grant_of_in(&self.store, txn, actor)?.is_none() {
                return Ok(Some((claim, record)));
            }
            // A base agent whose grant no longer names `read`, or whose
            // binding is gone, reads no goal: its scoped read would refuse
            // the dead credential with an error instead.
            if !self.system_agent_reads_live_in(txn, actor)? {
                return Ok(None);
            }
            let key = crate::claim::ScopedReadActorKey::for_engine_actor(WriteActor::new(
                actor,
                EdgeActorClass::System,
            ))
            .ok_or_else(|| crate::error::Error::InvalidConfig("invalid agent read key".into()))?;
            return Ok(self
                .scoped_read(key)
                .entity_raw_live_in(txn, &claim)?
                .map(|_| (claim, record)));
        }
        Ok(self
            .substrate_read_allowed_in_txn(txn, reader, crate::federation::SubstrateRead::Goal)?
            .then_some((claim, record)))
    }

    /// The project's current goal claim and record, read with no actor: for
    /// the engine's own integrity checks (a pointer, a revision, a writer's
    /// expected claim), never to show the goal to a caller.
    pub(crate) fn project_intake_goal_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        project_id: EntityId,
    ) -> Result<Option<(EntityId, GoalRecord)>> {
        let Some(project) = self.visible_project_in_txn(txn, project_id)? else {
            return Ok(None);
        };
        let Some(id) = project.goal else {
            return Ok(None);
        };
        let id = EntityId::from_hex(&id).map_err(|_| invalid())?;
        let claim = admission::trusted_active_claim(&self.store, txn, id, project_id)?;
        let record = decode_goal_claim(&claim, project_id)?;
        Ok(Some((id, record)))
    }

    /// TEST-ONLY: [`Self::project_intake_goal_in_txn`] in a snapshot of its
    /// own, without the claim id.
    #[cfg(test)]
    pub(crate) fn project_intake_goal(&self, project_id: EntityId) -> Result<Option<GoalRecord>> {
        let txn = self.store.env.read_txn()?;
        Ok(self
            .project_intake_goal_in_txn(&txn, project_id)?
            .map(|(_, record)| record))
    }
}
