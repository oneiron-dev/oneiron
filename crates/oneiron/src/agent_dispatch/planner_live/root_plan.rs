//! The owner's root plan (DOOR-111 S3): the live planner a leased parent's
//! spawn reads, for a spawn the authenticated owner asks for at the root.
//!
//! The owner holds no attempt and no lease, so nothing here reads or fakes
//! one. Each entry revalidates the owner and resolves the root project first,
//! the one a root dispatch enters; its tree in force places the type and
//! holds the plan's stamp. The launch is stated as a root's, under the root
//! spend scope the host opened when it names one. The team-shape and rung
//! skills, and the pattern skill a planned launch runs, are read as their
//! admitted packages: a root routes no exploration trial and has no
//! manifest to stamp. Planning never dispatches and confers no authority.

use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::skill::{LoadedSkillPack, SkillRole, resident_of, skill_loadable};
use crate::task_type::{PlacementDecisions, TaskTypeRef};
use crate::team::PatternSkillRef;

use super::super::task_type_tree::{load_team_type_tree, place_in_tree};
use super::super::{AgentDispatcher, SpawnPlanReceipt, SpawnSpend};
use super::LivePlanRequest;

impl AgentDispatcher<'_> {
    /// Places the owner's spawn type once, against the root project's tree
    /// in force: a requested stamp that tree accepts is kept, anything else
    /// is placed through the placement skill's ladder (the host's
    /// `decisions` route it past the rule rung), and unsure is the root.
    pub(super) fn place_spawn_type_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        need: &str,
        requested: Option<&TaskTypeRef>,
        decisions: Option<&PlacementDecisions<'_>>,
    ) -> Result<TaskTypeRef> {
        let (_, project) = self.owner_root_in_txn(owner, &self.vault.store.env.read_txn()?)?;
        let tree = load_team_type_tree(self.vault, Some(project))?;
        Ok(place_in_tree(
            &tree,
            requested,
            None,
            Some(need.to_owned()),
            Some(project),
            decisions,
        ))
    }

    /// Plans the owner's spawn at the root on the live planner: the evidence,
    /// ranking and ladder a leased parent's plan reads, in the root project
    /// with the launch stated as a root's. The receipt names the skill
    /// revisions and executors it read. Nothing launches.
    pub(super) fn plan_spawn_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        request: &LivePlanRequest<'_>,
        spend: Option<&SpawnSpend>,
        at: u64,
    ) -> Result<SpawnPlanReceipt> {
        let (_, project) = self.owner_root_in_txn(owner, &self.vault.store.env.read_txn()?)?;
        request.need.validate()?;
        let team_shape = self.root_skill_pack(&request.skills.team_shape)?;
        let request = &request.with_owner_choices(self.vault, Some(project))?;
        let evidence = self.planner_evidence_for(
            Some(project),
            None,
            spend,
            &request.need,
            request.seats,
            at,
        )?;
        Ok(self
            .plan_over_evidence(request, &team_shape, &evidence, |skill| {
                self.root_skill_pack(skill)
            })?
            .0)
    }

    /// The owner's actor and the root project, in one snapshot: the proof
    /// first, then the project a root dispatch enters.
    pub(super) fn owner_root_in_txn(
        &self,
        owner: &AuthenticatedOwner,
        txn: &heed::RoTxn<'_>,
    ) -> Result<(EntityId, EntityId)> {
        let actor = owner.revalidate_in_txn(self.vault, txn)?;
        Ok((actor, self.project_depth_limit_in_txn(txn, None, None)?.0))
    }

    /// One admitted shared skill as the root reads it: live, no resident's,
    /// active and approved, its instructions the runtime package the hub
    /// verified against the record.
    fn root_skill_pack(&self, skill: &EntityId) -> Result<LoadedSkillPack> {
        let txn = self.vault.store.env.read_txn()?;
        if !crate::vault::live_entity_row_in_txn(&self.vault.store, &txn, skill)?.is_live() {
            return Err(Error::EntityNotFound);
        }
        let record = self.vault.read_skill_record_in_txn(&txn, skill)?;
        if resident_of(&record)?.is_some() {
            return Err(Error::InvalidClaimBody(
                "a root plan reads shared skills, not a resident's",
            ));
        }
        if !skill_loadable(&record) {
            return Err(Error::InvalidClaimBody(
                "pack load requires an active approved skill",
            ));
        }
        let source_files = self
            .vault
            .runtime_skill_package_in_txn(&txn, skill, &record)?
            .map(|package| package.files);
        Ok(LoadedSkillPack {
            entity: *skill,
            record,
            source_files,
        })
    }

    /// A plan's pattern skill as the root reads an admitted package, on the
    /// caller's snapshot: the exact revision the plan froze, still a live
    /// shared workflow skill, active and approved, its instructions the
    /// runtime package the hub verified against the record. A planned
    /// launch reads it before its runner runs and again in its writer.
    pub(super) fn root_pattern_pack_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        pattern: &PatternSkillRef,
    ) -> Result<LoadedSkillPack> {
        let skill = &pattern.skill;
        if !crate::vault::live_entity_row_in_txn(&self.vault.store, txn, skill)?.is_live() {
            return Err(Error::EntityNotFound);
        }
        let record = self.vault.read_skill_record_in_txn(txn, skill)?;
        if resident_of(&record)?.is_some() {
            return Err(Error::InvalidClaimBody(
                "a root plan reads shared skills, not a resident's",
            ));
        }
        if !skill_loadable(&record) || record.role != SkillRole::Workflow {
            return Err(Error::InvalidClaimBody(
                "a pattern launch runs an active approved workflow skill",
            ));
        }
        if record.version != pattern.version {
            return Err(Error::InvalidClaimBody(
                "the pattern skill moved off the revision its plan froze",
            ));
        }
        let source_files = self
            .vault
            .runtime_skill_package_in_txn(txn, skill, &record)?
            .map(|package| package.files);
        Ok(LoadedSkillPack {
            entity: *skill,
            record,
            source_files,
        })
    }
}
