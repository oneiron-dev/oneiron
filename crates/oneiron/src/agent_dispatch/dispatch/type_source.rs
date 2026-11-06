//! The original task-type placement and its optional source carrier.

use super::{AgentDispatcher, AgentSpawnContext, ArtifactError, EntityId, Error};
use crate::error::Result;

impl AgentDispatcher<'_> {
    /// The task-type stamp shared by preparation and a direct launch preview.
    pub(in crate::agent_dispatch) fn spawn_type_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        project_ref: EntityId,
        requested_target: EntityId,
        spawn: &AgentSpawnContext,
    ) -> Result<crate::task_type::TaskTypeRef> {
        self.spawn_type_with_source_in_txn(txn, project_ref, requested_target, spawn, None)
    }

    pub(super) fn spawn_type_with_source_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        project_ref: EntityId,
        requested_target: EntityId,
        spawn: &AgentSpawnContext,
        type_source: Option<&mut Option<crate::team::run::SelectedTeamType>>,
    ) -> Result<crate::task_type::TaskTypeRef> {
        let (tree, selected) = if type_source.is_some() {
            let selected = super::super::task_type_tree::load_team_type_tree_with_sources_in_txn(
                self.vault,
                txn,
                Some(project_ref),
            )?;
            (
                selected.tree,
                Some((selected.file, selected.entity_rows, selected.root_lookup)),
            )
        } else {
            (
                super::super::task_type_tree::load_team_type_tree_in_txn(
                    self.vault,
                    txn,
                    Some(project_ref),
                )?,
                None,
            )
        };
        if spawn
            .type_ref
            .as_ref()
            .is_some_and(|type_ref| type_ref.node_id.is_empty())
        {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "task_type_ref node_id must not be empty",
            )));
        }
        let type_ref = match &spawn.plan {
            Some(plan) => {
                plan.validate()?;
                if spawn
                    .type_ref
                    .as_ref()
                    .is_some_and(|type_ref| *type_ref != plan.asked.type_ref)
                {
                    return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "spawn type stamp differs from the one its plan read",
                    )));
                }
                if requested_target != plan.plan.agent_def {
                    return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "dispatch target is not the seat its plan resolved",
                    )));
                }
                tree.validate_current_ref(&plan.asked.type_ref)
                    .map_err(|_| {
                        Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                            "the plan's type stamp is not in the tree in force; plan again",
                        ))
                    })?;
                plan.asked.type_ref.clone()
            }
            // Inside the write transaction no model call may run: the
            // placement skill's rule rung reads alone, on a direct spawn's
            // need text (FIX 2107). A host that wants its rungs to place
            // does so before dispatch (`place_spawn_type`).
            None => super::super::task_type_tree::place_in_tree(
                &tree,
                spawn.type_ref.as_ref(),
                None,
                spawn
                    .direct_spawn
                    .as_ref()
                    .map(|receipt| receipt.ask.need.clone()),
                Some(project_ref),
                None,
            ),
        };
        if let (Some(output), Some((file, entity_rows, root_lookup))) = (type_source, selected) {
            *output = Some(crate::team::run::SelectedTeamType {
                asked_project: spawn.project_ref,
                project: project_ref,
                requested_type: spawn.type_ref.clone(),
                placed_type: type_ref.clone(),
                file: file.map(|file| crate::team::run::SelectedTeamTypeFile {
                    head: file.head,
                    package_hash: *file.package_hash.as_bytes(),
                    file_hash: file.file_hash,
                }),
                entity_rows,
                root_lookup,
            });
        }
        Ok(type_ref)
    }
}
