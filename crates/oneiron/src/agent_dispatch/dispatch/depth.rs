//! Dispatch depth (FIX 9560). Only an explicit slice is spent, one level per
//! spawn, and refused once spent: an authorized owner depth setting on a
//! project, or the slice a spawn asked for. A lineage under the seeded
//! default alone is unbounded, and an unresolved policy holds at zero, never
//! at unlimited. Cycle, missing-ancestor and project-transition checks stand.

use std::collections::HashSet;

use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::gate::project_depth::{ProjectDepthSetting, resolve_explicit_project_depth};
use crate::scan_check::{EngineScan, ScanCount};

use super::super::codec::record_dispatch_input;
use super::super::types::AGENT_DISPATCH_COMPAT_DEPTH_CAP;
use super::AgentDispatcher;

/// The limit the depth fold carries where no explicit slice binds: nothing
/// is spent against it.
pub(in crate::agent_dispatch) const UNBOUNDED_DEPTH: u64 = u64::MAX;

/// The depth a spawn stores: the slice it asked for, the explicit live
/// `limit`, both met, or `None` when neither binds.
pub(in crate::agent_dispatch) fn stored_depth(asked: Option<u64>, limit: u64) -> Option<u64> {
    let limit = (limit != UNBOUNDED_DEPTH).then_some(limit);
    match (asked, limit) {
        (Some(asked), Some(limit)) => Some(asked.min(limit)),
        (asked, limit) => asked.or(limit),
    }
}

impl AgentDispatcher<'_> {
    /// Read the live project in the same snapshot as the stored parent slice.
    /// Root defaults to the vault project; an omitted child project inherits.
    /// A project transition may only enter a direct child responsibility space.
    /// Every ancestor is read, however many (rule 5): past its threshold row
    /// the walk asks whether everything is okay, counted on every way out.
    /// The limit is [`UNBOUNDED_DEPTH`] where no explicit slice binds.
    pub(in crate::agent_dispatch) fn project_depth_limit_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        parent_attempt: Option<AttemptId>,
        requested_project: Option<EntityId>,
    ) -> Result<(EntityId, u64)> {
        let root = self.vault.project_for_spawn_in_txn(txn, None)?.0;
        let (parent_project, has_parent_input, mut parent_limit) = match parent_attempt {
            Some(parent) => {
                let mut walk = ScanCount::start(
                    &self.vault.store,
                    txn,
                    EngineScan::DispatchAncestorRows,
                    parent.as_bytes(),
                )?;
                let mut seen = HashSet::new();
                let slice = self.parent_slice_in_txn(txn, parent, root, &mut seen);
                walk.rows(seen.len());
                walk.defer(&self.vault.store);
                // A lineage with no explicit slice once stopped at the
                // compatibility depth; it reads on, and past that depth asks
                // whether everything is okay.
                if matches!(slice, Ok((_, true, UNBOUNDED_DEPTH))) {
                    let scope = [parent.as_bytes().as_slice(), b"implicit-depth"].concat();
                    let mut implicit = ScanCount::start_at(
                        EngineScan::DispatchAncestorRows,
                        &scope,
                        u64::from(AGENT_DISPATCH_COMPAT_DEPTH_CAP),
                    );
                    implicit.rows(seen.len());
                    implicit.defer(&self.vault.store);
                }
                slice?
            }
            // A root spawn takes its project's live policy depth whole.
            None => (root, false, UNBOUNDED_DEPTH),
        };
        let (id, project) = self.vault.project_for_spawn_in_txn(
            txn,
            requested_project.or_else(|| parent_attempt.map(|_| parent_project)),
        )?;
        if id != root && (parent_attempt.is_none() || !has_parent_input) {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "a project spawn requires a real parent in its ancestor project",
            )));
        }
        if parent_attempt.is_some() {
            if id != parent_project && !project.parents.contains(&parent_project.to_hex()) {
                return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                    "project is not a child of the parent project",
                )));
            }
            if parent_limit != UNBOUNDED_DEPTH {
                parent_limit = parent_limit.checked_sub(1).ok_or(Error::Artifact(
                    ArtifactError::InvalidAgentDispatchInput("project depth is exhausted"),
                ))?;
            }
        }
        let live = self.explicit_depth_in_txn(txn, id, project.depth)?;
        Ok((id, live.min(parent_limit)))
    }

    /// The walk [`Self::project_depth_limit_in_txn`] counts, each attempt it
    /// reads in `seen`: the parent's project, whether it stored a dispatch
    /// input, and its slice folded with every ancestor project's explicit
    /// live depth.
    fn parent_slice_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        parent_attempt: AttemptId,
        root: EntityId,
        seen: &mut HashSet<AttemptId>,
    ) -> Result<(EntityId, bool, u64)> {
        let mut parent_project = root;
        let mut has_parent_input = false;
        let mut parent_limit = UNBOUNDED_DEPTH;
        let mut cursor = Some(parent_attempt);
        let mut distance = 0_u64;
        while let Some(attempt) = cursor {
            if !seen.insert(attempt) {
                return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                    "project depth ancestor cycle",
                )));
            }
            let row = AttemptQueue::new(self.vault).get_in_txn(txn, attempt)?;
            if let Some(row) = &row
                && super::super::workflow_record::is_wrapper(row)
            {
                if distance == 0 {
                    super::super::workflow_record::reject_wrapper_parent(row)?;
                }
                // The wrapper is inert bookkeeping, not a spawned authority
                // level. Verify its registered workflow and cross to its real
                // parent without spending another unit of project depth.
                cursor = self.workflow_authority_parent_in_txn(txn, Some(attempt))?;
                continue;
            }
            let input = row.as_ref().and_then(record_dispatch_input);
            if distance == 0 {
                has_parent_input = input.is_some();
                // A parent that stored no explicit slice spends none.
                parent_limit = input
                    .as_ref()
                    .and_then(|input| input.depth_remaining)
                    .unwrap_or(UNBOUNDED_DEPTH);
                parent_project = input
                    .as_ref()
                    .and_then(|input| input.project_ref)
                    .unwrap_or(root);
            } else if input.is_none() {
                if row.is_none() {
                    return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "project depth ancestor is missing",
                    )));
                }
                break; // Non-agent board/legacy parent has no project slice to fold.
            }
            let ancestor_project = input
                .as_ref()
                .and_then(|input| input.project_ref)
                .unwrap_or(root);
            let (_, live) = self
                .vault
                .project_for_spawn_in_txn(txn, Some(ancestor_project))?;
            let live = self.explicit_depth_in_txn(txn, ancestor_project, live.depth)?;
            if live != UNBOUNDED_DEPTH {
                let live_remaining = live.checked_sub(distance).ok_or(Error::Artifact(
                    ArtifactError::InvalidAgentDispatchInput("project ancestor depth is exhausted"),
                ))?;
                parent_limit = parent_limit.min(live_remaining);
            }
            cursor = match (row, input) {
                (Some(row), Some(_)) => {
                    decode_dreamer_attempt_payload(&row.payload)?.parent_attempt
                }
                _ => None, // A schema-v1/non-dispatch parent ends the walk.
            };
            distance += 1;
        }
        Ok((parent_project, has_parent_input, parent_limit))
    }

    /// The depth `project`'s live policy spends, `resolved` being the depth
    /// its fold read in the same snapshot: an explicit owner setting's value,
    /// [`UNBOUNDED_DEPTH`] under the seeded default alone, and zero while the
    /// policy is unresolved.
    fn explicit_depth_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        project: EntityId,
        resolved: u64,
    ) -> Result<u64> {
        Ok(
            match resolve_explicit_project_depth(
                &self.vault.store,
                txn,
                self.vault.privacy_posture(),
                project,
            )? {
                ProjectDepthSetting::Explicit(depth) => depth.min(resolved),
                ProjectDepthSetting::Seeded => UNBOUNDED_DEPTH,
                ProjectDepthSetting::Unresolved => 0,
            },
        )
    }

    /// The live depth a child of `parent_attempt` may persist, after folding
    /// the stored slice with every ancestor project's explicit depth:
    /// `u64::MAX` where none binds.
    pub fn child_depth_remaining(&self, parent_attempt: AttemptId) -> Result<u64> {
        let txn = self.vault.store.env.read_txn()?;
        self.project_depth_limit_in_txn(&txn, Some(parent_attempt), None)
            .map(|(_, depth)| depth)
    }
}
