//! Scheduler binding for the production TASK/issue mirror.
//! The host owns transport and credentials; core checks the verified TASK
//! writer and the scheduler against the exact current mirror operation.
use std::collections::BTreeMap;

use super::{
    LinearEffectKind, LinearEffectRequest, LinearEgress, LinearIssueChange, LinearIssueRef,
    LinearSyncError, LinearSyncResult, LinearTaskStore, MirroredTaskFields, VaultLinearTaskStore,
};
use crate::{EntityId, Vault};

pub struct ServedLinearEgress<'v, O> {
    vault: &'v Vault,
    scheduler_actor: EntityId,
    outbound: O,
}

impl<'v, O> ServedLinearEgress<'v, O> {
    pub const fn new(vault: &'v Vault, scheduler_actor: EntityId, outbound: O) -> Self {
        Self {
            vault,
            scheduler_actor,
            outbound,
        }
    }

    fn admit(
        &self,
        kind: LinearEffectKind,
        operation_id: [u8; 32],
        task_ref: EntityId,
        issue: Option<&LinearIssueRef>,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<()> {
        self.vault.authorize_linear_effect(&LinearEffectRequest {
            operation_id,
            task_ref,
            scheduler_actor: self.scheduler_actor,
            issue: issue.cloned(),
            kind,
            fields: fields.clone(),
        })?;
        Ok(())
    }
}

impl<O: LinearEgress> LinearEgress for ServedLinearEgress<'_, O> {
    fn create_issue(
        &mut self,
        operation_id: [u8; 32],
        task_ref: EntityId,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        self.admit(
            LinearEffectKind::Create,
            operation_id,
            task_ref,
            None,
            fields,
        )?;
        self.outbound.create_issue(operation_id, task_ref, fields)
    }

    fn update_issue_conditional(
        &mut self,
        operation_id: [u8; 32],
        issue: &LinearIssueRef,
        expected_remote: &BTreeMap<String, [u8; 32]>,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        let task_ref = VaultLinearTaskStore::new(self.vault)
            .link_for_issue(issue)?
            .ok_or(LinearSyncError::AuthorizationDenied)?
            .task_ref;
        self.admit(
            LinearEffectKind::Update,
            operation_id,
            task_ref,
            Some(issue),
            fields,
        )?;
        self.outbound
            .update_issue_conditional(operation_id, issue, expected_remote, fields)
    }
}
