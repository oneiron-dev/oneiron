//! Outbound mutation mapping; host door enforces policy and replay custody.

use oneiron::{
    EntityId, LinearEgress, LinearIssueChange, LinearIssueRef, LinearSyncResult, MirroredTaskFields,
};
use serde_json::{Value, json};

use crate::http::GraphQlCall;
use crate::source::LinearTrackerConfig;
use crate::{data, invalid};

const CREATE: &str = "mutation OneironCreateIssue($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id identifier updatedAt title description priority team { id } state { id } assignee { id } } } }";
const UPDATE: &str = "mutation OneironUpdateIssue($id: String!, $input: IssueUpdateInput!) { issueUpdate(id: $id, input: $input) { success issue { id identifier updatedAt title description priority team { id } state { id } assignee { id } } } }";

/// The host's *authorized* outbound door. It binds an operation ID to the
/// exact serialized call, stores the successful response durably, and returns
/// that SAME response on retries without executing a second mutation. If a
/// write may have reached Linear but no response was committed, the door must
/// reconcile or return an ambiguous failure; it must NOT blindly resend.
/// A process-local HashMap or an `Idempotency-Key` header is insufficient.
pub trait LinearOutboundDoor {
    /// Executes the mutation only after the host's external-effect policy
    /// admits it. A denial or uncertain delivery returns a transport error.
    ///
    /// # Errors
    /// Returns a transport error on denied, failed or ambiguous delivery.
    fn dispatch(&mut self, operation_id: [u8; 32], call: &GraphQlCall) -> LinearSyncResult<Value>;
}

/// Maps the engine's computed idempotency key and field set to GraphQL. The
/// only write path is the injected outbound door; no token lives here.
pub struct LinearHostEgress<D> {
    door: D,
    config: LinearTrackerConfig,
}

impl<D> LinearHostEgress<D> {
    /// # Errors
    /// Refuses invalid/ambiguous host field mappings before a write.
    pub fn new(door: D, config: LinearTrackerConfig) -> LinearSyncResult<Self> {
        config.validate()?;
        Ok(Self { door, config })
    }

    pub fn into_door(self) -> D {
        self.door
    }

    fn input(&self, fields: &MirroredTaskFields) -> LinearSyncResult<Value> {
        Ok(json!({
            "title": fields.title,
            "description": fields.description,
            "priority": fields.priority,
            "stateId": LinearTrackerConfig::mapped(&self.config.status_ids, &fields.status)?,
            "assigneeId": fields.assignee_ref.as_ref()
                .map(|reference| LinearTrackerConfig::mapped(&self.config.assignee_ids, reference))
                .transpose()?,
        }))
    }
}

impl<D: LinearOutboundDoor> LinearHostEgress<D> {
    fn write(
        &mut self,
        operation_id: [u8; 32],
        call: &GraphQlCall,
        field: &str,
    ) -> LinearSyncResult<LinearIssueChange> {
        let response = self.door.dispatch(operation_id, call)?;
        let result = data(&response, field)?;
        if result.get("success").and_then(Value::as_bool) != Some(true) {
            return Err(invalid("Linear mutation was not successful"));
        }
        let issue = result
            .get("issue")
            .ok_or_else(|| invalid("Linear mutation has no issue"))?;
        self.config.issue(issue)
    }
}

impl<D: LinearOutboundDoor> LinearEgress for LinearHostEgress<D> {
    fn create_issue(
        &mut self,
        operation_id: [u8; 32],
        _task_ref: EntityId,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        let mut input = self.input(fields)?;
        input["teamId"] = json!(self.config.team_id);
        let call = GraphQlCall {
            query: CREATE,
            variables: json!({"input": input}),
        };
        self.write(operation_id, &call, "issueCreate")
    }

    fn update_issue(
        &mut self,
        operation_id: [u8; 32],
        issue: &LinearIssueRef,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        if issue.team_id != self.config.team_id || issue.issue_id.trim().is_empty() {
            return Err(invalid("Linear update targets an invalid issue"));
        }
        let call = GraphQlCall {
            query: UPDATE,
            variables: json!({"id": issue.issue_id, "input": self.input(fields)?}),
        };
        let updated = self.write(operation_id, &call, "issueUpdate")?;
        if updated.issue.issue_id != issue.issue_id {
            return Err(invalid("Linear update returned another issue"));
        }
        Ok(updated)
    }
}
