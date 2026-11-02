//! A connector call's reply after its send (FIX 7646, FIX 7647): the host
//! that sent it cleared it of the custody value the send presented, inside
//! that send's own door, with the bytes the door released
//! ([`ConnectorCallHost::clears_at_door`](super::ConnectorCallHost::clears_at_door)).
//! Only a host that cannot say so has the reply of a call that names a
//! record cleared here, by reading the value once more, as before; withheld
//! when it cannot be read, under its own absence reason (FIX 2823).

use serde_json::Value;

use crate::Vault;
use crate::entity_id::EntityId;

use super::connector_call::{
    ConnectorResultAbsence, PendingConnectorCall, Step, UntrustedToolResult,
    connector_call_effector,
};

impl Vault {
    /// `step` as the caller gets it: as the host left it when the host
    /// `cleared_at_door`, else a delivered reply to a call that names a
    /// custody record cleared of that record's value, or withheld.
    pub(super) fn connector_reply_cleared(
        &self,
        cleared_at_door: bool,
        pending: &PendingConnectorCall,
        step: Step,
    ) -> Step {
        if cleared_at_door {
            return step;
        }
        match (pending.credential, step) {
            (
                Some(custody),
                Step::Delivered {
                    intent,
                    result: Some(result),
                    budget_steering,
                    ..
                },
            ) => match self.cleared_connector_reply(&custody, &pending.name, result) {
                Ok(result) => Step::Delivered {
                    intent,
                    result: Some(result),
                    result_absence: None,
                    budget_steering,
                },
                Err(absence) => Step::Delivered {
                    intent,
                    result: None,
                    result_absence: Some(absence),
                    budget_steering,
                },
            },
            (_, step) => step,
        }
    }

    /// `result`, a reply to a send that presented the value of the custody
    /// record `custody`, with each copy of the value replaced by the
    /// record's handle text; withheld as `CredentialClearFailed` when the
    /// route or the value could not be read again to find it. The cause
    /// itself is never carried: it may name the value's record or its bytes.
    fn cleared_connector_reply(
        &self,
        custody: &EntityId,
        name: &str,
        mut result: UntrustedToolResult,
    ) -> Result<UntrustedToolResult, ConnectorResultAbsence> {
        let withheld = ConnectorResultAbsence::CredentialClearFailed;
        let route = self
            .route_connector_call(name)
            .ok()
            .flatten()
            .ok_or(withheld)?;
        let effector = connector_call_effector(&route);
        let mut fields: Vec<&mut Value> = std::iter::once(&mut result.content)
            .chain(result.structured_content.as_mut())
            .chain(result.rpc_error.as_mut())
            .collect();
        self.clear_secret_record_from(custody, &effector, &mut fields)
            .map_err(|_| withheld)?;
        Ok(result)
    }
}
