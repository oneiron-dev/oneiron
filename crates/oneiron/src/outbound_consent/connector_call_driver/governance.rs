//! The one grant, governing key and approved-schema resolution a connector
//! call and a schema read share (FIX 2283).
//! Entry: `Vault::governing_tool`. Defines its own items.

use serde_json::Value;

use crate::Vault;
use crate::connector_key::{ConnectorKeyRecord, ConnectorKeyStatus, ScopedCapabilityProvenance};
use crate::entity_id::EntityId;
use crate::outbound_grant::StandingOutboundGrant;
use crate::outbound_intent_ledger::IntentLedgerError;

use super::{Step, held, refused};

/// The tool beneath one grant: the grant, the governing key it mints and the
/// tool's approved schema there.
pub(super) struct GoverningTool {
    pub(super) grant_id: EntityId,
    pub(super) grant: StandingOutboundGrant,
    pub(super) key_id: EntityId,
    pub(super) key: ConnectorKeyRecord,
    pub(super) schema: Value,
}

/// Where the shared resolution stopped: the hold or refusal, and the grant
/// the lookup had found when a later check stopped it.
pub(super) struct GovernanceStop {
    pub(super) grant_id: Option<EntityId>,
    pub(super) step: Step,
}

impl GovernanceStop {
    fn before_grant(step: Step) -> Self {
        Self {
            grant_id: None,
            step,
        }
    }
}

impl Vault {
    /// The principal's grant for `server` and `tool`, the governing key it
    /// mints and the tool's approved schema there: the grant lookup,
    /// capability, governing key, status and manifest checks a call and a
    /// schema read both make. `preferred` is the grant a call last ran
    /// under; a schema read passes `None`. A stop is the hold or refusal
    /// either meets there; a call's own issuer, confirmation and protocol
    /// checks follow it in the call. Each grant and key it reads is listed
    /// in `read` (FIX 5816).
    pub(super) fn governing_tool(
        &self,
        principal_ref: &str,
        server: &str,
        tool: &str,
        preferred: Option<EntityId>,
        read: &mut Vec<EntityId>,
    ) -> Result<std::result::Result<GoverningTool, GovernanceStop>, IntentLedgerError> {
        let Some((grant_id, grant)) =
            self.connector_call_grant(principal_ref, server, tool, preferred, read)?
        else {
            return Ok(Err(GovernanceStop::before_grant(held(
                "standing_grant_required",
            ))));
        };
        let stop = |step: Step| {
            Ok(Err(GovernanceStop {
                grant_id: Some(grant_id),
                step,
            }))
        };
        // The gate binds the same actor from the same principal reference.
        let actor = EntityId::from_hex(principal_ref).unwrap_or(grant_id);
        let Some(capability) = ScopedCapabilityProvenance::mint(server, &grant_id) else {
            return stop(refused("connector_name_not_scoped"));
        };
        let Some((key_id, key)) = self.connector_key_for(capability.connector(), Some(&actor))?
        else {
            return stop(held("connector_key_unregistered"));
        };
        read.push(key_id);
        match key.status {
            ConnectorKeyStatus::Active => {}
            ConnectorKeyStatus::Revoked => return stop(refused("connector_key_revoked")),
            ConnectorKeyStatus::Suspended => return stop(held("connector_key_suspended")),
            ConnectorKeyStatus::Pending => return stop(held("connector_key_pending")),
        }
        let Some(manifest) = key.retained_manifest.as_ref() else {
            return stop(held("connector_manifest_unapproved"));
        };
        let Some(schema) = manifest
            .tools()
            .iter()
            .find(|found| found.name == tool)
            .map(|found| found.input_schema.clone())
        else {
            return stop(if key.pending_manifest.is_some() {
                held("connector_manifest_drift")
            } else {
                refused("connector_tool_unknown")
            });
        };
        Ok(Ok(GoverningTool {
            grant_id,
            grant,
            key_id,
            key,
            schema,
        }))
    }

    /// The principal's live scoped grant for exactly this server and tool:
    /// the one the call last ran under when it still matches, else the first
    /// in id order. Each grant it reads is listed in `read`.
    fn connector_call_grant(
        &self,
        principal_ref: &str,
        server: &str,
        tool: &str,
        preferred: Option<EntityId>,
        read: &mut Vec<EntityId>,
    ) -> crate::Result<Option<(EntityId, StandingOutboundGrant)>> {
        let (grants, floor) = {
            let txn = self.store.env.read_txn()?;
            let floor =
                crate::gate::resolve_policy_manifest(&self.store, &txn)?.read_frontier_hash()?;
            let grants = crate::outbound_grant::standing_outbound_grants_for_principal_in_txn(
                &self.store,
                &txn,
                principal_ref,
            )?;
            (grants, floor)
        };
        let mut first = None;
        for grant in grants {
            let id = grant.id;
            read.push(id);
            if !grant.is_active_under_policy(&floor) {
                continue;
            }
            let Some(scope) = grant.scope.scoped_mcp_grant() else {
                continue;
            };
            if scope.server != server || scope.tool != tool {
                continue;
            }
            if preferred == Some(id) {
                return Ok(Some((id, grant)));
            }
            if first.is_none() {
                first = Some((id, grant));
            }
        }
        Ok(first)
    }
}
