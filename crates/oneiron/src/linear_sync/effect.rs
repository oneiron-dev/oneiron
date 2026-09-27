//! External-effect admission for Linear mirror mutations. A TASK write is
//! data, never by itself permission to publish to an external tracker.

use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Error;
use crate::gate::{
    self, ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateOutcome,
    GateProvenanceHandles,
};
use crate::linear_sync::{
    LinearSyncDirection, LinearSyncError, LinearSyncResult, LinearTaskStore, MirroredTaskFields,
    VaultLinearTaskStore, linear_operation_id,
};
use crate::task_verb::linear_effect_state_in_txn;

const EFFECT_AUTH_KEY: &[u8] = b"linear:effect_authorized:v1/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinearEffectKind {
    Create,
    Update,
}
impl LinearEffectKind {
    const fn verb(self) -> &'static str {
        match self {
            Self::Create => "linear_issue_create",
            Self::Update => "linear_issue_update",
        }
    }
}

/// Exactly the mutation the host will send. Every field participates in the
/// frozen operation binding; an authorized TASK row is not a generic key.
#[derive(Debug, Clone)]
pub struct LinearEffectRequest {
    pub operation_id: [u8; 32],
    pub task_ref: EntityId,
    pub scheduler_actor: EntityId,
    pub team_id: String,
    pub issue_id: Option<String>,
    pub kind: LinearEffectKind,
    pub fields: MirroredTaskFields,
}

fn binding(request: &LinearEffectRequest, writer: EntityId) -> LinearSyncResult<[u8; 32]> {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "operation_id": bytes_to_hex_lower(&request.operation_id),
        "task": request.task_ref.to_hex(), "scheduler": request.scheduler_actor.to_hex(),
        "writer": writer.to_hex(), "team": request.team_id, "issue": request.issue_id,
        "verb": request.kind.verb(), "fields": request.fields,
    }))
    .map_err(|_| Error::InvariantViolation("linear effect binding encoding"))?;
    Ok(*blake3::hash(&[b"oneiron:linear-effect:v1".as_slice(), &bytes].concat()).as_bytes())
}

fn effect(
    actor: EntityId,
    class: EdgeActorClass,
    request: &LinearEffectRequest,
) -> ExternalEffectGateInput {
    ExternalEffectGateInput {
        actor: GateActor {
            actor_class: class.gate_actor_class().to_owned(),
            actor_ref: Some(actor.to_hex()),
            delegation_grant_ref: None,
        },
        provenance: GateProvenanceHandles {
            actor_entity_ref: Some(actor),
            ..Default::default()
        },
        verb: request.kind.verb().to_owned(),
        channel: "linear".to_owned(),
        channel_identity_ref: None,
        counterparty: Some(
            request
                .issue_id
                .as_deref()
                .unwrap_or(&request.team_id)
                .to_owned(),
        ),
        brief_ref: Some(request.team_id.clone()),
        send_ref: Some(bytes_to_hex_lower(&request.operation_id)),
        standing_grant_ref: None,
        scoped_mcp_call: None,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        // Only a live, actor-bound standing grant may make this Auto. A host
        // environment variable is not an owner consent grant.
        has_opted_in: false,
        has_permission: true,
        policy_risk: ExternalEffectPolicyRisk::Normal,
    }
}

impl Vault {
    /// Authorizes a frozen Linear mutation against BOTH the current TASK
    /// writer and the configured host scheduler, through the existing
    /// ExternalEffect Gate. The two decisions are durable before HTTP starts.
    /// A replay rechecks live grants but does not charge the same operation's
    /// effector budget twice. Raw/replayed TASK writes have no writer stamp.
    pub fn authorize_linear_effect(
        &self,
        request: &LinearEffectRequest,
    ) -> LinearSyncResult<String> {
        if request.operation_id == [0; 32]
            || request.team_id.trim().is_empty()
            || request.kind == LinearEffectKind::Create && request.issue_id.is_some()
            || request.kind == LinearEffectKind::Update
                && request.issue_id.as_deref().is_none_or(str::is_empty)
        {
            return Err(LinearSyncError::AuthorizationDenied);
        }
        let snapshot = if request.kind == LinearEffectKind::Update {
            Some(VaultLinearTaskStore::new(self).task_snapshot(request.task_ref)?)
        } else {
            None
        };
        let admitted = self.try_with_write_txn::<_, _, LinearSyncError>(|txn| {
            let state = linear_effect_state_in_txn(self, txn, request.task_ref)?;
            let writer = match request.kind {
                LinearEffectKind::Create => {
                    let intent = state
                        .create_intent
                        .as_ref()
                        .ok_or(LinearSyncError::AuthorizationDenied)?;
                    if state.link.is_some()
                        || intent.operation_id != request.operation_id
                        || intent.fields != request.fields
                        || intent.task_ref != request.task_ref
                    {
                        return Err(LinearSyncError::AuthorizationDenied);
                    }
                    intent.writer.ok_or(LinearSyncError::AuthorizationDenied)?
                }
                LinearEffectKind::Update => {
                    let issue = request
                        .issue_id
                        .as_deref()
                        .ok_or(LinearSyncError::AuthorizationDenied)?;
                    let link = state
                        .link
                        .as_ref()
                        .ok_or(LinearSyncError::AuthorizationDenied)?;
                    let snapshot = snapshot
                        .as_ref()
                        .ok_or(LinearSyncError::AuthorizationDenied)?;
                    let expected = linear_operation_id(
                        LinearSyncDirection::TaskToIssue,
                        request.task_ref,
                        state.revision,
                        Some(issue),
                        None,
                        None,
                    );
                    if link.issue.issue_id != issue
                        || link.issue.team_id != request.team_id
                        || state.dirty_revision != Some(state.revision)
                        || snapshot.revision != state.revision
                        || snapshot.fields != request.fields
                        || expected != request.operation_id
                    {
                        return Err(LinearSyncError::AuthorizationDenied);
                    }
                    state.writer.ok_or(LinearSyncError::AuthorizationDenied)?
                }
            };
            let class = EdgeActorClass::try_from_u8(writer.actor_class)
                .ok_or(LinearSyncError::AuthorizationDenied)?;
            for (id, actor_class) in [
                (request.scheduler_actor, EdgeActorClass::System),
                (writer.actor_ref, class),
            ] {
                let entity_type = self
                    .get_entity_type_in_txn(txn, &id)?
                    .ok_or(LinearSyncError::AuthorizationDenied)?;
                crate::provenance::validate_actor_class(entity_type, actor_class)?;
            }
            let digest = binding(request, writer.actor_ref)?;
            let mut key = EFFECT_AUTH_KEY.to_vec();
            key.extend_from_slice(&request.operation_id);
            let previously_authorized = if let Some(raw) = self.store.vault_meta.get(txn, &key)? {
                if raw.as_ref() != digest.as_slice() {
                    return Err(LinearSyncError::AuthorizationDenied);
                }
                true
            } else {
                false
            };
            let policy = gate::resolve_policy_manifest(&self.store, txn)?;
            let host_effect = effect(request.scheduler_actor, EdgeActorClass::System, request);
            let writer_effect = effect(writer.actor_ref, class, request);
            let host_governance = gate::evaluate_external_effect_policy(
                &self.store,
                txn,
                &host_effect,
                &policy,
                None,
                None,
            )?;
            let writer_governance = gate::evaluate_external_effect_policy(
                &self.store,
                txn,
                &writer_effect,
                &policy,
                None,
                None,
            )?;
            if host_governance.outcome() != GateOutcome::Allow
                || writer_governance.outcome() != GateOutcome::Allow
            {
                gate::record_external_effect_policy(&self.store, txn, host_governance)?;
                gate::record_external_effect_policy(&self.store, txn, writer_governance)?;
                return Ok(None);
            }
            // Host authority is governed and recorded; the original writer's
            // effect pays the once-per-operation budget charge.
            gate::record_external_effect_policy(&self.store, txn, host_governance)?;
            let (id, decision, _) = gate::check_external_effect_policy(
                &self.store,
                txn,
                &writer_effect,
                &policy,
                !previously_authorized,
            )?;
            if decision.outcome() != GateOutcome::Allow {
                return Ok(None);
            }
            if !previously_authorized {
                self.store.vault_meta.put(txn, &key, &digest)?;
            }
            Ok(Some(format!("gate:{}", id.to_hex())))
        })?;
        admitted.ok_or(LinearSyncError::AuthorizationDenied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::EdgeActorClass;
    use crate::genui::{GrantMintIntent, GrantMintIntentScope};
    use crate::linear_sync::{LinearCreateIntent, LinearTaskStore};
    use crate::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
    use crate::task_verb::TaskCreateSpec;
    use crate::{TimeRange, VaultConfig};
    use rmpv::Value;

    #[test]
    fn writer_and_scheduler_grants_are_both_required_and_rechecked_after_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
        let writer = EntityId::now();
        let scheduler = EntityId::now();
        for (id, kind) in [
            (writer, ENTITY_TYPE_PERSON),
            (scheduler, ENTITY_TYPE_MACHINE),
        ] {
            vault
                .put_entity(&id, kind, TimeRange { start: 1, end: 1 }, 1, b"actor")
                .unwrap();
        }
        // The host scheduler is a stored Machine, but its Auto ceiling is a
        // separate owner policy choice. A grant alone cannot lift a Proposed
        // actor ceiling. Seed that exact policy row before minting grants.
        let default = crate::gate::default_policy_manifest();
        let mut cursor = std::io::Cursor::new(default);
        let mut value = rmpv::decode::read_value(&mut cursor).unwrap();
        let rmpv::Value::Map(entries) = &mut value else {
            panic!("policy map")
        };
        let (_, rmpv::Value::Array(rows)) = entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("actor_ceilings"))
            .expect("actor ceilings")
        else {
            panic!("ceiling rows")
        };
        rows.push(Value::Map(vec![
            (Value::from("actor_class"), Value::from("system")),
            (Value::from("actor_ref"), Value::from(scheduler.to_hex())),
            (Value::from("ceiling"), Value::from("auto")),
        ]));
        let mut policy = Vec::new();
        rmpv::encode::write_value(&mut policy, &value).unwrap();
        crate::test_util::put_policy_manifest_bytes(
            &vault,
            crate::gate::default_policy_manifest_id().unwrap(),
            &policy,
        )
        .unwrap();
        let task = vault
            .memory(writer, EdgeActorClass::Human)
            .tasks_create(&TaskCreateSpec::new(
                Value::from("work"),
                Some("write".into()),
                None,
                Some(100),
            ))
            .unwrap()
            .task_ref
            .unwrap();
        let mut store = VaultLinearTaskStore::new(&vault);
        let snapshot = store.task_snapshot(task).unwrap();
        let operation_id = linear_operation_id(
            LinearSyncDirection::TaskToIssue,
            task,
            snapshot.revision,
            None,
            None,
            None,
        );
        let intent = store
            .create_intent(&LinearCreateIntent {
                task_ref: task,
                task_revision: snapshot.revision,
                operation_id,
                fields: snapshot.fields,
                writer: None,
            })
            .unwrap();
        assert_eq!(intent.writer.unwrap().actor_ref, writer);
        let request = LinearEffectRequest {
            operation_id,
            task_ref: task,
            scheduler_actor: scheduler,
            team_id: "team-1".into(),
            issue_id: None,
            kind: LinearEffectKind::Create,
            fields: intent.fields,
        };
        assert!(matches!(
            vault.authorize_linear_effect(&request),
            Err(LinearSyncError::AuthorizationDenied)
        ));
        let mint = |actor: EntityId, id: EntityId| {
            vault
                .mint_standing_outbound_grant(
                    &id,
                    &GrantMintIntent {
                        principal_ref: actor.to_hex(),
                        origin_component_id: "linear-test".into(),
                        origin_action_id: "escalate_always_this_verb_class".into(),
                        origin_receipt_ref: Some("gate:linear-test".into()),
                        scope: GrantMintIntentScope::VerbClass {
                            verb_class: "linear_issue_create".into(),
                        },
                    },
                    10,
                )
                .unwrap();
        };
        let scheduler_grant = EntityId::now();
        let writer_grant = EntityId::now();
        mint(scheduler, scheduler_grant);
        assert!(matches!(
            vault.authorize_linear_effect(&request),
            Err(LinearSyncError::AuthorizationDenied)
        ));
        mint(writer, writer_grant);
        let admitted = vault.authorize_linear_effect(&request);
        assert!(
            admitted.is_ok(),
            "admission {admitted:?}; decisions {:?}",
            vault.store.gate_decisions(20).unwrap()
        );
        let receipt = admitted.unwrap();
        assert!(receipt.starts_with("gate:"));
        // An already-admitted operation cannot use yesterday's grant after
        // the owner revokes it, even though its operation key was persisted.
        vault
            .revoke_standing_outbound_grant(&writer_grant, 20)
            .unwrap();
        assert!(matches!(
            vault.authorize_linear_effect(&request),
            Err(LinearSyncError::AuthorizationDenied)
        ));
    }
}
