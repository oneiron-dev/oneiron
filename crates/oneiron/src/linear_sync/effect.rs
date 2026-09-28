//! External-effect admission for Linear mirror mutations. A TASK write is
//! data, never by itself permission to publish to an external tracker.

use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Error;
use crate::gate::{
    self, ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateProvenanceHandles,
};
use crate::linear_sync::{
    LinearIssueRef, LinearSyncDirection, LinearSyncError, LinearSyncResult, MirroredTaskFields,
    linear_operation_id,
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
    /// `None` for a create (the bridge picks the team); the linked issue for
    /// an update.
    pub issue: Option<LinearIssueRef>,
    pub kind: LinearEffectKind,
    pub fields: MirroredTaskFields,
}

fn binding(request: &LinearEffectRequest, writer: EntityId) -> LinearSyncResult<[u8; 32]> {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "operation_id": bytes_to_hex_lower(&request.operation_id),
        "task": request.task_ref.to_hex(), "scheduler": request.scheduler_actor.to_hex(),
        "writer": writer.to_hex(), "issue": request.issue,
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
        counterparty: request.issue.as_ref().map(|issue| issue.issue_id.clone()),
        brief_ref: None,
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
    /// Authorizes a Linear mutation against BOTH the current TASK writer and
    /// the configured host scheduler, through the existing ExternalEffect
    /// Gate. The two decisions are durable before HTTP starts. A replay
    /// rechecks live grants but does not charge the same operation's effector
    /// budget twice. Raw/replayed TASK writes have no writer stamp.
    ///
    /// # Errors
    /// [`LinearSyncError::AuthorizationDenied`] when the request is not the
    /// exact current mirror operation, the TASK revision has no verified
    /// writer, or either actor's grant or connector budget refuses it.
    pub fn authorize_linear_effect(
        &self,
        request: &LinearEffectRequest,
    ) -> LinearSyncResult<String> {
        let issue_id = request.issue.as_ref().map(|issue| issue.issue_id.as_str());
        if request.operation_id == [0; 32]
            || (request.kind == LinearEffectKind::Create) != request.issue.is_none()
            || issue_id.is_some_and(|id| id.trim().is_empty())
        {
            return Err(LinearSyncError::AuthorizationDenied);
        }
        let admitted = self.try_with_write_txn::<_, _, LinearSyncError>(|txn| {
            let state = linear_effect_state_in_txn(self, txn, request.task_ref)?;
            // Only the operation the mirror would send for the current dirty
            // revision: same TASK, same link state, same fields.
            let expected = linear_operation_id(
                LinearSyncDirection::TaskToIssue,
                request.task_ref,
                state.revision,
                issue_id,
                None,
                None,
            );
            let link_matches = match (&state.link, &request.issue) {
                (None, None) => true,
                (Some(link), Some(issue)) => {
                    link.issue.issue_id == issue.issue_id && link.issue.team_id == issue.team_id
                }
                _ => false,
            };
            if !link_matches
                || state.dirty_revision != Some(state.revision)
                || state.snapshot.revision != state.revision
                || state.snapshot.fields != request.fields
                || expected != request.operation_id
            {
                return Err(LinearSyncError::AuthorizationDenied);
            }
            let writer = state.writer.ok_or(LinearSyncError::AuthorizationDenied)?;
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
            if policy.diagnostics.is_fail_closed() {
                return Err(LinearSyncError::AuthorizationDenied);
            }
            let host_effect = effect(request.scheduler_actor, EdgeActorClass::System, request);
            let writer_effect = effect(writer.actor_ref, class, request);
            let admitted = gate::check_external_effect_policy_pair(
                &self.store,
                txn,
                &host_effect,
                &writer_effect,
                &policy,
                !previously_authorized,
            )?;
            let Some(id) = admitted else { return Ok(None) };
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
    use crate::genui::{GrantMintIntent, GrantMintIntentScope};
    use crate::linear_sync::{LinearTaskStore, VaultLinearTaskStore};
    use crate::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
    use crate::task_verb::TaskCreateSpec;
    use crate::{TimeRange, VaultConfig};
    use rmpv::Value;

    struct Fixture {
        _dir: tempfile::TempDir,
        vault: Vault,
        writer: EntityId,
        scheduler: EntityId,
    }

    fn fixture() -> Fixture {
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
        Fixture {
            _dir: dir,
            vault,
            writer,
            scheduler,
        }
    }

    impl Fixture {
        /// A verified TASK write and the exact create the mirror would send.
        fn create_request(&self, label: &str) -> LinearEffectRequest {
            let task = self
                .vault
                .memory(self.writer, EdgeActorClass::Human)
                .tasks_create(&TaskCreateSpec::new(
                    Value::from(label),
                    Some(label.into()),
                    None,
                    Some(100),
                ))
                .unwrap()
                .task_ref
                .unwrap();
            let store = VaultLinearTaskStore::new(&self.vault);
            assert_eq!(
                store.dirty_writer(task).unwrap().map(|w| w.actor_ref),
                Some(self.writer)
            );
            let snapshot = store.task_snapshot(task).unwrap();
            LinearEffectRequest {
                operation_id: linear_operation_id(
                    LinearSyncDirection::TaskToIssue,
                    task,
                    snapshot.revision,
                    None,
                    None,
                    None,
                ),
                task_ref: task,
                scheduler_actor: self.scheduler,
                issue: None,
                kind: LinearEffectKind::Create,
                fields: snapshot.fields,
            }
        }

        fn grant(&self, actor: EntityId) -> EntityId {
            let id = EntityId::now();
            self.vault
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
            id
        }

        /// One-send `linear` connector key, bound to `actor` or shared.
        fn cap_one_key(&self, actor: Option<EntityId>) {
            self.vault
                .register_connector_key(
                    &EntityId::now(),
                    crate::connector_key::ConnectorKeyRecord::active(
                        "linear",
                        actor,
                        vec![crate::connector_key::EffectorBudget::rate(1, 3600)],
                        self.vault.now_recorded_at(),
                    ),
                )
                .unwrap();
        }

        fn used(&self, actor: EntityId) -> u64 {
            self.vault
                .effector_budget_read("linear", Some(&actor))
                .unwrap()
                .unwrap()
                .rows[0]
                .used
        }

        fn denied(&self, request: &LinearEffectRequest) -> bool {
            matches!(
                self.vault.authorize_linear_effect(request),
                Err(LinearSyncError::AuthorizationDenied)
            )
        }
    }

    #[test]
    fn writer_and_scheduler_grants_are_both_required_and_rechecked_after_revocation() {
        let fx = fixture();
        let request = fx.create_request("work");
        assert!(fx.denied(&request));
        fx.grant(fx.scheduler);
        assert!(fx.denied(&request), "scheduler grant alone is not enough");
        let writer_grant = fx.grant(fx.writer);
        // Only the exact current mirror payload is admissible.
        let mut forged = request.clone();
        forged.fields.title = "not the TASK".into();
        assert!(fx.denied(&forged));
        // Two different actor-bound connector keys each have one send. A
        // writer with no key must not bypass the scheduler's key, and no
        // logical replay may debit either key twice.
        fx.cap_one_key(Some(fx.scheduler));
        fx.cap_one_key(Some(fx.writer));
        let admitted = fx.vault.authorize_linear_effect(&request);
        assert!(
            admitted.as_ref().is_ok_and(|id| id.starts_with("gate:")),
            "admission {admitted:?}; decisions {:?}",
            fx.vault.store.gate_decisions(20).unwrap()
        );
        assert!(fx.vault.authorize_linear_effect(&request).is_ok());
        for actor in [fx.scheduler, fx.writer] {
            assert_eq!(fx.used(actor), 1, "replay charges no budget");
        }
        let second = fx.create_request("other");
        assert!(fx.denied(&second));
        for actor in [fx.scheduler, fx.writer] {
            assert_eq!(
                fx.used(actor),
                1,
                "exhausted second operation must not debit the other key"
            );
        }
        // An already-admitted operation cannot use yesterday's grant after
        // the owner revokes it, even though its operation key was persisted.
        fx.vault
            .revoke_standing_outbound_grant(&writer_grant, 20)
            .unwrap();
        assert!(fx.denied(&request));
    }

    #[test]
    fn scheduler_bound_cap_of_one_refuses_second_task_from_unkeyed_writer() {
        let fx = fixture();
        fx.grant(fx.scheduler);
        fx.grant(fx.writer);
        // Only the scheduler holds a key. Actor-bound keys never match the
        // writer, so the scheduler's budget alone must bound the mirror.
        fx.cap_one_key(Some(fx.scheduler));
        let first = fx.create_request("first");
        assert!(fx.vault.authorize_linear_effect(&first).is_ok());
        assert_eq!(fx.used(fx.scheduler), 1);
        assert!(
            fx.vault.authorize_linear_effect(&first).is_ok(),
            "one logical effect pays once"
        );
        assert_eq!(fx.used(fx.scheduler), 1);
        let second = fx.create_request("second");
        assert!(fx.denied(&second), "scheduler cap of one refuses task two");
        assert_eq!(fx.used(fx.scheduler), 1);
    }

    #[test]
    fn shared_connector_key_charges_once_and_refuses_second_task() {
        let fx = fixture();
        fx.grant(fx.writer);
        fx.grant(fx.scheduler);
        fx.cap_one_key(None);
        let request = fx.create_request("work");
        assert!(
            fx.vault.authorize_linear_effect(&request).is_ok(),
            "a shared cap-one key must be charged only once for two authorities"
        );
        assert_eq!(fx.used(fx.scheduler), 1);
        assert!(
            fx.vault.authorize_linear_effect(&request).is_ok(),
            "replay costs zero"
        );
        assert_eq!(fx.used(fx.writer), 1);
        let other = fx.create_request("other");
        assert!(fx.denied(&other));
        assert_eq!(fx.used(fx.scheduler), 1);
    }
}
