use super::*;
use rmpv::Value;

use crate::channel_identity::CHANNEL_IDENTITY_MIN_QUARANTINE_SECS;
use crate::receipt::{ReceiptKind, ReceiptQuery};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::store::Store;
use crate::types::{ENTITY_ID_LEN, VaultConfig};

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

fn entity(seed: u8) -> EntityId {
    let mut bytes = [seed; ENTITY_ID_LEN];
    bytes[0] = seed.max(1);
    EntityId::from_bytes(bytes).expect("test entity id")
}

fn policy_manifest(actor_ref: &str, channel: &str, verbs: &[&str]) -> Vec<u8> {
    let scoped_grants = verbs
        .iter()
        .map(|verb| {
            Value::Map(vec![
                (Value::from("actor_ref"), Value::from(actor_ref)),
                (
                    Value::from("effector"),
                    Value::from(format!("external:{verb}")),
                ),
                (
                    Value::from("scope"),
                    Value::Map(vec![(Value::from("channel"), Value::from(channel))]),
                ),
            ])
        })
        .collect::<Vec<_>>();
    let entries = vec![
        (Value::from("schema_version"), Value::from("1.1")),
        (Value::from("pack_id"), Value::from("cid-2-test")),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            Value::from("defaults"),
            Value::Map(vec![
                (Value::from("criticality"), Value::from("normal")),
                (Value::from("sensitivity"), Value::from("normal")),
            ]),
        ),
        (Value::from("rules"), Value::Array(Vec::new())),
        (
            Value::from("actor_ceilings"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("actor_class"), Value::from("agent")),
                (Value::from("actor_ref"), Value::from(actor_ref)),
                (Value::from("ceiling"), Value::from("auto")),
            ])]),
        ),
        (Value::from("scoped_grants"), Value::Array(scoped_grants)),
    ];
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("manifest encode");
    out
}

fn put_policy_manifest(vault: &Vault, seed: u8, data: &[u8]) -> Result<()> {
    let id = entity(seed);
    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
    payload.push(ENTITY_TYPE_POLICY_MANIFEST);
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(data);

    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
        let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
        vault.store.type_index.put(wtxn, &type_key, &[])?;
        Ok(())
    })
}

fn requested_identity(agent: EntityId, at: u64) -> ChannelIdentity {
    ChannelIdentity::requested(
        "email",
        format!("agent-{}@example.test", agent.to_hex()),
        crate::channel_identity::ChannelIdentityShape::DedicatedAddress,
        crate::channel_identity::ChannelIdentityBinding::agent(agent),
        at,
    )
}

fn request(
    actor: ChannelIdentityLifecycleActor,
    at: u64,
    intent: ChannelIdentityLifecycleIntent,
) -> ChannelIdentityLifecycleRequest {
    ChannelIdentityLifecycleRequest {
        actor,
        gate: ChannelIdentityLifecycleGate::allow_when_policy_grants(),
        requested_at: at,
        intent,
    }
}

#[test]
fn lifecycle_verbs_gate_receipt_and_manual_fulfillment() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xA1);
    let actor = ChannelIdentityLifecycleActor::agent(agent);
    put_policy_manifest(
        &vault,
        0xD0,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["provision", "bind", "rotate", "release", "route_inbound"],
        ),
    )?;

    let provision_id = entity(0xB1);
    let provision = vault.apply_channel_identity_lifecycle_intent(request(
        actor.clone(),
        1_000,
        ChannelIdentityLifecycleIntent::Provision(ProvisionIntent {
            identity_id: provision_id,
            identity: requested_identity(agent, 1_000),
            fulfillment_mode: ChannelIdentityFulfillment::Manual,
        }),
    ))?;
    assert_eq!(provision.outcome, "pending_fulfillment");
    assert!(provision.gate_receipt_id.is_some());
    assert_eq!(
        provision.identity.as_ref().expect("identity").state,
        ChannelIdentityState::PendingFulfillment
    );

    let fulfilled = vault.fulfill_channel_identity(ChannelIdentityFulfillmentInput {
        actor: actor.clone(),
        identity_id: provision_id,
        fulfilled_at: 1_010,
    })?;
    assert_eq!(fulfilled.outcome, "active");
    assert_eq!(
        fulfilled.identity.as_ref().expect("identity").state,
        ChannelIdentityState::Active
    );

    let bind_id = entity(0xB2);
    vault.create_channel_identity(&bind_id, &requested_identity(entity(0xA2), 1_020))?;
    let bound = vault.apply_channel_identity_lifecycle_intent(request(
        actor.clone(),
        1_030,
        ChannelIdentityLifecycleIntent::Bind(BindIntent {
            identity_id: bind_id,
            fulfillment_mode: ChannelIdentityFulfillment::Manual,
        }),
    ))?;
    assert_eq!(bound.outcome, "pending_fulfillment");
    vault.fulfill_channel_identity(ChannelIdentityFulfillmentInput {
        actor: actor.clone(),
        identity_id: bind_id,
        fulfilled_at: 1_040,
    })?;

    let rotated = vault.apply_channel_identity_lifecycle_intent(request(
        actor.clone(),
        1_050,
        ChannelIdentityLifecycleIntent::Rotate(RotateIntent {
            identity_id: provision_id,
        }),
    ))?;
    assert_eq!(rotated.outcome, "rotating");
    vault.fulfill_channel_identity(ChannelIdentityFulfillmentInput {
        actor: actor.clone(),
        identity_id: provision_id,
        fulfilled_at: 1_060,
    })?;

    let quarantine_until = 1_070 + CHANNEL_IDENTITY_MIN_QUARANTINE_SECS;
    let released = vault.apply_channel_identity_lifecycle_intent(request(
        actor.clone(),
        1_070,
        ChannelIdentityLifecycleIntent::Release(ReleaseIntent {
            identity_id: provision_id,
            quarantine_until,
        }),
    ))?;
    assert_eq!(released.outcome, "quarantine");
    assert!(released.outbound_closed);
    assert!(released.identity_retiring);
    assert_eq!(
        released.identity.as_ref().expect("identity").state,
        ChannelIdentityState::Quarantine
    );

    let inbound = vault.apply_channel_identity_lifecycle_intent(request(
        actor,
        1_080,
        ChannelIdentityLifecycleIntent::RouteInbound(RouteInboundIntent {
            identity_id: provision_id,
        }),
    ))?;
    assert_eq!(inbound.outcome, "routable");
    assert_eq!(inbound.owner_visible_state, "identity_retiring");
    assert!(inbound.outbound_closed);
    assert!(inbound.identity_retiring);

    let identity_receipts = vault.receipts(
        ReceiptQuery::new(20)
            .with_kind(ReceiptKind::IdentityLifecycle)
            .with_actor(agent.to_hex()),
    )?;
    for verb in ["provision", "bind", "rotate", "release", "route_inbound"] {
        assert!(
            identity_receipts.iter().any(|receipt| receipt
                .fields
                .get("verb")
                .is_some_and(|value| value == verb)),
            "missing lifecycle receipt for {verb}"
        );
    }
    assert!(identity_receipts.iter().any(|receipt| {
        receipt.fields.get("fulfillment_mode").map(String::as_str) == Some("manual")
            && receipt.outcome == "pending_fulfillment"
    }));
    assert!(identity_receipts.iter().any(|receipt| {
        receipt
            .fields
            .get("owner_visible_state")
            .map(String::as_str)
            == Some("identity_retiring")
            && receipt.fields.get("outbound_closed").map(String::as_str) == Some("true")
    }));

    let gate_receipts = vault.receipts(
        ReceiptQuery::new(20)
            .with_kind(ReceiptKind::Gate)
            .with_actor(agent.to_hex()),
    )?;
    assert_eq!(
        gate_receipts
            .iter()
            .filter(|receipt| {
                receipt.fields.get("content_kind").map(String::as_str) == Some("external_effect")
            })
            .count(),
        5
    );
    Ok(())
}

#[test]
fn pending_external_effect_holds_without_mutating_identity() {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xC1);
    let actor = ChannelIdentityLifecycleActor::agent(agent);
    let identity_id = entity(0xC2);
    let requested = requested_identity(agent, 2_000);

    let held = vault
        .apply_channel_identity_lifecycle_intent(request(
            actor,
            2_000,
            ChannelIdentityLifecycleIntent::Provision(ProvisionIntent {
                identity_id,
                identity: requested,
                fulfillment_mode: ChannelIdentityFulfillment::Manual,
            }),
        ))
        .expect("pending provision should hold and receipt");

    assert_eq!(held.outcome, "held");
    assert_eq!(held.owner_visible_state, "held");
    assert!(
        vault
            .get_channel_identity(&identity_id)
            .expect("read held identity")
            .is_none()
    );
    let receipts = vault
        .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::IdentityLifecycle))
        .expect("query held lifecycle receipts");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, "held");
    assert_eq!(
        receipts[0].fields.get("verb").map(String::as_str),
        Some("provision")
    );
}

#[test]
fn denied_external_effect_receipts_denied_without_mutating_identity() {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xD1);
    // Missing actor provenance forces the ExternalEffect gate to Deny.
    let denied_actor = ChannelIdentityLifecycleActor {
        actor_class: "agent".to_owned(),
        actor_ref: Some(agent.to_hex()),
        actor_entity_ref: None,
    };
    let identity_id = entity(0xD2);
    let requested = requested_identity(agent, 3_000);

    let denied = vault
        .apply_channel_identity_lifecycle_intent(request(
            denied_actor,
            3_000,
            ChannelIdentityLifecycleIntent::Provision(ProvisionIntent {
                identity_id,
                identity: requested,
                fulfillment_mode: ChannelIdentityFulfillment::Manual,
            }),
        ))
        .expect("denied provision should receipt without erroring");

    assert_eq!(denied.outcome, "denied");
    assert_eq!(denied.owner_visible_state, "denied");
    assert!(!denied.outbound_closed);
    assert!(!denied.identity_retiring);
    assert!(
        vault
            .get_channel_identity(&identity_id)
            .expect("read denied identity")
            .is_none(),
        "denied provision must not create the identity"
    );
    let receipts = vault
        .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::IdentityLifecycle))
        .expect("query denied lifecycle receipts");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, "denied");
}

#[test]
fn route_inbound_against_tombstone_reports_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xE1);
    let actor = ChannelIdentityLifecycleActor::agent(agent);
    put_policy_manifest(
        &vault,
        0xE0,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["route_inbound"],
        ),
    )?;

    let identity_id = entity(0xE2);
    let mut tombstoned = requested_identity(agent, 4_000);
    tombstoned.state = ChannelIdentityState::Tombstone;
    vault.create_channel_identity(&identity_id, &tombstoned)?;

    let routed = vault.apply_channel_identity_lifecycle_intent(request(
        actor,
        4_000,
        ChannelIdentityLifecycleIntent::RouteInbound(RouteInboundIntent { identity_id }),
    ))?;

    assert_eq!(routed.outcome, "closed");
    assert_eq!(routed.owner_visible_state, "tombstone");
    assert!(routed.outbound_closed);
    assert!(!routed.identity_retiring);
    assert_eq!(
        routed.identity.as_ref().expect("identity").state,
        ChannelIdentityState::Tombstone
    );
    Ok(())
}
