use super::*;
use rmpv::Value;

use crate::channel_identity::CHANNEL_IDENTITY_MIN_QUARANTINE_SECS;
use crate::config::VaultConfig;
use crate::receipt::{ReceiptKind, ReceiptQuery};

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

use crate::test_util::{entity, put_policy_manifest_bytes};

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
    // 0x91: [0xA1; 16] is a write-door-reserved system-agent actor id
    // (ONE-1444). The actor entity is stored because the live ceiling
    // resolver fails absent agent-class actors closed to Proposed — an
    // Auto-granted effect actor must be entity-backed.
    let agent = entity(0x91);
    vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"lifecycle actor",
    )?;
    let actor = ChannelIdentityLifecycleActor::agent(agent);
    put_policy_manifest_bytes(
        &vault,
        entity(0xD0),
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
    vault.create_channel_identity(&bind_id, &requested_identity(entity(0x92), 1_020))?;
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

fn delegated_identity(agent: EntityId, at: u64) -> ChannelIdentity {
    crate::channel_identity::ChannelIdentity::requested_delegated(
        "email",
        format!("member-{}@member-owned.test", agent.to_hex()),
        crate::channel_identity::ChannelIdentityBinding::agent(agent),
        crate::channel_identity::DelegatedGrant::new(
            format!("gmail-delegated:{}", agent.to_hex()),
            vec![crate::channel_identity::DelegatedGrantScope::MailRead],
        ),
        at,
    )
}

#[test]
fn verb_shape_truth_table_denies_rotate_on_delegated_rows_only() {
    use crate::channel_identity::ChannelIdentityShape;

    let all_verbs = [
        ChannelIdentityLifecycleVerb::Provision,
        ChannelIdentityLifecycleVerb::Bind,
        ChannelIdentityLifecycleVerb::Rotate,
        ChannelIdentityLifecycleVerb::Release,
        ChannelIdentityLifecycleVerb::RouteInbound,
    ];
    let all_shapes = [
        ChannelIdentityShape::DedicatedAddress,
        ChannelIdentityShape::DedicatedHandle,
        ChannelIdentityShape::SharedPresence,
        ChannelIdentityShape::DelegatedGrant,
    ];

    for shape in all_shapes {
        for verb in all_verbs {
            let expected = !(shape == ChannelIdentityShape::DelegatedGrant
                && verb == ChannelIdentityLifecycleVerb::Rotate);
            assert_eq!(
                verb.admitted_by_shape(shape),
                expected,
                "{} x {}",
                shape.as_str(),
                verb.as_str()
            );
        }
    }
}

#[test]
fn delegated_rotate_is_denied_before_the_gate_is_spent() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0x6A);
    vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"delegated actor",
    )?;
    let actor = ChannelIdentityLifecycleActor::agent(agent);
    put_policy_manifest_bytes(
        &vault,
        entity(0xE4),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            // The policy grants rotate outright. The deny below is therefore
            // demonstrably structural: no grant can reach the shape.
            &["provision", "bind", "rotate", "release", "route_inbound"],
        ),
    )?;

    let identity_id = entity(0xE5);
    let mut active = delegated_identity(agent, 5_000);
    active.state = ChannelIdentityState::Active;
    vault.create_channel_identity(&identity_id, &active)?;

    let err = vault
        .apply_channel_identity_lifecycle_intent(request(
            actor.clone(),
            5_010,
            ChannelIdentityLifecycleIntent::Rotate(RotateIntent { identity_id }),
        ))
        .expect_err("rotate on a delegated row must be denied");
    assert!(matches!(
        err,
        Error::ChannelIdentityVerbNotAdmitted {
            shape: "delegated_grant",
            verb: "rotate",
        }
    ));

    // Nothing was written and no gate decision was spent: a verb the shape
    // does not admit is not a denied effect, it is not an effect at all.
    assert_eq!(
        vault
            .get_channel_identity(&identity_id)?
            .expect("identity row")
            .state,
        ChannelIdentityState::Active
    );
    assert!(
        vault
            .receipts(
                ReceiptQuery::new(20)
                    .with_kind(ReceiptKind::IdentityLifecycle)
                    .with_actor(agent.to_hex()),
            )?
            .is_empty()
    );
    assert!(
        vault
            .receipts(
                ReceiptQuery::new(20)
                    .with_kind(ReceiptKind::Gate)
                    .with_actor(agent.to_hex()),
            )?
            .is_empty()
    );

    // The other four verbs are admitted on the very same row.
    let routed = vault.apply_channel_identity_lifecycle_intent(request(
        actor,
        5_020,
        ChannelIdentityLifecycleIntent::RouteInbound(RouteInboundIntent { identity_id }),
    ))?;
    assert_eq!(routed.outcome, "routable");
    Ok(())
}

#[test]
fn delegated_release_stops_short_of_quarantine() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0x6B);
    vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"release actor",
    )?;
    let actor = ChannelIdentityLifecycleActor::agent(agent);
    put_policy_manifest_bytes(
        &vault,
        entity(0xE6),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["release"],
        ),
    )?;

    let delegated_id = entity(0xE7);
    let mut delegated = delegated_identity(agent, 6_000);
    delegated.state = ChannelIdentityState::Active;
    vault.create_channel_identity(&delegated_id, &delegated)?;

    let dedicated_id = entity(0xE8);
    let mut dedicated = requested_identity(entity(0x6C), 6_000);
    dedicated.state = ChannelIdentityState::Active;
    vault.create_channel_identity(&dedicated_id, &dedicated)?;

    let quarantine_until = 6_010 + CHANNEL_IDENTITY_MIN_QUARANTINE_SECS;
    let delegated_release = vault.apply_channel_identity_lifecycle_intent(request(
        actor.clone(),
        6_010,
        ChannelIdentityLifecycleIntent::Release(ReleaseIntent {
            identity_id: delegated_id,
            quarantine_until,
        }),
    ))?;

    // Quarantine is a never-recycle hold on an address we own. The member
    // keeps using this mailbox the moment we let go, so the delegated path
    // ends at RELEASED and sets no self-hold window — even though the caller
    // supplied one.
    assert_eq!(delegated_release.outcome, "released");
    let released = delegated_release.identity.as_ref().expect("identity");
    assert_eq!(released.state, ChannelIdentityState::Released);
    assert_eq!(released.quarantine_until, None);
    assert!(released.is_delegated());

    // Owner-visible framing is unchanged: the row is still retiring and
    // outbound is still closed. Only the custody claim differs.
    assert_eq!(delegated_release.owner_visible_state, "identity_retiring");
    assert!(delegated_release.outbound_closed);
    assert!(delegated_release.identity_retiring);

    let dedicated_release = vault.apply_channel_identity_lifecycle_intent(request(
        actor,
        6_020,
        ChannelIdentityLifecycleIntent::Release(ReleaseIntent {
            identity_id: dedicated_id,
            quarantine_until: 6_020 + CHANNEL_IDENTITY_MIN_QUARANTINE_SECS,
        }),
    ))?;
    assert_eq!(dedicated_release.outcome, "quarantine");
    let quarantined = dedicated_release.identity.as_ref().expect("identity");
    assert_eq!(quarantined.state, ChannelIdentityState::Quarantine);
    assert_eq!(
        quarantined.quarantine_until,
        Some(6_020 + CHANNEL_IDENTITY_MIN_QUARANTINE_SECS)
    );

    let receipts = vault.receipts(
        ReceiptQuery::new(20)
            .with_kind(ReceiptKind::IdentityLifecycle)
            .with_actor(agent.to_hex()),
    )?;
    assert!(receipts.iter().any(|receipt| {
        receipt.outcome == "released" && !receipt.fields.contains_key("quarantine_until")
    }));
    assert!(
        receipts
            .iter()
            .any(|receipt| receipt.outcome == "quarantine")
    );
    Ok(())
}

#[test]
fn route_inbound_against_tombstone_reports_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // The actor entity is stored because the live ceiling resolver fails
    // absent agent-class actors closed to Proposed (ONE-1444 B3) — an
    // Auto-granted effect actor must be entity-backed.
    let agent = entity(0x5E);
    vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"route actor",
    )?;
    let actor = ChannelIdentityLifecycleActor::agent(agent);
    put_policy_manifest_bytes(
        &vault,
        entity(0xE0),
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
