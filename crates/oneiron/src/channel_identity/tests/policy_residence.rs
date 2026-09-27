//! The quarantine WAIT and the delegated SEND posture as vault-resident policy.
//!
//! Each test here fails without the policy move: before it, the 90-day floor
//! was an engine constant no manifest row could change, and a delegated row was
//! unsendable by its class rather than by a row an owner owns.

use super::*;

use crate::channel_identity::{
    ACT_CLASS_CHANNEL_IDENTITY_OUTBOUND_SEND, DEFAULT_CHANNEL_IDENTITY_QUARANTINE_MIN_SECS,
    SUBJECT_CLASS_SELF_HELD, WAIT_CLASS_CHANNEL_IDENTITY_QUARANTINE,
};
use crate::test_util::put_policy_manifest_bytes;
use rmpv::Value as PolicyValue;

const AT: u64 = 1_800_000_040;
const DAY: u64 = 24 * 60 * 60;

/// Rewrites the shipped default manifest with `edit` applied to its top-level
/// map, and installs it as the vault's manifest.
///
/// Editing the SHIPPED manifest rather than authoring a bare one is the point:
/// the rows under test are the ones a real vault carries, so a test that
/// changes one is doing exactly what an owner would do.
fn install_default_manifest_with(
    vault: &Vault,
    edit: impl FnOnce(&mut Vec<(PolicyValue, PolicyValue)>),
) -> Result<()> {
    let bytes = crate::gate::default_policy_manifest();
    let PolicyValue::Map(mut entries) =
        rmpv::decode::read_value(&mut bytes.as_slice()).expect("default manifest decodes")
    else {
        panic!("the default manifest is a map");
    };
    edit(&mut entries);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &PolicyValue::Map(entries))
        .expect("edited manifest encodes");
    put_policy_manifest_bytes(vault, crate::gate::default_policy_manifest_id()?, &bytes)
}

fn replace_key(entries: &mut Vec<(PolicyValue, PolicyValue)>, key: &str, value: PolicyValue) {
    entries.retain(|(seen, _)| seen.as_str() != Some(key));
    entries.push((PolicyValue::from(key), value));
}

fn wait_rows(rows: Vec<PolicyValue>) -> impl FnOnce(&mut Vec<(PolicyValue, PolicyValue)>) {
    move |entries| replace_key(entries, "wait_policy", PolicyValue::Array(rows))
}

fn quarantine_row(min_secs: u64, holder: Option<&EntityId>) -> PolicyValue {
    let mut row = vec![
        (
            PolicyValue::from("wait_class"),
            PolicyValue::from(WAIT_CLASS_CHANNEL_IDENTITY_QUARANTINE),
        ),
        (PolicyValue::from("min_secs"), PolicyValue::from(min_secs)),
    ];
    if let Some(holder) = holder {
        row.push((
            PolicyValue::from("holder_ref"),
            PolicyValue::from(holder.to_hex()),
        ));
    }
    PolicyValue::Map(row)
}

fn outbound_row(subject_class: &str, posture: &str) -> PolicyValue {
    PolicyValue::Map(vec![
        (
            PolicyValue::from("act_class"),
            PolicyValue::from(ACT_CLASS_CHANNEL_IDENTITY_OUTBOUND_SEND),
        ),
        (
            PolicyValue::from("subject_class"),
            PolicyValue::from(subject_class.to_owned()),
        ),
        (
            PolicyValue::from("posture"),
            PolicyValue::from(posture.to_owned()),
        ),
    ])
}

/// Walks a fresh self-held row to RELEASED at `id`, ready to be quarantined
/// through the vault door.
fn released_identity(vault: &Vault, id: &EntityId) -> Result<()> {
    let identity = sample_identity();
    vault.create_channel_identity(id, &identity)?;
    vault.step_channel_identity(
        id,
        ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
        1_800_000_010,
    )?;
    vault.step_channel_identity(id, ChannelIdentityStep::Fulfill, 1_800_000_020)?;
    vault.step_channel_identity(id, ChannelIdentityStep::Release, 1_800_000_030)?;
    Ok(())
}

#[test]
fn the_quarantine_floor_is_the_manifest_row_the_vault_carries() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let id = entity(0x61);
    released_identity(&vault, &id)?;
    install_default_manifest_with(&vault, |entries| {
        // The owner keeps the shipped 90-day row, unchanged.
        replace_key(
            entries,
            "wait_policy",
            PolicyValue::Array(vec![quarantine_row(
                DEFAULT_CHANNEL_IDENTITY_QUARANTINE_MIN_SECS,
                None,
            )]),
        );
    })?;

    let short = vault.step_channel_identity(
        &id,
        ChannelIdentityStep::Quarantine {
            until: AT + 30 * DAY,
        },
        AT,
    );
    assert!(
        short.is_err(),
        "a 30-day hold is under the row the vault carries"
    );
    let quarantined = vault.step_channel_identity(
        &id,
        ChannelIdentityStep::Quarantine {
            until: AT + DEFAULT_CHANNEL_IDENTITY_QUARANTINE_MIN_SECS,
        },
        AT,
    )?;
    assert_eq!(
        quarantined.quarantine_until(),
        Some(AT + DEFAULT_CHANNEL_IDENTITY_QUARANTINE_MIN_SECS)
    );
    Ok(())
}

#[test]
fn a_vault_row_lowering_the_floor_admits_the_shorter_hold() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let id = entity(0x62);
    released_identity(&vault, &id)?;
    // THE test for the finding: the number is the vault's, not the engine's.
    // Before the policy move no manifest row could reach this floor at all.
    install_default_manifest_with(&vault, wait_rows(vec![quarantine_row(30 * DAY, None)]))?;

    let quarantined = vault.step_channel_identity(
        &id,
        ChannelIdentityStep::Quarantine {
            until: AT + 30 * DAY,
        },
        AT,
    )?;
    assert_eq!(quarantined.quarantine_until(), Some(AT + 30 * DAY));
    Ok(())
}

#[test]
fn a_holder_row_holds_one_actors_addresses_longer() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let id = entity(0x63);
    released_identity(&vault, &id)?;
    // `sample_identity` binds actor `entity(0x51)`; the holder row names it.
    install_default_manifest_with(
        &vault,
        wait_rows(vec![
            quarantine_row(30 * DAY, None),
            quarantine_row(200 * DAY, Some(&entity(0x51))),
        ]),
    )?;

    assert!(
        vault
            .step_channel_identity(
                &id,
                ChannelIdentityStep::Quarantine {
                    until: AT + 30 * DAY
                },
                AT,
            )
            .is_err(),
        "the vault floor is not the answer for an actor its holder row names"
    );
    let quarantined = vault.step_channel_identity(
        &id,
        ChannelIdentityStep::Quarantine {
            until: AT + 200 * DAY,
        },
        AT,
    )?;
    assert_eq!(quarantined.quarantine_until(), Some(AT + 200 * DAY));
    Ok(())
}

#[test]
fn an_unreadable_wait_policy_refuses_the_act_rather_than_shortening_it() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let id = entity(0x64);
    released_identity(&vault, &id)?;
    install_default_manifest_with(&vault, |entries| {
        // A row whose floor sits above its own ceiling drops the manifest, which
        // fails the gate closed.
        replace_key(
            entries,
            "wait_policy",
            PolicyValue::Array(vec![PolicyValue::Map(vec![
                (
                    PolicyValue::from("wait_class"),
                    PolicyValue::from(WAIT_CLASS_CHANNEL_IDENTITY_QUARANTINE),
                ),
                (PolicyValue::from("min_secs"), PolicyValue::from(90 * DAY)),
                (PolicyValue::from("max_secs"), PolicyValue::from(DAY)),
            ])]),
        );
    })?;

    let refused = vault.step_channel_identity(
        &id,
        ChannelIdentityStep::Quarantine {
            until: AT + 400 * DAY,
        },
        AT,
    );
    assert!(
        refused.is_err(),
        "an unreadable policy is never read as a shorter hold, nor as none"
    );
    Ok(())
}

#[test]
fn decode_checks_window_coherence_and_leaves_duration_to_policy() -> Result<()> {
    // Decode holds no manifest snapshot, so it asks only what a body can answer
    // about itself: a window that ends before the stamp it dates from is two
    // things at once. A SHORT window is a policy question, and decode does not
    // have the policy.
    let released = sample_identity_stored(Custody::SelfHeld {
        shape: SelfHeldShape::DedicatedAddress,
        lifecycle: SelfHeldLifecycle::Released,
    });
    let stamp = released.state_changed_at();
    let short = sample_identity_stored(Custody::SelfHeld {
        shape: SelfHeldShape::DedicatedAddress,
        lifecycle: SelfHeldLifecycle::Quarantine { until: stamp + DAY },
    });
    let encoded = encode_channel_identity_body(&short)?;
    assert_eq!(decode_channel_identity_body(&encoded)?, short);

    let backwards = sample_identity_stored(Custody::SelfHeld {
        shape: SelfHeldShape::DedicatedAddress,
        lifecycle: SelfHeldLifecycle::Quarantine { until: stamp - 1 },
    });
    let encoded = encode_channel_identity_body(&backwards)?;
    assert!(decode_channel_identity_body(&encoded).is_err());
    Ok(())
}

/// A stored delegated row: OAuth by construction, as the delegated shape
/// requires.
fn delegated_identity(grant: DelegatedGrant, lifecycle: DelegatedLifecycle) -> ChannelIdentity {
    ChannelIdentity::from_stored_parts(StoredIdentityParts {
        auth_mode: ChannelAuthMode::OAuth,
        channel: "email".to_owned(),
        address_or_handle: "member@member-owned.example".to_owned(),
        binding: ChannelIdentityBinding::agent(entity(0x51)),
        custody: Custody::Delegated { grant, lifecycle },
        state_changed_at: 1_800_000_000,
        reputation_ref: None,
        manifest_ref: None,
    })
    .expect("delegated identity")
}

#[test]
fn the_default_manifest_denies_a_delegated_send_by_row_not_by_class() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let grant = DelegatedGrant::new("member-gmail", vec![DelegatedGrantScope::MailRead]);
    let delegated = delegated_identity(grant.clone(), DelegatedLifecycle::Active);
    // The shipped row is `deny`, so the restrictive default is unchanged.
    assert!(!delegated.may_send());
    // And the reason is now separable: the row denies the class, AND the grant
    // carries no outbound scope. Two facts, not one class property.
    assert!(!delegated.holds_outbound_capability());
    assert!(!grant.covers_outbound_send());

    install_default_manifest_with(&vault, |_| {})?;
    let policy = {
        let rtxn = vault.store.env.read_txn()?;
        crate::gate::resolve_policy_manifest(&vault.store, &rtxn)?
    };
    assert_eq!(
        policy.resolved_act_posture(
            ACT_CLASS_CHANNEL_IDENTITY_OUTBOUND_SEND,
            delegated.outbound_subject_class(),
            delegated.binding().actor_ref(),
        ),
        Some(crate::gate::class_policy::ActPosture::Deny),
    );
    Ok(())
}

#[test]
fn raising_the_delegated_row_still_refuses_on_the_read_only_grant() {
    // The owner rule that governs this: ship the restrictive value as a row,
    // and keep the CAPABILITY check in code. So an owner who raises the row
    // gets a different refusal, never a send authorized by a read-only OAuth
    // scope.
    let grant = DelegatedGrant::new("member-gmail", vec![DelegatedGrantScope::MailRead]);
    let delegated = delegated_identity(grant, DelegatedLifecycle::Active);
    assert!(
        !delegated.may_send_under(crate::gate::class_policy::ActPosture::RequireCapability),
        "the class is no longer barred, and the grant still carries no outbound scope"
    );
}

#[test]
fn a_vault_row_can_bar_self_held_sends_the_engine_used_to_allow() {
    let active = sample_identity_stored(Custody::SelfHeld {
        shape: SelfHeldShape::DedicatedAddress,
        lifecycle: SelfHeldLifecycle::Active,
    });
    // Under the shipped row, an active self-held row sends.
    assert!(active.may_send());
    assert!(active.holds_outbound_capability());
    // The same row set to `deny` closes it, which is the proof that the posture
    // is resolved policy rather than a property of the shape.
    assert!(!active.may_send_under(crate::gate::class_policy::ActPosture::Deny));
    assert_eq!(active.outbound_subject_class(), SUBJECT_CLASS_SELF_HELD);
}

#[test]
fn a_retired_self_held_row_never_sends_whatever_the_row_says() {
    // The substrate half: `require_capability` is not permission. A released,
    // quarantined or tombstoned row holds no capability, so the posture cannot
    // hand it one.
    for lifecycle in [
        SelfHeldLifecycle::Released,
        SelfHeldLifecycle::Quarantine {
            until: 1_800_000_000 + DEFAULT_CHANNEL_IDENTITY_QUARANTINE_MIN_SECS,
        },
        SelfHeldLifecycle::Tombstone,
        SelfHeldLifecycle::Rotating,
    ] {
        let identity = sample_identity_stored(Custody::SelfHeld {
            shape: SelfHeldShape::DedicatedAddress,
            lifecycle,
        });
        assert!(
            !identity.may_send_under(crate::gate::class_policy::ActPosture::RequireCapability),
            "a retired self-held row holds no outbound capability: {lifecycle:?}"
        );
    }
}

#[test]
fn the_selection_door_resolves_the_act_row_in_the_reading_transaction() -> Result<()> {
    use crate::channel_identity::resolve_channel_identity_ref_for_connector;
    use crate::connector_key::ConnectorKeyRecord;

    let (_tmp, vault) = test_vault();
    let actor = crate::test_util::seed_agent_definition(&vault, entity(0x65), "policy sender");
    vault.register_connector_key(
        &entity(0x66),
        ConnectorKeyRecord::active("email", Some(actor), Vec::new(), 100),
    )?;
    let identity = crate::test_util::self_held_identity_in_state(
        "email",
        "sender@example.com",
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::actor(actor),
        ChannelIdentityState::Active,
        100,
    );
    let identity_ref = entity(0x67);
    vault.create_channel_identity(&identity_ref, &identity)?;

    let selected = || -> Result<Option<EntityId>> {
        let txn = vault.store.env.read_txn()?;
        resolve_channel_identity_ref_for_connector(&vault.store, &txn, "email", Some(&actor))
    };

    // Under the shipped rows, the live self-held row is the sender.
    install_default_manifest_with(&vault, |_| {})?;
    assert_eq!(selected()?, Some(identity_ref));

    // The same row set to `deny` closes the door — proof that the selection
    // door reads the vault's policy in the transaction it selects in, rather
    // than an engine class rule.
    install_default_manifest_with(&vault, |entries| {
        replace_key(
            entries,
            "act_policy",
            PolicyValue::Array(vec![
                outbound_row(SUBJECT_CLASS_SELF_HELD, "deny"),
                outbound_row("delegated_grant", "deny"),
            ]),
        );
    })?;
    assert_eq!(selected()?, None);
    Ok(())
}
