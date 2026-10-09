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
    let bytes = crate::gate::default_policy_manifest().unwrap();
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
fn missing_quarantine_policy_row_refuses_instead_of_using_a_code_floor() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let id = entity(0x6A);
    released_identity(&vault, &id)?;
    install_default_manifest_with(&vault, wait_rows(Vec::new()))?;
    assert!(
        vault
            .step_channel_identity(
                &id,
                ChannelIdentityStep::Quarantine {
                    until: AT + DEFAULT_CHANNEL_IDENTITY_QUARANTINE_MIN_SECS,
                },
                AT,
            )
            .is_err(),
        "an absent wait row is not replaced by a hardcoded duration",
    );
    assert_eq!(
        vault
            .get_channel_identity(&id)?
            .expect("row remains")
            .state(),
        ChannelIdentityState::Released
    );
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

#[test]
fn a_vault_without_a_manifest_leaves_the_send_verdict_to_the_gate() -> Result<()> {
    use crate::channel_identity::{
        enrich_dispatch_channel_identity, resolve_channel_identity_ref_for_connector,
    };
    use crate::connector_key::ConnectorKeyRecord;

    // `test_vault` carries no policy manifest, so its gate pends every
    // external effect. The sender door must not answer for it on a row that
    // does not exist; only the substrate capability stays in code.
    let (_tmp, vault) = test_vault();
    let actor = crate::test_util::seed_agent_definition(&vault, entity(0x68), "bootstrap sender");
    vault.register_connector_key(
        &entity(0x69),
        ConnectorKeyRecord::active("email", Some(actor), Vec::new(), 100),
    )?;
    let identity = crate::test_util::self_held_identity_in_state(
        "email",
        "bootstrap@example.com",
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::actor(actor),
        ChannelIdentityState::Active,
        100,
    );
    let identity_ref = entity(0x6B);
    vault.create_channel_identity(&identity_ref, &identity)?;

    let selected = || -> Result<Option<EntityId>> {
        let txn = vault.store.env.read_txn()?;
        resolve_channel_identity_ref_for_connector(&vault.store, &txn, "email", Some(&actor))
    };
    let explicit = || -> Result<Option<EntityId>> {
        let txn = vault.store.env.read_txn()?;
        enrich_dispatch_channel_identity(
            &vault.store,
            &txn,
            "email",
            Some(&actor),
            Some(identity_ref),
        )
    };
    assert_eq!(selected()?, Some(identity_ref));
    assert_eq!(explicit()?, Some(identity_ref));

    // A retired row still holds no capability, manifest or not.
    vault.step_channel_identity(&identity_ref, ChannelIdentityStep::Release, 101)?;
    assert_eq!(selected()?, None);
    assert!(
        explicit().is_err(),
        "an explicit retired sender is refused without a manifest too"
    );
    Ok(())
}
