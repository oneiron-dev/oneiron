//! Notification queue fairness, failure isolation, and recipient digest cadence.
use super::notifications::{PolicyQueuedNotification, QUEUED};
use super::*;
use crate::VaultConfig;
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityStep,
    SelfHeldShape,
};
use crate::comm::resolve_or_create_comm_party;
use crate::counterparty_contact::CounterpartyContactRecord;
use crate::federation::{FederationGrantRole, InitialSharedMember};
use crate::gate::{PolicyRowAction, PolicyRowScope};
use crate::store::GateDecisionId;

const NOW: u64 = 1_772_600_000;

fn setup() -> Result<(tempfile::TempDir, Vault, AuthenticatedOwner, EntityId)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let id = crate::vault::embedded_owner_actor_id()?;
    let owner = vault.authenticate_owner(id, &id.to_hex(), true, GateDecisionId::now())?;
    let recipient = resolve_or_create_comm_party(&vault, "notify@example.test")
        .map_err(|err| Error::InvalidConfig(format!("test contact: {err}")))?;
    vault.initialize_shared_vault(
        &owner,
        54,
        None,
        &[
            InitialSharedMember {
                member_ref: id,
                role: Some(FederationGrantRole::Owner),
            },
            InitialSharedMember {
                member_ref: recipient,
                role: Some(FederationGrantRole::Owner),
            },
        ],
        NOW,
    )?;
    Ok((dir, vault, owner, recipient))
}

fn route(vault: &Vault) -> Result<()> {
    let face = EntityId::from_bytes([0xb1; 16])?;
    vault.create_channel_identity(
        &face,
        &ChannelIdentity::requested(
            "email",
            "sender@example.test",
            SelfHeldShape::DedicatedAddress,
            ChannelIdentityBinding::vault(1),
            NOW,
        ),
    )?;
    vault.step_channel_identity(
        &face,
        ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
        NOW,
    )?;
    vault.step_channel_identity(&face, ChannelIdentityStep::Fulfill, NOW)?;
    vault.create_counterparty_contact(
        &EntityId::from_bytes([0xb2; 16])?,
        &CounterpartyContactRecord::user_introduction(face, "notify@example.test", NOW)?,
    )?;
    Ok(())
}

fn change(vault: &Vault, owner: &AuthenticatedOwner, seq: usize) -> Result<PolicyRowReceipt> {
    vault.change_policy_row(
        owner,
        crate::gate::PolicyRowChange::Add {
            row_ref: format!("notify-{seq}"),
            text: format!("Policy {seq}"),
            action: PolicyRowAction::Warn,
            scope: PolicyRowScope::Vault,
        },
        NOW + seq as u64,
    )
}

#[test]
fn skipped_positions_over_wake_limit_do_not_starve_following_notice() -> Result<()> {
    let (_dir, vault, owner, recipient) = setup()?;
    route(&vault)?;
    // Lexically earlier intents have invalid senders. They cannot mint TASKs.
    vault.with_write_txn(|txn| {
        for n in 0..65 {
            let entry = PolicyQueuedNotification {
                receipt_id: format!("000-{n:03}"),
                recipient: recipient.to_hex(),
                author: EntityId::from_bytes([0xec; 16])?.to_hex(),
                scope: PolicyRowScope::Vault,
                grant_target: super::policy_row_grant_target(&PolicyRowScope::Vault, "bad"),
                mode: PolicyNotificationMode::PushAll,
                followup_task: None,
                digest_due_at: None,
            };
            let key = [
                QUEUED,
                format!("000-{n:03}:{}", recipient.to_hex()).as_bytes(),
            ]
            .concat();
            vault.store.vault_meta.put(
                txn,
                &key,
                &rmp_serde::to_vec_named(&entry)
                    .map_err(|_| crate::error::Error::InvariantViolation("test notification"))?,
            )?;
        }
        Ok(())
    })?;
    change(&vault, &owner, 1)?;
    assert_eq!(vault.drive_policy_notification_queue(NOW + 2, 64)?, 0);
    assert_eq!(vault.drive_policy_notification_queue(NOW + 2, 64)?, 1);
    assert_eq!(vault.policy_notification_failures()?.len(), 65);
    assert_eq!(
        vault
            .policy_queued_notifications()?
            .iter()
            .filter(|row| row.followup_task.is_some())
            .count(),
        1
    );
    Ok(())
}

#[test]
fn bad_author_has_durable_retry_and_cannot_abort_next_or_human_wake() -> Result<()> {
    let (_dir, vault, owner, recipient) = setup()?;
    let first = change(&vault, &owner, 1)?;
    // First change has no route. This remains pending, with an inspectable retry.
    assert_eq!(vault.drive_policy_notification_queue(NOW + 2, 10)?, 0);
    assert_eq!(vault.policy_notification_failures()?.len(), 1);
    route(&vault)?;
    change(&vault, &owner, 2)?;
    assert_eq!(vault.drive_policy_notification_queue(NOW + 3, 10)?, 1);
    let first_row = vault
        .policy_queued_notifications()?
        .into_iter()
        .find(|row| row.receipt_id == first.receipt_id)
        .expect("first row");
    assert!(first_row.followup_task.is_none());
    assert_eq!(vault.drive_policy_notification_queue(NOW + 63, 10)?, 1);
    assert!(vault.policy_notification_failures()?.is_empty());
    assert!(
        vault
            .policy_queued_notifications()?
            .iter()
            .all(|row| row.recipient == recipient.to_hex() && row.followup_task.is_some())
    );
    Ok(())
}

#[test]
fn digest_waits_for_recipient_schedule_and_groups_receipts_push_all_does_not() -> Result<()> {
    let (_dir, vault, owner, recipient) = setup()?;
    route(&vault)?;
    let recipient_actor =
        vault.authenticate_owner(recipient, &recipient.to_hex(), true, GateDecisionId::now())?;
    vault.set_policy_notification_mode(&recipient_actor, PolicyNotificationMode::Digest)?;
    vault.set_policy_notification_digest_interval(&recipient_actor, Some(120))?;
    let first = change(&vault, &owner, 1)?;
    let second = change(&vault, &owner, 2)?;
    let rows = vault.policy_queued_notifications()?;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].digest_due_at, rows[1].digest_due_at);
    assert_eq!(vault.drive_policy_notification_queue(NOW + 100, 10)?, 0);
    assert_eq!(vault.drive_policy_notification_queue(NOW + 121, 10)?, 2);
    let rows = vault.policy_queued_notifications()?;
    assert_eq!(rows[0].followup_task, rows[1].followup_task);
    assert!(rows.iter().any(|row| row.receipt_id == first.receipt_id));
    assert!(rows.iter().any(|row| row.receipt_id == second.receipt_id));
    vault.set_policy_notification_mode(&recipient_actor, PolicyNotificationMode::PushAll)?;
    change(&vault, &owner, 3)?;
    change(&vault, &owner, 4)?;
    assert_eq!(vault.drive_policy_notification_queue(NOW + 125, 10)?, 2);
    let rows = vault.policy_queued_notifications()?;
    let pushes = rows
        .iter()
        .filter(|row| row.mode == PolicyNotificationMode::PushAll)
        .map(|row| row.followup_task.as_deref().expect("push TASK"))
        .collect::<Vec<_>>();
    assert_eq!(pushes.len(), 2);
    assert_ne!(pushes[0], pushes[1]);
    assert_ne!(
        pushes[0],
        rows[0].followup_task.as_deref().expect("digest TASK")
    );
    Ok(())
}

#[test]
fn rule_event_names_all_overrides_not_a_fake_project_scope() -> Result<()> {
    let (_dir, vault, owner, _recipient) = setup()?;
    vault.change_policy_notification_rule(
        &owner,
        PolicyNotificationTarget::AllOverrides,
        PolicyNotificationRule::PushOtherHolders,
        NOW,
    )?;
    let event = vault.policy_changed_events()?.pop().expect("event");
    assert_eq!(event.target, Some(PolicyNotificationTarget::AllOverrides));
    assert_eq!(event.scope, None);
    Ok(())
}

#[test]
fn digest_without_recipient_override_uses_manifest_schedule() -> Result<()> {
    let (_dir, vault, owner, recipient) = setup()?;
    let recipient_actor =
        vault.authenticate_owner(recipient, &recipient.to_hex(), true, GateDecisionId::now())?;
    vault.set_policy_notification_mode(&recipient_actor, PolicyNotificationMode::Digest)?;
    let interval = {
        let txn = vault.store.env.read_txn()?;
        super::notifications::read_rule_in(&vault, &txn, true)?.1
    };
    let receipt = change(&vault, &owner, 1)?;
    let row = vault
        .policy_queued_notifications()?
        .into_iter()
        .next()
        .expect("digest row");
    assert_eq!(row.receipt_id, receipt.receipt_id);
    assert_eq!(row.digest_due_at, Some(NOW + 1 + interval));
    assert_eq!(vault.drive_policy_notification_queue(NOW + 1, 10)?, 0);
    Ok(())
}
