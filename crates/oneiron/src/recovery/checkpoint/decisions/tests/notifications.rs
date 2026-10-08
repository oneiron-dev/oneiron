//! Census case for who a pending notification is delivered to.
use super::Case;
use crate::context_board::{notification_body_json, notification_scoped_to_caller};
use crate::registry::ENTITY_TYPE_NOTIFICATION;
use crate::test_util::entity;
use crate::{EntityId, Error, Result, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

fn open_vault() -> (tempfile::TempDir, Vault) {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    crate::test_util::open_test_vault_with(config)
}

/// Stores `body` as notification `id` at `learned_at`, through the entity
/// door a host writes notifications with.
fn notify(vault: &Vault, id: EntityId, body: &Value, learned_at: u64) -> Result<()> {
    let body = rmp_serde::to_vec(body).map_err(|error| Error::InvalidConfig(error.to_string()))?;
    vault.put_entity(
        &id,
        ENTITY_TYPE_NOTIFICATION,
        TimeRange { start: 1, end: 1 },
        learned_at,
        &body,
    )
}

/// A notification for the callers A and B, both of whom may read.
fn for_a_and_b() -> Result<(tempfile::TempDir, Vault, EntityId)> {
    let (dir, vault) = open_vault();
    let notification = entity(0xD1);
    notify(
        &vault,
        notification,
        &json!({ "message": "payload", "recipient": ["A", "B"] }),
        10,
    )?;
    crate::test_util::authorize_readers(&vault, &["A", "B"]);
    Ok((dir, vault, notification))
}

/// A notification delivered to two callers. Its text edited and its
/// acknowledged and surfaced markers set since the backup, its recipients
/// unchanged, is content a restore brings back; one of the two taken off it
/// since is a caller a restore would deliver it to again.
pub(super) fn notification_recipients() -> Result<Case> {
    let (dir, vault, notification) = for_a_and_b()?;
    Case::after_backup(
        "notification recipients",
        (dir, vault),
        move |vault| {
            notify(
                vault,
                notification,
                &json!({
                    "message": "edited",
                    "recipient": ["A", "B"],
                    "acked": true,
                    "surfaced_by": ["A"]
                }),
                20,
            )
        },
        move |vault| {
            notify(
                vault,
                notification,
                &json!({ "message": "payload", "recipient": ["A"] }),
                30,
            )
        },
    )
}

/// Whether the context board delivers `notification` to `caller`, read from
/// its stored body as the board reads it.
fn delivered(vault: &Vault, notification: &EntityId, caller: &str) -> Result<bool> {
    let body = vault.get(notification)?.ok_or(Error::EntityNotFound)?;
    Ok(notification_body_json(&body)
        .is_some_and(|body| notification_scoped_to_caller(&body, caller)))
}

/// Astra R4-7: a caller taken off a notification's recipients since the
/// backup had it delivered again after a restore that kept live authority.
#[test]
fn a_restore_does_not_deliver_a_notification_to_a_recipient_taken_off_it() -> Result<()> {
    let (_dir, vault, notification) = for_a_and_b()?;
    assert!(delivered(&vault, &notification, "B")?);
    let backups = tempfile::tempdir()?;
    let image = backups.path().join("backup");
    vault.snapshot_checkpoint(&image, 100)?;
    notify(
        &vault,
        notification,
        &json!({ "message": "payload", "recipient": ["A"] }),
        30,
    )?;
    assert!(delivered(&vault, &notification, "A")?);
    assert!(!delivered(&vault, &notification, "B")?);
    let Err(refused) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &backups.path().join("restored"),
        vault.config.clone(),
        &vault,
        1_000,
    ) else {
        panic!("a restore delivering the notification to B again went ahead");
    };
    assert!(
        refused.to_string().contains("notification recipients"),
        "{refused}"
    );
    Ok(())
}
