//! ASTRA-9A-2 F2: a restore over the live vault never brings back room
//! authority narrowed since the checkpoint.
use super::*;

fn restore(vault: &Vault, image: &std::path::Path, destination: &std::path::Path) -> Result<Vault> {
    let config = VaultConfig {
        embedding_model: Some("test/model@v1".to_owned()),
        ..VaultConfig::default()
    };
    Vault::restore_checkpoint_keeping_authority(image, destination, config, vault, 200)
        .map(|(restored, _)| restored)
}

/// A room made after the checkpoint leaves with the restore. A role narrowed
/// since in a room the checkpoint holds refuses it: the image would make bob
/// an Admin again.
#[test]
fn restore_refuses_to_bring_back_a_room_role_narrowed_since() {
    let (_dir, vault, owner, room, bob) = fixture();
    vault
        .join_member(room, bob, owner, 2, HistoryChoice::Share)
        .unwrap();
    vault
        .set_room_role(room, bob, RoomRole::Admin, owner)
        .unwrap();
    let backups = tempfile::tempdir().unwrap();
    let image = backups.path().join("backup");
    vault.snapshot_checkpoint(&image, 100).unwrap();

    let later = EntityId::now();
    vault
        .create_conversation(later, &ConversationBody::default(), owner, 3)
        .unwrap();
    vault
        .join_member(later, bob, owner, 4, HistoryChoice::Share)
        .unwrap();
    let restored = restore(&vault, &image, &backups.path().join("first")).unwrap();
    assert!(restored.conversation_body(later).is_err());
    assert_eq!(
        restored.conversation_body(room).unwrap().roles[&bob.to_hex()],
        RoomRole::Admin
    );
    drop(restored);

    vault
        .set_room_role(room, bob, RoomRole::Member, owner)
        .unwrap();
    let destination = backups.path().join("second");
    let error = restore(&vault, &image, &destination)
        .err()
        .expect("the restore must be refused");
    assert!(
        error.to_string().contains("room roles and membership"),
        "{error}"
    );
    assert!(!destination.exists());
}

/// Shared history narrowed to join time since the checkpoint is not widened
/// again by restoring it.
#[test]
fn restore_refuses_to_reopen_room_history_narrowed_since() {
    let (_dir, vault, owner, room, bob) = fixture();
    let before = vault
        .append_dag_record(&record(&vault, room, owner, 2))
        .unwrap();
    vault
        .join_member(room, bob, owner, 3, HistoryChoice::Share)
        .unwrap();
    assert!(audience_admits(&vault, before.id, bob).unwrap());
    let backups = tempfile::tempdir().unwrap();
    let image = backups.path().join("backup");
    vault.snapshot_checkpoint(&image, 100).unwrap();
    vault
        .set_history_visibility(room, bob, owner, 4, 3)
        .unwrap();
    assert!(!audience_admits(&vault, before.id, bob).unwrap());

    let destination = backups.path().join("restored");
    let error = restore(&vault, &image, &destination)
        .err()
        .expect("the restore must be refused");
    assert!(
        error.to_string().contains("room roles and membership"),
        "{error}"
    );
    assert!(!destination.exists());
}
