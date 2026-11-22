//! CHECKPOINT-RESTORE-SKIPS-DERIVED-INDEX-REBUILD: a checkpoint restore
//! rebuilds a derived index an image does not carry, from the bodies it kept.
//!
//! The extra-room index (`project.extra_room.v1/`) is derived from a room
//! body's `project_group` key at every CONVERSATION put. A restore writes raw
//! rows past that seam, so an image without the derived row, as one cut
//! before the index holds the room, leaves the index empty until each room's
//! next put. The restore rebuilds it from the body it kept instead.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test checkpoint_restore_derived_index_rebuild`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::core_write::ConversationCreateInput;
use oneiron::workspace_roster::{
    ProjectRecord, ProjectRoomLinkRequest, ProjectRoomPlace, ProjectRoomsRequest,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A vault this process owns, its embedded owner, and a device keystore with
/// a vault key, so it snapshots and restores. The vault closes before its
/// directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    dir: tempfile::TempDir,
}

fn open() -> TestResult<Fixture> {
    let dir = oneiron::test_support::restore_tempdir();
    let vault = Vault::open_owned(dir.path().join("vault"), VaultConfig::default())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.ensure_vault_key()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok(Fixture { vault, owner, dir })
}

/// A project led by the owner, and its home room. An unsigned owner-door row
/// serves its stored leader as its effective authority at once, as
/// `project_extra_rooms.rs` does.
fn project(fixture: &Fixture, at: u64) -> TestResult<(EntityId, EntityId)> {
    let root = fixture.vault.root_project()?;
    let id = EntityId::now();
    let record = ProjectRecord::new(id, Some(root), root, fixture.owner)?;
    fixture.vault.put_project(id, &record, at)?;
    Ok((id, EntityId::from_hex(&record.home_room)?))
}

/// An ordinary group room holding the owner, stamped before the snapshot.
fn room(fixture: &Fixture, title: &str) -> TestResult<EntityId> {
    let receipt = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .conversations_create(&ConversationCreateInput {
            id: None,
            occurred_start: Some(3),
            occurred_end: Some(3),
            learned_at: Some(3),
            body: json!({
                "v": 1,
                "kind": "group",
                "member_ids": [fixture.owner.to_hex()],
                "title": title,
            }),
            text: None,
        })?;
    Ok(EntityId::from_hex(&receipt.id)?)
}

/// The rooms `project` lists to the owner: each room with its place.
fn listed(
    vault: &Vault,
    owner: EntityId,
    project: EntityId,
) -> TestResult<Vec<(String, ProjectRoomPlace)>> {
    let page = vault
        .memory(owner, EdgeActorClass::Human)
        .projects_rooms_list(&ProjectRoomsRequest {
            project_ref: project.to_hex(),
        })?;
    Ok(page
        .rows
        .into_iter()
        .map(|row| (row.room_ref, row.place))
        .collect())
}

/// Links `extra` into `project` as the owner's extra room.
fn link(fixture: &Fixture, project: EntityId, extra: EntityId) -> TestResult {
    fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .projects_rooms_link(&ProjectRoomLinkRequest {
            project_ref: project.to_hex(),
            room_ref: extra.to_hex(),
        })?;
    Ok(())
}

/// A restore rebuilds the extra-room index from the room body it kept when
/// the image does not carry the derived row.
#[test]
fn restore_rebuilds_the_extra_room_index_an_image_does_not_carry() -> TestResult {
    let fixture = open()?;
    let (project, home) = project(&fixture, 2)?;
    let extra = room(&fixture, "extra room")?;
    link(&fixture, project, extra)?;
    assert_eq!(
        listed(&fixture.vault, fixture.owner, project)?,
        vec![
            (home.to_hex(), ProjectRoomPlace::Home),
            (extra.to_hex(), ProjectRoomPlace::Extra),
        ],
        "the link lists the extra room before the index row is dropped"
    );

    // The image of a vault this old carries no derived row: the room body
    // keeps its `project_group` key, and the index row is gone.
    assert!(
        oneiron::test_doors::extra_room_index::drop_extra_room_row(&fixture.vault, extra)?,
        "the link wrote the extra-room index row"
    );
    assert_eq!(
        listed(&fixture.vault, fixture.owner, project)?,
        vec![(home.to_hex(), ProjectRoomPlace::Home)],
        "the list reads the index, not the body"
    );

    let key = fixture.vault.checkpoint_key()?;
    let image = fixture.dir.path().join("image");
    fixture.vault.snapshot_checkpoint(&image, 100)?;
    let (copy, _) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &key,
        &fixture.dir.path().join("restored"),
        VaultConfig::device(),
        &fixture.vault,
        200,
    )?;
    assert_eq!(
        listed(&copy, fixture.owner, project)?,
        vec![
            (home.to_hex(), ProjectRoomPlace::Home),
            (extra.to_hex(), ProjectRoomPlace::Extra),
        ],
        "the restore rebuilds the extra-room index from the room body it kept"
    );
    Ok(())
}

/// The carried case still restores: an image that holds the derived row
/// lists the extra room after the restore. This passes on main too; it pins
/// that the rebuild leaves carried rows alone.
#[test]
fn restore_keeps_the_extra_room_index_an_image_carries() -> TestResult {
    let fixture = open()?;
    let (project, home) = project(&fixture, 2)?;
    let extra = room(&fixture, "extra room")?;
    link(&fixture, project, extra)?;

    let key = fixture.vault.checkpoint_key()?;
    let image = fixture.dir.path().join("image");
    fixture.vault.snapshot_checkpoint(&image, 100)?;
    let (copy, _) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &key,
        &fixture.dir.path().join("restored"),
        VaultConfig::device(),
        &fixture.vault,
        200,
    )?;
    assert_eq!(
        listed(&copy, fixture.owner, project)?,
        vec![
            (home.to_hex(), ProjectRoomPlace::Home),
            (extra.to_hex(), ProjectRoomPlace::Extra),
        ],
        "the restore keeps the extra-room index the image carries"
    );
    Ok(())
}
