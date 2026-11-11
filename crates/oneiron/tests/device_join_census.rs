//! A fresh vault that `device enrol` opens holds only its own seeds
//! (FIX-LIST [DEVICE-JOIN-CENSUS-MISSES-CARRIERS-AND-HOME-ROOM]). The
//! empty-vault join guard asks `first_non_bootstrap_row`. A seeded open
//! also writes the root project's home CONVERSATION and a source-carrier
//! ASSET for each clean seeded skill tree; the census did not know those,
//! so the guard refused a vault that held nothing of its own. The guard
//! must still name every row the open did not seed, an owner-edited home
//! room included, so a join from empty never discards user data.

use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON};
use oneiron::temporal::TimeRange;
use oneiron::{EntityId, Vault, VaultConfig};

#[test]
fn fresh_stopped_vault_holds_no_non_bootstrap_row() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let vault_path = temp.path().join("vault");

    // Initialize, stop, and reopen through the CLI's owned-vault door, as
    // `device enrol` does before its join guard.
    drop(Vault::open_owned(&vault_path, VaultConfig::device()).expect("initialize vault"));
    let vault = Vault::open_owned(&vault_path, VaultConfig::device()).expect("reopen vault");
    vault.root_project().expect("a seeded open roots the vault");

    assert_eq!(
        vault.first_non_bootstrap_row().expect("seed census scan"),
        None,
        "a fresh seeded vault holds no row of its own"
    );
}

// Positive control from OPUS-E2E-3 (join_guard_single_snapshot.rs on
// opus-e2e-3/join-guard-one-snapshot-3, ruled into this file 12 Nov 03:07).
#[test]
fn join_guard_reads_one_snapshot_and_keeps_the_nonempty_check() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");

    // A freshly opened vault holds only the rows its own open seeded: joinable.
    assert_eq!(
        vault
            .first_non_bootstrap_row()
            .expect("the join guard reads a fresh vault"),
        None,
    );

    // One row the open did not seed: the guard still names it, so a join
    // from empty cannot discard user data.
    // A fresh id: [0xA1; 16]..[0xA6; 16] hold the seeded system agents.
    let person = EntityId::now();
    let at = 1_773_532_800;
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: at, end: at },
            at,
            b"join guard witness",
        )
        .expect("write a non-seed PERSON");
    assert_eq!(
        vault
            .first_non_bootstrap_row()
            .expect("the join guard reads a vault with user data"),
        Some((ENTITY_TYPE_PERSON, person)),
    );
}

#[test]
fn edited_root_home_room_is_not_bootstrap() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let vault_path = temp.path().join("vault");
    let vault = Vault::open_owned(&vault_path, VaultConfig::device()).expect("open vault");
    let root = vault.root_project().expect("a seeded open roots the vault");
    let mut record = vault
        .project(root)
        .expect("read the root project")
        .expect("the root project is visible");
    let home_room = EntityId::from_hex(&record.home_room).expect("home room id");

    // A roster change re-projects the home room's members: the room at the
    // seeded id now holds a body the open did not write.
    record.roster.push(EntityId::now().to_hex());
    vault
        .put_project(root, &record, 1_773_532_800)
        .expect("edit the root roster");

    assert_eq!(
        vault
            .first_non_bootstrap_row()
            .expect("the join guard reads an edited vault"),
        Some((ENTITY_TYPE_CONVERSATION, home_room)),
        "an edited home room is real content"
    );
}
