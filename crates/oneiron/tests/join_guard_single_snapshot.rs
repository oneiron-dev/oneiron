//! The empty-vault join guard (`Vault::first_non_bootstrap_row`, the check
//! `oneiron device enrol` runs before a fresh peer joins) reads one snapshot.
//! It held a read transaction and paged the type index through a helper that
//! opened a second one on the same thread, so LMDB refused with
//! MDB_BAD_RSLOT on the first page and every fresh-peer enrolment failed
//! (E2E SYNC-01, SYNC-04).

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::{EntityId, Vault, VaultConfig};

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
    let person = EntityId::from_bytes([0xa5; 16]).expect("valid entity id");
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
