//! A batch put at an id holding the permanent `dt:` hard-delete marker must
//! not commit a body that then reads deleted forever: the put arm refuses it,
//! so the batch aborts and the row keeps reading deleted. A batch put at a
//! live id commits as today.
//!
//! Red on main: both refusal tests (the batch commits Ok). Guard (passes on
//! main too): the live-id put.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test batch_put_over_hard_delete_marker` (public paths
//! only).

use std::sync::Arc;

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{DeleteReason, EntityId, TimeRange, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn open_vault(dir: &std::path::Path) -> TestResult<Vault> {
    let vault = Vault::open(dir, VaultConfig::device())?;
    // A hard delete signs its redaction receipt with this install's key.
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    Ok(vault)
}

/// Puts one PERSON row through the public batch door and commits it.
fn put_person(vault: &Vault, id: EntityId, body: &[u8]) -> oneiron::Result<()> {
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            body,
        )
        .commit()
}

/// A batch put at a hard-deleted id is refused, and the row keeps reading
/// deleted. On main the batch commits Ok and the body reads deleted forever.
#[test]
fn batch_put_at_hard_deleted_id_is_refused_and_row_stays_deleted() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let id = EntityId::now();
    put_person(&vault, id, b"human")?;
    assert_eq!(
        vault.get(&id)?.as_deref(),
        Some(b"human".as_slice()),
        "the seeded person reads live"
    );

    let outcome = vault.delete_entity_with_reason(&id, DeleteReason::UserHardDelete)?;
    assert!(outcome.existed, "the seeded person exists to delete");
    assert_eq!(vault.get(&id)?, None, "a hard-deleted row reads deleted");

    let refused = put_person(&vault, id, b"human-again");
    assert!(
        matches!(&refused, Err(error) if error.to_string().contains("hard-deleted")),
        "a batch put at a hard-deleted id was not refused: {refused:?}"
    );
    assert_eq!(
        vault.get(&id)?,
        None,
        "the row still reads deleted after the refused put"
    );
    Ok(())
}

/// A batch holding a put at a hard-deleted id aborts whole: the live id put
/// beside it is not written either. On main the batch commits Ok.
#[test]
fn batch_with_put_at_hard_deleted_id_aborts_whole_batch() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let dead = EntityId::now();
    let live = EntityId::now();
    put_person(&vault, dead, b"human")?;
    vault.delete_entity_with_reason(&dead, DeleteReason::UserHardDelete)?;

    let refused = vault
        .batch()
        .put(
            &live,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .put(
            &dead,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human-again",
        )
        .commit();
    assert!(
        matches!(&refused, Err(error) if error.to_string().contains("hard-deleted")),
        "a batch holding a put at a hard-deleted id was not refused: {refused:?}"
    );
    assert_eq!(
        vault.get(&live)?,
        None,
        "the aborted batch wrote nothing, not even its live put"
    );
    Ok(())
}

/// A batch put at a live id commits as today: the refusal above must not
/// spread to ids no hard-delete marker holds.
#[test]
fn batch_put_at_live_id_still_commits() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let id = EntityId::now();
    put_person(&vault, id, b"human")?;
    assert_eq!(
        vault.get(&id)?.as_deref(),
        Some(b"human".as_slice()),
        "a batch put at a live id commits"
    );
    Ok(())
}
