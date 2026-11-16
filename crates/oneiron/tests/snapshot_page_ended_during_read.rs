//! FIX SNAPSHOT-PAGE-STALE-BOUNDS-NO-EXPIRY (UNBUILT3-36): a snapshot page is
//! judged again in the write that counts its rows. A page whose handle ended
//! while it was read, or that passes a bound the owner lowered while it was
//! read, is refused, not served. A handle's end is capped at its reader's
//! credential end, so a page served past it is served past the credential.
//!
//! Needs `--cfg oneiron_test_support`: the door
//! `test_doors::snapshot_page_accounting` runs one step between the page's
//! read and its accounting write.

use std::time::Duration;

use oneiron::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};
use oneiron::settings::snapshot_read::SnapshotReadSettings;
use oneiron::snapshot_read::{
    SnapshotHandle, SnapshotKind, SnapshotOpenRequest, SnapshotPage, SnapshotPageRequest,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::snapshot_page_accounting::before_next_page_accounting;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PERSON: u8 = oneiron::registry::ENTITY_TYPE_PERSON;

fn open_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    Ok((dir, vault))
}

/// `count` PERSON rows, so one page serves at least that many rows.
fn put_people(vault: &Vault, count: u64) -> TestResult {
    for learned_at in 1..=count {
        vault.put_entity(
            &EntityId::now(),
            PERSON,
            TimeRange { start: 1, end: 1 },
            learned_at,
            b"a person",
        )?;
    }
    Ok(())
}

fn open_people(memory: &Memory<'_>, lifetime_secs: Option<u64>) -> MemoryResult<SnapshotHandle> {
    oneiron::verbs::vault_snapshot_open(
        memory,
        SnapshotOpenRequest {
            kinds: vec![SnapshotKind::Entity {
                entity_type: PERSON,
            }],
            filter: None,
            lifetime_secs,
        },
    )
}

fn first_page(memory: &Memory<'_>, handle: &SnapshotHandle) -> MemoryResult<SnapshotPage> {
    Ok(oneiron::verbs::vault_snapshot_page(
        memory,
        SnapshotPageRequest {
            handle: handle.handle,
            cursor: None,
            limit: None,
        },
    )?
    .value)
}

/// The owner replaces the bounds with `bounds` after the next page's read and
/// before its accounting write.
fn set_bounds_during_next_read(owner: EntityId, bounds: SnapshotReadSettings) {
    before_next_page_accounting(move |vault| {
        let auth = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("the owner authenticates");
        vault
            .replace_snapshot_read_settings_as_owner(&auth, bounds)
            .expect("the owner lowers the snapshot bounds");
    });
}

fn refused_as_lowered(refused: &MemoryError) {
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert!(
        refused
            .message
            .contains("lowered the snapshot bounds while this page was read"),
        "{refused:?}"
    );
}

#[test]
fn a_page_whose_handle_ended_while_it_was_read_is_refused() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    put_people(&vault, 3)?;
    let handle = open_people(&memory, Some(3))?;

    // The handle's three seconds run out while the page is read.
    before_next_page_accounting(|_| std::thread::sleep(Duration::from_millis(4_100)));
    let refused = match first_page(&memory, &handle) {
        Ok(served) => {
            return Err(format!(
                "a page whose handle ended while it was read was served ({} rows)",
                served.rows.len()
            )
            .into());
        }
        Err(refused) => refused,
    };
    assert_eq!(refused.code, MEMORY_CODE_NOT_FOUND, "{refused:?}");
    assert!(
        refused.message.contains("ended while this page was read"),
        "{refused:?}"
    );
    // The ended handle is deleted, as the check before the read deletes it.
    let again = first_page(&memory, &handle).expect_err("an ended handle serves nothing");
    assert_eq!(again.code, MEMORY_CODE_NOT_FOUND, "{again:?}");
    assert!(
        again.message.contains("no open snapshot with this handle"),
        "{again:?}"
    );
    Ok(())
}

#[test]
fn a_page_past_rows_per_snapshot_lowered_while_it_was_read_is_refused() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    put_people(&vault, 4)?;
    let handle = open_people(&memory, None)?;

    set_bounds_during_next_read(
        owner,
        SnapshotReadSettings {
            handle_rows: 2,
            ..SnapshotReadSettings::DEFAULT
        },
    );
    match first_page(&memory, &handle) {
        Ok(served) => Err(format!(
            "a page of {} rows was served past the 2 rows per snapshot the owner set while it was read",
            served.rows.len()
        )
        .into()),
        Err(refused) => {
            refused_as_lowered(&refused);
            Ok(())
        }
    }
}

#[test]
fn a_page_past_rows_or_bytes_per_page_lowered_while_it_was_read_is_refused() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    put_people(&vault, 4)?;
    let handle = open_people(&memory, None)?;

    set_bounds_during_next_read(
        owner,
        SnapshotReadSettings {
            page_rows: 1,
            ..SnapshotReadSettings::DEFAULT
        },
    );
    match first_page(&memory, &handle) {
        Ok(served) => {
            return Err(format!(
                "a page of {} rows was served past the 1 row per page the owner set while it was read",
                served.rows.len()
            )
            .into());
        }
        Err(refused) => refused_as_lowered(&refused),
    }

    // Bytes: one served row is larger than 64 bytes (its version and view).
    set_bounds_during_next_read(
        owner,
        SnapshotReadSettings {
            page_bytes: 64,
            ..SnapshotReadSettings::DEFAULT
        },
    );
    match first_page(&memory, &handle) {
        Ok(served) => Err(format!(
            "a page of {} rows was served past the 64 bytes per page the owner set while it was read",
            served.rows.len()
        )
        .into()),
        Err(refused) => {
            refused_as_lowered(&refused);
            Ok(())
        }
    }
}

#[test]
fn a_page_within_bounds_lowered_while_it_was_read_is_served() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    put_people(&vault, 4)?;
    let handle = open_people(&memory, None)?;

    set_bounds_during_next_read(
        owner,
        SnapshotReadSettings {
            page_rows: 100,
            handle_rows: 1_000,
            ..SnapshotReadSettings::DEFAULT
        },
    );
    let served = first_page(&memory, &handle)?;
    assert!(served.rows.len() >= 4, "{} rows", served.rows.len());
    assert_eq!(
        served.served,
        u64::try_from(served.rows.len())?,
        "the page is counted against its handle"
    );
    Ok(())
}
