//! Primitive A, slice 6.4b (SLICE6-MAP row A; ENGINE CALL S64; lead 19:4x
//! S64-2-SETTINGS): `vault.snapshot.open` and `vault.snapshot.page` serve the
//! caller's rows a page at a time, each with its source version, under the
//! owner's bounds; a page is current as of its own call.
//!
//! Public paths only: the generated engine fns in `oneiron::verbs`.

use oneiron::memory::{Memory, MemoryResult, WitnessAssertions};
use oneiron::settings::snapshot_read::SnapshotReadSettings;
use oneiron::snapshot_read::{
    SnapshotHandle, SnapshotKind, SnapshotOpenRequest, SnapshotPage, SnapshotPageRequest,
};
use oneiron::store::GateDecisionId;
use oneiron::{
    EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WitnessAuthor, WitnessMessage,
    WitnessTurn,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PERSON: u8 = oneiron::registry::ENTITY_TYPE_PERSON;

fn open_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    Ok((dir, vault))
}

fn put_person(vault: &Vault, learned_at: u64) -> Result<EntityId, Box<dyn std::error::Error>> {
    let id = EntityId::now();
    vault.put_entity(
        &id,
        PERSON,
        TimeRange { start: 1, end: 1 },
        learned_at,
        b"a person",
    )?;
    Ok(id)
}

fn snapshot(memory: &Memory<'_>, kinds: Vec<SnapshotKind>) -> MemoryResult<SnapshotHandle> {
    oneiron::verbs::vault_snapshot_open(
        memory,
        SnapshotOpenRequest {
            kinds,
            filter: None,
            lifetime_secs: None,
        },
    )
}

fn page(
    memory: &Memory<'_>,
    handle: &SnapshotHandle,
    cursor: Option<String>,
    limit: Option<u32>,
) -> MemoryResult<SnapshotPage> {
    Ok(oneiron::verbs::vault_snapshot_page(
        memory,
        SnapshotPageRequest {
            handle: handle.handle,
            cursor,
            limit,
        },
    )?
    .value)
}

fn replace_bounds(vault: &Vault, owner: EntityId, bounds: SnapshotReadSettings) -> TestResult {
    let auth = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    vault.replace_snapshot_read_settings_as_owner(&auth, bounds)?;
    Ok(())
}

#[test]
fn a_snapshot_pages_versioned_rows_and_marks_the_rows_learned_after_its_open() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let turn = memory
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: None,
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: "hello there".to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: 900,
            assertions: WitnessAssertions::default(),
        })?
        .turn_id;
    let before = put_person(&vault, 1)?;
    let handle = snapshot(
        &memory,
        vec![
            SnapshotKind::Turn,
            SnapshotKind::Entity {
                entity_type: PERSON,
            },
        ],
    )?;
    let later = put_person(
        &vault,
        vault
            .latest_learned_at()?
            .unwrap_or(0)
            .saturating_add(1_000),
    )?;

    let mut rows = Vec::new();
    let mut cursor = None;
    loop {
        let served = page(&memory, &handle, cursor, None)?;
        rows.extend(served.rows);
        match served.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    let row = |id: EntityId| rows.iter().find(|row| row.version.entity == id);
    let turn_row = row(turn).expect("the TURN is paged");
    assert_eq!(turn_row.text.as_deref(), Some("hello there"));
    assert!(turn_row.version.projection.is_some());
    assert!(!turn_row.changed_since_open);
    assert!(
        !row(before)
            .expect("the earlier row is paged")
            .changed_since_open
    );
    // A page is current as of its own call: a row learned after the open is
    // served, marked.
    assert!(
        row(later)
            .expect("the later row is paged")
            .changed_since_open
    );
    Ok(())
}

#[test]
fn a_changed_rows_per_page_setting_takes_effect_on_the_next_page() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    for learned_at in 1..=5 {
        put_person(&vault, learned_at)?;
    }
    let handle = snapshot(
        &memory,
        vec![SnapshotKind::Entity {
            entity_type: PERSON,
        }],
    )?;

    replace_bounds(
        &vault,
        owner,
        SnapshotReadSettings {
            page_rows: 2,
            ..SnapshotReadSettings::DEFAULT
        },
    )?;
    let first = page(&memory, &handle, None, None)?;
    assert_eq!(first.rows.len(), 2);
    let next = first.next.expect("three rows are left");

    replace_bounds(
        &vault,
        owner,
        SnapshotReadSettings {
            page_rows: 3,
            ..SnapshotReadSettings::DEFAULT
        },
    )?;
    let second = page(&memory, &handle, Some(next), None)?;
    assert_eq!(second.rows.len(), 3, "the next page reads the new bound");
    assert_eq!(second.served, 5);

    // The owner's setter refuses a zero bound and a default above the most.
    let auth = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    assert!(
        vault
            .replace_snapshot_read_settings_as_owner(
                &auth,
                SnapshotReadSettings {
                    page_rows: 0,
                    ..SnapshotReadSettings::DEFAULT
                }
            )
            .is_err()
    );
    assert!(
        vault
            .replace_snapshot_read_settings_as_owner(
                &auth,
                SnapshotReadSettings {
                    default_lifetime_secs: 7_200,
                    max_lifetime_secs: 3_600,
                    ..SnapshotReadSettings::DEFAULT
                }
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn a_handle_serves_only_its_opener_within_the_owners_bounds() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    put_person(&vault, 1)?;
    let stranger = put_person(&vault, 2)?;
    let theirs = vault.memory(stranger, EdgeActorClass::Human);

    let handle = snapshot(
        &memory,
        vec![SnapshotKind::Entity {
            entity_type: PERSON,
        }],
    )?;
    assert!(
        page(&theirs, &handle, None, None).is_err(),
        "a handle is its opener's"
    );

    replace_bounds(
        &vault,
        owner,
        SnapshotReadSettings {
            open_per_actor: 1,
            ..SnapshotReadSettings::DEFAULT
        },
    )?;
    assert!(
        snapshot(&memory, vec![SnapshotKind::Claim]).is_err(),
        "the owner's most open handles per actor hold"
    );

    // A handle ends at its lifetime.
    replace_bounds(&vault, owner, SnapshotReadSettings::DEFAULT)?;
    let brief = oneiron::verbs::vault_snapshot_open(
        &memory,
        SnapshotOpenRequest {
            kinds: vec![SnapshotKind::Note],
            filter: None,
            lifetime_secs: Some(1),
        },
    )?;
    std::thread::sleep(std::time::Duration::from_millis(2_100));
    assert!(
        page(&memory, &brief, None, None).is_err(),
        "an ended handle serves nothing"
    );
    Ok(())
}

#[test]
fn a_caller_is_paged_only_the_rows_it_reads() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: None,
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: "the owner's words".to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: 900,
            assertions: WitnessAssertions::default(),
        })?;
    let stranger = put_person(&vault, 1)?;
    let theirs = vault.memory(stranger, EdgeActorClass::Human);
    let handle = snapshot(&theirs, vec![SnapshotKind::Turn])?;
    let served = page(&theirs, &handle, None, None)?;
    assert!(
        served.rows.is_empty(),
        "a TURN the caller does not read is never paged"
    );
    assert_eq!(served.next, None);
    Ok(())
}

#[test]
fn a_row_written_after_the_open_is_marked_whatever_learned_time_it_names() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let before = put_person(&vault, 5)?;
    let handle = snapshot(
        &memory,
        vec![SnapshotKind::Entity {
            entity_type: PERSON,
        }],
    )?;
    // A writer names its own learned time: one below the open's is still a
    // write since the open, as the change log records it.
    let later = put_person(&vault, 1)?;
    let served = page(&memory, &handle, None, None)?;
    let row = |id: EntityId| served.rows.iter().find(|row| row.version.entity == id);
    assert!(
        !row(before)
            .expect("the earlier row is paged")
            .changed_since_open
    );
    assert!(
        row(later)
            .expect("the later row is paged")
            .changed_since_open
    );
    Ok(())
}

#[test]
fn a_row_larger_than_the_bytes_per_page_is_named_and_not_served() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let mut mine = Vec::new();
    for learned_at in 1..=3 {
        mine.push(put_person(&vault, learned_at)?);
    }
    replace_bounds(
        &vault,
        owner,
        SnapshotReadSettings {
            page_bytes: 16,
            ..SnapshotReadSettings::DEFAULT
        },
    )?;
    let handle = snapshot(
        &memory,
        vec![SnapshotKind::Entity {
            entity_type: PERSON,
        }],
    )?;
    let served = page(&memory, &handle, None, None)?;
    assert!(served.rows.is_empty(), "no row fits 16 bytes");
    // The vault's own seeded PERSON rows are named too, beside these three.
    for id in &mine {
        assert!(served.oversized.iter().any(|row| row.entity == *id));
    }
    assert!(served.oversized.iter().all(|row| row.bytes > 16));
    assert_eq!(served.next, None, "the cursor moved past every named row");
    assert_eq!(served.served, 0);
    Ok(())
}
