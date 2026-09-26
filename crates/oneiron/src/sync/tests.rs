//! Observer B and forward rematerialization admit through one entity-ingest entry and one
//! tombstone classification: the same values through either pass commit the same rows.

use std::sync::Arc;

use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::config::VaultConfig;
use crate::deletion::{TombstoneReason, TombstoneValueV2};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::identity_topology::{StoredIdentityOpAction, StoredIdentityOpEvent};
use crate::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT};
use crate::sync::bridge::{Materializer, register_observer_b};
use crate::sync::ingest::{IngestCtx, ingest_entity_in_savepoint};
use crate::sync::loro_support::map_insert_bytes;
use crate::sync::quarantine::{QuarantineContainer, quarantined_records};
use crate::sync::schema::create_window_doc;
use crate::sync::types::WindowKey;
use crate::sync::window::forward_rematerialize;
use crate::temporal::TimeRange;
use crate::test_util::row_dump::{RowChange, changed_rows, dump_rows};
use crate::vault::Vault;

const WINDOW: &str = "2026-03";

/// A vault on a manual clock with a fixed device signing key, so two vaults given the same
/// writes store the same bytes (a replayed hard delete signs its local receipt).
fn deterministic_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let mut config = VaultConfig::device();
    config.store_clock = crate::ports::ManualClock::new(1_772_400_000).bundle();
    let (dir, vault) = crate::test_util::open_test_vault_with(config);
    let device = ed25519_dalek::SigningKey::from_bytes(&[0x2d; 32]);
    vault
        .with_write_txn(|txn| {
            let store = &vault.store;
            store
                .sync_state
                .put(txn, crate::identity::KEY_DEVICE_SK, device.as_bytes())?;
            store.sync_state.put(
                txn,
                crate::identity::KEY_DEVICE_PK,
                &device.verifying_key().to_bytes(),
            )?;
            Ok(())
        })
        .expect("fixed device key");
    (dir, Arc::new(vault))
}

fn id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("fixture id")
}

fn stamp() -> u64 {
    WindowKey::new(WINDOW)
        .start_timestamp()
        .expect("window start")
        + 60
}

fn entity_blob(entity_type: u8, at: u64, body: &[u8]) -> Vec<u8> {
    let mut blob = vec![entity_type];
    for field in [at, at, at] {
        blob.extend_from_slice(&field.to_be_bytes());
    }
    blob.extend_from_slice(body);
    blob
}

/// A structurally valid type-76 merge event over participants this vault has not seen: the
/// ledger door admits it, and it is a delete-protected engine record.
fn identity_topology_blob() -> Result<Vec<u8>> {
    let record = StoredIdentityOpEvent {
        seq: 50,
        at: 200,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Merge {
            sources: vec![id(0x61)],
            survivor: id(0x62),
        },
    };
    let body = crate::identity_topology::encode_identity_topology_event_body(&record)?;
    Ok(entity_blob(
        ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
        record.at,
        &body,
    ))
}

fn tombstone(reason: TombstoneReason) -> Vec<u8> {
    TombstoneValueV2 {
        reason,
        deleted_at: stamp(),
        request_id: [0x5a; 16],
    }
    .encode()
    .to_vec()
}

/// The values one window carries: entities-map rows, then tombstones-map rows.
struct WindowValues {
    entities: Vec<(String, Vec<u8>)>,
    tombstones: Vec<(String, Vec<u8>)>,
}

/// Live sync: Observer B sees the entities commit, then the tombstones commit, in the order
/// forward rematerialization runs its passes.
fn through_observer_b(vault: &Arc<Vault>, values: &WindowValues) -> Result<Vec<RowChange>> {
    let before = dump_rows(vault);
    let doc = create_window_doc("remote", &WindowKey::new(WINDOW));
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, vault, &materializer, WINDOW);
    for (map, rows) in [
        ("entities", &values.entities),
        ("tombstones", &values.tombstones),
    ] {
        if rows.is_empty() {
            continue;
        }
        for (key, value) in rows {
            map_insert_bytes(&doc.get_map(map), key, value)?;
        }
        doc.commit();
    }
    Ok(changed_rows(&before, &dump_rows(vault)))
}

/// Startup recovery: forward rematerialization over a window document holding every value.
fn through_forward_remat(vault: &Arc<Vault>, values: &WindowValues) -> Result<Vec<RowChange>> {
    let before = dump_rows(vault);
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("remote", &window_key);
    for (key, value) in &values.entities {
        map_insert_bytes(&doc.get_map("entities"), key, value)?;
    }
    for (key, value) in &values.tombstones {
        map_insert_bytes(&doc.get_map("tombstones"), key, value)?;
    }
    doc.commit();
    forward_rematerialize(vault, &doc, &Materializer::new(), &window_key)?;
    Ok(changed_rows(&before, &dump_rows(vault)))
}

/// The entry itself, in a caller-owned write transaction.
fn through_the_entry(vault: &Arc<Vault>, values: &WindowValues) -> Result<Vec<RowChange>> {
    assert!(values.tombstones.is_empty(), "the entry ingests entities");
    let before = dump_rows(vault);
    let doc = create_window_doc("remote", &WindowKey::new(WINDOW));
    let tombstones = doc.get_map("tombstones");
    let ingest = IngestCtx::new(
        vault,
        WINDOW,
        crate::sync::lease::DEFAULT_LEASE_VAULT_ID,
        &tombstones,
    );
    vault.with_write_txn(|wtxn| {
        for (key, value) in &values.entities {
            ingest_entity_in_savepoint(&ingest, wtxn, key, Some(value))?;
        }
        Ok(())
    })?;
    Ok(changed_rows(&before, &dump_rows(vault)))
}

fn put_event(vault: &Vault, entity: &EntityId, body: &[u8]) -> Result<()> {
    let at = stamp();
    vault
        .batch()
        .put(
            entity,
            ENTITY_TYPE_EVENT,
            TimeRange { start: at, end: at },
            at,
            body,
        )
        .commit()
}

/// Local state both twin vaults hold before the values arrive.
type Seed = fn(&Vault) -> Result<()>;

/// One way a window's values reach LMDB; returns the rows it committed.
type Pass = fn(&Arc<Vault>, &WindowValues) -> Result<Vec<RowChange>>;

/// One scenario: what the vaults hold first, and what the window carries.
struct Case {
    name: &'static str,
    seed: Option<Seed>,
    values: WindowValues,
}

impl Case {
    fn entities(name: &'static str, seed: Option<Seed>, key: String, blob: Vec<u8>) -> Self {
        Self {
            name,
            seed,
            values: WindowValues {
                entities: vec![(key, blob)],
                tombstones: Vec::new(),
            },
        }
    }

    /// Runs the values through each pass on twin vaults seeded alike and returns what each
    /// pass committed, in pass order.
    fn committed_by(&self, passes: &[Pass]) -> Result<Vec<Vec<RowChange>>> {
        passes
            .iter()
            .map(|pass| {
                let (_dir, vault) = deterministic_vault();
                if let Some(seed) = self.seed {
                    seed(&vault)?;
                }
                pass(&vault, &self.values)
            })
            .collect()
    }
}

#[test]
fn window_and_bridge_ingest_one_entity_through_one_entry() -> Result<()> {
    let row = id(0x31).to_hex();
    let blob = entity_blob(ENTITY_TYPE_EVENT, stamp(), b"one replicated row");
    let cases = [
        (
            Case::entities("a new row materializes", None, row.clone(), blob.clone()),
            true,
        ),
        (
            Case::entities(
                "an echo of the local row writes nothing",
                Some(|vault| put_event(vault, &id(0x31), b"one replicated row")),
                row.clone(),
                blob.clone(),
            ),
            false,
        ),
        (
            // Observer B now keeps the shell too: `user_delete` wrote no CRDT record, so the
            // carrier still holds the pre-delete body.
            Case::entities(
                "a local SoftErase shell keeps its delete over the longer carrier body",
                Some(|vault| {
                    put_event(vault, &id(0x31), b"one replicated row")?;
                    vault.apply_replayed_tombstone(
                        &id(0x31),
                        &tombstone(TombstoneReason::UserDelete),
                    )?;
                    Ok(())
                }),
                row,
                blob,
            ),
            false,
        ),
        (
            Case::entities(
                "a delete-protected ledger event takes its own door",
                None,
                id(0x70).to_hex(),
                identity_topology_blob()?,
            ),
            true,
        ),
    ];
    for (case, writes) in cases {
        let committed =
            case.committed_by(&[through_observer_b, through_forward_remat, through_the_entry])?;
        let [bridge, window, entry] = committed.as_slice() else {
            unreachable!("three passes");
        };
        let name = case.name;
        assert_eq!(
            bridge, window,
            "{name}: Observer B and forward remat commit the same rows"
        );
        assert_eq!(
            bridge, entry,
            "{name}: both passes commit what the entry commits"
        );
        assert_eq!(!bridge.is_empty(), writes, "{name}: {bridge:?}");
    }
    Ok(())
}

#[test]
fn a_tombstone_takes_one_path_in_either_pass() -> Result<()> {
    let row = id(0x41);
    let event = id(0x70);
    let seed_row: Seed = |vault| put_event(vault, &id(0x41), b"a row a peer deletes");
    let protected = || -> Result<WindowValues> {
        Ok(WindowValues {
            entities: vec![(event.to_hex(), identity_topology_blob()?)],
            tombstones: vec![(event.to_hex(), 200_u64.to_be_bytes().to_vec())],
        })
    };
    let tombstone_only = |key: String, value: Vec<u8>| WindowValues {
        entities: Vec::new(),
        tombstones: vec![(key, value)],
    };
    let cases = [
        Case {
            name: "a hard tombstone purges the local row",
            seed: Some(seed_row),
            values: tombstone_only(row.to_hex(), tombstone(TombstoneReason::UserHardDelete)),
        },
        Case {
            name: "a soft tombstone keeps the local shell",
            seed: Some(seed_row),
            values: tombstone_only(row.to_hex(), tombstone(TombstoneReason::UserDelete)),
        },
        Case {
            name: "a tombstone whose key names no entity is refused",
            seed: None,
            values: tombstone_only(
                "not-an-entity".to_owned(),
                tombstone(TombstoneReason::UserHardDelete),
            ),
        },
        Case {
            name: "a tombstone over a delete-protected row is refused once",
            seed: None,
            values: protected()?,
        },
    ];
    for case in cases {
        let committed = case.committed_by(&[through_observer_b, through_forward_remat])?;
        let [bridge, window] = committed.as_slice() else {
            unreachable!("two passes");
        };
        let name = case.name;
        assert_eq!(bridge, window, "{name}: both passes commit the same rows");
        assert!(!bridge.is_empty(), "{name}: the tombstone leaves a row");
    }

    // The refusal rows themselves: one `x:` row per refused tombstone, in either pass.
    let passes: [Pass; 2] = [through_observer_b, through_forward_remat];
    for pass in passes {
        let (_dir, vault) = deterministic_vault();
        pass(&vault, &protected()?)?;
        let refused = quarantined_records(&vault)?;
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_eq!(refused[0].1.container, QuarantineContainer::Tombstones);
        assert_eq!(refused[0].1.reason_code, "MaintenanceKindNotWritable");
        assert!(vault.get_raw(&event)?.is_some());
    }
    Ok(())
}
