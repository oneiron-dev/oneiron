//! A dev vault's window can hold, in its ordinary history only, a custody row
//! from before the seal: a delete took it out of the live map before any
//! export scrub saw it, so nothing pinned the window (ARCH-0069
//! #custody-seal-planned, "custody residue from before the seal in dev
//! vaults"; census L6-27e). Custody bodies never sync (#custody-seal-built),
//! so the window's export door keeps that history from every peer: the peer
//! gets the history-free replacement, and the window is pinned history-free,
//! as the live scrub pins it. A diagnostic carrier, local-only by the same
//! rule, is held back the same way. The window's other rows still arrive.
//!
//! Public crate surface only: a window doc,
//! `sync::window::export_window_updates_since` and
//! `sync::window::history_free_window_required`.
//! `cargo test --locked -p oneiron --all-features --test legacy_custody_history_export`.
#![cfg(feature = "sync")]

use loro::json::{JsonOpContent, MapOp};
use loro::{ContainerID, ContainerType, ExportMode, LoroDoc, LoroValue, VersionVector};
use oneiron::registry::{ENTITY_TYPE_DIAGNOSTIC, ENTITY_TYPE_SECRET_CUSTODY, ENTITY_TYPE_TURN};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{self, WindowExport};
use oneiron::{EntityId, HnswConfig, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const WINDOW: &str = "2026-03";

/// What the peer holds of the window when it asks.
#[derive(Clone, Copy, Debug)]
enum Receiver {
    /// Nothing: a fresh peer.
    Empty,
    /// The window's first commit, made before the carrier landed.
    Prefix,
}

/// An entity row from literal parts: type u8, then occurred start and end,
/// learned-at and row version, each a big-endian u64, then the body.
fn entity_blob(entity_type: u8, at: u64, body: &[u8]) -> Vec<u8> {
    let mut blob = vec![entity_type];
    for part in [at, at, at, 0] {
        blob.extend_from_slice(&part.to_be_bytes());
    }
    blob.extend_from_slice(body);
    blob
}

fn insert(doc: &LoroDoc, id: &EntityId, blob: &[u8]) -> TestResult {
    doc.get_map("entities").insert(&id.to_hex(), blob)?;
    doc.commit();
    Ok(())
}

/// Every entities-map value an operation `doc` holds inserted.
fn inserted_entity_values(doc: &LoroDoc) -> Vec<Vec<u8>> {
    let entities = ContainerID::new_root("entities", ContainerType::Map);
    doc.export_json_updates(&VersionVector::default(), &doc.oplog_vv())
        .changes
        .into_iter()
        .flat_map(|change| change.ops)
        .filter(|op| op.container == entities)
        .filter_map(|op| match op.content {
            JsonOpContent::Map(MapOp::Insert {
                value: LoroValue::Binary(blob),
                ..
            }) => Some(blob.to_vec()),
            _ => None,
        })
        .collect()
}

fn live_entity(doc: &LoroDoc, id: &EntityId) -> bool {
    doc.get_map("entities").get(&id.to_hex()).is_some()
}

fn open_vault(dir: &std::path::Path) -> oneiron::Result<Vault> {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    Vault::open(dir, config)
}

#[test]
fn a_local_only_carrier_a_delete_left_in_history_never_reaches_a_peer() -> TestResult {
    let key = WindowKey::new(WINDOW);
    let at = key.start_timestamp().ok_or("window start")? + 60;
    let carriers: [(u8, &[u8]); 2] = [
        (ENTITY_TYPE_SECRET_CUSTODY, b"placeholder custody body"),
        (ENTITY_TYPE_DIAGNOSTIC, b"placeholder diagnostic body"),
    ];
    for (carrier_type, marker) in carriers {
        for receiver in [Receiver::Empty, Receiver::Prefix] {
            let case = format!("carrier type {carrier_type}, {receiver:?} receiver");
            let dir = tempfile::tempdir()?;
            let vault = open_vault(dir.path())?;
            let doc = create_window_doc("source", &key);
            doc.set_peer_id(1)?;

            // The window's first row, which a prefix receiver already holds.
            let first = EntityId::now();
            insert(
                &doc,
                &first,
                &entity_blob(ENTITY_TYPE_TURN, at, b"first row"),
            )?;
            let peer = LoroDoc::new();
            peer.set_peer_id(2)?;
            if let Receiver::Prefix = receiver {
                peer.import(&doc.export(ExportMode::all_updates())?)?;
            }

            // The pre-seal residue: inserted, then deleted before any export.
            let carrier = EntityId::now();
            let carrier_blob = entity_blob(carrier_type, at + 1, marker);
            insert(&doc, &carrier, &carrier_blob)?;
            doc.get_map("entities").delete(&carrier.to_hex())?;
            doc.commit();
            let second = EntityId::now();
            insert(
                &doc,
                &second,
                &entity_blob(ENTITY_TYPE_TURN, at + 2, b"second row"),
            )?;
            assert!(
                !window::history_free_window_required(&vault, &key)?,
                "{case}: fixture: no live carrier pinned the window"
            );
            assert!(
                inserted_entity_values(&doc).contains(&carrier_blob),
                "{case}: fixture: the carrier is in the window's history"
            );

            let export =
                window::export_window_updates_since(&vault, &key, &doc, &peer.oplog_vv().encode())?;
            let (received, bytes) = match export {
                WindowExport::Update(bytes) => {
                    let received = peer.fork();
                    received.import(&bytes)?;
                    (received, bytes)
                }
                WindowExport::Replacement(bytes) => {
                    let received = LoroDoc::new();
                    received.import(&bytes)?;
                    (received, bytes)
                }
            };

            assert!(
                !inserted_entity_values(&received).contains(&carrier_blob),
                "{case}: the carrier reached the peer in the window's history"
            );
            assert!(
                !bytes.windows(marker.len()).any(|part| part == marker),
                "{case}: the carrier's body is in the export's bytes"
            );
            assert!(
                !live_entity(&received, &carrier),
                "{case}: the carrier is live on the peer"
            );
            assert!(
                live_entity(&received, &first) && live_entity(&received, &second),
                "{case}: the window's rows reach the peer"
            );
            assert!(
                window::history_free_window_required(&vault, &key)?,
                "{case}: the residue pinned the window history-free"
            );
        }
    }
    Ok(())
}
