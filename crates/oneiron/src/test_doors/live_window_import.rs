//! L7-45 (ARCH-0023b `#tombstone-index-built`, the H15 follow-up): a forward
//! pass over a window document other threads reach, and a peer import into
//! that document from another thread, landing just after the pass built its
//! tombstone index.

use std::cell::{Cell, RefCell};
use std::path::Path;
use std::rc::Rc;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use loro::LoroDoc;

use crate::Vault;
use crate::config::VaultConfig;
use crate::deletion::TombstoneReason;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_TURN;
use crate::sync::WindowKey;
use crate::sync::bridge::Materializer;
use crate::sync::loro_support::{export_snapshot, map_insert_bytes};
use crate::sync::window::{arm_index_built_hook, forward_rematerialize, import_into_live_window};

const LEARNED_AT: u64 = 1_771_027_200;
const WINDOW: &str = "2026-02";

/// What one forward pass wrote while a peer import raced it.
pub struct RacedPass {
    /// Rows the raced pass reports written.
    pub rows_written: u32,
    /// Rows the same pass reports over the window's own carrier alone.
    pub rows_written_alone: u32,
    /// The window's own carrier is a row after the pass.
    pub resident_landed: bool,
    /// The peer's carrier is a row after the pass and the import.
    pub tombstoned_landed: bool,
    /// The import had landed when the pass went on to read its carriers.
    pub import_landed_mid_pass: bool,
    /// The import landed at all.
    pub import_landed: bool,
}

fn carrier_blob(body: &str) -> Vec<u8> {
    let mut blob = vec![ENTITY_TYPE_TURN];
    for _ in 0..3 {
        blob.extend_from_slice(&LEARNED_AT.to_be_bytes());
    }
    blob.extend_from_slice(body.as_bytes());
    blob
}

/// A v2 tombstone value: `[reason:1][deleted_at:8 LE][request_id:16]`.
fn hard_tombstone() -> Vec<u8> {
    let mut value = vec![TombstoneReason::UserHardDelete.wire_byte()];
    value.extend_from_slice(&(LEARNED_AT + 60).to_le_bytes());
    value.extend_from_slice(&[0xAE; 16]);
    value
}

/// A window document holding one carrier of its own.
fn resident_window(resident: EntityId) -> Result<LoroDoc> {
    let doc = LoroDoc::new();
    map_insert_bytes(
        &doc.get_map("entities"),
        &resident.to_hex(),
        &carrier_blob("resident"),
    )?;
    doc.commit();
    Ok(doc)
}

/// A peer's bytes: a carrier and, in the same import, its hard tombstone
/// under an UPPERCASE alias of its id. A pass's tombstone index reads such
/// an alias from a snapshot taken when the index is built; lowercase keys it
/// reads live.
fn peer_import(tombstoned: EntityId) -> Result<Vec<u8>> {
    let peer = LoroDoc::new();
    map_insert_bytes(
        &peer.get_map("entities"),
        &tombstoned.to_hex(),
        &carrier_blob("tombstoned"),
    )?;
    let alias = tombstoned.to_hex().to_uppercase();
    if alias == tombstoned.to_hex() {
        return Err(Error::InvariantViolation("the alias must differ in case"));
    }
    map_insert_bytes(&peer.get_map("tombstones"), &alias, &hard_tombstone())?;
    peer.commit();
    export_snapshot(&peer)
}

/// Runs one forward pass over a window holding one carrier of its own in a
/// fresh vault under `dir`. As the pass has built its tombstone index, another
/// thread imports a peer carrier and its uppercase-alias tombstone through the
/// live-window import, and the pass waits up to `wait` for that import before
/// it reads its carriers. A second vault runs the same pass with no import, for
/// the rows the pass writes over the resident carrier alone.
pub fn forward_pass_meets_peer_import(dir: &Path, wait: Duration) -> Result<RacedPass> {
    let resident = EntityId::from_hex(&format!("cafe{:028x}", 1))?;
    let tombstoned = EntityId::from_hex(&format!("cafe{:028x}", 2))?;
    let key = WindowKey::new(WINDOW);

    for vault_dir in ["alone", "raced"] {
        std::fs::create_dir_all(dir.join(vault_dir))
            .map_err(|_| Error::InvariantViolation("the vault directory could not be made"))?;
    }
    let alone = Vault::open(&dir.join("alone"), VaultConfig::device())?;
    let rows_written_alone = forward_rematerialize(
        &alone,
        &resident_window(resident)?,
        &Materializer::new(),
        &key,
    )?;

    let vault = Vault::open(&dir.join("raced"), VaultConfig::device())?;
    let doc = resident_window(resident)?;
    let materializer = Arc::new(Materializer::new());
    let bytes = peer_import(tombstoned)?;
    let mid_pass = Rc::new(Cell::new(false));
    let importer = Rc::new(RefCell::new(None));
    {
        let (materializer, doc) = (Arc::clone(&materializer), doc.clone());
        let (mid_pass, importer) = (Rc::clone(&mid_pass), Rc::clone(&importer));
        arm_index_built_hook(move || {
            let (landed_tx, landed_rx) = mpsc::channel();
            let handle = std::thread::spawn(move || {
                let landed = import_into_live_window(&materializer, &doc, &bytes).is_ok();
                let _ = landed_tx.send(());
                landed
            });
            mid_pass.set(landed_rx.recv_timeout(wait).is_ok());
            *importer.borrow_mut() = Some(handle);
        });
    }
    let rows_written = forward_rematerialize(&vault, &doc, &materializer, &key)?;
    let handle = importer
        .borrow_mut()
        .take()
        .ok_or(Error::InvariantViolation(
            "the pass never ran its index hook",
        ))?;
    let import_landed = handle
        .join()
        .map_err(|_| Error::InvariantViolation("the import thread panicked"))?;
    Ok(RacedPass {
        rows_written,
        rows_written_alone,
        resident_landed: vault.get_raw(&resident)?.is_some(),
        tombstoned_landed: vault.get_raw(&tombstoned)?.is_some(),
        import_landed_mid_pass: mid_pass.get(),
        import_landed,
    })
}
