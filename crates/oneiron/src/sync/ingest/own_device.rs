//! The lane a replicated MESSAGE row lands in when one of the owner's own
//! machines sent it (FIX 9600, FIX 11709).
//!
//! A MESSAGE body names no signer, so its door cannot tell an own machine's
//! row from a federation peer's by the bytes alone. The import that brings
//! them can: an own-device import ([`OwnDeviceImport`]) comes from a client
//! with no federation peer bound, or into the home from an own-device
//! socket's push ([`with_own_device_push`], FIX 12112), over a connection
//! whose machine proved itself and still stands here on the key it proved.
//! While such an import runs, the doors on its thread mint a
//! [`VerifiedOwnDeviceLane`] for a MESSAGE row of the window it lands in
//! only when the import's own bytes insert that row with those exact bytes:
//! the proof covers the connection, the digest binds the row to it. A row of
//! the window the import did not bring, such as one a forward pass replays
//! from the document, takes none.
//!
//! A federation peer's row stays the peer's on whichever own machine relays
//! it: federation admission files its digest in the window's peer origin map
//! (`peer_import`), and the door reads that record before it mints. Nothing
//! here outlives the import or travels in the window: recovery, window open
//! and every later pass replay persisted bytes with no live proof of who sent
//! them, so none of them mints a lane.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::path::PathBuf;

use loro::json::{JsonOpContent, MapOp};
use loro::{ContainerID, ContainerType, ImportBlobMetadata, LoroDoc, LoroValue};

use super::entity::{IngestCtx, Residence};
use crate::authority::PeerMachine;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::Result;
use crate::registry::ENTITY_TYPE_MESSAGE;
use crate::sync::client::OwnDeviceImport;
use crate::sync::loro_support::map_for_each_value_bytes;
use crate::sync::types::WindowKey;
use crate::{EntityId, Vault};

/// A replicated MESSAGE row's proof that one of the owner's own machines
/// sent its exact bytes, over a connection that proved that machine (FIX
/// 9600). Only an own-device import's span mints one, in the door that lands
/// the row, and it vouches for that row's body alone. It names the machine
/// at the other end of that connection, the home that relayed the row, not
/// the device or actor that wrote it.
#[derive(Debug)]
pub(crate) struct VerifiedOwnDeviceLane {
    machine: EntityId,
    row: EntityId,
    /// The blake3 digest of the body the row's put lands.
    body: [u8; 32],
}

impl VerifiedOwnDeviceLane {
    /// The own machine whose proven connection sent `data` as the body of
    /// row `id`, or `None` when this lane vouches for another row or other
    /// bytes.
    #[allow(
        dead_code,
        reason = "FIX 9600: the batch put reads the lane at the witness gate"
    )]
    pub(crate) fn machine_for(&self, id: &EntityId, data: &[u8]) -> Option<EntityId> {
        (self.row == *id && self.body == digest(data)).then_some(self.machine)
    }
}

thread_local! {
    static OWN_DEVICE_SPAN: RefCell<Option<OwnDeviceSpan>> = const { RefCell::new(None) };
}

/// One own-device import's span: the vault and window it lands in, the own
/// machine that sent it, and each MESSAGE row its own bytes insert, with the
/// digest of the whole entity blob it inserts.
struct OwnDeviceSpan {
    vault: PathBuf,
    window: String,
    machine: EntityId,
    rows: BTreeSet<(EntityId, [u8; 32])>,
}

/// Puts back the span an outer import installed, on every exit.
struct Restore(Option<OwnDeviceSpan>);

impl Drop for Restore {
    fn drop(&mut self) {
        let outer = self.0.take();
        OWN_DEVICE_SPAN.with(|slot| *slot.borrow_mut() = outer);
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn is_message(blob: &[u8]) -> bool {
    EntityMetadataHeader::parse(blob)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_MESSAGE)
}

/// Runs `land`, which imports `update` into `doc`, the live document of the
/// window `key`. Under `import`, each MESSAGE row `update` itself inserts
/// takes the own-device lane in the doors `land` runs on this thread. With no
/// import, no door `land` runs mints a lane, whatever import encloses it.
pub(in crate::sync) fn with_own_device_import<T>(
    vault: &Vault,
    import: Option<&OwnDeviceImport>,
    (key, doc): (&WindowKey, &LoroDoc),
    update: &[u8],
    land: impl FnOnce() -> T,
) -> T {
    let span = import.map(|import| OwnDeviceSpan {
        vault: vault.store.env.path().to_path_buf(),
        window: key.as_str().to_owned(),
        machine: import.machine(),
        rows: inserted_messages(key, doc, update),
    });
    let _restore =
        Restore(OWN_DEVICE_SPAN.with(|slot| std::mem::replace(&mut *slot.borrow_mut(), span)));
    land()
}

/// The home's landing of `update`, a window push the machine `from` sent
/// over a socket whose upgrade proved it, into the window `key` whose live
/// document is `doc` (FIX 12112): `land` runs under that socket's own-device
/// import, rechecked now, as a client's import of its home's bytes does. A
/// machine that does not stand here on the key it proved lands it with no
/// lane. Call it only on an own-device lane: a federation socket's pushes
/// take federated admission, never this.
pub fn with_own_device_push<T>(
    vault: &Vault,
    from: PeerMachine,
    (key, doc): (&WindowKey, &LoroDoc),
    update: &[u8],
    land: impl FnOnce() -> T,
) -> T {
    let import = OwnDeviceImport::proven(vault, from);
    with_own_device_import(vault, import.as_ref(), (key, doc), update, land)
}

/// Each MESSAGE row `update` itself inserts into the window `key` whose live
/// document is `doc`, with the digest of the bytes it inserts: a snapshot's
/// rows as it holds them, an update's as its own operations write them, not
/// those of another import its operations complete. An update that does not
/// decode, or whose history `doc` lacks, inserts none here; its import fails.
/// An update forks `doc` to read its operations only when it may insert a
/// MESSAGE row at all ([`may_insert_message`]).
fn inserted_messages(
    key: &WindowKey,
    doc: &LoroDoc,
    update: &[u8],
) -> BTreeSet<(EntityId, [u8; 32])> {
    let Ok(meta) = LoroDoc::decode_import_blob_meta(update, true) else {
        return BTreeSet::new();
    };
    let mut rows = BTreeSet::new();
    let mut note = |key: &str, blob: &[u8]| {
        if is_message(blob)
            && let Ok(id) = EntityId::from_hex(key)
        {
            rows.insert((id, digest(blob)));
        }
    };
    if meta.mode.is_snapshot() {
        if let Ok(sent) = LoroDoc::from_snapshot(update) {
            map_for_each_value_bytes(&sent.get_map("entities"), |key, blob| {
                if let Some(blob) = blob {
                    note(key, blob);
                }
            });
        }
    } else if may_insert_message(key, doc, &meta) {
        let candidate = doc.fork();
        if candidate
            .import(update)
            .is_ok_and(|imported| imported.pending.is_none())
        {
            let entities = ContainerID::new_root("entities", ContainerType::Map);
            let sent = candidate.export_json_updates(&meta.partial_start_vv, &meta.partial_end_vv);
            for op in sent.changes.into_iter().flat_map(|change| change.ops) {
                if op.container == entities
                    && let JsonOpContent::Map(MapOp::Insert {
                        key,
                        value: LoroValue::Binary(blob),
                    }) = op.content
                {
                    note(&key, &blob);
                }
            }
        }
    }
    rows
}

/// Whether `update`, not a snapshot, may insert a MESSAGE row into the window
/// `key` whose live document is `doc`, read without forking `doc`. It cannot
/// when:
/// - `key` is a world's window: a MESSAGE row resides only in a base window,
///   and a world window's door refuses one (`entity_belongs_to_window`);
/// - `doc` already holds every change `update` carries, so it lands no row.
fn may_insert_message(key: &WindowKey, doc: &LoroDoc, meta: &ImportBlobMetadata) -> bool {
    key.world().is_none() && !doc.oplog_vv().includes_vv(&meta.partial_end_vv)
}

/// The lane of the MESSAGE row `blob` at `id`, whose put lands `data`: an
/// own-device import on this thread brought exactly these bytes into the
/// window `ctx` lands, and no federation peer's import brought them. A
/// trusted recovery pass, a ladder run outside a window's own passes, and a
/// put of other bytes than the ones sent take none.
pub(super) fn lane_in_txn(
    ctx: &IngestCtx<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    blob: &[u8],
    data: &[u8],
) -> Result<Option<VerifiedOwnDeviceLane>> {
    let window_pass = matches!(
        ctx.residence,
        Some(Residence::Quarantine(_) | Residence::Forward { trusted: false, .. })
    );
    if !window_pass || !is_message(blob) || blob.get(ENTITY_METADATA_HEADER_LEN..) != Some(data) {
        return Ok(None);
    }
    let sent = (*id, digest(blob));
    let vault = ctx.vault.store.env.path();
    let machine = OWN_DEVICE_SPAN.with(|slot| {
        slot.borrow().as_ref().and_then(|span| {
            (span.vault == vault && span.window == ctx.window_key && span.rows.contains(&sent))
                .then_some(span.machine)
        })
    });
    let Some(machine) = machine else {
        return Ok(None);
    };
    // A federation peer's row stays the peer's, whichever own machine relays
    // it: the origin its window carries for these bytes is recorded by now.
    if super::peer_row_in_txn(ctx.vault, wtxn, ctx.window_key, id, blob)? {
        return Ok(None);
    }
    Ok(Some(VerifiedOwnDeviceLane {
        machine,
        row: *id,
        body: digest(data),
    }))
}
