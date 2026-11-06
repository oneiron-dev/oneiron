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
//! (`peer_import`), and the door reads that record before it mints. That map
//! and the row are two LWW registers, so a race can leave a peer's bytes with
//! no origin beside them (FIX 12113): the lane also asks for the writer's
//! proof of the exact bytes (`message_writer`), which the import carries in
//! the window beside the row, and names the machine that proof verifies.
//! That proof is durable, so a later window pass that retries a row the
//! import left waiting on a dependency (FIX 20830) reads it from the window
//! and mints the lane again for the exact bytes it verifies. A trusted
//! recovery pass and a ladder run outside a window's own passes mint none.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
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
/// wrote its exact bytes and another sent them, over a connection that
/// proved the sender (FIX 9600, FIX 12113). Only an own-device import's span
/// mints one, in the door that lands the row, and it vouches for that row's
/// body alone. It names the machine whose writer proof verified, the machine
/// that wrote the row, not the home that relayed it nor the actor who spoke.
#[derive(Debug)]
pub(crate) struct VerifiedOwnDeviceLane {
    machine: EntityId,
    row: EntityId,
    /// The blake3 digest of the body the row's put lands.
    body: [u8; 32],
    /// The writer proof that verified, which the put records so this
    /// machine passes it on beside the row.
    proof: Vec<u8>,
    /// The actor the row's `AuthoredBy` edge names in the window the import
    /// landed, when it names exactly one (FIX 9600): the author a companion
    /// row is judged by. The edge lands in a later pass than the row; the
    /// import brought both at once.
    authored_by: Option<EntityId>,
}

impl VerifiedOwnDeviceLane {
    /// The own machine that wrote `data` as the body of row `id`, or `None`
    /// when this lane vouches for another row or other bytes.
    pub(crate) fn machine_for(&self, id: &EntityId, data: &[u8]) -> Option<EntityId> {
        (self.row == *id && self.body == digest(data)).then_some(self.machine)
    }

    /// The actor this lane's row's window names as its author, if one.
    pub(crate) fn authored_by(&self) -> Option<EntityId> {
        self.authored_by
    }

    /// The writer proof of row `id` with body `data`, or `None` when this
    /// lane vouches for another row or other bytes.
    pub(crate) fn proof_for(&self, id: &EntityId, data: &[u8]) -> Option<&[u8]> {
        (self.row == *id && self.body == digest(data)).then_some(self.proof.as_slice())
    }
}

thread_local! {
    static OWN_DEVICE_SPAN: RefCell<Option<OwnDeviceSpan>> = const { RefCell::new(None) };
}

/// One own-device import's span: the vault and window it lands in, the own
/// machine that sent it, and each MESSAGE row its own bytes insert, with the
/// digest of the whole entity blob it inserts and the writer proof the
/// window carries beside it once the import lands, if any.
struct OwnDeviceSpan {
    vault: PathBuf,
    window: String,
    machine: EntityId,
    rows: BTreeMap<(EntityId, [u8; 32]), Option<Vec<u8>>>,
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
/// import, no door `land` runs mints one from a span, whatever import
/// encloses it; a row whose window carries a writer proof that verifies is
/// the writer's either way (FIX 20830).
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
/// document is `doc`, with the digest of the bytes it inserts and the writer
/// proof the window carries beside the row once `update` lands: a snapshot's
/// rows as it holds them, an update's as its own operations write them, not
/// those of another import its operations complete. An update that does not
/// decode, or whose history `doc` lacks, inserts none here; its import fails.
/// An update forks `doc` to read its operations only when it may insert a
/// MESSAGE row at all ([`may_insert_message`]).
fn inserted_messages(
    key: &WindowKey,
    doc: &LoroDoc,
    update: &[u8],
) -> BTreeMap<(EntityId, [u8; 32]), Option<Vec<u8>>> {
    let Ok(meta) = LoroDoc::decode_import_blob_meta(update, true) else {
        return BTreeMap::new();
    };
    let mut rows = BTreeSet::new();
    let mut note = |key: &str, blob: &[u8]| {
        if is_message(blob)
            && let Ok(id) = EntityId::from_hex(key)
        {
            rows.insert((id, digest(blob)));
        }
    };
    // The window as it stands once the import lands: the writer proofs beside
    // the rows are read there, whichever import brought them.
    let mut landed = None;
    if meta.mode.is_snapshot() {
        if let Ok(sent) = LoroDoc::from_snapshot(update) {
            map_for_each_value_bytes(&sent.get_map("entities"), |key, blob| {
                if let Some(blob) = blob {
                    note(key, blob);
                }
            });
            landed = Some(sent);
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
            landed = Some(candidate);
        }
    }
    rows.into_iter()
        .map(|row| {
            let proof = landed
                .as_ref()
                .and_then(|landed| super::message_writer::carried_proof(landed, &row.0));
            (row, proof)
        })
        .collect()
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

/// The lane of the MESSAGE row `blob` at `id`, whose put lands `data`: the
/// writer proof the window `ctx` lands carries beside these exact bytes
/// verifies (FIX 12113), and no federation peer's import brought them. An
/// own-device import on this thread that brought them names its proof; a
/// window pass that retries the row reads it from the window (FIX 20830). A
/// trusted recovery pass, a ladder run outside a window's own passes, a put
/// of other bytes than the ones in the window, and a row with no proof that
/// verifies take none.
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
    let relayed = OWN_DEVICE_SPAN.with(|slot| {
        slot.borrow()
            .as_ref()
            .filter(|span| span.vault == vault && span.window == ctx.window_key)
            .and_then(|span| {
                span.rows
                    .get(&sent)
                    .map(|proof| (span.machine, proof.clone()))
            })
    });
    // A row this import did not bring, one a later pass retries after it
    // waited on a dependency or an older operation this import completed, is
    // the writer's on the proof its window carries for these exact bytes
    // (FIX 20830): the proof, not a live connection, says an own machine
    // wrote them.
    let (relay, proof) = match relayed {
        Some((relay, proof)) => (Some(relay), proof),
        None => (
            None,
            ctx.carrier_doc()
                .and_then(|doc| super::message_writer::carried_proof(doc, id)),
        ),
    };
    if relay.is_none() && proof.is_none() {
        return Ok(None);
    }
    // A federation peer's row stays the peer's, whichever own machine relays
    // it: the origin its window carries for these bytes is recorded by now.
    if super::peer_row_in_txn(ctx.vault, wtxn, ctx.window_key, id, blob)? {
        return Ok(None);
    }
    // And only the machine that wrote these exact bytes vouches for them: a
    // connection proves who relayed them, never who wrote them.
    let writer = match &proof {
        Some(proof) => {
            super::message_writer::verified_writer_in_txn(ctx.vault, wtxn, id, blob, proof)?
        }
        None => None,
    };
    let (Some(machine), Some(proof)) = (writer, proof) else {
        tracing::debug!(
            ?relay,
            "a MESSAGE row in a window pass with no writer proof that verifies"
        );
        return Ok(None);
    };
    let authored_by = match ctx.residence {
        Some(Residence::Quarantine(doc) | Residence::Forward { doc, .. }) => {
            authored_by_in_window(ctx, wtxn, doc, id)?
        }
        None => None,
    };
    Ok(Some(VerifiedOwnDeviceLane {
        machine,
        row: *id,
        body: digest(data),
        proof,
        authored_by,
    }))
}

/// The actor the `AuthoredBy` edge of MESSAGE `id` names in `doc`, the
/// window the import landed, judged as the edge pass will judge that edge:
/// its carrier decodes as an `AuthoredBy` value, neither end is tombstoned
/// in the window, and the edge resides in it. `None` when no such edge is
/// there, when one of the row's author carriers does not decode, or when
/// they name more than one author: a row the edge pass would leave with no
/// author takes none here.
fn authored_by_in_window(
    ctx: &IngestCtx<'_>,
    wtxn: &heed::RwTxn<'_>,
    doc: &LoroDoc,
    id: &EntityId,
) -> Result<Option<EntityId>> {
    let mut named = None;
    let mut sound = true;
    map_for_each_value_bytes(&doc.get_map("edges"), |key, value| {
        let Some((source, kind, target)) = crate::sync::bridge::parse_edge_key(key) else {
            return;
        };
        if source != *id || kind != crate::EdgeKind::AuthoredBy {
            return;
        }
        let decodes =
            value.is_some_and(|bytes| crate::edge::decode_edge_value_for_kind(kind, bytes).is_ok());
        if !decodes || named.replace(target).is_some_and(|prior| prior != target) {
            sound = false;
        }
    });
    let Some(actor) = named.filter(|_| sound) else {
        return Ok(None);
    };
    let tombstones = crate::sync::loro_support::TombstoneIndex::build(&doc.get_map("tombstones"));
    if tombstones.contains(id) || tombstones.contains(&actor) {
        return Ok(None);
    }
    let Some(window) = WindowKey::try_new(ctx.window_key) else {
        return Ok(None);
    };
    let resides = crate::sync::types::edge_belongs_to_window_in(
        ctx.vault,
        wtxn,
        doc,
        &tombstones,
        id,
        &actor,
        &window,
    )?;
    Ok(resides.then_some(actor))
}
