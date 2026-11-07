//! A marked repo source's copy stream on a device that holds the source
//! (FIX 10872, Engine 04:48). The source's own frames never leave (the
//! destination fence); its text crosses only as its copy lineage, under its
//! copy id, exported when it is released.
//!
//! **The home floor.** One row per stream keeps the copy vector the home
//! holds: the last one it acknowledged, raised by what each home frame
//! proves it holds. Each reply to a home frame, each acknowledgement that
//! raises the floor, and each local edit sends the lineage's operations past
//! it, brought current first with the source's copy as this device's own
//! author, never the home's. The row is also the stream's basis: before it,
//! the device writes no lineage operation, so nothing born here can share no
//! history with the home's.
//!
//! **A home frame.** An update joins the lineage; a state is staged as the
//! canonical replace stages one: the device's own lineage operations past it
//! replayed on it must cover the lineage, or nothing of it is taken. The
//! staged text lands on the source through the shipped visible diff. A ruled
//! hold takes nothing, so no later release reverts the home's text. The
//! first home frame is the basis: what it and the device each changed since
//! the marked blob are merged as concurrent edits of the blob's copy.

use heed::{RoTxn, RwTxn};
use loro::{ExportMode, LoroDoc, UpdateOptions, VersionVector};

use super::{
    BODY, SyncSecretProjection, TextBound, TextCopy, bring_current, carried, land_copy_in_txn,
    load_lineage, project_text_in_txn, save_lineage, text_copy_in_txn,
};
use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncEngineContext, SyncProtocolValidation};
use crate::origin::secret_projection::copy_id::copy_id;
use crate::origin::secret_projection::index::RepoIndexMarks;
use crate::ports::{DocumentRow, DocumentRowStore, DocumentSlot, EntityStoreRead};
use crate::sync::documents::{AD_E, storage};
use crate::sync::transport::document_sub_tags;

/// The domain a device's own copy lineage author is derived in.
const DEVICE_AUTHOR_CONTEXT: &str = "oneiron.repo-sync-projection.device-author.v1";

/// A marked repo source held here and the copy id its text crosses under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CopyStream {
    /// The marked snapshot ASSET held here.
    pub(crate) source: EntityId,
    /// Its copy id: the id every frame of the stream goes under.
    pub(crate) wire: EntityId,
}

/// What the device sends back for one home frame of a copy stream.
pub(crate) struct CopyReply {
    /// The vector to acknowledge the frame with; `None` for a frame not
    /// taken, and for an acknowledgement.
    pub(crate) ack: Option<Vec<u8>>,
    /// The lineage's operations past the home floor, to send under the copy
    /// id.
    pub(crate) update: Option<Vec<u8>>,
    /// The home holds every operation of the lineage.
    pub(crate) settled: bool,
    /// The frame was not taken and a new request is owed.
    pub(crate) retry: bool,
}

/// A home frame staged on the lineage.
struct Staged {
    /// The lineage as it is with the frame taken.
    doc: LoroDoc,
    /// What the frame proves the home holds.
    home: VersionVector,
    /// The copy text that lands on the source.
    submitted: String,
}

/// The copy stream `id` names here: `id` itself when it is a marked
/// snapshot ASSET held here, or that source's copy id. `None` for any other
/// id, and whenever the marks do not read (today's path: the source's own
/// frames stay fenced, FIX 10793).
///
/// # Errors
/// A store failure, or a copy id derivation's own failure.
pub(crate) fn copy_stream_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: EntityId,
) -> Result<Option<CopyStream>> {
    let Ok(marks) = RepoIndexMarks::read_scoped_in_txn(vault, txn) else {
        return Ok(None);
    };
    let mut source = marks.source_of(&id).map(|_| id);
    if source.is_none() {
        for (marked, _) in marks.marked_sources() {
            if copy_id(&marked)? == id {
                source = Some(marked);
                break;
            }
        }
    }
    let Some(source) = source else {
        return Ok(None);
    };
    if vault.get_entity_type_in_txn(txn, &source)? != Some(crate::registry::ENTITY_TYPE_ASSET) {
        return Ok(None);
    }
    Ok(Some(CopyStream {
        source,
        wire: copy_id(&source)?,
    }))
}

/// The vector `stream`'s request carries: its lineage's once the stream has
/// a home basis, an empty one before, so the home answers with its whole
/// copy.
///
/// # Errors
/// A store failure.
pub(crate) fn request_vector(vault: &Vault, stream: CopyStream) -> Result<Vec<u8>> {
    let txn = vault.store.env.read_txn()?;
    if home_floor_in_txn(vault, &txn, stream.wire)?.is_none() {
        return Ok(VersionVector::new().encode());
    }
    Ok(vault
        .store
        .port_document_row(
            &txn,
            DocumentSlot::of(stream.wire),
            DocumentRow::StateVector,
        )?
        .unwrap_or_else(|| VersionVector::new().encode()))
}

/// The home's frame `bytes` of `stream`, of `kind`, taken in one writer:
/// `admit` judges it first, then it is staged on the lineage (see the module
/// note) and its text lands on the source, carrying the copy's mark. A frame
/// not taken changes neither; the device's own operations past the home
/// floor still go back, so a home whose state could not cover them gets
/// them. A ruled hold keeps its held record.
///
/// # Errors
/// `admit`'s refusal, a binding that no longer stands, an unmarked or unread
/// copy, a store failure, the visible diff's own failure, or the canonical
/// writer's.
pub(crate) fn import_home_copy<F>(
    vault: &Vault,
    stream: CopyStream,
    kind: u8,
    bytes: &[u8],
    admit: F,
) -> Result<CopyReply>
where
    F: FnOnce(&mut RwTxn<'_>) -> Result<()>,
{
    let source = stream.source;
    let (reply, hold) = vault.with_write_txn_grouped(|txn| {
        admit(txn)?;
        if copy_stream_in_txn(vault, txn, stream.wire)? != Some(stream) {
            return Err(denied());
        }
        let SourceText {
            resident,
            text,
            copy,
        } = source_text_in_txn(vault, txn, source)?.ok_or(Error::InvariantViolation(
            "copy frame of an unmarked document",
        ))?;
        // An unread copy cannot be diffed: the frame is not admitted (FIX
        // 10793).
        if copy.unread() {
            return Err(Error::InvariantViolation(
                "a copy frame whose copy is unread this pass is not admitted",
            ));
        }
        let lineage = load_lineage(vault, txn, stream.wire)?;
        let floor = home_floor_in_txn(vault, txn, stream.wire)?;
        let (moved, staged) = match &floor {
            Some(_) => {
                let moved = bring_current(&lineage, &copy.copy, || {
                    device_author(vault, &*txn, &source)
                })?;
                (moved, on_basis(&lineage, kind, bytes)?)
            }
            None => (false, first_basis(vault, txn, source, &copy, bytes)?),
        };
        let Some(staged) = staged else {
            let reply = untaken(vault, txn, stream, &lineage, moved, floor.as_ref(), true)?;
            return Ok((reply, None));
        };
        if let Some(cause) = land_copy_in_txn(
            vault,
            txn,
            source,
            &resident,
            &text,
            &copy,
            &staged.submitted,
        )? {
            let reply = untaken(vault, txn, stream, &lineage, moved, floor.as_ref(), false)?;
            let (edit, _) = super::held(source, cause, bytes, VersionVector::new());
            return Ok((reply, Some(edit)));
        }
        save_lineage(vault, txn, stream.wire, &staged.doc)?;
        let floor = raise_home_floor_in_txn(vault, txn, stream.wire, floor, &staged.home)?;
        let update = pending_in_txn(vault, txn, stream, &staged.doc, &floor)?;
        Ok((
            CopyReply {
                ack: Some(staged.doc.oplog_vv().encode()),
                settled: update.is_none(),
                update,
                retry: false,
            },
            None,
        ))
    })?;
    if let Some(edit) = hold {
        let place = format!("e:{}", stream.wire.to_hex());
        super::super::held::record_held_edits(vault, &place, std::slice::from_ref(&edit))?;
    }
    Ok(reply)
}

/// The home's acknowledgement `remote` of `stream`: it raises the home
/// floor, and a raised floor sends the lineage's operations still past it.
/// Before a basis it proves no history this device shares and changes
/// nothing.
///
/// # Errors
/// A vector that does not decode, a binding that no longer stands, or a
/// store failure.
pub(crate) fn acknowledge_home_copy(
    vault: &Vault,
    stream: CopyStream,
    remote: &[u8],
) -> Result<CopyReply> {
    let remote = storage::decode_vv(remote)?;
    vault.with_write_txn_grouped(|txn| {
        if copy_stream_in_txn(vault, txn, stream.wire)? != Some(stream) {
            return Err(denied());
        }
        let quiet = CopyReply {
            ack: None,
            update: None,
            settled: false,
            retry: false,
        };
        let Some(floor) = home_floor_in_txn(vault, txn, stream.wire)? else {
            return Ok(quiet);
        };
        let lineage = load_lineage(vault, txn, stream.wire)?;
        if covers(&floor, &remote) {
            return Ok(CopyReply {
                settled: covers(&floor, &lineage.oplog_vv()),
                ..quiet
            });
        }
        let floor = raise_home_floor_in_txn(vault, txn, stream.wire, Some(floor), &remote)?;
        let update = pending_in_txn(vault, txn, stream, &lineage, &floor)?;
        Ok(CopyReply {
            settled: update.is_none(),
            update,
            ..quiet
        })
    })
}

/// A local edit's release of `stream`: the lineage's operations past the
/// home floor, brought current first; `None` when the home holds them all
/// or before the stream has a home basis.
///
/// # Errors
/// A store failure, or an export's own failure.
pub(crate) fn release_device_copy(vault: &Vault, stream: CopyStream) -> Result<Option<Vec<u8>>> {
    vault.with_write_txn_grouped(|txn| {
        if copy_stream_in_txn(vault, txn, stream.wire)? != Some(stream) {
            return Ok(None);
        }
        let Some(floor) = home_floor_in_txn(vault, txn, stream.wire)? else {
            return Ok(None);
        };
        let lineage = load_lineage(vault, txn, stream.wire)?;
        pending_in_txn(vault, txn, stream, &lineage, &floor)
    })
}

/// This device's one author of `source`'s copy lineage: derived from the
/// source, this install's machine and the incarnation its document head
/// names, so it never shares counters with the home's author ([`super::author`])
/// or another device's. Before this install has a machine, a fresh author,
/// which restarts no one's counters.
///
/// # Errors
/// A store failure reading the machine or the document head.
pub(super) fn device_author(vault: &Vault, txn: &RoTxn<'_>, source: &EntityId) -> Result<u64> {
    let Some(machine) = crate::identity::read_machine_id_in_txn(vault, txn)? else {
        return Ok(LoroDoc::new().peer_id());
    };
    let incarnation = crate::entity_doc::source_incarnation_in_txn(&vault.store, txn, source)?
        .unwrap_or_default();
    let mut material = Vec::with_capacity(2 + 16 + 16 + incarnation.len());
    material.extend_from_slice(&SyncSecretProjection::SCHEMA.to_be_bytes());
    material.extend_from_slice(source.as_bytes());
    material.extend_from_slice(machine.as_bytes());
    material.extend_from_slice(incarnation.as_bytes());
    let key = blake3::derive_key(DEVICE_AUTHOR_CONTEXT, &material);
    let mut head = [0u8; 8];
    head.copy_from_slice(&key[..8]);
    Ok(u64::from_be_bytes(head) >> 1)
}

/// The source's durable text as a writer reads it and its copy.
struct SourceText {
    resident: LoroDoc,
    text: String,
    copy: TextCopy,
}

fn source_text_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    source: EntityId,
) -> Result<Option<SourceText>> {
    let marks = RepoIndexMarks::read_scoped_in_txn(vault, txn)?;
    let resident = crate::entity_doc::sync_text_in(vault, txn, &source)?
        .map_or_else(LoroDoc::new, |text| text.doc);
    let text = resident.get_text(BODY).to_string();
    Ok(
        text_copy_in_txn(vault, txn, &marks, &source, &text)?.map(|copy| SourceText {
            resident,
            text,
            copy,
        }),
    )
}

/// A home frame on a lineage with a basis: an update joins a fork of it; a
/// state takes the lineage's operations past it, which must then cover the
/// lineage. `None` for a frame that does not stage whole.
fn on_basis(lineage: &LoroDoc, kind: u8, bytes: &[u8]) -> Result<Option<Staged>> {
    match kind {
        document_sub_tags::UPDATE => {
            let doc = lineage.fork();
            if storage::import_complete(&doc, bytes).is_err() {
                return Ok(None);
            }
            let home = LoroDoc::decode_import_blob_meta(bytes, true)
                .map_or_else(|_| VersionVector::new(), |meta| meta.partial_end_vv);
            Ok(Some(Staged::of(doc, home)))
        }
        document_sub_tags::STATE => {
            let doc = LoroDoc::new();
            if storage::import_complete(&doc, bytes).is_err() {
                return Ok(None);
            }
            let home = doc.oplog_vv();
            let pending = lineage
                .export(ExportMode::updates(&home))
                .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportUpdates, e))?;
            if storage::import_complete(&doc, &pending).is_err()
                || !covers(&doc.oplog_vv(), &lineage.oplog_vv())
            {
                return Ok(None);
            }
            Ok(Some(Staged::of(doc, home)))
        }
        _ => Err(denied()),
    }
}

/// The first home frame, the stream's basis: the home's copy as it stands.
/// What the home and this device each changed since the marked blob's copy
/// lands as concurrent edits of it; the device's own part goes back as its
/// first release. Only a home lineage with no operations at all is
/// uninitialized: an empty body with history is the home's own edit (a clear
/// at home), merged against the marked blob's copy like any other.
fn first_basis(
    vault: &Vault,
    txn: &RoTxn<'_>,
    source: EntityId,
    copy: &TextCopy,
    bytes: &[u8],
) -> Result<Option<Staged>> {
    let doc = LoroDoc::new();
    if storage::import_complete(&doc, bytes).is_err() {
        return Ok(None);
    }
    let home = doc.oplog_vv();
    let theirs = doc.get_text(BODY).to_string();
    let submitted = if home.is_empty() || theirs == copy.copy {
        copy.copy.clone()
    } else {
        let base = blob_copy_in_txn(vault, txn, source);
        merged(base.as_deref().unwrap_or(&theirs), &copy.copy, &theirs)?
    };
    Ok(Some(Staged {
        doc,
        home,
        submitted,
    }))
}

impl Staged {
    fn of(doc: LoroDoc, home: VersionVector) -> Self {
        let submitted = doc.get_text(BODY).to_string();
        Self {
            doc,
            home,
            submitted,
        }
    }
}

/// A home frame not taken: the lineage keeps only this device's own
/// operations (saved when bringing it current moved it), and those past the
/// home floor go back.
fn untaken(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    stream: CopyStream,
    lineage: &LoroDoc,
    moved: bool,
    floor: Option<&VersionVector>,
    retry: bool,
) -> Result<CopyReply> {
    if moved {
        save_lineage(vault, txn, stream.wire, lineage)?;
    }
    let update = match floor {
        Some(floor) => pending_in_txn(vault, txn, stream, lineage, floor)?,
        None => None,
    };
    Ok(CopyReply {
        ack: None,
        update,
        settled: false,
        retry,
    })
}

/// `lineage` brought current with the source's copy as this device's
/// author (saved when it moves), then its operations past `floor`; `None`
/// when `floor` covers them all. An unread copy is not brought current.
fn pending_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    stream: CopyStream,
    lineage: &LoroDoc,
    floor: &VersionVector,
) -> Result<Option<Vec<u8>>> {
    if let Some(SourceText { copy, .. }) = source_text_in_txn(vault, txn, stream.source)?
        && !copy.unread()
        && bring_current(lineage, &copy.copy, || {
            device_author(vault, &*txn, &stream.source)
        })?
    {
        save_lineage(vault, txn, stream.wire, lineage)?;
    }
    if covers(floor, &lineage.oplog_vv()) {
        return Ok(None);
    }
    lineage
        .export(ExportMode::updates(floor))
        .map(Some)
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportUpdates, e))
}

/// The home floor row of the stream under `wire`.
fn floor_key(wire: EntityId) -> Vec<u8> {
    format!("{}:home", wire.to_hex()).into_bytes()
}

fn home_floor_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    wire: EntityId,
) -> Result<Option<VersionVector>> {
    AD_E.get(&vault.store, txn, &floor_key(wire))?
        .map(|bytes| storage::decode_vv(&bytes))
        .transpose()
}

/// `floor` raised by `held`, a vector the home holds, and stored.
fn raise_home_floor_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    wire: EntityId,
    floor: Option<VersionVector>,
    held: &VersionVector,
) -> Result<VersionVector> {
    let mut floor = floor.unwrap_or_default();
    floor.merge(held);
    AD_E.put(&vault.store, txn, &floor_key(wire), &floor.encode())?;
    Ok(floor)
}

/// The copy of the marked blob `source` was ingested as, read as a release
/// reads it: the text the home and this device both began from. `None`
/// when its stored bytes are no marked blob or do not read.
fn blob_copy_in_txn(vault: &Vault, txn: &RoTxn<'_>, source: EntityId) -> Option<String> {
    let marks = RepoIndexMarks::read_scoped_in_txn(vault, txn).ok()?;
    let marked = marks.source_of(&source)?;
    let raw = vault.store.port_entity_raw(txn, &source).ok().flatten()?;
    let body = raw.get(ENTITY_METADATA_HEADER_LEN..)?.to_vec();
    let hash = carried(&marks, marked, &body);
    if blake3::hash(&body).as_bytes() != &hash {
        return None;
    }
    let bound = TextBound {
        key: copy_id(&source).ok()?,
        hash,
        bytes: body,
        own: false,
    };
    project_text_in_txn(vault, txn, &marks, bound)
        .ok()
        .flatten()
        .filter(|copy| !copy.unread())
        .map(|copy| copy.copy)
}

/// `ours` and `theirs`, two copies that each began at `base`, merged as
/// concurrent edits of it.
fn merged(base: &str, ours: &str, theirs: &str) -> Result<String> {
    let edit = |doc: &LoroDoc, peer: u64, text: &str| -> Result<()> {
        doc.set_peer_id(peer)
            .map_err(|_| Error::InvariantViolation("document copy merge author"))?;
        doc.get_text(BODY)
            .update(text, UpdateOptions::default())
            .map_err(|_| Error::InvariantViolation("document copy merge diff"))?;
        doc.commit();
        Ok(())
    };
    let root = LoroDoc::new();
    edit(&root, 1, base)?;
    let mine = root.fork();
    let other = root.fork();
    edit(&mine, 2, ours)?;
    edit(&other, 3, theirs)?;
    let theirs = other
        .export(ExportMode::updates(&root.oplog_vv()))
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportUpdates, e))?;
    storage::import_complete(&mine, &theirs)?;
    Ok(mine.get_text(BODY).to_string())
}

fn covers(peer: &VersionVector, floor: &VersionVector) -> bool {
    matches!(
        peer.partial_cmp(floor),
        Some(std::cmp::Ordering::Equal | std::cmp::Ordering::Greater)
    )
}

fn denied() -> Error {
    Error::sync_protocol(SyncProtocolValidation::DocumentAdmissionDenied)
}
