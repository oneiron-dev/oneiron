//! A capsule's step start as shared pieces (FIX 4192).
//!
//! Each executor step's start repeats the run's replay row as it stood
//! before the step, so a run's starts grow with the square of its steps. A
//! capsule keeps its start as pieces, each stored once, cut as its request
//! is ([`super::pieces`]): the config (the start with its record emptied:
//! the task, model, tier, fingerprint and compaction), the record's frame
//! (its map with each growing array emptied), and each growing array (the
//! calls, step checkpoints, outputs, layout checks, bindings and callable
//! rows) as one piece per element and one node per element. A node names
//! its element and the node before it, so consecutive steps share the
//! nodes of their common record prefix.
//!
//! The capsule's own start body is the manifest: the config, the frame and
//! the last node of each array. The capsule names it by ref and path, with
//! the digest of the whole start it materializes, so the continuation
//! seed, a shadow source's digest and every pin on it stay valid. Every
//! reader puts the whole start together ([`start_bytes_in_txn`],
//! [`held_start_bytes_in_txn`]); none reads a manifest as a start. A start
//! whose pieces would not spell its bytes again exactly is one piece.
//!
//! The config, the frame and each element hold the start's content. A node
//! and the manifest hold only digests and lengths. FIX 4192 review fix: a
//! checkpoint carries a carried start's content in its rest alone
//! ([`step_start_content_pieces`]), so the erase that retires the rest
//! retires every copy of that content; a restore lists the pieces from the
//! manifest and the nodes ([`manifest_content_pieces`]).
//!
//! FIX 19821: a capsule's writer holds the manifest and each node of every
//! growing array inline whatever the inline bound, so a restore reads them
//! all among its rows and finds every content piece of the start. The frame
//! is content, which a checkpoint carries in the rest alone, so it keeps
//! the bound as every other piece does.
//!
//! Byte sharing is not authority sharing. The capsule's run holds each
//! piece at a path that names the actor and the piece's digest, apart from
//! the request pieces, and each occurrence keeps its own marks. A writer
//! that supersedes pieces releases each one once no kept start of the run
//! and actor names it.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::super::super::codec::encode_code_run_replay_value;
use super::super::super::replay::{CodeRunRawOutput, ResultOccurrence};
use super::super::super::replay_capsule::ExecutorStepStart;
use super::super::records::{RAW_OUTPUT_SECRETS, RAW_OUTPUTS, owned_body};
use super::super::response_erase::release_occurrence_in_txn;
use super::CAPSULES;
use super::admit::Spill;
use super::pieces::{
    PieceScope, decode, held_piece_in_txn, holds_in_txn, piece_bytes_in_txn, piece_ref,
};
use super::spawn_erase::{publish_start_in_txn, republished_start_body};
use crate::code_run::CODE_RUN_REPLAY_RECORD_KEYS;
use crate::compaction::output::OutputRef;
use crate::provenance::body::{digest_holders_in_txn, owned_body_in_txn, publish_body_in_txn};
use crate::store::{BodyMeter, Store};
use crate::{EntityId, Error, Result, Vault};

/// The field of a step start body that holds its record.
const RECORD_FIELD: &str = "record";

/// The key of a record's calls: the array whose elements may hold an ask.
const CALLS: &str = CODE_RUN_REPLAY_RECORD_KEYS[3];

/// The keys of a record's growing arrays (FIX 4192): its calls, step
/// checkpoints, outputs, layout checks, bindings and callable rows.
const GROWING: [&str; 6] = [
    CALLS,
    CODE_RUN_REPLAY_RECORD_KEYS[4],
    CODE_RUN_REPLAY_RECORD_KEYS[5],
    CODE_RUN_REPLAY_RECORD_KEYS[6],
    CODE_RUN_REPLAY_RECORD_KEYS[7],
    CODE_RUN_REPLAY_RECORD_KEYS[9],
];

/// A capsule's own start body (FIX 4192).
#[derive(Debug, Serialize, Deserialize)]
enum StartManifest {
    /// The config piece, the record's frame, and the last node of each
    /// growing array the frame empties, in the frame's order: `None` for an
    /// empty one.
    Cut {
        config: OutputRef,
        frame: OutputRef,
        arrays: Vec<Option<OutputRef>>,
    },
    /// A start whose pieces would not spell its bytes again exactly: one
    /// piece, the whole start.
    Whole { start: OutputRef },
}

/// One node of a growing array (FIX 4192): the node before it, `None` for
/// the first element, and its element.
#[derive(Debug, Serialize, Deserialize)]
struct ElementNode {
    prior: Option<OutputRef>,
    element: OutputRef,
}

/// The pieces of one start as a cut adds them: each once, in the order the
/// start first names it.
#[derive(Default)]
struct Shared {
    pieces: Vec<(OutputRef, Vec<u8>)>,
    at: BTreeMap<[u8; 32], usize>,
}

impl Shared {
    /// Adds `bytes` once; their ref.
    fn add(&mut self, bytes: Vec<u8>) -> OutputRef {
        let piece = piece_ref(&bytes);
        if let Entry::Vacant(slot) = self.at.entry(piece.hash) {
            slot.insert(self.pieces.len());
            self.pieces.push((piece, bytes));
        }
        piece
    }

    /// The bytes of `piece`, if the cut added it.
    fn get(&self, piece: OutputRef) -> Option<Vec<u8>> {
        let at = *self.at.get(&piece.hash)?;
        self.pieces.get(at).map(|(_, bytes)| bytes.clone())
    }
}

/// A step start cut into its pieces (FIX 4192): each shared piece once,
/// the manifest, and the digest of each piece that holds the start's
/// content (FIX 4192 review fix): its config, its record's frame and each
/// element, or its one piece when it is kept whole. FIX 19821: also the
/// digest of each node of each growing array, which a capsule's writer
/// holds inline whatever the bound, as it holds the manifest.
pub(super) struct StartPieces {
    shared: Vec<(OutputRef, Vec<u8>)>,
    manifest: Vec<u8>,
    content: BTreeSet<[u8; 32]>,
    inline_nodes: BTreeSet<[u8; 32]>,
}

impl StartPieces {
    /// `bytes`, a step start body, cut into its config, its record's frame,
    /// each element and node of each growing array, and the manifest. Each
    /// piece is MessagePack as the start spells it, so equal content is
    /// equal bytes. A start whose pieces would not spell it again exactly
    /// is one piece.
    ///
    /// # Errors
    ///
    /// A piece or the manifest that does not encode.
    pub(super) fn of(bytes: &[u8]) -> Result<Self> {
        if let Some(cut) = Self::cut(bytes)? {
            return Ok(cut);
        }
        let mut shared = Shared::default();
        let start = shared.add(bytes.to_vec());
        Ok(Self {
            manifest: encode_piece(&StartManifest::Whole { start })?,
            shared: shared.pieces,
            content: BTreeSet::from([start.hash]),
            inline_nodes: BTreeSet::new(),
        })
    }

    /// [`Self::of`] for a start its pieces spell again exactly; `None` for
    /// any other bytes.
    fn cut(bytes: &[u8]) -> Result<Option<Self>> {
        let Some(Value::Map(mut body)) = value_of(bytes) else {
            return Ok(None);
        };
        let Some(record) = field_mut(&mut body, RECORD_FIELD)
            .and_then(|slot| spelled(&std::mem::replace(slot, Value::Array(Vec::new()))))
        else {
            return Ok(None);
        };
        let Some(Value::Map(mut frame)) = value_of(&record) else {
            return Ok(None);
        };
        let mut shared = Shared::default();
        let config = shared.add(rmpv_bytes(&Value::Map(body))?);
        let (mut arrays, mut content) = (Vec::new(), BTreeSet::from([config.hash]));
        let mut inline_nodes = BTreeSet::new();
        for (key, value) in &mut frame {
            let (Some(_), Value::Array(elements)) = (growing(key), value) else {
                continue;
            };
            let mut last = None;
            for element in std::mem::take(elements) {
                let element = shared.add(rmpv_bytes(&element)?);
                content.insert(element.hash);
                let node = ElementNode {
                    prior: last,
                    element,
                };
                let node = shared.add(encode_piece(&node)?);
                inline_nodes.insert(node.hash);
                last = Some(node);
            }
            arrays.push(last);
        }
        let frame = shared.add(rmpv_bytes(&Value::Map(frame))?);
        content.insert(frame.hash);
        let manifest = encode_piece(&StartManifest::Cut {
            config,
            frame,
            arrays,
        })?;
        let spells = materialize(&manifest, |piece| Ok(shared.get(piece)))?;
        Ok((spells.as_deref() == Some(bytes)).then_some(Self {
            shared: shared.pieces,
            manifest,
            content,
            inline_nodes,
        }))
    }

    /// Each shared piece, once.
    pub(super) fn shared(&self) -> &[(OutputRef, Vec<u8>)] {
        &self.shared
    }

    /// The manifest: the capsule's own start body.
    pub(super) fn manifest(&self) -> &[u8] {
        &self.manifest
    }

    /// The shared pieces `scope`'s run does not hold whole yet, in `txn`.
    fn unheld_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        scope: PieceScope,
    ) -> Result<Vec<&(OutputRef, Vec<u8>)>> {
        let mut unheld = Vec::new();
        for piece in &self.shared {
            let path = scope.start_path(&piece.0.hash);
            if !holds_in_txn(store, txn, scope.run, &path, piece.0)? {
                unheld.push(piece);
            }
        }
        Ok(unheld)
    }

    /// The length of each body [`Self::publish_in_txn`] publishes for
    /// `scope` in `txn` under the inline bound: each piece the run does not
    /// hold yet. The writer's spill must hold them. FIX 19821: the manifest
    /// and the nodes are held inline whatever the bound, so none of them is
    /// here.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(super) fn lens_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        scope: PieceScope,
    ) -> Result<Vec<usize>> {
        Ok(self
            .unheld_in_txn(store, txn, scope)?
            .into_iter()
            .filter(|piece| !self.inline_nodes.contains(&piece.0.hash))
            .map(|piece| piece.1.len())
            .collect())
    }

    /// FIX 4192: publishes the start for `scope` in `wtxn` through the
    /// native body publisher. Each piece the run does not hold whole yet
    /// becomes a body the run holds at its start piece path; a piece it
    /// holds already is named again, and nothing of it is written. The
    /// manifest becomes the capsule's own body at `path`. Returns the
    /// manifest's ref. FIX 19821: the manifest and each node are held
    /// inline whatever the bound, so a restore finds them among its rows.
    /// Every other piece keeps the bound.
    ///
    /// # Errors
    ///
    /// Storage and custody errors.
    pub(super) fn publish_in_txn(
        &self,
        vault: &Vault,
        wtxn: &mut RwTxn<'_>,
        spill: &Spill,
        scope: PieceScope,
        path: &str,
    ) -> Result<OutputRef> {
        for (piece, bytes) in self.unheld_in_txn(&vault.store, wtxn, scope)? {
            let at = scope.start_path(&piece.hash);
            let published = if self.inline_nodes.contains(&piece.hash) {
                spill.publish_inline_in_txn(vault, wtxn, scope.run, &at, bytes)?
            } else {
                spill.publish_in_txn(vault, wtxn, scope.run, &at, bytes)?
            };
            if published != *piece {
                return Err(Error::InvariantViolation(
                    "a capsule start piece was published as other bytes",
                ));
            }
        }
        spill.publish_inline_in_txn(vault, wtxn, scope.run, path, &self.manifest)
    }
}

/// The start the manifest `manifest` names, put together from its pieces,
/// each read by `read`: `None` when a piece does not read or decode, or the
/// manifest names other arrays than its frame empties.
fn materialize(
    manifest: &[u8],
    mut read: impl FnMut(OutputRef) -> Result<Option<Vec<u8>>>,
) -> Result<Option<Vec<u8>>> {
    let (config, frame, arrays) = match decode::<StartManifest>(manifest) {
        Some(StartManifest::Cut {
            config,
            frame,
            arrays,
        }) => (config, frame, arrays),
        Some(StartManifest::Whole { start }) => return read(start),
        None => return Ok(None),
    };
    let Some(Value::Map(mut body)) = read(config)?.and_then(|bytes| value_of(&bytes)) else {
        return Ok(None);
    };
    let Some(Value::Map(mut record)) = read(frame)?.and_then(|bytes| value_of(&bytes)) else {
        return Ok(None);
    };
    if !fill_arrays(&mut record, arrays, &mut read)? {
        return Ok(None);
    }
    let Some(slot) = field_mut(&mut body, RECORD_FIELD) else {
        return Ok(None);
    };
    let record = rmpv_bytes(&Value::Map(record))?;
    *slot = Value::Array(record.into_iter().map(Value::from).collect());
    rmpv_bytes(&Value::Map(body)).map(Some)
}

/// Fills each growing array the frame `record` empties with its elements,
/// from the last node of each among `arrays` back to the first, each piece
/// read by `read`. Whether every array filled and `arrays` named no other.
fn fill_arrays(
    record: &mut [(Value, Value)],
    arrays: Vec<Option<OutputRef>>,
    read: &mut impl FnMut(OutputRef) -> Result<Option<Vec<u8>>>,
) -> Result<bool> {
    let mut arrays = arrays.into_iter();
    for (key, value) in record {
        let (Some(_), Value::Array(elements)) = (growing(key), value) else {
            continue;
        };
        let Some(mut next) = arrays.next() else {
            return Ok(false);
        };
        while let Some(at) = next {
            let Some(node) = read(at)?.and_then(|bytes| decode::<ElementNode>(&bytes)) else {
                return Ok(false);
            };
            let Some(element) = read(node.element)?.and_then(|bytes| value_of(&bytes)) else {
                return Ok(false);
            };
            elements.push(element);
            next = node.prior;
        }
        elements.reverse();
    }
    Ok(arrays.next().is_none())
}

/// FIX 4192: the whole start `start` names, put together from its pieces
/// as run `scope.run` holds them for the actor, read in `txn` whoever else
/// holds the same bytes: `None` when it is marked erased, when the run no
/// longer holds its manifest or a piece whole, and when a piece is gone,
/// drifted or does not decode.
///
/// # Errors
///
/// Storage errors.
pub(super) fn start_bytes_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    scope: PieceScope,
    start: &ExecutorStepStart,
) -> Result<Option<Vec<u8>>> {
    if start.erased || !holds_in_txn(store, txn, scope.run, &start.path, start.body)? {
        return Ok(None);
    }
    let Some(manifest) = piece_bytes_in_txn(store, txn, start.body)? else {
        return Ok(None);
    };
    materialize(&manifest, |piece| {
        let path = scope.start_path(&piece.hash);
        if !holds_in_txn(store, txn, scope.run, &path, piece)? {
            return Ok(None);
        }
        piece_bytes_in_txn(store, txn, piece)
    })
}

/// FIX 4192: [`start_bytes_in_txn`] as a capsule's reader reads it, in
/// `rtxn`: the manifest and each piece only while no erase, withdrawal,
/// secret mark or taint withholds the run's occurrence of it.
///
/// # Errors
///
/// Storage errors.
pub(super) fn held_start_bytes_in_txn(
    vault: &Vault,
    rtxn: &RoTxn<'_>,
    scope: PieceScope,
    start: &ExecutorStepStart,
) -> Result<Option<Vec<u8>>> {
    let path = start.path.clone();
    let Some(manifest) = held_piece_in_txn(vault, rtxn, scope.run, path, start.body)? else {
        return Ok(None);
    };
    materialize(&manifest, |piece| {
        let path = scope.start_path(&piece.hash);
        held_piece_in_txn(vault, rtxn, scope.run, path, piece)
    })
}

/// FIX 4192: the digest of each piece the start manifest `manifest` names,
/// added to `named`: its config and frame, and each node and element of
/// each array, read in `txn` whoever holds them. A node already in `named`
/// names nothing new, so one walk over a run's starts reads each shared
/// node once. A piece that does not read ends its walk.
///
/// # Errors
///
/// Storage errors.
pub(super) fn start_manifest_pieces_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    manifest: OutputRef,
    named: &mut BTreeSet<[u8; 32]>,
) -> Result<()> {
    let bytes = piece_bytes_in_txn(store, txn, manifest)?;
    let arrays = match bytes.and_then(|bytes| decode::<StartManifest>(&bytes)) {
        Some(StartManifest::Cut {
            config,
            frame,
            arrays,
        }) => {
            named.extend([config.hash, frame.hash]);
            arrays
        }
        Some(StartManifest::Whole { start }) => {
            named.insert(start.hash);
            return Ok(());
        }
        None => return Ok(()),
    };
    for mut next in arrays {
        while let Some(at) = next {
            if !named.insert(at.hash) {
                break;
            }
            let bytes = piece_bytes_in_txn(store, txn, at)?;
            let Some(node) = bytes.and_then(|bytes| decode::<ElementNode>(&bytes)) else {
                break;
            };
            named.insert(node.element.hash);
            next = node.prior;
        }
    }
    Ok(())
}

/// What a store-only writer's republish of a start left (FIX 4192): the
/// start its capsule names now, the digest its old manifest occurrence held
/// when that is other bytes, and each piece the old start named that the
/// new one does not.
pub(super) struct RepublishedStart {
    pub(super) start: ExecutorStepStart,
    pub(super) manifest: Option<[u8; 32]>,
    pub(super) superseded: BTreeSet<[u8; 32]>,
}

/// FIX 4192: `bytes`, a start's new body, republished as pieces in a
/// store-only writer (CALLS "republished step start stays inline"), in
/// place of the start `start` names. Each piece run `scope.run` does not
/// hold whole yet is held inline at its start piece path, and the manifest
/// goes under the start's own occurrence with its marks
/// ([`publish_start_in_txn`]). The caller puts the capsule that names the
/// new start first, then releases each superseded piece no kept start
/// names ([`release_unnamed_start_pieces_in_txn`]).
///
/// # Errors
///
/// Storage and custody errors, and a piece that does not encode.
pub(super) fn republish_start_pieces_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    scope: PieceScope,
    start: &ExecutorStepStart,
    bytes: &[u8],
) -> Result<RepublishedStart> {
    let pieces = StartPieces::of(bytes)?;
    let mut superseded = BTreeSet::new();
    start_manifest_pieces_in_txn(store, wtxn, start.body, &mut superseded)?;
    for (piece, piece_bytes) in pieces.unheld_in_txn(store, wtxn, scope)? {
        let path = scope.start_path(&piece.hash);
        publish_piece_inline_in_txn(store, wtxn, scope.run, &path, piece_bytes)?;
    }
    let (body, held) = publish_start_in_txn(store, wtxn, scope.run, start, &pieces.manifest)?;
    for (piece, _) in &pieces.shared {
        superseded.remove(&piece.hash);
    }
    Ok(RepublishedStart {
        start: ExecutorStepStart {
            body,
            digest: *blake3::hash(bytes).as_bytes(),
            erased: false,
            ..start.clone()
        },
        manifest: held.filter(|digest| *digest != body.hash),
        superseded,
    })
}

/// `bytes`, a start piece, published as the complete body run `run` holds
/// at `path` in a store-only writer: bytes no row holds yet are held
/// inline, the run's occurrence takes the secret mark the scan hits, and
/// its descriptor names the body.
fn publish_piece_inline_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    run: EntityId,
    path: &str,
    bytes: &[u8],
) -> Result<()> {
    let mut meter = BodyMeter::new();
    meter.feed(bytes);
    let facts = meter.finish(crate::serialize::CODE_RUN_OUTPUT_PREVIEW_MAX_CHARS);
    let output = CodeRunRawOutput::from_facts(path, &facts, true)?;
    // Bytes some row already holds stay as that row holds them.
    let body = match RAW_OUTPUTS.get(store, wtxn, &output.handle)? {
        Some(body) => body,
        None => {
            let body = republished_start_body(bytes);
            RAW_OUTPUTS.put(store, wtxn, &output.handle, &body)?;
            body
        }
    };
    if let Some(reason) = facts.secret {
        let marks = ResultOccurrence::of(Some(run), &output)?.mark_key(&output.handle);
        RAW_OUTPUT_SECRETS.put(store, wtxn, &marks, &reason.to_owned())?;
    }
    publish_body_in_txn(store, wtxn, &owned_body(run, &output, &body)?)
}

/// FIX 4192: releases run `scope.run`'s occurrence of each of `candidates`,
/// a start piece of `scope`, that no kept start of `scope` names, in
/// `wtxn`, with its own marks. A kept start is one a capsule of the actor
/// names unerased whose manifest occurrence the run still holds. The caller
/// has put every capsule that names a new start. Returns the digest each
/// released occurrence held, which the caller retires or drops.
///
/// # Errors
///
/// Storage errors.
pub(super) fn release_unnamed_start_pieces_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    scope: PieceScope,
    candidates: &BTreeSet<[u8; 32]>,
) -> Result<Vec<[u8; 32]>> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let named = kept_start_pieces_in_txn(store, wtxn, scope)?;
    let mut held = Vec::new();
    for digest in candidates.difference(&named) {
        let handle = CodeRunRawOutput::of_ref(OutputRef {
            hash: *digest,
            byte_len: 0,
        })
        .handle;
        let path = scope.start_path(digest);
        held.extend(release_occurrence_in_txn(
            store, wtxn, scope.run, path, handle,
        )?);
    }
    Ok(held)
}

/// Every piece a kept start of `scope` names, read in `txn`. A capsule's
/// run is its attempt, so the attempt's rows are every capsule of `scope`.
fn kept_start_pieces_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    scope: PieceScope,
) -> Result<BTreeSet<[u8; 32]>> {
    let mut starts = Vec::new();
    for row in CAPSULES.iter_raw_from(store, txn, scope.run.as_bytes())? {
        let (_, bytes) = row?;
        if let Ok(capsule) = CAPSULES.decode_value(&bytes)
            && capsule.run == scope.run
            && capsule.content.actor() == Some(scope.actor)
            && let Some(start) = capsule.start.filter(|start| !start.erased)
        {
            starts.push(start);
        }
    }
    let mut named = BTreeSet::new();
    for start in starts {
        let occurrence = ResultOccurrence::owned(scope.run, &start.path)?.id();
        if owned_body_in_txn(store, txn, &scope.run, &occurrence)?.is_some() {
            start_manifest_pieces_in_txn(store, txn, start.body, &mut named)?;
        }
    }
    Ok(named)
}

/// FIX 4192 review fix: whether the bytes `digest` names have a holder
/// besides the start pieces of the runs and actors `scopes`: a descriptor
/// at any other occurrence, or a result body row that holds its body on its
/// own. A census never carries such bytes apart from their own shared body
/// instance, so stripping a start's content leaves another holder whole.
///
/// # Errors
///
/// Storage errors, and an occurrence that does not derive.
pub(crate) fn start_piece_held_apart_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    digest: &[u8; 32],
    scopes: &BTreeSet<(EntityId, EntityId)>,
) -> Result<bool> {
    for (occurrence, owner) in digest_holders_in_txn(store, txn, digest)? {
        let mut start = false;
        for (run, actor) in scopes.iter().filter(|(run, _)| *run == owner) {
            let path = PieceScope {
                run: *run,
                actor: *actor,
            }
            .start_path(digest);
            if ResultOccurrence::owned(*run, &path)?.id() == occurrence {
                start = true;
                break;
            }
        }
        if !start {
            return Ok(true);
        }
    }
    super::super::records::code_run_body_held_in_txn(store, txn, digest)
}

/// FIX 4192 review fix: the pieces of the step start `bytes` that hold
/// its content: its config, its record's frame and each element of each
/// growing array, or its one piece when it is kept whole. A census carries
/// the rows of a carried start's content pieces without their bytes, so
/// only its rest carries that content. Each node and the manifest name
/// only digests and lengths, and travel as any body does.
///
/// # Errors
///
/// A piece that does not encode.
pub(crate) fn step_start_content_pieces(bytes: &[u8]) -> Result<BTreeSet<[u8; 32]>> {
    Ok(StartPieces::of(bytes)?.content)
}

/// FIX 4192 review fix: the pieces that hold the content of the start
/// whose manifest is `manifest`, each structural piece read by `read`: its
/// config and frame, and the element each node of each array names, or the
/// start's one piece when it is kept whole. A restore reads the manifest
/// and the nodes among its rows, as each travels as any body does. An
/// array whose node does not read names no element past it; a manifest
/// that does not read names none.
pub(super) fn manifest_content_pieces(
    manifest: OutputRef,
    read: impl Fn(OutputRef) -> Option<Vec<u8>>,
) -> Vec<[u8; 32]> {
    let (config, frame, arrays) =
        match read(manifest).and_then(|bytes| decode::<StartManifest>(&bytes)) {
            Some(StartManifest::Cut {
                config,
                frame,
                arrays,
            }) => (config, frame, arrays),
            Some(StartManifest::Whole { start }) => return vec![start.hash],
            None => return Vec::new(),
        };
    let mut content = vec![config.hash, frame.hash];
    for mut next in arrays {
        while let Some(at) = next {
            let Some(node) = read(at).and_then(|bytes| decode::<ElementNode>(&bytes)) else {
                break;
            };
            content.push(node.element.hash);
            next = node.prior;
        }
    }
    content
}

/// The digest whose MessagePack encoding in a ref is the widest (FIX
/// 11415): each of its bytes is 0x80 or above.
pub(super) const WIDEST_DIGEST: [u8; 32] = [0xff; 32];

/// The ref whose encoding is the widest a manifest or a node names (FIX
/// 11415): the widest digest and the widest length.
const WIDEST_REF: OutputRef = OutputRef {
    hash: WIDEST_DIGEST,
    byte_len: u64::MAX,
};

/// FIX 11415: the most bytes one node of a growing array takes, as the cut
/// encodes it: a node that names the widest ref before it and the widest
/// element.
///
/// # Errors
///
/// A node that does not encode.
pub(super) fn widest_node_len() -> Result<u64> {
    let node = ElementNode {
        prior: Some(WIDEST_REF),
        element: WIDEST_REF,
    };
    Ok(encode_piece(&node)?.len() as u64)
}

/// FIX 11415: the most a manifest grows by when one ref it names changes.
/// A retired ask changes one ref: its calls' last node, or the start kept
/// as one piece. The growth is the widest ref's encoding less the
/// narrowest ref's.
///
/// # Errors
///
/// A ref that does not encode.
pub(super) fn ref_change_growth() -> Result<u64> {
    let narrowest = OutputRef {
        hash: [0; 32],
        byte_len: 0,
    };
    let (widest, narrowest) = (encode_piece(&WIDEST_REF)?, encode_piece(&narrowest)?);
    Ok(widest.len().saturating_sub(narrowest.len()) as u64)
}

/// The name of the growing array `key` names, if it names one.
fn growing(key: &Value) -> Option<&'static str> {
    let key = key.as_str()?;
    GROWING.into_iter().find(|name| *name == key)
}

/// The value of the field `name` of the map `map`.
fn field_mut<'m>(map: &'m mut [(Value, Value)], name: &str) -> Option<&'m mut Value> {
    map.iter_mut()
        .find(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value)
}

/// The bytes a start body spells one integer per byte, as it holds its
/// record; `None` for any other value.
fn spelled(value: &Value) -> Option<Vec<u8>> {
    let Value::Array(bytes) = value else {
        return None;
    };
    bytes
        .iter()
        .map(|byte| byte.as_u64().and_then(|byte| u8::try_from(byte).ok()))
        .collect()
}

/// The one MessagePack value `bytes` hold; `None` for any other bytes.
fn value_of(bytes: &[u8]) -> Option<Value> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    cursor.is_empty().then_some(value)
}

/// `value` as MessagePack, as the start spells it.
fn rmpv_bytes(value: &Value) -> Result<Vec<u8>> {
    encode_code_run_replay_value(value, "a step start piece does not encode")
}

/// A manifest or a node as MessagePack.
fn encode_piece(value: &impl Serialize) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value)
        .map_err(|error| Error::InvalidConfig(format!("capsule start piece: {error}")))
}
