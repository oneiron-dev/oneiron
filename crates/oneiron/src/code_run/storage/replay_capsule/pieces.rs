//! A capsule's request as shared pieces (FIX 4192).
//!
//! Each step's request repeats every message before it. So a capsule keeps
//! its request as pieces, each stored once: the request without its
//! messages (its config), each message, and one sequence node per message.
//! A node names its message and the node before it, so a request that
//! starts with the messages of an earlier one shares that request's nodes.
//! An equal message is the same piece wherever it sits, so a request that
//! changes after compaction or a browser handoff still shares it.
//!
//! The capsule's own request body is the manifest: the config piece and the
//! last node. The capsule names it by ref and path as before, with the hash
//! of the whole request it materializes, so every logical hash stays.
//!
//! Byte sharing is not authority sharing. The capsule's run holds each piece
//! as a body of its own, at a path that names the capsule's actor and the
//! piece's digest: the pieces of one run and actor are held once, and the
//! run's occurrence of each keeps its own holder, taint and secret marks. A
//! read checks that the run holds every piece whole and that none is
//! withheld; a matching digest grants nothing. An erase of the actor
//! releases every piece its runs hold for it. A refresh releases a piece
//! only once no request of the run and actor names it.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::super::super::replay::{CodeRunRawOutput, ResultOccurrence};
use super::super::records::{RAW_OUTPUTS, body_drifted, load_whole_body};
use super::super::response_erase::release_occurrence_in_txn;
use super::admit::Spill;
use super::start_parts::drop_unheld_body_in_txn;
use super::{CAPSULES, CapsuleRequest};
use crate::compaction::output::OutputRef;
use crate::provenance::body::{BodyState, owned_bodies_in_txn, owned_body_in_txn};
use crate::store::{Store, body_key_row_in_txn};
use crate::{EntityId, Error, Result, Vault};

/// The run and actor whose pieces a capsule's request names (FIX 4192).
/// The run holds each piece. The path of each names the actor, so each
/// actor's capsules of the run share their pieces only with each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PieceScope {
    pub(super) run: EntityId,
    pub(super) actor: EntityId,
}

impl PieceScope {
    /// Where the run holds the piece whose digest is `digest`.
    fn path(self, digest: &[u8; 32]) -> String {
        format!(
            "replay/capsule/piece/{}/{}",
            self.actor.to_hex(),
            blake3::Hash::from(*digest)
        )
    }
}

/// A capsule's own request body (FIX 4192): the config piece, and the last
/// node of the message sequence. `last` is `None` for a request with no
/// message.
#[derive(Debug, Serialize, Deserialize)]
struct RequestManifest {
    config: OutputRef,
    last: Option<OutputRef>,
}

/// One node of a request's message sequence (FIX 4192): the node before it,
/// `None` for the first message, and its message.
#[derive(Debug, Serialize, Deserialize)]
struct SequenceNode {
    prior: Option<OutputRef>,
    message: OutputRef,
}

/// A stored request cut into its pieces (FIX 4192): each shared piece once,
/// in the order the request first names it, and the manifest.
pub(super) struct RequestPieces {
    shared: Vec<(OutputRef, Vec<u8>)>,
    manifest: Vec<u8>,
}

impl RequestPieces {
    /// `stored`, a request's canonical JSON as stored, cut into its config,
    /// each message, each sequence node and the manifest. Each piece is
    /// canonical JSON or MessagePack, so equal content is equal bytes.
    ///
    /// # Errors
    ///
    /// Bytes that are no request object with messages, and a piece that
    /// does not encode.
    pub(super) fn of(stored: &[u8]) -> Result<Self> {
        let Ok(Value::Object(mut request)) = serde_json::from_slice::<Value>(stored) else {
            return Err(Error::InvariantViolation(
                "a stored capsule request is no JSON object",
            ));
        };
        let Some(Value::Array(messages)) = request.remove("messages") else {
            return Err(Error::InvariantViolation(
                "a stored capsule request holds no messages",
            ));
        };
        let (mut shared, mut seen) = (Vec::new(), BTreeSet::new());
        let mut add = |bytes: Vec<u8>| {
            let piece = piece_ref(&bytes);
            if seen.insert(piece.hash) {
                shared.push((piece, bytes));
            }
            piece
        };
        let config = add(canonical(&Value::Object(request))?);
        let mut last = None;
        for message in &messages {
            let message = add(canonical(message)?);
            last = Some(add(encode(&SequenceNode {
                prior: last,
                message,
            })?));
        }
        let manifest = encode(&RequestManifest { config, last })?;
        Ok(Self { shared, manifest })
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
            if !holds_in_txn(store, txn, scope.run, &scope.path(&piece.0.hash), piece.0)? {
                unheld.push(piece);
            }
        }
        Ok(unheld)
    }

    /// The length of each body [`Self::publish_in_txn`] publishes for
    /// `scope` in `txn`: each shared piece the run does not hold yet, then
    /// the manifest. The writer's spill must hold them.
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
        let mut lens: Vec<usize> = self
            .unheld_in_txn(store, txn, scope)?
            .into_iter()
            .map(|piece| piece.1.len())
            .collect();
        lens.push(self.manifest.len());
        Ok(lens)
    }

    /// FIX 4192: publishes the request for `scope` in `wtxn` through the
    /// native body publisher. Each shared piece the run does not hold whole
    /// yet becomes a body the run holds at the piece's path. A piece the run
    /// holds already is named again, and nothing of it is written. The
    /// manifest then becomes the capsule's own body at `path`. Returns the
    /// manifest's ref.
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
            let at = scope.path(&piece.hash);
            if spill.publish_in_txn(vault, wtxn, scope.run, &at, bytes)? != *piece {
                return Err(Error::InvariantViolation(
                    "a capsule request piece was published as other bytes",
                ));
            }
        }
        spill.publish_in_txn(vault, wtxn, scope.run, path, &self.manifest)
    }
}

/// FIX 4192: the length of each body a writer publishes for `stored`, a
/// request's canonical JSON, and `scope`, read before the writer opens: the
/// instances it mints first. The wall's masks rarely change a piece; a
/// writer that needs more mints them on its next run.
///
/// # Errors
///
/// Storage errors, and bytes that are no request.
pub(super) fn unheld_lens(vault: &Vault, stored: &[u8], scope: PieceScope) -> Result<Vec<usize>> {
    let pieces = RequestPieces::of(stored)?;
    let rtxn = vault.store.env.read_txn()?;
    pieces.lens_in_txn(&vault.store, &rtxn, scope)
}

/// FIX 4192: the request the manifest `manifest` at `path` names, read
/// whole. Every piece it names is pinned past the collector first. Then one
/// snapshot reads them all, in which `still` names the scope that holds
/// them, or `None` when the capsule no longer names this request. `None`
/// too when the run no longer holds a piece whole, a piece is withheld (an
/// erase, a withdrawal, a secret mark or a taint), gone or drifted, or a
/// piece does not decode.
///
/// # Errors
///
/// Storage errors.
pub(super) fn held_request_bytes(
    vault: &Vault,
    manifest: OutputRef,
    path: &str,
    still: impl FnOnce(&RoTxn<'_>) -> Result<Option<PieceScope>>,
) -> Result<Option<Vec<u8>>> {
    let _custody = vault.store.gate_custody_read_guard()?;
    let mut named = BTreeSet::from([manifest.hash]);
    {
        let rtxn = vault.store.env.read_txn()?;
        manifest_pieces_in_txn(&vault.store, &rtxn, manifest, &mut named)?;
    }
    let _pins: Vec<_> = named
        .into_iter()
        .map(|digest| vault.pin_result_body(digest))
        .collect();
    let rtxn = vault.store.env.read_txn()?;
    let Some(scope) = still(&rtxn)? else {
        return Ok(None);
    };
    request_bytes_in_txn(vault, &rtxn, scope, manifest, path)
}

/// The request [`held_request_bytes`] reads, in `rtxn`: the manifest as the
/// capsule's own body, the config, and each message from the last node back
/// to the first, put together as the request's canonical JSON.
fn request_bytes_in_txn(
    vault: &Vault,
    rtxn: &RoTxn<'_>,
    scope: PieceScope,
    manifest: OutputRef,
    path: &str,
) -> Result<Option<Vec<u8>>> {
    let held = held_piece_in_txn(vault, rtxn, scope.run, path.to_owned(), manifest)?;
    let Some(manifest) = held.and_then(|bytes| decode::<RequestManifest>(&bytes)) else {
        return Ok(None);
    };
    let Some(Value::Object(mut request)) = held_json_in_txn(vault, rtxn, scope, manifest.config)?
    else {
        return Ok(None);
    };
    let mut messages = Vec::new();
    let mut next = manifest.last;
    while let Some(at) = next {
        let held = held_piece_in_txn(vault, rtxn, scope.run, scope.path(&at.hash), at)?;
        let Some(node) = held.and_then(|bytes| decode::<SequenceNode>(&bytes)) else {
            return Ok(None);
        };
        let Some(message) = held_json_in_txn(vault, rtxn, scope, node.message)? else {
            return Ok(None);
        };
        messages.push(message);
        next = node.prior;
    }
    messages.reverse();
    request.insert("messages".to_owned(), Value::Array(messages));
    canonical(&Value::Object(request)).map(Some)
}

/// The JSON of the shared piece `piece`, as `scope`'s run holds it.
fn held_json_in_txn(
    vault: &Vault,
    rtxn: &RoTxn<'_>,
    scope: PieceScope,
    piece: OutputRef,
) -> Result<Option<Value>> {
    let held = held_piece_in_txn(vault, rtxn, scope.run, scope.path(&piece.hash), piece)?;
    Ok(held.and_then(|bytes| serde_json::from_slice(&bytes).ok()))
}

/// The bytes of `piece` as run `run` holds them at `path`, in `rtxn`: `None`
/// when the run's occurrence is not whole with those bytes, is withheld, or
/// its bytes are gone or drifted.
fn held_piece_in_txn(
    vault: &Vault,
    rtxn: &RoTxn<'_>,
    run: EntityId,
    path: String,
    piece: OutputRef,
) -> Result<Option<Vec<u8>>> {
    let output = CodeRunRawOutput {
        path,
        ..CodeRunRawOutput::of_ref(piece)
    };
    if !holds_in_txn(&vault.store, rtxn, run, &output.path, piece)?
        || vault
            .code_run_result_withheld_in_txn(rtxn, Some(run), &output)?
            .is_some()
    {
        return Ok(None);
    }
    match vault.code_run_result_body_in_txn(rtxn, &output) {
        Err(error) if body_drifted(&error) => Ok(None),
        read => read,
    }
}

/// Whether run `run`'s occurrence at `path` holds `piece` whole, in `txn`.
fn holds_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    run: EntityId,
    path: &str,
    piece: OutputRef,
) -> Result<bool> {
    let occurrence = ResultOccurrence::owned(run, path)?.id();
    Ok(owned_body_in_txn(store, txn, &run, &occurrence)?.is_some_and(|owned| {
        matches!(
            &owned.state,
            BodyState::Complete { body } if body.blake3 == piece.hash && body.bytes == piece.byte_len
        )
    }))
}

/// FIX 4192: the digest of each shared piece the manifest `manifest` names,
/// added to `named`: its config, each node and each message, read in `txn`
/// whoever holds them. A node already in `named` names nothing new, so one
/// walk over many manifests of a run reads each shared node once. A piece
/// that does not read ends its walk.
///
/// # Errors
///
/// Storage errors.
pub(super) fn manifest_pieces_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    manifest: OutputRef,
    named: &mut BTreeSet<[u8; 32]>,
) -> Result<()> {
    let bytes = piece_bytes_in_txn(store, txn, manifest)?;
    let Some(manifest) = bytes.and_then(|bytes| decode::<RequestManifest>(&bytes)) else {
        return Ok(());
    };
    named.insert(manifest.config.hash);
    let mut next = manifest.last;
    while let Some(at) = next {
        if !named.insert(at.hash) {
            break;
        }
        let bytes = piece_bytes_in_txn(store, txn, at)?;
        let Some(node) = bytes.and_then(|bytes| decode::<SequenceNode>(&bytes)) else {
            break;
        };
        named.insert(node.message.hash);
        next = node.prior;
    }
    Ok(())
}

/// The bytes `piece` names, read in `txn` whoever holds them: `None` when
/// they are gone or drifted.
fn piece_bytes_in_txn(store: &Store, txn: &RoTxn<'_>, piece: OutputRef) -> Result<Option<Vec<u8>>> {
    let output = CodeRunRawOutput::of_ref(piece);
    let Some(body) = RAW_OUTPUTS.get(store, txn, &output.handle)? else {
        return Ok(None);
    };
    let key = body_key_row_in_txn(store, txn, &output.raw_blake3)?;
    match load_whole_body(&output, body, key.as_ref(), || Ok(vec![store.body_dir()?])) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if body_drifted(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

/// FIX 4192: every shared piece each of `runs` holds for `actor`, by run,
/// read in `txn`: each descriptor of the run whose occurrence sits at the
/// piece path of its own digest. An erase of the actor releases them all,
/// whatever a manifest still reads.
///
/// # Errors
///
/// Storage errors.
pub(super) fn actor_pieces_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    actor: &EntityId,
    runs: impl IntoIterator<Item = EntityId>,
) -> Result<Vec<(EntityId, Vec<(OutputRef, String)>)>> {
    let runs: BTreeSet<EntityId> = runs.into_iter().collect();
    let mut pieces = Vec::with_capacity(runs.len());
    for run in runs {
        let scope = PieceScope { run, actor: *actor };
        let mut held = Vec::new();
        for body in owned_bodies_in_txn(store, txn, &run)? {
            let Some(at) = body.state.held() else {
                continue;
            };
            let path = scope.path(&at.blake3);
            if ResultOccurrence::owned(run, &path)?.id() == body.occurrence {
                let piece = OutputRef {
                    hash: at.blake3,
                    byte_len: at.bytes,
                };
                held.push((piece, path));
            }
        }
        pieces.push((run, held));
    }
    Ok(pieces)
}

/// FIX 4192: releases each of `superseded`, a shared piece a request of
/// `scope` named before, that no kept request of `scope` names now, in
/// `wtxn`. The caller has put the CAPSULES row that names the new request.
/// The run's occurrence goes with its own marks, and its body once nothing
/// holds it. A capsule's run is its attempt, so the attempt's rows are every
/// capsule of `scope`.
///
/// # Errors
///
/// Storage errors.
pub(super) fn release_superseded_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    scope: PieceScope,
    superseded: &BTreeSet<[u8; 32]>,
) -> Result<()> {
    if superseded.is_empty() {
        return Ok(());
    }
    let mut manifests = Vec::new();
    for row in CAPSULES.iter_raw_from(store, wtxn, scope.run.as_bytes())? {
        let (_, bytes) = row?;
        let Ok(capsule) = CAPSULES.decode_value(&bytes) else {
            continue;
        };
        if capsule.run == scope.run
            && capsule.content.actor() == Some(scope.actor)
            && let CapsuleRequest::Kept { body, .. } = capsule.request
        {
            manifests.push(body);
        }
    }
    let mut named = BTreeSet::new();
    for manifest in manifests {
        manifest_pieces_in_txn(store, wtxn, manifest, &mut named)?;
    }
    for digest in superseded.difference(&named) {
        let handle = CodeRunRawOutput::of_ref(OutputRef {
            hash: *digest,
            byte_len: 0,
        })
        .handle;
        if let Some(held) =
            release_occurrence_in_txn(store, wtxn, scope.run, scope.path(digest), handle)?
        {
            drop_unheld_body_in_txn(store, wtxn, &held)?;
        }
    }
    Ok(())
}

/// The ref the bytes `bytes` are published under.
fn piece_ref(bytes: &[u8]) -> OutputRef {
    OutputRef {
        hash: *blake3::hash(bytes).as_bytes(),
        byte_len: bytes.len() as u64,
    }
}

/// `value` as canonical JSON: keys sorted, array order kept.
fn canonical(value: &Value) -> Result<Vec<u8>> {
    crate::llm::canonical_json_bytes(value)
        .map_err(|error| Error::InvalidConfig(format!("capsule request piece: {error}")))
}

/// A manifest or a node as MessagePack.
fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value)
        .map_err(|error| Error::InvalidConfig(format!("capsule request piece: {error}")))
}

/// A manifest or a node from its MessagePack; `None` for bytes that are not
/// one.
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Option<T> {
    rmp_serde::from_slice(bytes).ok()
}
