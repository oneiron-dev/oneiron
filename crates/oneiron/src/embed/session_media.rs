//! The session-aware media door (OF-370): a media vector written while a room is off record
//! stays in the room.
//!
//! [`Vault::put_media_vector`] writes base. A host that embeds a record an off-record room holds
//! writes here instead: the vector stages into the room's overlay as one typed, journaled
//! `BatchOp::MediaVector`, owned by a turn of the room, so session recall's media channel reads
//! it through the room's view and base never holds it. Promoting the turn replays it into base;
//! closing the room drops it. A room on record writes base, while its saver holds. A vector is
//! derived from the room's own records and recomputable, so neither its row nor its journal entry
//! spends the room's byte budget: a write that fits the room without it still fits (FIX 2345,
//! Engine 10-20 23:4x). It still lives in the room's overlay and goes when the room closes.
//!
//! The host's embed pass over live rooms (FIX 2345, [`Vault::reconcile_session_media_embeddings`])
//! fills a declared space for the records each room off record stages, through this door, one
//! vector per write and outside every room write: a room's ASSETs and text records find their
//! media vectors in the room before they are promoted. Its egress and route checks are the base
//! backfill's, judged on the room's view.
//!
//! A promotion keeps the room's copies of the vectors it replayed, byte-equal to base's. A delete
//! or erase of the record drops them in every room in the same writer as base's
//! ([`drop_room_media_copies_in_txn`], FIX 9398), so no room serves a vector of a record that
//! is gone.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use heed::RwTxn;

use super::device::media_device_row_key;
use super::media::{
    MediaEgressGate, MediaEmbedReport, MediaEmbedder, PendingMedia, is_text_document_type,
    media_egress_for, media_held_in, text_document_of,
};
use super::space::{
    EmbeddingSpace, InputKind, embedding_space_in_txn, media_text_hash_of, media_vector_row_key,
};
use super::space_move::space_fill_kinds_in_txn;
use super::{EgressPredicate, EmbeddingProvenance, TEXT_HASH_LEN};
use crate::Vault;
use crate::batch::BatchOp;
use crate::entity_id::EntityId;
use crate::error::{Error, OffRecordError, Result};
use crate::off_record::{OffRecordMode, OffRecordSession};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_TURN};
use crate::session_overlay::{
    JournalEntry, JournalRole, JournalScope, OverlayKeyspace, RecordMetaRows, RouteTarget,
};
use crate::side_table;
use crate::store::Store;
use crate::temporal::TimeRange;

/// What the embed pass over live rooms saw a space's model refuse by content, per room, kept by
/// the host in RAM for as long as the room lives (FIX 2345). A room's ids never reach base, so
/// its refusals are not stored in the vault as base's are; the same bytes are not sent again
/// while the room lives, and other bytes are. Each pass forgets the rooms no longer live.
#[derive(Debug, Default, Clone)]
pub struct SessionMediaRefusals {
    /// Room key, then space id and record, to the BLAKE3 of the refused bytes.
    refused: BTreeMap<String, BTreeMap<(String, EntityId), [u8; 32]>>,
}

impl SessionMediaRefusals {
    fn holds(&self, room: &str, space: &str, document: &PendingMedia) -> bool {
        self.refused.get(room).is_some_and(|rows| {
            rows.get(&(space.to_owned(), document.id))
                .is_some_and(|print| *print == *blake3::hash(&document.bytes).as_bytes())
        })
    }

    fn record(&mut self, room: &str, space: &str, document: &PendingMedia) {
        self.refused.entry(room.to_owned()).or_default().insert(
            (space.to_owned(), document.id),
            *blake3::hash(&document.bytes).as_bytes(),
        );
    }

    fn clear(&mut self, room: &str, space: &str, id: EntityId) {
        if let Some(rows) = self.refused.get_mut(room) {
            rows.remove(&(space.to_owned(), id));
        }
    }
}

/// What the embed pass read of a record before its model ran (FIX 2345): a vector of it lands
/// only while the room is still off record and, for a text vector, still holds that text.
#[derive(Clone, Copy)]
struct PassRead {
    text_hash: Option<[u8; TEXT_HASH_LEN]>,
    /// The whole BLAKE3 of the media bytes the model was sent (FIX 7608
    /// slice 3).
    copy: Option<[u8; 32]>,
}

impl Vault {
    /// Stores one host-computed media vector of record `id` in `space_id` through `session`'s
    /// own write route. While the room is off record the vector stages in the room, owned by
    /// its `turn`, and promotion carries it into base with that turn; once the room is on
    /// record it lands in base as [`Self::put_media_vector`] does, while the room's saver holds.
    /// A text vector is of the record's current text as the room reads it.
    ///
    /// # Errors
    ///
    /// [`Error::InvariantViolation`] for a session of another vault; [`Error::EntityNotFound`]
    /// when the room holds no record `id` or no TURN `turn`; [`Error::InvalidConfig`] when the
    /// space is undeclared, no slot binds or moves `kind` to it, or a text record holds no text;
    /// [`Error::DimensionMismatch`] for a vector of another width. An anonymous room records
    /// nothing, so it refuses. A vector a caller supplies names no device, so it keeps no mark
    /// (FIX 7796).
    pub fn put_session_media_vector(
        &self,
        session: &OffRecordSession<'_>,
        turn: &EntityId,
        space_id: &str,
        id: &EntityId,
        kind: InputKind,
        vector: &[f32],
    ) -> Result<()> {
        self.put_session_media_vector_of(session, turn, space_id, id, kind, vector, None, None)
            .map(|_| ())
    }

    /// [`Self::put_session_media_vector`]; with the embed pass's `read`, `false`, landing
    /// nothing, once the room is no longer off record or a text record's text has moved from
    /// the one its vector was embedded from. The vector's mark, the device and runtime the
    /// pass's model answered with, lands beside it (FIX 7796).
    #[expect(
        clippy::too_many_arguments,
        reason = "the session door's arguments, what the pass read before its model ran, and its answer's mark"
    )]
    fn put_session_media_vector_of(
        &self,
        session: &OffRecordSession<'_>,
        turn: &EntityId,
        space_id: &str,
        id: &EntityId,
        kind: InputKind,
        vector: &[f32],
        read: Option<PassRead>,
        provenance: Option<&EmbeddingProvenance>,
    ) -> Result<bool> {
        if session.vault_id() != self.vault_id() {
            return Err(Error::InvariantViolation(
                "a session media write names a session of another vault",
            ));
        }
        let route = session.write_route()?;
        route.require_recording(session.session_ref())?;
        if route.target() == RouteTarget::Base {
            if read.is_some() {
                return Ok(false);
            }
            return session
                .with_saver_write_txn(session.saver_check_for(&route)?, |wtxn| {
                    self.put_base_media_vector_in_txn(wtxn, space_id, id, kind, vector, provenance)
                })
                .map(|()| true);
        }
        let conversation = session.overlay_conversation_shell()?;
        session.overlay_write_routed(&route, |wtxn, apply| {
            let text_hash = {
                let view = session.read_view()?;
                if view.port_entity_record(&*wtxn, id)?.is_none() {
                    return Err(Error::EntityNotFound);
                }
                if view
                    .port_entity_record(&*wtxn, turn)?
                    .is_none_or(|row| row.entity_type != ENTITY_TYPE_TURN)
                {
                    return Err(Error::EntityNotFound);
                }
                // A record the room holds promotes with the turn that put it,
                // so its vector rides that turn: under another one, promote
                // would replay it into base without its record.
                if view.entities.stages_row(id.as_bytes())
                    && !session
                        .overlay()
                        .snapshot()?
                        .journal_entries()
                        .iter()
                        .any(|entry| {
                            entry.scope.turn() == *turn
                                && matches!(&entry.op, BatchOp::Put { id: put, .. } if put == id)
                        })
                {
                    return Err(Error::InvalidConfig(
                        "a record the room holds takes its media vector under the turn that put it"
                            .into(),
                    ));
                }
                match read {
                    Some(PassRead {
                        text_hash: None,
                        copy: Some(sent),
                    }) if super::repo_projection::media_copy_hash_in(self, &view, &*wtxn, id)?
                        != Some(sent) =>
                    {
                        return Ok(false);
                    }
                    Some(PassRead {
                        text_hash: Some(embedded),
                        ..
                    }) => {
                        let current = super::media::text_document_in(self, &view, &*wtxn, id)?;
                        if current.is_none_or(|text| super::space::text_hash(&text) != embedded) {
                            return Ok(false);
                        }
                        Some(embedded)
                    }
                    _ => media_text_hash_of(self, &view, &*wtxn, id, kind)?,
                }
            };
            // The vector's row is the room's bookkeeping, past its byte budget, as its
            // journal entry is: the `vault_meta` row the side table stages.
            session.overlay().mark_bookkeeping_row(
                OverlayKeyspace::VaultMeta,
                &media_vector_row_key(space_id, id),
            )?;
            session.overlay().mark_bookkeeping_row(
                OverlayKeyspace::VaultMeta,
                &media_device_row_key(space_id, id),
            )?;
            let at = self.store.clock.now_recorded_at();
            apply(
                wtxn,
                JournalEntry {
                    scope: JournalScope::new(conversation, *turn),
                    role: JournalRole::TurnOwnedArtifact,
                    learned_at: at,
                    occurred: TimeRange { start: at, end: at },
                    op: BatchOp::MediaVector {
                        space: space_id.to_owned(),
                        id: *id,
                        kind,
                        text_hash,
                        vector: vector.to_vec(),
                        provenance: provenance.cloned(),
                    },
                    source_run: None,
                },
            )?;
            Ok(true)
        })
    }

    /// Fills `embedder`'s space, through [`Self::put_session_media_vector`], for the records
    /// each live room off record stages and the space lacks a vector of as the room reads them:
    /// its image and audio ASSETs of the kinds the space fills, and, when it fills text, its
    /// text records at their current text. Up to `max_items` per room this pass, each embedded
    /// outside every transaction and landed under the turn that put it, one write per vector,
    /// so a failure here never fails a room's own write. A room on record, anonymous or closing
    /// is passed over: its own writes land in base, or keep nothing.
    ///
    /// The egress and route checks are [`Self::reconcile_media_embeddings_admitted`]'s, judged
    /// on the room's view: a third-party embedder, or one on the owner's server with a gate,
    /// reads only what `egress` allows and no device-local world keeps. A document the model
    /// refuses by its content is kept in `refusals` for the room's life, never in the vault.
    ///
    /// # Errors
    ///
    /// As [`Self::reconcile_media_embeddings_admitted`] for the space and the embedder, whose
    /// failure ends the pass. A room's own read or write error is logged and that room passed
    /// over for this pass.
    pub fn reconcile_session_media_embeddings(
        &self,
        embedder: &dyn MediaEmbedder,
        max_items: usize,
        egress: Option<&dyn EgressPredicate>,
        refusals: &mut SessionMediaRefusals,
    ) -> Result<MediaEmbedReport> {
        let egress = media_egress_for(embedder, egress)?;
        let mut report = MediaEmbedReport::default();
        let rooms = self.live_off_record_session_keys();
        refusals.refused.retain(|room, _| rooms.contains(room));
        let space_id = embedder.space_id();
        let (space, kinds) = {
            let rtxn = self.store.env.read_txn()?;
            let Some(space) = embedding_space_in_txn(&self.store, &rtxn, space_id)? else {
                return Err(Error::InvalidConfig(format!(
                    "embedding space {space_id} is not declared"
                )));
            };
            if embedder.dimensions() != space.dimensions {
                return Err(Error::DimensionMismatch {
                    expected: space.dimensions,
                    got: embedder.dimensions(),
                });
            }
            let kinds = space_fill_kinds_in_txn(&self.store, &rtxn, &space)?;
            (space, kinds)
        };
        if kinds.is_empty() {
            return Ok(report);
        }
        let vault = self.off_record_session_vault();
        for room in &rooms {
            // A room that closed since the list was read binds no more.
            let Ok(session) = vault.bind(room) else {
                continue;
            };
            if !matches!(session.mode(), Ok(OffRecordMode::OffRecord)) {
                continue;
            }
            self.reconcile_room_media(
                &session,
                embedder,
                &space,
                &kinds,
                max_items,
                egress,
                refusals,
                &mut report,
            )?;
        }
        Ok(report)
    }

    /// One live room's share of [`Self::reconcile_session_media_embeddings`]: the model's
    /// failure is returned; the room's own read or write failure is logged and ends its share.
    #[expect(
        clippy::too_many_arguments,
        reason = "one room's pass names its room, model, space, kinds, bound, gate and tallies"
    )]
    fn reconcile_room_media(
        &self,
        session: &OffRecordSession<'_>,
        embedder: &dyn MediaEmbedder,
        space: &EmbeddingSpace,
        kinds: &BTreeSet<InputKind>,
        max_items: usize,
        egress: Option<&dyn EgressPredicate>,
        refusals: &mut SessionMediaRefusals,
        report: &mut MediaEmbedReport,
    ) -> Result<()> {
        let room = session.session_ref().to_owned();
        let destination = embedder.endpoint();
        let stopped = |error: &Error| {
            tracing::warn!(
                kind = ?error.kind(),
                space = %space.id,
                "a live room's media pass stopped; the room's own writes are untouched"
            );
        };
        let backlog = self.room_media_backlog(
            session,
            space,
            kinds,
            max_items,
            egress,
            &destination,
            |document| refusals.holds(&room, &space.id, document),
            report,
        );
        let (documents, turns) = match backlog {
            Ok(backlog) => backlog,
            Err(error) => {
                stopped(&error);
                return Ok(());
            }
        };
        if documents.is_empty() {
            return Ok(());
        }
        let outcomes =
            self.embed_documents(embedder, &documents, Some(session), egress, &destination)?;
        for ((document, turn), outcome) in documents.iter().zip(&turns).zip(outcomes) {
            let (vector, provenance) = match outcome {
                Ok(answer) => answer,
                Err(_) => {
                    refusals.record(&room, &space.id, document);
                    report.refused += 1;
                    continue;
                }
            };
            match self.put_session_media_vector_of(
                session,
                turn,
                &space.id,
                &document.id,
                document.kind,
                &vector,
                Some(PassRead {
                    text_hash: document.text_hash,
                    copy: Some(*blake3::hash(&document.bytes).as_bytes()),
                }),
                Some(&provenance),
            ) {
                Ok(true) => {
                    refusals.clear(&room, &space.id, document.id);
                    report.embedded += 1;
                }
                // Its text moved, or the room went on record, while the model ran: the next
                // pass embeds what the room holds then.
                Ok(false) | Err(Error::EntityNotFound) => report.vanished += 1,
                // The slot was rebound, or the space went, while the model ran.
                Err(Error::InvalidConfig(_)) => report.unbound += 1,
                // The room closed or went on record while the model ran.
                Err(Error::OffRecord(
                    OffRecordError::OffRecordSessionClosing { .. }
                    | OffRecordError::OffRecordSessionNotFound { .. },
                )) => return Ok(()),
                Err(error) => {
                    stopped(&error);
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// Up to `max_items` documents of `kinds` that `session`'s room stages and `space` lacks a
    /// vector of as the room reads it, each with the turn that put it, in record id order. A
    /// document `refused` names, or `egress` keeps home, is counted and left.
    #[expect(
        clippy::too_many_arguments,
        reason = "one room's backlog names its room, space, kinds, bound, gate, refusals and tallies"
    )]
    fn room_media_backlog(
        &self,
        session: &OffRecordSession<'_>,
        space: &EmbeddingSpace,
        kinds: &BTreeSet<InputKind>,
        max_items: usize,
        egress: Option<&dyn EgressPredicate>,
        destination: &crate::settings::ReadDestination,
        refused: impl Fn(&PendingMedia) -> bool,
        report: &mut MediaEmbedReport,
    ) -> Result<(Vec<PendingMedia>, Vec<EntityId>)> {
        // Each record the room put, under the first turn that put it: the turn its vector rides.
        let mut put_by: BTreeMap<EntityId, EntityId> = BTreeMap::new();
        for entry in session.overlay().snapshot()?.journal_entries() {
            if let BatchOp::Put { id, .. } = &entry.op {
                put_by.entry(*id).or_insert_with(|| entry.scope.turn());
            }
        }
        let _bodies = self.pin_all_result_bodies();
        let rtxn = self.store.env.read_txn()?;
        let view = session.read_view()?;
        let gate = egress
            .map(|egress| MediaEgressGate::read(self, &rtxn, egress, destination))
            .transpose()?;
        let media_kinds = kinds.contains(&InputKind::Image) || kinds.contains(&InputKind::Audio);
        let (mut pending, mut turns) = (Vec::new(), Vec::new());
        for (id, turn) in put_by {
            if pending.len() >= max_items {
                break;
            }
            // Only what the room itself stages: base's records are base's backfill's.
            if !view.entities.stages_row(id.as_bytes()) {
                continue;
            }
            let Some(row) = view.port_entity_record(&rtxn, &id)? else {
                continue;
            };
            let asset = media_kinds && row.entity_type == ENTITY_TYPE_ASSET;
            let text = kinds.contains(&InputKind::Text) && is_text_document_type(row.entity_type);
            if !asset && !text {
                continue;
            }
            report.scanned += 1;
            // The base scan's own tallies of what each read finds; this pass counts its own.
            let mut read = MediaEmbedReport::default();
            let mut document = None;
            if asset {
                document = super::repo_projection::asset_document_projected_in(
                    self, &view, &rtxn, id, kinds, &mut read,
                )?;
            }
            if document.is_none() && text {
                document = text_document_of(self, &view, &rtxn, id, &mut read)?;
            }
            let Some(document) = document else {
                report.no_media += 1;
                continue;
            };
            if media_held_in(&view, &rtxn, space, &document)? {
                report.already_embedded += 1;
            } else if refused(&document) {
                report.refused += 1;
            } else if let Some(gate) = &gate
                && !gate.admits(&view, &rtxn, &document)?
            {
                report.withheld += 1;
            } else {
                pending.push(document);
                turns.push(turn);
            }
        }
        Ok((pending, turns))
    }
}

thread_local! {
    /// The records a batch on this thread has deleted or erased while its
    /// [`RoomMediaDrops`] is open, with the store it writes: their room copies drop once, as it
    /// closes.
    static PENDING_ROOM_DROPS: RefCell<Option<(*const Store, BTreeSet<EntityId>)>> =
        const { RefCell::new(None) };
}

/// One batch's room media drop (FIX 9398). While it is open on a thread,
/// [`drop_room_media_copies_in_txn`] collects the ids the batch deletes or erases in its store,
/// and closing it drops their copies in each room once, still inside the batch's writer. A batch
/// of many deletes then copies a room's state once, not once per record. Only the outermost of
/// nested batches drops; an inner one adds to it.
pub(crate) struct RoomMediaDrops<'s> {
    store: &'s Store,
    outermost: bool,
}

impl<'s> RoomMediaDrops<'s> {
    /// Opens it for a batch applied in `_writer`, which commits only after it closes.
    pub(crate) fn open(store: &'s Store, _writer: &RwTxn<'_>) -> Self {
        let outermost = PENDING_ROOM_DROPS.with(|pending| {
            let mut pending = pending.borrow_mut();
            let outermost = pending.is_none();
            if outermost {
                *pending = Some((std::ptr::from_ref(store), BTreeSet::new()));
            }
            outermost
        });
        Self { store, outermost }
    }
}

impl Drop for RoomMediaDrops<'_> {
    fn drop(&mut self) {
        if !self.outermost {
            return;
        }
        if let Some((_, ids)) = PENDING_ROOM_DROPS.with(|pending| pending.borrow_mut().take()) {
            drop_room_media_copies(self.store, &ids);
        }
    }
}

/// Drops, in every live room and retained sealed stretch, `id`'s staged media vector and device
/// rows in every space, one retired since included, and its `MediaVector` journal entries, inside
/// `_writer`, the writer that deletes or erases it beside base's own
/// ([`super::delete_media_vectors_in_txn`]), FIX 9398. It runs before that writer commits, so no
/// older room write can publish a dropped row again: at once, or as the open [`RoomMediaDrops`]
/// of a batch in the same store closes. A promotion keeps the room's copies of the vectors it
/// replayed, so without this they would outlive the record until the room closes. Its copies of
/// the record's own text index rows, vector, phonetic codes, revision rows and embedding marks go
/// the same way (FIX 17382, 19094).
pub(crate) fn drop_room_media_copies_in_txn(store: &Store, _writer: &RwTxn<'_>, id: &EntityId) {
    let collected = PENDING_ROOM_DROPS.with(|pending| match pending.borrow_mut().as_mut() {
        Some((owner, ids)) if std::ptr::eq(*owner, store) => {
            ids.insert(*id);
            true
        }
        _ => false,
    });
    if !collected {
        drop_room_media_copies(store, &BTreeSet::from([*id]));
    }
}

/// The vault-meta rows a room stages of one record beside its text index rows, which a delete
/// or erase of the record drops from every room with them (FIX 19094): its index source fields
/// and phonetic source codes, its revision state and history document (every revision's raw
/// row), its pending index inputs, phonetic codes and vector refill, and its embedding device
/// and locality marks, each keyed by its id; each pinned frontier, keyed by its id and the
/// revision; each revision identity, whose value is its id. Base drops its own of these with the
/// record (`entity_revision::remove_entity_revisions`, the phonetic and index-source deletes).
fn record_meta_prefixes() -> ([&'static [u8]; 9], [&'static [u8]; 1], [&'static [u8]; 1]) {
    (
        [
            side_table::INDEX_SOURCE_TEXT.prefix,
            side_table::BATCH_PHONETIC_INDEX_SOURCE.prefix,
            side_table::ENTITY_REVISION_STATE.prefix,
            side_table::ENTITY_REVISION_DOC.prefix,
            side_table::ENTITY_REVISION_PENDING_INDEX_INPUTS.prefix,
            side_table::ENTITY_REVISION_PENDING_PHONETIC.prefix,
            side_table::ENTITY_REVISION_VECTOR_REFILL.prefix,
            side_table::EMBEDDING_DEVICE.prefix,
            side_table::EMBEDDING_LOCALITY.prefix,
        ],
        [side_table::ENTITY_REVISION_FRONTIER.prefix],
        [side_table::ENTITY_REVISION_IDENTITY.prefix],
    )
}

/// Drops every room's staged media copies of `ids`, and its copies of their own text index rows,
/// vectors, phonetic codes and vault-meta rows (FIX 17382, 19094): a promotion keeps those
/// byte-equal to base's, and base's go with the record. A room whose overlay lock is poisoned
/// serves no read; it keeps its rows until it closes.
fn drop_room_media_copies(store: &Store, ids: &BTreeSet<EntityId>) {
    if ids.is_empty() {
        return;
    }
    let overlays = store.off_record_sessions.live_overlay_handles();
    if overlays.is_empty() {
        return;
    }
    let prefixes = super::space::repo_projection::media_row_prefixes();
    let (keyed, scoped, reverse) = record_meta_prefixes();
    let meta = RecordMetaRows {
        keyed: &keyed,
        scoped: &scoped,
        reverse: &reverse,
    };
    for overlay in overlays {
        if let Err(error) = overlay.invalidate_repo_media_copies(&prefixes, ids) {
            tracing::warn!(
                error = %error,
                "a room keeps its staged media copies of a deleted record until it closes"
            );
        }
        if let Err(error) = overlay.invalidate_retrieval_copies(meta, ids) {
            tracing::warn!(
                error = %error,
                "a room keeps its index copies of a deleted record until it closes"
            );
        }
    }
}

/// Drops room-staged media rows and journal entries for a retired space.
/// Run inside the retiring writer. A poisoned room stays unreadable until it closes.
pub(super) fn drop_room_media_space_copies(store: &Store, space_id: &str, space_key: &[u8; 16]) {
    let overlays = store.off_record_sessions.live_overlay_handles();
    if overlays.is_empty() {
        return;
    }
    let prefixes = super::space::repo_projection::media_row_prefixes();
    for overlay in overlays {
        if let Err(error) =
            overlay.invalidate_repo_media_space_copies(&prefixes, space_key, space_id)
        {
            tracing::warn!(
                error = %error,
                "a room keeps its staged media copies of a retired space until it closes"
            );
        }
    }
}
