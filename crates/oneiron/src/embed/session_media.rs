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

use std::collections::{BTreeMap, BTreeSet};

use super::device::media_device_row_key;
use super::media::{
    MediaEgressGate, MediaEmbedReport, MediaEmbedder, PendingMedia, asset_document_in,
    is_text_document_type, media_egress_for, media_held_in, text_document_of,
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
    JournalEntry, JournalRole, JournalScope, OverlayKeyspace, RouteTarget,
};
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
                        text_hash: Some(embedded),
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
    /// on the room's view: a third-party embedder reads only what `egress` allows and no
    /// device-local world keeps. A document the model refuses by its content is kept in
    /// `refusals` for the room's life, never in the vault.
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
        let outcomes = self.embed_documents(embedder, &documents, Some(session))?;
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
        let rtxn = self.store.env.read_txn()?;
        let view = session.read_view()?;
        let gate = egress
            .map(|egress| MediaEgressGate::read(self, &rtxn, egress))
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
                document = asset_document_in(&view, &rtxn, id, kinds, &mut read)?;
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
