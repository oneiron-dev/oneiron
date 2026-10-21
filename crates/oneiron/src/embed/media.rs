//! The media embedder adapter and the backfill that fills a declared media space from stored
//! image and audio ASSETs, and from text documents once the text slot binds the space (OF-370;
//! ARCH-0036 `#media-embedder`).
//!
//! The host supplies the model behind [`MediaEmbedder`]; the engine finds the ASSETs whose
//! media kind is bound to that embedder's space and lacks a vector there, and on the one-space
//! preset the records the text index would embed whose current text has no vector there. It
//! hands their bytes over outside any transaction and stores each vector under its space and
//! kind.
//!
//! A model at a third party reads only what the host's egress gate admits, document by
//! document, and never a row a device-local world keeps (FIX 382, DEC-0005): the same gate and
//! world check the text rung's rows pass, each asked again right before the bytes leave.

use std::collections::BTreeSet;

use rmpv::Value;

use super::space::{
    EmbeddingSpace, InputKind, clear_media_refusal_in_txn, embedding_space_in_txn,
    has_media_vector_in_txn, media_refused_in_txn, media_text_hash_in_txn,
    put_media_refusal_in_txn, put_media_vector_in_txn, text_hash,
};
use super::space_move::space_fill_kinds_in_txn;
use super::{EgressDecision, EgressPredicate, EmbedderLocality};
use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::off_record::OffRecordSession;
use crate::ports::EntityStoreRead;
use crate::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};
use crate::store::ManifestDbs;

/// ASSET body field holding the bytes.
const ASSET_BODY_BYTES: &str = "bytes";
/// ASSET body field holding the bytes' media type.
const ASSET_BODY_MEDIA_TYPE: &str = "mime_type";
/// The media type a text document is handed over as.
const TEXT_MEDIA_TYPE: &str = "text/plain; charset=utf-8";
/// The records the text index embeds ([`super::embeddable_payload_in_txn`]), and so the text
/// documents a text-bound space holds.
const TEXT_DOCUMENT_TYPES: [u8; 4] = [
    ENTITY_TYPE_CLAIM,
    ENTITY_TYPE_SUMMARY,
    ENTITY_TYPE_TURN,
    ENTITY_TYPE_ASSET,
];

/// One stored media item handed to a media embedder.
#[derive(Debug, Clone, Copy)]
pub struct MediaEmbeddingInput<'a> {
    pub entity_id: EntityId,
    pub kind: InputKind,
    pub media_type: &'a str,
    pub bytes: &'a [u8],
    /// The rows `bytes` are read from (FIX 7001): an ASSET's own row, or a
    /// text document's record and the messages a TURN's text joins. `None`
    /// when they are not known whole.
    pub source_rows: Option<&'a [EntityId]>,
}

/// A host model that embeds image and audio documents, and on the one-space preset text
/// documents, into one declared space.
pub trait MediaEmbedder: Send + Sync {
    /// The declared space this model's vectors belong to.
    fn space_id(&self) -> &str;
    /// The vector width the model emits; it must equal the space's.
    fn dimensions(&self) -> usize;
    /// Where the model runs. Media bytes leave for a third party from this door only as the
    /// host's egress gate admits each document ([`Vault::reconcile_media_embeddings_admitted`]).
    fn locality(&self) -> EmbedderLocality;
    /// One vector per input, in input order.
    fn embed_media(&self, inputs: &[MediaEmbeddingInput<'_>]) -> Result<Vec<Vec<f32>>>;
    /// One outcome per input, in input order: its vector, or why the model refused that
    /// document by its content (a format it cannot read, a content filter), so the backfill
    /// skips it until its bytes change. An error refuses the whole call. The default refuses
    /// no single document.
    fn embed_each(
        &self,
        inputs: &[MediaEmbeddingInput<'_>],
    ) -> Result<Vec<std::result::Result<Vec<f32>, String>>> {
        Ok(self.embed_media(inputs)?.into_iter().map(Ok).collect())
    }

    /// [`Self::embed_each`] for a model at a third party: `release` judges the documents of
    /// each request right before that request leaves, and a refusal sends nothing more and
    /// fails the call. One that sends a single request needs no more than this default; one
    /// that sends a request per document asks for each.
    fn embed_each_released(
        &self,
        inputs: &[MediaEmbeddingInput<'_>],
        release: &dyn Fn(&[EntityId]) -> Result<()>,
    ) -> Result<Vec<std::result::Result<Vec<f32>, String>>> {
        let rows: Vec<EntityId> = inputs.iter().map(|input| input.entity_id).collect();
        release(&rows)?;
        self.embed_each(inputs)
    }
}

/// What one media backfill pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MediaEmbedReport {
    /// ASSETs and text documents read.
    pub scanned: usize,
    /// Vectors stored this pass.
    pub embedded: usize,
    /// Items that already had a vector in the space, a text document one of its current text.
    pub already_embedded: usize,
    /// ASSETs whose media kind is not bound to the embedder's space.
    pub unbound: usize,
    /// ASSETs holding no inline image or audio bytes, and text documents holding no text to
    /// embed.
    pub no_media: usize,
    /// Items deleted, or text documents whose text moved, before their vector landed.
    pub vanished: usize,
    /// Documents the space's model refused by their content, this pass or before at the same
    /// bytes; the backfill skips them until their bytes change.
    pub refused: usize,
    /// Documents a third-party model was not sent: the host's egress gate gave no `Allow`, or
    /// a device-local world keeps them (FIX 382). They stay unsent, for a later pass.
    pub withheld: usize,
}

/// One stored document a scan read: an ASSET's media, or a record's text.
pub(super) struct PendingMedia {
    pub(super) id: EntityId,
    pub(super) kind: InputKind,
    pub(super) media_type: String,
    pub(super) bytes: Vec<u8>,
    /// A text document's text hash, checked again before its vector lands.
    pub(super) text_hash: Option<[u8; 32]>,
    /// When the vault learned the record, in vault seconds: a probe cohort's date cut.
    pub(super) learned_at: u64,
    /// The rows `bytes` are read from ([`MediaEmbeddingInput::source_rows`]).
    pub(super) source_rows: Option<Vec<EntityId>>,
}

impl PendingMedia {
    /// The document as a model reads it.
    pub(super) fn input(&self) -> MediaEmbeddingInput<'_> {
        MediaEmbeddingInput {
            entity_id: self.id,
            kind: self.kind,
            media_type: &self.media_type,
            bytes: &self.bytes,
            source_rows: self.source_rows.as_deref(),
        }
    }
}

/// What a third-party media model may read (FIX 382): the host's verdict on each document, and
/// the device-local worlds whose rows stay on this device (DEC-0005), read once per scan.
pub(super) struct MediaEgressGate<'a> {
    egress: &'a dyn EgressPredicate,
    flagged: BTreeSet<EntityId>,
}

impl<'a> MediaEgressGate<'a> {
    /// The gate for a scan in `txn`.
    pub(super) fn read(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        egress: &'a dyn EgressPredicate,
    ) -> Result<Self> {
        Ok(Self {
            egress,
            flagged: crate::settings::device_local_worlds_at(
                vault,
                txn,
                crate::claim::CallerLocality::OffDevice,
            )?,
        })
    }

    /// Whether `document`, as `store` reads it, may go: the host allows it, and no device-local
    /// world keeps it, nor is its world unreadable while one is flagged.
    pub(super) fn admits(
        &self,
        store: &impl ManifestDbs,
        txn: &heed::RoTxn<'_>,
        document: &PendingMedia,
    ) -> Result<bool> {
        if self.egress.decide_media(&document.input()) != EgressDecision::Allow {
            return Ok(false);
        }
        Ok(self.flagged.is_empty()
            || !crate::settings::device_local_keeps_among(store, txn, &self.flagged, &document.id)?)
    }
}

impl Vault {
    /// Fills `embedder`'s space with up to `max_items` vectors for stored image and audio
    /// ASSETs whose kind the space fills ([`super::space_move::space_fill_kinds_in_txn`]: its
    /// slot binds the space, or an open version move carries it there), and, when it fills text
    /// (the one-space preset, or a text move), for the records the text index embeds, at their
    /// current text. A text document whose text moved since its vector was stored is embedded
    /// again.
    ///
    /// A document the model refuses by its content ([`MediaEmbedder::embed_each`]) is recorded
    /// and skipped until its bytes change, once the model has shown it serves the space: the
    /// space holds a vector already, or another document this pass embedded. A model that
    /// refuses every document it is sent, and has embedded none, is an error instead.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the space is undeclared, fills no kind, is of another
    /// width, or the embedder runs at a third party; storage and embedder errors otherwise.
    pub fn reconcile_media_embeddings(
        &self,
        embedder: &dyn MediaEmbedder,
        max_items: usize,
    ) -> Result<MediaEmbedReport> {
        self.reconcile_media_embeddings_admitted(embedder, max_items, None)
    }

    /// [`Self::reconcile_media_embeddings`] with the host's media egress gate (FIX 382): an
    /// embedder at a third party is sent only the documents `egress` allows
    /// ([`EgressPredicate::decide_media`]) that no device-local world keeps (DEC-0005), each
    /// asked again right before its bytes leave ([`MediaEmbedder::embed_each_released`]); the
    /// rest stay unsent and are counted [`MediaEmbedReport::withheld`]. An embedder on this
    /// device or the owner's server reads as it does without a gate.
    ///
    /// # Errors
    ///
    /// As [`Self::reconcile_media_embeddings`]; a third-party embedder with no gate is refused
    /// as there.
    pub fn reconcile_media_embeddings_admitted(
        &self,
        embedder: &dyn MediaEmbedder,
        max_items: usize,
        egress: Option<&dyn EgressPredicate>,
    ) -> Result<MediaEmbedReport> {
        let egress = media_egress_for(embedder, egress)?;
        let mut report = MediaEmbedReport::default();
        let space_id = embedder.space_id();
        let (space, kinds, pending) = {
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
            if kinds.is_empty() {
                return Err(Error::InvalidConfig(format!(
                    "no kind slot is bound or moving to embedding space {space_id}"
                )));
            }
            let gate = egress
                .map(|egress| MediaEgressGate::read(self, &rtxn, egress))
                .transpose()?;
            let pending = self.media_backlog_where_in_txn(
                &rtxn,
                &space,
                &kinds,
                max_items,
                &mut report,
                gate.as_ref(),
            )?;
            (space, kinds, pending)
        };
        if pending.is_empty() {
            return Ok(report);
        }

        let outcomes = self.embed_documents(embedder, &pending, None)?;
        // A model that has embedded nothing here may be refusing them all for a reason of its
        // own; no document is blamed for that.
        if report.already_embedded == 0
            && outcomes.iter().all(std::result::Result::is_err)
            && let Some(Err(reason)) = outcomes.first()
        {
            return Err(Error::InvalidConfig(format!(
                "the media embedder for {space_id} refused every document it was sent: {reason}"
            )));
        }

        let mut wtxn = self.store.env.write_txn()?;
        // The bindings and moves may have changed while the model ran; land only what this
        // space still fills.
        let fills = space_fill_kinds_in_txn(&self.store, &wtxn, &space)?;
        let at = self.store.clock.now_recorded_at();
        for (item, outcome) in pending.iter().zip(outcomes) {
            if !kinds.contains(&item.kind) || !fills.contains(&item.kind) {
                report.unbound += 1;
                continue;
            }
            if self.store.port_entity_record(&wtxn, &item.id)?.is_none() {
                report.vanished += 1;
                continue;
            }
            // A text that moved, or was erased, while the model ran lands no vector of the
            // old words; the next pass embeds what it holds now.
            if let Some(hash) = item.text_hash
                && text_document_in_txn(self, &wtxn, &item.id)?
                    .is_none_or(|text| text_hash(&text) != hash)
            {
                report.vanished += 1;
                continue;
            }
            let vector = match outcome {
                Ok(vector) => vector,
                Err(reason) => {
                    put_media_refusal_in_txn(
                        &self.store,
                        &mut wtxn,
                        &space,
                        &item.id,
                        &item.bytes,
                        reason,
                        at,
                    )?;
                    report.refused += 1;
                    continue;
                }
            };
            put_media_vector_in_txn(
                &self.store,
                &mut wtxn,
                &space,
                &fills,
                &item.id,
                item.kind,
                item.text_hash,
                &vector,
            )?;
            clear_media_refusal_in_txn(&self.store, &mut wtxn, &space, &item.id)?;
            report.embedded += 1;
        }
        wtxn.commit()?;
        Ok(report)
    }

    /// Up to `max_items` documents of `kinds` that `space` lacks a vector for, a text document
    /// one of its current text, in scan order; `report` counts what the scan read.
    pub(super) fn media_backlog_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        space: &EmbeddingSpace,
        kinds: &BTreeSet<InputKind>,
        max_items: usize,
        report: &mut MediaEmbedReport,
    ) -> Result<Vec<PendingMedia>> {
        self.media_backlog_where_in_txn(rtxn, space, kinds, max_items, report, None)
    }

    /// [`Self::media_backlog_in_txn`] of the documents `gate` admits, when there is one; the
    /// others are counted [`MediaEmbedReport::withheld`].
    pub(super) fn media_backlog_where_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        space: &EmbeddingSpace,
        kinds: &BTreeSet<InputKind>,
        max_items: usize,
        report: &mut MediaEmbedReport,
        gate: Option<&MediaEgressGate<'_>>,
    ) -> Result<Vec<PendingMedia>> {
        let mut pending = Vec::new();
        let mut held = 0;
        let mut refused = 0;
        let mut withheld = 0;
        self.scan_documents_in_txn(rtxn, kinds, report, |document| {
            if pending.len() >= max_items {
                return Ok(false);
            }
            if media_held_in(&self.store, rtxn, space, &document)? {
                held += 1;
            } else if media_refused_in_txn(&self.store, rtxn, space, &document.id, &document.bytes)?
            {
                refused += 1;
            } else if let Some(gate) = gate
                && !gate.admits(&self.store, rtxn, &document)?
            {
                withheld += 1;
            } else {
                pending.push(document);
            }
            Ok(pending.len() < max_items)
        })?;
        report.already_embedded += held;
        report.refused += refused;
        report.withheld += withheld;
        Ok(pending)
    }

    /// Each pending document's outcome from `embedder`, in order, read outside any
    /// transaction. A model at a third party is sent each request only once the vault
    /// releases its documents, as `session`'s room reads them or base with none: none is one
    /// a device-local world keeps (DEC-0005). A refusal sends nothing more and fails the call.
    pub(super) fn embed_documents(
        &self,
        embedder: &dyn MediaEmbedder,
        pending: &[PendingMedia],
        session: Option<&OffRecordSession<'_>>,
    ) -> Result<Vec<std::result::Result<Vec<f32>, String>>> {
        let inputs: Vec<MediaEmbeddingInput<'_>> =
            pending.iter().map(PendingMedia::input).collect();
        let outcomes = if embedder.locality() == EmbedderLocality::ThirdParty {
            embedder.embed_each_released(&inputs, &|rows| {
                if self.media_rows_may_leave(session, rows)? {
                    Ok(())
                } else {
                    Err(Error::UpstreamToolFailure {
                        tool: "media-embedder-remote",
                        code: "device_local_row".to_owned(),
                    })
                }
            })?
        } else {
            embedder.embed_each(&inputs)?
        };
        if outcomes.len() != pending.len() {
            return Err(Error::InvalidConfig(format!(
                "media embedder returned {} outcomes for {} inputs",
                outcomes.len(),
                pending.len()
            )));
        }
        for vector in outcomes.iter().flatten() {
            if let Some(error) = Error::invalid_vector_component(vector) {
                return Err(error);
            }
        }
        Ok(outcomes)
    }

    /// Whether `input`'s bytes may go to `embedder` now, as the backfill sends a stored document
    /// (FIX 382): to a model on this device or the owner's server, always; to one at a third
    /// party only with the host's gate `egress`, which must allow it, and only while no
    /// device-local world keeps it (DEC-0005), read under the flag lock right before the bytes
    /// go. A move's check asks it for each media query it encodes (FIX 1637); `false` sends
    /// nothing, and that probe does not run.
    ///
    /// # Errors
    ///
    /// Storage errors reading the world flags or the row.
    pub fn media_document_may_leave(
        &self,
        embedder: &dyn MediaEmbedder,
        egress: Option<&dyn EgressPredicate>,
        input: &MediaEmbeddingInput<'_>,
    ) -> Result<bool> {
        if embedder.locality() != EmbedderLocality::ThirdParty {
            return Ok(true);
        }
        if egress.is_none_or(|egress| egress.decide_media(input) != EgressDecision::Allow) {
            return Ok(false);
        }
        self.media_rows_may_leave(None, &[input.entity_id])
    }

    /// Whether every row of `rows` may leave this device now, as `session`'s room reads them,
    /// or base with none: none is one a device-local world keeps (DEC-0005), or whose world
    /// cannot be read while one is flagged. Read under the flag lock right before the bytes
    /// go, and held across no send.
    pub(super) fn media_rows_may_leave(
        &self,
        session: Option<&OffRecordSession<'_>>,
        rows: &[EntityId],
    ) -> Result<bool> {
        #[cfg(feature = "sync")]
        let _acceptance = self.device_only_acceptance();
        let rtxn = self.store.env.read_txn()?;
        let flagged = crate::settings::device_local_worlds_at(
            self,
            &rtxn,
            crate::claim::CallerLocality::OffDevice,
        )?;
        if flagged.is_empty() {
            return Ok(true);
        }
        let kept = match session {
            None => any_kept_in(&self.store, &rtxn, &flagged, rows)?,
            Some(session) => any_kept_in(&session.read_view()?, &rtxn, &flagged, rows)?,
        };
        Ok(!kept)
    }

    /// Visits every stored document of `kinds` in id order, image and audio ASSETs first, then
    /// the records the text index embeds, until `visit` answers `false`. `report` counts the
    /// documents read, the ASSETs of other kinds and those holding nothing to embed.
    pub(super) fn scan_documents_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        kinds: &BTreeSet<InputKind>,
        report: &mut MediaEmbedReport,
        mut visit: impl FnMut(PendingMedia) -> Result<bool>,
    ) -> Result<()> {
        if kinds.contains(&InputKind::Image) || kinds.contains(&InputKind::Audio) {
            for id in self
                .store
                .port_entity_ids_by_type(rtxn, ENTITY_TYPE_ASSET, None)?
            {
                let id = id?;
                report.scanned += 1;
                let Some(document) = asset_document_in(&self.store, rtxn, id, kinds, report)?
                else {
                    continue;
                };
                if !visit(document)? {
                    return Ok(());
                }
            }
        }
        if kinds.contains(&InputKind::Text) {
            for entity_type in TEXT_DOCUMENT_TYPES {
                for id in self
                    .store
                    .port_entity_ids_by_type(rtxn, entity_type, None)?
                {
                    let id = id?;
                    report.scanned += 1;
                    let Some(document) = text_document_of(self, &self.store, rtxn, id, report)?
                    else {
                        continue;
                    };
                    if !visit(document)? {
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }
}

/// Whether a device-local world of `flagged` keeps any row of `rows` as `store` reads it, or
/// cannot place one.
fn any_kept_in(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    flagged: &BTreeSet<EntityId>,
    rows: &[EntityId],
) -> Result<bool> {
    for row in rows {
        if crate::settings::device_local_keeps_among(store, txn, flagged, row)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `space`, as `store` reads it, holds `document`'s vector already, a text document's
/// of its current text.
pub(super) fn media_held_in(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    space: &EmbeddingSpace,
    document: &PendingMedia,
) -> Result<bool> {
    match document.text_hash {
        Some(hash) => Ok(media_text_hash_in_txn(store, txn, space, &document.id)? == Some(hash)),
        None => has_media_vector_in_txn(store, txn, space, &document.id),
    }
}

/// The image or audio document ASSET `id` holds as `store` reads it, when its media kind is one
/// of `kinds`. `report` counts an ASSET holding no inline image or audio, and one of another
/// kind; a gone one is `None` uncounted.
pub(super) fn asset_document_in(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kinds: &BTreeSet<InputKind>,
    report: &mut MediaEmbedReport,
) -> Result<Option<PendingMedia>> {
    let Some(row) = store.port_entity_record(txn, &id)? else {
        return Ok(None);
    };
    let learned_at = row.learned_at;
    let raw = row.encode();
    let Some((media_type, bytes)) = raw.get(ENTITY_METADATA_HEADER_LEN..).and_then(asset_media)
    else {
        report.no_media += 1;
        return Ok(None);
    };
    let Some(kind) = InputKind::for_media_type(&media_type) else {
        report.no_media += 1;
        return Ok(None);
    };
    if !kinds.contains(&kind) {
        report.unbound += 1;
        return Ok(None);
    }
    Ok(Some(PendingMedia {
        id,
        kind,
        media_type,
        bytes,
        text_hash: None,
        learned_at,
        source_rows: Some(vec![id]),
    }))
}

/// The text document record `id` holds as `store` reads it ([`text_document_in`]); `report`
/// counts one holding no text to embed.
pub(super) fn text_document_of(
    vault: &Vault,
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    report: &mut MediaEmbedReport,
) -> Result<Option<PendingMedia>> {
    let Some((text, learned_at, rows)) = text_row_in(vault, store, txn, &id)? else {
        report.no_media += 1;
        return Ok(None);
    };
    Ok(Some(PendingMedia {
        id,
        kind: InputKind::Text,
        media_type: TEXT_MEDIA_TYPE.to_owned(),
        text_hash: Some(text_hash(&text)),
        bytes: text.into_bytes(),
        learned_at,
        source_rows: Some(rows),
    }))
}

/// Whether record type `entity_type` is one a text-bound space holds as a document.
pub(super) fn is_text_document_type(entity_type: u8) -> bool {
    TEXT_DOCUMENT_TYPES.contains(&entity_type)
}

/// The host's gate a pass with `embedder` reads through: a third-party embedder's must be
/// there, or the pass is refused as it was before the gate; any other reads ungated.
pub(super) fn media_egress_for<'a>(
    embedder: &dyn MediaEmbedder,
    egress: Option<&'a dyn EgressPredicate>,
) -> Result<Option<&'a dyn EgressPredicate>> {
    if embedder.locality() != EmbedderLocality::ThirdParty {
        return Ok(None);
    }
    egress.map(Some).ok_or_else(|| {
        Error::InvalidConfig(
            "a third-party media embedder has no egress grant for stored media".into(),
        )
    })
}

/// The text a text-bound space embeds for record `id`: what the text index would embed for it
/// ([`super::embeddable_payload_in_txn`], [`super::payload_text`]). `None` for a record that is
/// gone, withdrawn, or holds nothing to embed.
pub(super) fn text_document_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<String>> {
    text_document_in(vault, &vault.store, txn, id)
}

/// [`text_document_in_txn`] read through `store`: base, or a room's view, whose records and
/// turns compose with base.
pub(super) fn text_document_in(
    vault: &Vault,
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<String>> {
    Ok(text_row_in(vault, store, txn, id)?.map(|(text, ..)| text))
}

/// [`text_document_in`], beside when the vault learned the record and the rows the text is
/// read from (FIX 7001).
fn text_row_in(
    vault: &Vault,
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<(String, u64, Vec<EntityId>)>> {
    if crate::ports::stale_in_txn(store, txn, id)? {
        return Ok(None);
    }
    let Some(row) = store.port_entity_record(txn, id)? else {
        return Ok(None);
    };
    let Some((payload, rows)) = super::eligibility::embeddable_payload_in(
        vault,
        store,
        txn,
        id,
        row.entity_type,
        &row.body,
    )?
    else {
        return Ok(None);
    };
    Ok(Some((
        super::payload_text(&payload)?.into_owned(),
        row.learned_at,
        rows,
    )))
}

/// The inline media an ASSET body holds: its media type and non-empty bytes.
fn asset_media(body: &[u8]) -> Option<(String, Vec<u8>)> {
    let Value::Map(entries) = rmpv::decode::read_value(&mut &body[..]).ok()? else {
        return None;
    };
    let field = |name: &str| {
        entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value)
    };
    let (Some(Value::Binary(bytes)), Some(media_type)) = (
        field(ASSET_BODY_BYTES),
        field(ASSET_BODY_MEDIA_TYPE).and_then(Value::as_str),
    ) else {
        return None;
    };
    (!bytes.is_empty()).then(|| (media_type.to_owned(), bytes.clone()))
}

/// The UTF-8 content of a text ASSET, shared by both embedding workers.
pub(super) fn asset_text(body: &[u8]) -> Option<String> {
    let (mime, bytes) = asset_media(body)?;
    if !mime.starts_with("text/") {
        return None;
    }
    let text = String::from_utf8(bytes).ok()?;
    text.chars()
        .any(|c| !c.is_whitespace() && !c.is_control())
        .then_some(text)
}
