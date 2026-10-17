//! The media embedder adapter and the backfill that fills a declared media space from stored
//! image and audio ASSETs, and from text documents once the text slot binds the space (OF-370;
//! ARCH-0036 `#media-embedder`).
//!
//! The host supplies the model behind [`MediaEmbedder`]; the engine finds the ASSETs whose
//! media kind is bound to that embedder's space and lacks a vector there, and on the one-space
//! preset the records the text index would embed whose current text has no vector there. It
//! hands their bytes over outside any transaction and stores each vector under its space and
//! kind.

use std::collections::BTreeSet;

use rmpv::Value;

use super::EmbedderLocality;
use super::space::{
    EmbeddingSpace, InputKind, embedding_space_in_txn, has_media_vector_in_txn,
    media_text_hash_in_txn, put_media_vector_in_txn, text_hash,
};
use super::space_move::space_fill_kinds_in_txn;
use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};

/// ASSET body field holding the bytes.
const ASSET_BODY_BYTES: &str = "bytes";
/// ASSET body field holding the bytes' media type.
const ASSET_BODY_MEDIA_TYPE: &str = "mime_type";
/// The media type a text document is handed over as.
const TEXT_MEDIA_TYPE: &str = "text/plain; charset=utf-8";
/// The records the text index embeds ([`super::embeddable_payload_in_txn`]), and so the text
/// documents a text-bound space holds.
const TEXT_DOCUMENT_TYPES: [u8; 3] = [ENTITY_TYPE_CLAIM, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN];

/// One stored media item handed to a media embedder.
#[derive(Debug, Clone, Copy)]
pub struct MediaEmbeddingInput<'a> {
    pub entity_id: EntityId,
    pub kind: InputKind,
    pub media_type: &'a str,
    pub bytes: &'a [u8],
}

/// A host model that embeds image and audio documents, and on the one-space preset text
/// documents, into one declared space.
pub trait MediaEmbedder: Send + Sync {
    /// The declared space this model's vectors belong to.
    fn space_id(&self) -> &str;
    /// The vector width the model emits; it must equal the space's.
    fn dimensions(&self) -> usize;
    /// Where the model runs. Media bytes never leave for a third party from this door.
    fn locality(&self) -> EmbedderLocality;
    /// One vector per input, in input order.
    fn embed_media(&self, inputs: &[MediaEmbeddingInput<'_>]) -> Result<Vec<Vec<f32>>>;
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
}

/// One stored document a scan read: an ASSET's media, or a record's text.
pub(super) struct PendingMedia {
    pub(super) id: EntityId,
    pub(super) kind: InputKind,
    pub(super) media_type: String,
    pub(super) bytes: Vec<u8>,
    /// A text document's text hash, checked again before its vector lands.
    pub(super) text_hash: Option<[u8; 32]>,
}

impl Vault {
    /// Fills `embedder`'s space with up to `max_items` vectors for stored image and audio
    /// ASSETs whose kind the space fills ([`super::space_move::space_fill_kinds_in_txn`]: its
    /// slot binds the space, or an open version move carries it there), and, when it fills text
    /// (the one-space preset, or a text move), for the records the text index embeds, at their
    /// current text. A text document whose text moved since its vector was stored is embedded
    /// again.
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
        if embedder.locality() == EmbedderLocality::ThirdParty {
            return Err(Error::InvalidConfig(
                "a third-party media embedder has no egress grant for stored media".into(),
            ));
        }
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
            let pending = self.media_backlog_in_txn(&rtxn, &space, &kinds, max_items, &mut report)?;
            (space, kinds, pending)
        };
        if pending.is_empty() {
            return Ok(report);
        }

        let inputs: Vec<MediaEmbeddingInput<'_>> = pending
            .iter()
            .map(|item| MediaEmbeddingInput {
                entity_id: item.id,
                kind: item.kind,
                media_type: &item.media_type,
                bytes: &item.bytes,
            })
            .collect();
        let vectors = embedder.embed_media(&inputs)?;
        if vectors.len() != pending.len() {
            return Err(Error::InvalidConfig(format!(
                "media embedder returned {} vectors for {} inputs",
                vectors.len(),
                pending.len()
            )));
        }
        for vector in &vectors {
            if let Some(error) = Error::invalid_vector_component(vector) {
                return Err(error);
            }
        }

        let mut wtxn = self.store.env.write_txn()?;
        // The bindings and moves may have changed while the model ran; land only what this
        // space still fills.
        let fills = space_fill_kinds_in_txn(&self.store, &wtxn, &space)?;
        for (item, vector) in pending.iter().zip(&vectors) {
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
            put_media_vector_in_txn(
                &self.store,
                &mut wtxn,
                &space,
                &fills,
                &item.id,
                item.kind,
                item.text_hash,
                vector,
            )?;
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
        let mut pending = Vec::new();
        let mut held = 0;
        self.scan_documents_in_txn(rtxn, kinds, report, |document| {
            if pending.len() >= max_items {
                return Ok(false);
            }
            let stored = match document.text_hash {
                Some(hash) => {
                    media_text_hash_in_txn(&self.store, rtxn, space, &document.id)? == Some(hash)
                }
                None => has_media_vector_in_txn(&self.store, rtxn, space, &document.id)?,
            };
            if stored {
                held += 1;
            } else {
                pending.push(document);
            }
            Ok(pending.len() < max_items)
        })?;
        report.already_embedded += held;
        Ok(pending)
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
                let Some(raw) = self
                    .store
                    .port_entity_record(rtxn, &id)?
                    .map(|row| row.encode())
                else {
                    continue;
                };
                let Some((media_type, bytes)) =
                    raw.get(ENTITY_METADATA_HEADER_LEN..).and_then(asset_media)
                else {
                    report.no_media += 1;
                    continue;
                };
                let Some(kind) = InputKind::for_media_type(&media_type) else {
                    report.no_media += 1;
                    continue;
                };
                if !kinds.contains(&kind) {
                    report.unbound += 1;
                    continue;
                }
                let document = PendingMedia {
                    id,
                    kind,
                    media_type,
                    bytes,
                    text_hash: None,
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
                    let Some(text) = text_document_in_txn(self, rtxn, &id)? else {
                        report.no_media += 1;
                        continue;
                    };
                    let document = PendingMedia {
                        id,
                        kind: InputKind::Text,
                        media_type: TEXT_MEDIA_TYPE.to_owned(),
                        text_hash: Some(text_hash(&text)),
                        bytes: text.into_bytes(),
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

/// The text a text-bound space embeds for record `id`: what the text index would embed for it
/// ([`super::embeddable_payload_in_txn`], [`super::payload_text`]). `None` for a record that is
/// gone, withdrawn, or holds nothing to embed.
pub(super) fn text_document_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<String>> {
    if crate::ports::stale_in_txn(&vault.store, txn, id)? {
        return Ok(None);
    }
    let Some(row) = vault.store.port_entity_record(txn, id)? else {
        return Ok(None);
    };
    let Some(payload) =
        super::embeddable_payload_in_txn(vault, txn, id, row.entity_type, &row.body)?
    else {
        return Ok(None);
    };
    Ok(Some(super::payload_text(&payload)?.into_owned()))
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
