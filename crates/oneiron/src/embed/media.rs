//! The media embedder adapter and the backfill that fills a declared media space from stored
//! image and audio ASSETs (OF-370; ARCH-0036 `#media-embedder`).
//!
//! The host supplies the model behind [`MediaEmbedder`]; the engine finds the ASSETs whose
//! media kind is bound to that embedder's space and lacks a vector there, hands their bytes
//! over outside any transaction, and stores each vector under its space and kind.

use std::collections::BTreeSet;

use rmpv::Value;

use super::EmbedderLocality;
use super::space::{
    InputKind, embedding_space_in_txn, has_media_vector_in_txn, kind_slot_bindings_in_txn,
    put_media_vector_in_txn,
};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_ASSET;
use crate::Vault;

/// ASSET body field holding the bytes.
const ASSET_BODY_BYTES: &str = "bytes";
/// ASSET body field holding the bytes' media type.
const ASSET_BODY_MEDIA_TYPE: &str = "mime_type";

/// One stored media item handed to a media embedder.
#[derive(Debug, Clone, Copy)]
pub struct MediaEmbeddingInput<'a> {
    pub entity_id: EntityId,
    pub kind: InputKind,
    pub media_type: &'a str,
    pub bytes: &'a [u8],
}

/// A host model that embeds image and audio documents into one declared space.
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
    /// ASSETs read.
    pub scanned: usize,
    /// Vectors stored this pass.
    pub embedded: usize,
    /// ASSETs that already had a vector in the space.
    pub already_embedded: usize,
    /// ASSETs whose media kind is not bound to the embedder's space.
    pub unbound: usize,
    /// ASSETs holding no inline image or audio bytes.
    pub no_media: usize,
    /// ASSETs deleted before their vector landed.
    pub vanished: usize,
}

struct PendingMedia {
    id: EntityId,
    kind: InputKind,
    media_type: String,
    bytes: Vec<u8>,
}

impl Vault {
    /// Fills `embedder`'s space with up to `max_items` vectors for stored image and audio
    /// ASSETs whose kind slot binds to that space.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the space is undeclared, bound to no kind, of another
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
            let bindings = kind_slot_bindings_in_txn(&self.store, &rtxn)?;
            let kinds: BTreeSet<InputKind> = [InputKind::Image, InputKind::Audio]
                .into_iter()
                .filter(|kind| {
                    bindings.space_for(*kind) == Some(space_id) && space.accepts.contains(kind)
                })
                .collect();
            if kinds.is_empty() {
                return Err(Error::InvalidConfig(format!(
                    "no media kind slot is bound to embedding space {space_id}"
                )));
            }
            let mut pending = Vec::new();
            for id in self
                .store
                .port_entity_ids_by_type(&rtxn, ENTITY_TYPE_ASSET, None)?
            {
                if pending.len() >= max_items {
                    break;
                }
                let id = id?;
                report.scanned += 1;
                let Some(raw) = self
                    .store
                    .port_entity_record(&rtxn, &id)?
                    .map(|row| row.encode())
                else {
                    continue;
                };
                let Some((media_type, bytes)) = raw
                    .get(ENTITY_METADATA_HEADER_LEN..)
                    .and_then(asset_media)
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
                if has_media_vector_in_txn(&self.store, &rtxn, &space, &id)? {
                    report.already_embedded += 1;
                    continue;
                }
                pending.push(PendingMedia {
                    id,
                    kind,
                    media_type,
                    bytes,
                });
            }
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
        // The bindings may have moved while the model ran; land only what still binds here.
        let bindings = kind_slot_bindings_in_txn(&self.store, &wtxn)?;
        for (item, vector) in pending.iter().zip(&vectors) {
            if !kinds.contains(&item.kind) || bindings.space_for(item.kind) != Some(space_id) {
                report.unbound += 1;
                continue;
            }
            if self.store.port_entity_record(&wtxn, &item.id)?.is_none() {
                report.vanished += 1;
                continue;
            }
            put_media_vector_in_txn(
                &self.store,
                &mut wtxn,
                &space,
                &bindings,
                &item.id,
                item.kind,
                vector,
            )?;
            report.embedded += 1;
        }
        wtxn.commit()?;
        Ok(report)
    }
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
