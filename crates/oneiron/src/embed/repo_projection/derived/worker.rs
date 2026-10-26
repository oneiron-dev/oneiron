//! The pass that derives a pending text's safe copy (FIX 7608 S3F, CALL
//! DERIVED-TEXT-COPY): each source is read as a model may read it (its
//! masked copy, the sealed-file placeholder as text, never a marked blob's
//! stored bytes), the host's own model derives a text from them outside
//! every writer, and the copy lands only when the writer finds the same
//! proof. A model that derives nothing leaves the copy pending for the next
//! pass; no deadline or retry count retires it.

use heed::RoTxn;

use super::{
    RepoDerivedOwner, RepoDerivedReady, is_storage_error, pending_in, put_ready_in_txn,
    republish_in_txn,
};
use crate::Vault;
use crate::embed::media::{MediaEmbeddingInput, TEXT_MEDIA_TYPE, asset_media};
use crate::embed::{EgressDecision, EgressPredicate, EmbedderLocality, InputKind};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::origin::secret_projection::index::{
    RepoDerivedIndexSources, RepoIndexMarks, opaque_index_text, repo_derived_index_sources_in,
};
use crate::ports::EntityStoreRead;

/// A host model that writes the text standing in for one a model derived
/// from repo bytes: a caption of an image, a transcript of audio, a short
/// description of a text.
pub trait RepoDerivedIndexTextAuthor: Send + Sync {
    /// The model that derives; kept beside each copy.
    fn author_id(&self) -> &str;

    /// Where its seats run: a third-party one reads stored image or audio
    /// copies only through the host's media egress gate.
    fn locality(&self) -> EmbedderLocality;

    /// A text derived from `sources` alone, each read as its safe copy;
    /// `None` when it derives none now (no seat bound, no egress for this
    /// media, nothing heard), which leaves the copy pending.
    ///
    /// # Errors
    /// The model's failure; the copy stays pending.
    fn derive_text(&self, sources: &[MediaEmbeddingInput<'_>]) -> Result<Option<String>>;
}

/// What one pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RepoDerivedIndexReport {
    /// Safe copies that landed.
    pub derived: usize,
    /// Copies the model derived nothing for, or failed on; still pending.
    pub declined: usize,
    /// Copies whose sources moved while the model wrote; still pending.
    pub superseded: usize,
    /// Copies whose media sources the host's egress gate kept from a
    /// third-party model, unsent; still pending.
    pub withheld: usize,
    /// Texts no marked source reaches any more, indexed as their own words.
    pub released: usize,
}

/// One source as the model reads it.
struct SourceCopy {
    id: EntityId,
    kind: InputKind,
    media_type: String,
    bytes: Vec<u8>,
}

impl SourceCopy {
    fn placeholder(id: EntityId) -> Self {
        Self {
            id,
            kind: InputKind::Text,
            media_type: TEXT_MEDIA_TYPE.to_owned(),
            bytes: opaque_index_text().into_bytes(),
        }
    }

    fn text(id: EntityId, bytes: Vec<u8>) -> Self {
        Self {
            id,
            kind: InputKind::Text,
            media_type: TEXT_MEDIA_TYPE.to_owned(),
            bytes,
        }
    }
}

impl Vault {
    /// Derives up to `max_items` pending safe copies of texts a model wrote
    /// from marked repo blobs, through `author`, and publishes each that
    /// lands into the text index (its vector refilled from it by the normal
    /// passes). Blocking: `author` runs outside every transaction. A
    /// third-party author reads image and audio copies only as `egress`
    /// allows each, as the probe author does (FIX 6743).
    ///
    /// # Errors
    /// A store failure, or the marks failing to read.
    pub fn rederive_repo_index_text_copies(
        &self,
        author: &dyn RepoDerivedIndexTextAuthor,
        max_items: usize,
        egress: Option<&dyn EgressPredicate>,
    ) -> Result<RepoDerivedIndexReport> {
        let mut report = RepoDerivedIndexReport::default();
        let texts: Vec<EntityId> = {
            let rtxn = self.store.env.read_txn()?;
            pending_in(&self.store, &rtxn, usize::MAX)?
                .into_iter()
                .filter_map(|owner| match owner {
                    RepoDerivedOwner::Text(id) => Some(id),
                    RepoDerivedOwner::Probe(_) => None,
                })
                .take(max_items)
                .collect()
        };
        for entity in texts {
            let read = {
                let rtxn = self.store.env.read_txn()?;
                let marks = RepoIndexMarks::read_scoped_in_txn(self, &rtxn)?;
                match repo_derived_index_sources_in(self, &self.store, &rtxn, &marks, &entity) {
                    Ok(Some(sources)) => Some((
                        sources.proof(),
                        source_copies_in(self, &rtxn, &marks, &sources)?,
                    )),
                    Ok(None) => None,
                    Err(error) if is_storage_error(&error) => return Err(error),
                    Err(error) => {
                        tracing::warn!(error = %error, "a derived text's sources stay unread");
                        report.declined += 1;
                        continue;
                    }
                }
            };
            let Some((proof, copies)) = read else {
                self.release_derived_text(&entity)?;
                report.released += 1;
                continue;
            };
            let inputs: Vec<MediaEmbeddingInput<'_>> = copies
                .iter()
                .map(|copy| MediaEmbeddingInput {
                    entity_id: copy.id,
                    kind: copy.kind,
                    media_type: &copy.media_type,
                    bytes: &copy.bytes,
                    source_rows: None,
                })
                .collect();
            if !self.media_copies_may_leave(author, egress, &inputs)? {
                report.withheld += 1;
                continue;
            }
            let text = match author.derive_text(&inputs) {
                Ok(text) => text
                    .map(|text| text.trim().to_owned())
                    .filter(|text| !text.is_empty()),
                Err(error) => {
                    tracing::warn!(error = %error, "a derived text's safe copy stays pending");
                    None
                }
            };
            let Some(safe_text) = text else {
                report.declined += 1;
                continue;
            };
            let mut wtxn = self.store.env.write_txn()?;
            let marks = RepoIndexMarks::read_scoped_in_txn(self, &wtxn)?;
            let sources =
                match repo_derived_index_sources_in(self, &self.store, &wtxn, &marks, &entity) {
                    Ok(sources) => sources,
                    Err(error) if is_storage_error(&error) => return Err(error),
                    Err(_) => None,
                };
            let Some(sources) = sources.filter(|sources| sources.proof() == proof) else {
                report.superseded += 1;
                continue;
            };
            put_ready_in_txn(
                &self.store,
                &mut wtxn,
                RepoDerivedOwner::Text(entity),
                RepoDerivedReady {
                    proof,
                    sources: sources
                        .sources
                        .iter()
                        .map(|source| *source.id.as_bytes())
                        .collect(),
                    safe_text,
                    provenance: author.author_id().to_owned(),
                },
            )?;
            republish_in_txn(self, &mut wtxn, &marks, &entity, None)?;
            wtxn.commit()?;
            report.derived += 1;
        }
        Ok(report)
    }

    /// Whether `inputs` may go to `author`: always on this device or the
    /// owner's server; at a third party, each image or audio copy only as
    /// `egress` allows it and no device-local world keeps its record.
    fn media_copies_may_leave(
        &self,
        author: &dyn RepoDerivedIndexTextAuthor,
        egress: Option<&dyn EgressPredicate>,
        inputs: &[MediaEmbeddingInput<'_>],
    ) -> Result<bool> {
        if author.locality() != EmbedderLocality::ThirdParty {
            return Ok(true);
        }
        for input in inputs.iter().filter(|input| input.kind != InputKind::Text) {
            let Some(egress) = egress else {
                return Ok(false);
            };
            if egress.decide_media(input) != EgressDecision::Allow
                || !self.media_rows_may_leave(None, &[input.entity_id])?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// A pending text no marked source reaches any more: its row goes and
    /// its index reads its own words again, when that still holds in the
    /// writer.
    fn release_derived_text(&self, entity: &EntityId) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        let marks = RepoIndexMarks::read_scoped_in_txn(self, &wtxn)?;
        if repo_derived_index_sources_in(self, &self.store, &wtxn, &marks, entity)?.is_some() {
            return Ok(());
        }
        super::delete_in_txn(&self.store, &mut wtxn, RepoDerivedOwner::Text(*entity))?;
        republish_in_txn(self, &mut wtxn, &marks, entity, None)?;
        wtxn.commit()?;
        Ok(())
    }
}

/// Each of `sources` as a model may read it: a marked blob's record or media
/// as its masked copy, or the placeholder as text when that is its copy or
/// it is marked only through what it derives from; an unmarked source as it
/// is stored. A source that is gone or holds no media is left out.
fn source_copies_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    marks: &RepoIndexMarks,
    sources: &RepoDerivedIndexSources,
) -> Result<Vec<SourceCopy>> {
    let mut copies = Vec::new();
    for source in &sources.sources {
        let Some(row) = vault.store.port_entity_record(txn, &source.id)? else {
            continue;
        };
        if let Some(blob) = marks.source_of(&source.id) {
            let input = marks.source_input_in_txn(vault, txn, &blob, row.body)?;
            copies.push(if input.opaque() {
                SourceCopy::placeholder(source.id)
            } else {
                SourceCopy::text(source.id, input.into_text().into_bytes())
            });
            continue;
        }
        let Some((media_type, bytes)) = asset_media(&row.body) else {
            continue;
        };
        let input = marks.input_in_txn(vault, txn, bytes)?;
        let direct = input.stamp().is_some();
        if input.opaque() || (source.marked && !direct) {
            copies.push(SourceCopy::placeholder(source.id));
            continue;
        }
        let bytes = input.into_bytes();
        let copy = match InputKind::for_media_type(&media_type) {
            Some(kind) => SourceCopy {
                id: source.id,
                kind,
                media_type,
                bytes,
            },
            None if media_type.starts_with("text/") => SourceCopy::text(source.id, bytes),
            None => continue,
        };
        copies.push(copy);
    }
    Ok(copies)
}
