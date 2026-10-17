//! The vault's own retrieval probes, which a space version move runs paired on its incumbent
//! and its candidate (OF-370; ARCH-0004 `#swap-check-not-worse`).
//!
//! A probe is one text query another model wrote from one stored document, which is its source
//! family, and the documents that answer it. The design note's recipe, not a ruling: about
//! twenty probes per kind, written at sleep by a model other than the spaces' own, for example
//! by describing a photo, so a probe cannot just copy a caption. [`Vault::author_space_probes`]
//! hands such a model the documents of a kind that no probe comes from yet.

use std::collections::BTreeSet;

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use super::EmbedderLocality;
use super::media::MediaEmbeddingInput;
use super::space::InputKind;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::side_table::{self, Named, SideTable, SideTableDbs};

/// Probes the authoring pass keeps per kind.
pub const SPACE_PROBES_PER_KIND: usize = 20;
/// Longest probe query, in bytes.
pub const SPACE_PROBE_QUERY_MAX_LEN: usize = 2048;
/// Most documents one probe names as its answers.
pub const SPACE_PROBE_MAX_TARGETS: usize = 16;

/// Stored probes. Key: probe id16.
const EMBEDDING_PROBE: SideTable<[u8; 16], SpaceProbe, Named> =
    SideTable::new(&side_table::EMBEDDING_PROBE);

/// One retrieval probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceProbe {
    /// The kind of the documents it finds; a move's check runs it for that kind's slot.
    pub kind: InputKind,
    pub query: String,
    /// The document it was written from, its source family; one of its targets.
    pub family: EntityId,
    /// Every document that answers the query.
    pub targets: BTreeSet<EntityId>,
    /// The model that wrote it.
    pub author: String,
    /// Vault seconds.
    pub written_at: u64,
}

impl SpaceProbe {
    /// The probe's id: its kind, family and query.
    #[must_use]
    pub fn id(&self) -> [u8; 16] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron/space_probe/v1");
        hasher.update(&[self.kind as u8]);
        hasher.update(self.family.as_bytes());
        hasher.update(self.query.as_bytes());
        let mut id = [0_u8; 16];
        id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        id
    }

    fn validate(&self) -> Result<()> {
        let query = self.query.trim();
        if query.is_empty() || self.query.len() > SPACE_PROBE_QUERY_MAX_LEN {
            return Err(Error::InvalidConfig(format!(
                "a space probe's query must hold 1..={SPACE_PROBE_QUERY_MAX_LEN} bytes of text"
            )));
        }
        if self.targets.is_empty() || self.targets.len() > SPACE_PROBE_MAX_TARGETS {
            return Err(Error::InvalidConfig(format!(
                "a space probe names 1..={SPACE_PROBE_MAX_TARGETS} target documents"
            )));
        }
        if !self.targets.contains(&self.family) {
            return Err(Error::InvalidConfig(
                "a space probe's source document is one of its targets".into(),
            ));
        }
        if self.author.trim().is_empty() {
            return Err(Error::InvalidConfig(
                "a space probe names the model that wrote it".into(),
            ));
        }
        Ok(())
    }
}

/// A host model that writes probes: a model other than the spaces' own.
pub trait SpaceProbeAuthor: Send + Sync {
    /// The model id a probe records as its author.
    fn author_id(&self) -> &str;
    /// Where the model runs. Stored image and audio bytes never leave for a third party from
    /// this door; a text document goes where the host's admitted call (the vault's inference
    /// policy) lets it.
    fn locality(&self) -> EmbedderLocality;
    /// One search query a person might type to find `document`, in other words than its own;
    /// `None` when the model writes none.
    fn write_probe(&self, document: &MediaEmbeddingInput<'_>) -> Result<Option<String>>;
}

/// What one authoring pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpaceProbeReport {
    /// Probes stored this pass.
    pub written: usize,
    /// Documents the model wrote no usable query for.
    pub declined: usize,
    /// Documents deleted, or texts moved, before their probe landed.
    pub vanished: usize,
    /// Probes of the kind already held, before this pass.
    pub held: usize,
}

pub(crate) fn space_probes_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
) -> Result<Vec<([u8; 16], SpaceProbe)>> {
    EMBEDDING_PROBE.scan(store, txn)
}

impl Vault {
    /// Stores one probe; every target must be a stored record.
    pub fn put_space_probe(&self, probe: SpaceProbe) -> Result<[u8; 16]> {
        probe.validate()?;
        let id = probe.id();
        let mut wtxn = self.store.env.write_txn()?;
        for target in &probe.targets {
            if self.store.port_entity_record(&wtxn, target)?.is_none() {
                return Err(Error::EntityNotFound);
            }
        }
        EMBEDDING_PROBE.put(&self.store, &mut wtxn, &id, &probe)?;
        wtxn.commit()?;
        Ok(id)
    }

    /// Every stored probe, in id order.
    pub fn space_probes(&self) -> Result<Vec<([u8; 16], SpaceProbe)>> {
        let rtxn = self.store.env.read_txn()?;
        space_probes_in_txn(&self.store, &rtxn)
    }

    /// Deletes one probe; `false` when none had that id.
    pub fn delete_space_probe(&self, id: &[u8; 16]) -> Result<bool> {
        let mut wtxn = self.store.env.write_txn()?;
        let existed = EMBEDDING_PROBE.contains(&self.store, &wtxn, id)?;
        EMBEDDING_PROBE.delete(&self.store, &mut wtxn, id)?;
        wtxn.commit()?;
        Ok(existed)
    }

    /// Tops `kind` up toward [`SPACE_PROBES_PER_KIND`] probes, at most `max_items` this pass:
    /// `author` reads documents of that kind no probe comes from yet, in id order, outside any
    /// transaction, and each query it writes is stored with that document as its family and
    /// its only target.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the author runs at a third party and `kind` is a media
    /// kind; storage and model errors otherwise.
    pub fn author_space_probes(
        &self,
        kind: InputKind,
        author: &dyn SpaceProbeAuthor,
        max_items: usize,
    ) -> Result<SpaceProbeReport> {
        if author.locality() == EmbedderLocality::ThirdParty && kind != InputKind::Text {
            return Err(Error::InvalidConfig(
                "a third-party probe author has no egress grant for stored media".into(),
            ));
        }
        let mut report = SpaceProbeReport::default();
        let documents = {
            let rtxn = self.store.env.read_txn()?;
            let families: BTreeSet<EntityId> = space_probes_in_txn(&self.store, &rtxn)?
                .into_iter()
                .filter(|(_, probe)| probe.kind == kind)
                .map(|(_, probe)| probe.family)
                .collect();
            report.held = families.len();
            let want = SPACE_PROBES_PER_KIND
                .saturating_sub(families.len())
                .min(max_items);
            let mut documents = Vec::new();
            let mut scan = super::MediaEmbedReport::default();
            if want > 0 {
                self.scan_documents_in_txn(
                    &rtxn,
                    &BTreeSet::from([kind]),
                    &mut scan,
                    |document| {
                        if !families.contains(&document.id) {
                            documents.push(document);
                        }
                        Ok(documents.len() < want)
                    },
                )?;
            }
            documents
        };
        let mut written = Vec::new();
        for document in &documents {
            let input = MediaEmbeddingInput {
                entity_id: document.id,
                kind: document.kind,
                media_type: &document.media_type,
                bytes: &document.bytes,
            };
            let Some(query) = author
                .write_probe(&input)?
                .map(|query| query.trim().to_owned())
                .filter(|query| !query.is_empty() && query.len() <= SPACE_PROBE_QUERY_MAX_LEN)
            else {
                report.declined += 1;
                continue;
            };
            // A probe that only repeats the text it came from tests nothing a model swap moves.
            if document.kind == InputKind::Text
                && std::str::from_utf8(&document.bytes)
                    .is_ok_and(|text| text.trim().eq_ignore_ascii_case(&query))
            {
                report.declined += 1;
                continue;
            }
            written.push((document, query));
        }
        if written.is_empty() {
            return Ok(report);
        }
        let mut wtxn = self.store.env.write_txn()?;
        let written_at = self.store.clock.now_recorded_at();
        for (document, query) in written {
            let moved = match document.text_hash {
                Some(hash) => super::media::text_document_in_txn(self, &wtxn, &document.id)?
                    .is_none_or(|text| super::space::text_hash(&text) != hash),
                None => false,
            };
            if moved
                || self
                    .store
                    .port_entity_record(&wtxn, &document.id)?
                    .is_none()
            {
                report.vanished += 1;
                continue;
            }
            let probe = SpaceProbe {
                kind,
                query,
                family: document.id,
                targets: BTreeSet::from([document.id]),
                author: author.author_id().to_owned(),
                written_at,
            };
            probe.validate()?;
            EMBEDDING_PROBE.put(&self.store, &mut wtxn, &probe.id(), &probe)?;
            report.written += 1;
        }
        wtxn.commit()?;
        Ok(report)
    }
}
