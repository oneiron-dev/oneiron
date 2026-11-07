//! Ordered NOTE document row checks over one immutable canonical snapshot.

use super::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, id, invalid, strict};
use crate::error::Result;
use crate::note::NoteBody;
use crate::recovery::canonical::{CanonicalEntity, CanonicalSnapshot};
use crate::recovery::document::{CanonicalDocument, CanonicalHead, CanonicalHeadMove};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound::{Excluded, Unbounded};

#[derive(Default)]
pub(in crate::recovery) struct DocumentRows {
    stage: Stage,
    next: usize,
    previous_document: Option<([u8; 16], [u8; 16])>,
    previous_id: Option<[u8; 16]>,
    last_core: Option<[u8; 16]>,
    cores: BTreeMap<[u8; 16], NoteBody>,
    docs: BTreeSet<([u8; 16], [u8; 16])>,
    heads: BTreeMap<[u8; 16], [u8; 16]>,
    retained: BTreeSet<([u8; 16], [u8; 16])>,
    switched: BTreeSet<([u8; 16], [u8; 16])>,
}

#[derive(Default)]
enum Stage {
    #[default]
    DocumentOrder,
    HeadOrder,
    ReceiptOrder,
    Cores,
    DocumentIndex,
    HeadIndex,
    Documents,
    Retained,
    Receipts,
    CoreHeads,
    HeadBindings,
    Workflows,
    Complete,
}

impl DocumentRows {
    pub(in crate::recovery) fn advance(
        &mut self,
        snapshot: &CanonicalSnapshot,
        max_rows: usize,
    ) -> Result<bool> {
        for _ in 0..max_rows.max(1) {
            if self.advance_row(snapshot)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn advance_row(&mut self, snapshot: &CanonicalSnapshot) -> Result<bool> {
        loop {
            match self.stage {
                Stage::DocumentOrder => {
                    let Some(row) = snapshot.doc_snapshots.get(self.next) else {
                        self.start(Stage::HeadOrder);
                        continue;
                    };
                    let key = (row.entity_id, row.head);
                    strict(
                        self.previous_document
                            .into_iter()
                            .chain(std::iter::once(key)),
                    )?;
                    self.previous_document = Some(key);
                }
                Stage::HeadOrder => {
                    let Some(row) = snapshot.document_heads.get(self.next) else {
                        self.previous_id = None;
                        self.start(Stage::ReceiptOrder);
                        continue;
                    };
                    strict(
                        self.previous_id
                            .into_iter()
                            .chain(std::iter::once(row.entity_id)),
                    )?;
                    self.previous_id = Some(row.entity_id);
                }
                Stage::ReceiptOrder => {
                    let Some(row) = snapshot.head_move_receipts.get(self.next) else {
                        self.start(Stage::Cores);
                        continue;
                    };
                    strict(self.previous_id.into_iter().chain(std::iter::once(row.id)))?;
                    self.previous_id = Some(row.id);
                }
                Stage::Cores => {
                    let Some(entity) = snapshot.entity_blobs.get(self.next) else {
                        self.start(Stage::DocumentIndex);
                        continue;
                    };
                    self.capture_core(entity)?;
                }
                Stage::DocumentIndex => {
                    let Some(row) = snapshot.doc_snapshots.get(self.next) else {
                        self.start(Stage::HeadIndex);
                        continue;
                    };
                    self.docs.insert((row.entity_id, row.head));
                }
                Stage::HeadIndex => {
                    let Some(row) = snapshot.document_heads.get(self.next) else {
                        self.start(Stage::Documents);
                        continue;
                    };
                    self.heads.insert(row.entity_id, row.head);
                }
                Stage::Documents => {
                    let Some(row) = snapshot.doc_snapshots.get(self.next) else {
                        self.start(Stage::Retained);
                        continue;
                    };
                    self.validate_document(snapshot, row)?;
                }
                Stage::Retained => {
                    self.retained = crate::recovery::document::retained_parents(snapshot)?
                        .into_iter()
                        .map(|(note, head)| (*note.as_bytes(), *head.as_bytes()))
                        .collect();
                    self.start(Stage::Receipts);
                    return Ok(false);
                }
                Stage::Receipts => {
                    let Some(row) = snapshot.head_move_receipts.get(self.next) else {
                        self.start(Stage::CoreHeads);
                        continue;
                    };
                    self.validate_receipt(row)?;
                }
                Stage::CoreHeads => {
                    let entity = match self.last_core {
                        Some(last) => self
                            .cores
                            .range((Excluded(last), Unbounded))
                            .next()
                            .map(|(id, _)| *id),
                        None => self.cores.first_key_value().map(|(id, _)| *id),
                    };
                    let Some(entity) = entity else {
                        self.start(Stage::HeadBindings);
                        continue;
                    };
                    self.validate_core_head(&entity)?;
                    self.last_core = Some(entity);
                }
                Stage::HeadBindings => {
                    let Some(row) = snapshot.document_heads.get(self.next) else {
                        self.start(Stage::Workflows);
                        continue;
                    };
                    self.validate_head(row)?;
                }
                Stage::Workflows => {
                    crate::recovery::document::validate_workflows(snapshot)?;
                    self.start(Stage::Complete);
                    return Ok(true);
                }
                Stage::Complete => return Ok(true),
            }
            self.next += 1;
            return Ok(false);
        }
    }

    fn start(&mut self, stage: Stage) {
        self.stage = stage;
        self.next = 0;
    }

    pub(in crate::recovery) fn position(&self) -> (&'static str, usize) {
        let stage = match self.stage {
            Stage::DocumentOrder => "document order",
            Stage::HeadOrder => "head order",
            Stage::ReceiptOrder => "receipt order",
            Stage::Cores => "NOTE cores",
            Stage::DocumentIndex => "document index",
            Stage::HeadIndex => "head index",
            Stage::Documents => "documents",
            Stage::Retained => "retained parents",
            Stage::Receipts => "receipts",
            Stage::CoreHeads => "core heads",
            Stage::HeadBindings => "head bindings",
            Stage::Workflows => "workflows",
            Stage::Complete => "complete",
        };
        (stage, self.next)
    }

    fn capture_core(&mut self, entity: &CanonicalEntity) -> Result<()> {
        let cores = &mut self.cores;
        let header =
            EntityMetadataHeader::parse(&entity.blob).ok_or(invalid("document owner header"))?;
        if header.entity_type == crate::registry::ENTITY_TYPE_NOTE
            && entity.blob.len() > ENTITY_METADATA_HEADER_LEN
        {
            cores.insert(
                entity.id,
                crate::note::decode_note_core_using(
                    &entity.blob[ENTITY_METADATA_HEADER_LEN..],
                    crate::note::NoteKind::wire,
                )?,
            );
        }
        Ok(())
    }

    fn validate_document(
        &self,
        snapshot: &CanonicalSnapshot,
        row: &CanonicalDocument,
    ) -> Result<()> {
        let cores = &self.cores;
        let heads = &self.heads;
        id(row.entity_id)?;
        id(row.head)?;
        if let Some(actor) = row.birth_actor {
            id(actor)?;
        }
        let core = cores
            .get(&row.entity_id)
            .ok_or(invalid("document owner is not a NOTE"))?;
        // An erased author binds as no one, never as a live actor (FIX 6072).
        let author = core.author_ref.id().map(|author| *author.as_bytes());
        if row.birth_actor != author || !heads.contains_key(&row.entity_id) {
            return Err(invalid("document birth binding"));
        }
        row.rebuild()?;
        let header = snapshot
            .entity_blobs
            .iter()
            .find(|entity| entity.id == row.entity_id)
            .and_then(|entity| EntityMetadataHeader::parse(&entity.blob))
            .ok_or(invalid("document envelope"))?;
        if row.birth_at != header.learned_at {
            return Err(invalid("document birth timestamp binding"));
        }
        // The head's own value carries its birth; any other value, a retained
        // parent among them (FIX 8829), claims no authority. The birth text is
        // the document's alone (FIX 7783): the core binds its author.
        let current = heads.get(&row.entity_id) == Some(&row.head);
        if row.head == row.entity_id && current {
            let birth = row
                .authorship
                .iter()
                .find(|record| record.operation.as_bytes() == &row.entity_id)
                .ok_or(invalid("NOTE birth provenance missing"))?;
            // An imported author is source provenance: the canonical birth
            // names no one for it, as native birth history does (FIX 7777).
            let birth_author = match core.author_ref {
                crate::note::NoteActor::Imported(_) => crate::note::NoteActor::Erased,
                author => author,
            };
            if birth.actor != birth_author
                || birth.actor_class != "ledger"
                || birth.grant.is_some()
            {
                return Err(invalid("NOTE birth provenance binding"));
            }
        }
        if !current && !row.authorship.is_empty() {
            return Err(invalid("proposal value claims authority"));
        }
        Ok(())
    }

    fn validate_receipt(&mut self, row: &CanonicalHeadMove) -> Result<()> {
        let cores = &self.cores;
        let docs = &self.docs;
        let heads = &self.heads;
        let retained = &self.retained;
        let switched = &mut self.switched;
        let receipt = row.decode()?;
        let head_binding = match receipt.verdict {
            crate::note::NoteVerdict::Switch => receipt.head == receipt.fork,
            _ => receipt.head == receipt.previous_head,
        };
        if !cores.contains_key(&row.entity_id) || !head_binding {
            return Err(invalid("receipt canonical identity"));
        }
        if receipt.verdict == crate::note::NoteVerdict::Switch {
            switched.insert((row.entity_id, *receipt.head.as_bytes()));
        }
        let fork = *receipt.fork.as_bytes();
        if docs.contains(&(row.entity_id, fork))
            && heads.get(&row.entity_id) != Some(&fork)
            && !retained.contains(&(row.entity_id, fork))
        {
            return Err(invalid("decided proposal retains text"));
        }
        Ok(())
    }

    fn validate_core_head(&self, entity: &[u8; 16]) -> Result<()> {
        let heads = &self.heads;
        let docs = &self.docs;
        if heads
            .get(entity)
            .is_none_or(|head| !docs.contains(&(*entity, *head)))
        {
            return Err(invalid("live NOTE has no canonical document value"));
        }
        Ok(())
    }

    fn validate_head(&self, row: &CanonicalHead) -> Result<()> {
        let cores = &self.cores;
        let docs = &self.docs;
        let switched = &self.switched;
        if !cores.contains_key(&row.entity_id)
            || (row.head != row.entity_id && !switched.contains(&(row.entity_id, row.head)))
            || !docs.contains(&(row.entity_id, row.head))
        {
            return Err(invalid("canonical document identity"));
        }
        Ok(())
    }
}
