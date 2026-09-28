//! Revision-pinned short references and Loro cursor citations.

use super::storage::{ensure_document, fork_revision, load_doc, read_entity_revision_in_txn};
use super::{PinnedCitation, ReadMode, ResolvedCitation, RevisionRef};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, parse_short_id_value};
use crate::error::{Error, Result};
use crate::{EntityId, Vault};
use loro::ContainerTrait;
use loro::cursor::{Cursor, Side};

impl Vault {
    /// Produces a durable citation reference for a retrieved entity. Hydration
    /// of this reference never follows the live short-id content hash.
    pub fn pinned_short_ref(&self, id: &EntityId) -> Result<String> {
        self.pinned_short_ref_with_mode(id, ReadMode::Indexed)
    }

    /// Same citation door with an explicit source frontier.
    pub fn pinned_short_ref_with_mode(&self, id: &EntityId, mode: ReadMode) -> Result<String> {
        let mut txn = self.store.env.write_txn()?;
        let (live, _) = ensure_document(self, &mut txn, id)?;
        let revision = selected_revision(self, &txn, id, mode, live)?;
        let raw = read_entity_revision_in_txn(self, &txn, id, ReadMode::Pinned(revision))?
            .ok_or(Error::EntityNotFound)?;
        let hash = (xxhash_rust::xxh32::xxh32(&raw[ENTITY_METADATA_HEADER_LEN..], 0) % 256) as u8;
        let reference = match self.store.short_ids_reverse.get(&txn, id.as_bytes())? {
            Some(raw) => {
                let (short, _) = parse_short_id_value(&raw)?;
                format!("{short}:{hash:02x}@{}", revision.to_hex())
            }
            None => format!("{}@{}", id.to_hex(), revision.to_hex()),
        };
        txn.commit()?;
        Ok(reference)
    }

    /// Pins a Unicode-codepoint span. The quote, hash and both cursors are
    /// minted together from the exact recorded frontier, never from LIVE later.
    pub fn cite_entity_text(
        &self,
        id: &EntityId,
        field: &str,
        start: usize,
        end: usize,
    ) -> Result<PinnedCitation> {
        self.cite_entity_text_with_mode(id, field, start, end, ReadMode::Live)
    }

    /// Pins the same cursor span at an explicitly chosen read frontier.
    pub fn cite_entity_text_with_mode(
        &self,
        id: &EntityId,
        field: &str,
        start: usize,
        end: usize,
        mode: ReadMode,
    ) -> Result<PinnedCitation> {
        let mut txn = self.store.env.write_txn()?;
        let (live, _) = ensure_document(self, &mut txn, id)?;
        let revision = selected_revision(self, &txn, id, mode, live)?;
        let doc = fork_revision(&self.store, &txn, id, revision)?;
        if doc.get_map("text_fields").get(field).is_none() {
            return Err(Error::InvalidConfig(
                "citation field is not editable text".into(),
            ));
        }
        let text = doc.get_text(format!("field:{field}"));
        let value = text.to_string();
        if start > end || end > value.chars().count() {
            return Err(Error::InvalidConfig("citation span is outside text".into()));
        }
        let quote: String = value.chars().skip(start).take(end - start).collect();
        let begin = text
            .get_cursor(start, Side::Right)
            .ok_or(Error::InvariantViolation("citation start cursor"))?;
        let finish = text
            .get_cursor(end, Side::Left)
            .ok_or(Error::InvariantViolation("citation end cursor"))?;
        let short_ref = match self.store.short_ids_reverse.get(&txn, id.as_bytes())? {
            Some(raw) => {
                let (short, _) = parse_short_id_value(&raw)?;
                let pinned_raw = super::storage::doc_raw(&doc)?;
                let hash = (xxhash_rust::xxh32::xxh32(&pinned_raw[ENTITY_METADATA_HEADER_LEN..], 0)
                    % 256) as u8;
                format!("{short}:{hash:02x}")
            }
            None => id.to_hex(),
        };
        let citation = PinnedCitation {
            entity: *id,
            short_ref,
            source_revision_ref: revision,
            field: field.into(),
            start_cursor: begin.encode(),
            end_cursor: finish.encode(),
            quote_hash: *blake3::hash(quote.as_bytes()).as_bytes(),
            quote,
        };
        txn.commit()?;
        Ok(citation)
    }

    /// Always returns the original verified quote. Drift describes whether
    /// the same cursor span still maps to that quote in the live document.
    pub fn resolve_citation(&self, citation: &PinnedCitation) -> Result<ResolvedCitation> {
        if *blake3::hash(citation.quote.as_bytes()).as_bytes() != citation.quote_hash {
            return Err(Error::InvalidConfig("citation quote hash mismatch".into()));
        }
        let txn = self.store.env.read_txn()?;
        // Deletion erases the binding needed to authenticate caller-supplied
        // citation fields. A self-consistent quote hash is not that evidence.
        if read_entity_revision_in_txn(self, &txn, &citation.entity, ReadMode::Live)?.is_none() {
            return Err(Error::EntityNotFound);
        }
        if resolve_reference(
            self,
            &txn,
            &citation.short_ref,
            citation.source_revision_ref,
        )? != Some(citation.entity)
        {
            return Err(Error::InvalidKey);
        }
        let pinned = fork_revision(
            &self.store,
            &txn,
            &citation.entity,
            citation.source_revision_ref,
        )?;
        let start = Cursor::decode(&citation.start_cursor)
            .map_err(|_| Error::InvalidConfig("invalid citation cursor".into()))?;
        let end = Cursor::decode(&citation.end_cursor)
            .map_err(|_| Error::InvalidConfig("invalid citation cursor".into()))?;
        let pinned_text = cursor_quote(&pinned, &citation.field, &start, &end);
        if pinned_text.as_deref() != Some(citation.quote.as_str()) {
            return Err(Error::InvalidConfig(
                "citation span does not match its pinned quote".into(),
            ));
        }
        let live = load_doc(&self.store, &txn, &citation.entity)?;
        let drifted = cursor_quote(&live, &citation.field, &start, &end).as_deref()
            != Some(citation.quote.as_str());
        Ok(ResolvedCitation {
            quote: citation.quote.clone(),
            drifted,
        })
    }

    /// Resolves a short reference against its pin rather than its current
    /// one-byte content hash. The full revision binds identity and bytes, so
    /// a collision in the presentation hash cannot silently pick a revision.
    pub fn resolve_pinned_entity_reference(
        &self,
        reference: &str,
        revision: RevisionRef,
    ) -> Result<Option<EntityId>> {
        let txn = self.store.env.read_txn()?;
        self.resolve_pinned_entity_reference_in(&txn, reference, revision)
    }

    pub(crate) fn resolve_pinned_entity_reference_in(
        &self,
        txn: &heed::RoTxn<'_>,
        reference: &str,
        revision: RevisionRef,
    ) -> Result<Option<EntityId>> {
        resolve_reference(self, txn, reference, revision)
    }
}

fn resolve_reference(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    reference: &str,
    revision: RevisionRef,
) -> Result<Option<EntityId>> {
    let Some(id) = super::storage::IDENTITY.get(&vault.store, txn, &revision.0)? else {
        return Ok(None);
    };
    let Some(raw) = read_entity_revision_in_txn(vault, txn, &id, ReadMode::Pinned(revision))?
    else {
        return Ok(None);
    };
    if reference == id.to_hex() {
        return Ok(Some(id));
    }
    let Ok((short, hash)) = crate::entity_id::parse_short_ref_syntax(reference) else {
        return Ok(None);
    };
    if hash != (xxhash_rust::xxh32::xxh32(&raw[ENTITY_METADATA_HEADER_LEN..], 0) % 256) as u8 {
        return Ok(None);
    }
    let Some(current) = vault.store.short_ids_reverse.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let (name, _) = parse_short_id_value(&current)?;
    if name == short {
        return Ok(Some(id));
    }
    if let Some(crate::store::ShortIdAliasTarget::EntityForwardKey(key)) =
        vault.store.resolve_short_id_alias(txn, short)?
    {
        let (canonical, _) = parse_short_id_value(&key)?;
        if canonical == name {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

fn cursor_quote(doc: &loro::LoroDoc, field: &str, start: &Cursor, end: &Cursor) -> Option<String> {
    doc.get_map("text_fields").get(field)?;
    let text = doc.get_text(format!("field:{field}"));
    // A hostile citation may carry a cursor for another field. The container
    // check binds the cursor span to the named text, not merely its offsets.
    if start.container != text.id() || end.container != text.id() {
        return None;
    }
    let begin = doc.get_cursor_pos(start).ok()?.current.pos;
    let finish = doc.get_cursor_pos(end).ok()?.current.pos;
    if begin > finish {
        return None;
    }
    let value = text.to_string();
    if finish > value.chars().count() {
        return None;
    }
    Some(value.chars().skip(begin).take(finish - begin).collect())
}

fn selected_revision(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    mode: ReadMode,
    live: RevisionRef,
) -> Result<RevisionRef> {
    Ok(match mode {
        ReadMode::Live => live,
        ReadMode::Indexed => {
            super::storage::state(&vault.store, txn, id)?
                .ok_or(Error::CorruptedIndex("entity revision state"))?
                .indexed
        }
        ReadMode::Pinned(revision) => revision,
    })
}
