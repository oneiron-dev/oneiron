//! Revision-pinned short references and Loro cursor citations.

use super::storage::{
    RevisionNamespace, citation_live_doc, ensure_document, fork_revision_with_namespace,
    read_entity_revision_from_store_in_txn, read_entity_revision_in_txn,
};
use super::{PinnedCitation, ReadMode, ResolvedCitation, RevisionRef};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, parse_short_id_value};
use crate::error::{Error, Result};
use crate::store::ManifestDbs;
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
        let reference =
            match crate::ports::ShortIdStoreRead::port_short_id_reference(&self.store, &txn, id)? {
                Some((short, _)) => format!("{short}:{hash:02x}@{}", revision.to_hex()),
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
        let (doc, namespace) = fork_revision_with_namespace(&self.store, &txn, id, revision)?;
        let text = citation_text(&self.store, &txn, id, &doc, field, Some(namespace))?
            .ok_or_else(|| Error::InvalidConfig("citation field is not editable text".into()))?;
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
        let current =
            crate::ports::ShortIdStoreRead::port_short_id_reference(&self.store, &txn, id)?;
        let short_ref = match current {
            Some((short, _)) => {
                let pinned_raw =
                    read_entity_revision_in_txn(self, &txn, id, ReadMode::Pinned(revision))?
                        .ok_or(Error::EntityNotFound)?;
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
        let (pinned, namespace) = fork_revision_with_namespace(
            &self.store,
            &txn,
            &citation.entity,
            citation.source_revision_ref,
        )?;
        let start = Cursor::decode(&citation.start_cursor)
            .map_err(|_| Error::InvalidConfig("invalid citation cursor".into()))?;
        let end = Cursor::decode(&citation.end_cursor)
            .map_err(|_| Error::InvalidConfig("invalid citation cursor".into()))?;
        let pinned_text = cursor_quote(
            &pinned,
            citation_text(
                &self.store,
                &txn,
                &citation.entity,
                &pinned,
                &citation.field,
                Some(namespace),
            )?,
            &start,
            &end,
        );
        if pinned_text.as_deref() != Some(citation.quote.as_str()) {
            return Err(Error::InvalidConfig(
                "citation span does not match its pinned quote".into(),
            ));
        }
        let live = citation_live_doc(&self.store, &txn, &citation.entity, namespace)?;
        let drifted = cursor_quote(
            &live,
            citation_text(
                &self.store,
                &txn,
                &citation.entity,
                &live,
                &citation.field,
                Some(namespace),
            )?,
            &start,
            &end,
        )
        .as_deref()
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
    let id = match super::storage::IDENTITY.get(&vault.store, txn, &revision.0)? {
        Some(id) => id,
        None => match turn_of_text_revision(vault, txn, reference, revision)? {
            Some(id) => id,
            None => return Ok(None),
        },
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
    let Some((name, _)) =
        crate::ports::ShortIdStoreRead::port_short_id_reference(&vault.store, txn, &id)?
    else {
        return Ok(None);
    };
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

/// The row a room's pinned alias `alias:hash@revision` names in `view`, one
/// view of the room, read in `txn` (FIX 5162). It names the row only when
/// all of these hold in that one view:
///
/// - the view holds the revision's identity row;
/// - the room stages its own entity row of that id, so it keeps every
///   revision row of it;
/// - that id's reverse short-id row names it `alias`;
/// - `hash` is the short hash of the pinned bytes.
///
/// The hash is never checked against the live body: an edit replaces the
/// hash-keyed forward alias, and the reverse row keeps the name. Any other
/// pin names nothing here. This grants no read: the caller's lane admits the
/// row and its revision.
///
/// # Errors
///
/// Storage and corruption errors reading the view's rows.
pub(crate) fn resolve_room_pinned_alias_in_txn(
    vault: &Vault,
    view: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    alias: &str,
    hash: u8,
    revision: RevisionRef,
) -> Result<Option<EntityId>> {
    let Some(id) = super::storage::IDENTITY.get(view, txn, &revision.0)? else {
        return Ok(None);
    };
    // A record the room holds no row of reads as absent. Without that row,
    // the view pairs the room's revision rows with base's rows of the
    // record, which may never have held the revision: the room saved a
    // later body, or base deleted, erased or redacted the record.
    if !view.entities().stages_row(id.as_bytes()) {
        return Ok(None);
    }
    match crate::ports::ShortIdStoreRead::port_short_id_reference(view, txn, &id)? {
        Some((name, _)) if name == alias => {}
        _ => return Ok(None),
    }
    let Some(raw) =
        read_entity_revision_from_store_in_txn(vault, view, txn, &id, ReadMode::Pinned(revision))?
    else {
        return Ok(None);
    };
    // The hash a room's read names this revision by (`AdmittedRevision`).
    let pinned = crate::store::short_content_hash_in_txn(&vault.store, txn, &id, &raw)?;
    Ok((pinned == hash).then_some(id))
}

/// The TURN `reference` names, when `revision` is a text revision of it that
/// still resolves (`turn_text`). No row revision indexes a text revision, so
/// it is found from the reference, which the caller then checks as any pin's.
/// The name is looked up whatever its hash: the hash is the one the row had
/// when the revision was served, which the caller checks against that row,
/// and the live row may have moved since.
fn turn_of_text_revision(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    reference: &str,
    revision: RevisionRef,
) -> Result<Option<EntityId>> {
    let id = match crate::entity_id::parse_short_ref_syntax(reference) {
        Ok((short, hash)) => {
            let mut named = None;
            for candidate in
                std::iter::once(hash).chain((0..=u8::MAX).filter(|other| *other != hash))
            {
                if let Some(entry) = vault.hydrate_short_id_in(txn, short, candidate)? {
                    named = Some(entry.id);
                    break;
                }
            }
            match named {
                Some(id) => id,
                None => return Ok(None),
            }
        }
        Err(_) => match EntityId::from_hex(reference) {
            Ok(id) => id,
            Err(_) => return Ok(None),
        },
    };
    let is_turn = crate::ports::EntityStoreRead::port_entity_record(&vault.store, txn, &id)?
        .is_some_and(|row| row.entity_type == crate::registry::ENTITY_TYPE_TURN);
    if !is_turn
        || super::turn_text::turn_row_for_text_revision_in_txn(
            vault,
            &vault.store,
            txn,
            &id,
            revision,
        )?
        .is_none()
    {
        return Ok(None);
    }
    Ok(Some(id))
}

fn citation_text(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    doc: &loro::LoroDoc,
    field: &str,
    namespace: Option<RevisionNamespace>,
) -> Result<Option<loro::LoroText>> {
    if matches!(namespace, Some(RevisionNamespace::Note)) {
        return Ok((field == "markdown").then(|| doc.get_text("body")));
    }
    if !matches!(namespace, Some(RevisionNamespace::Generic))
        && let Some(body_field) = crate::entity_doc::pointer_field_in(store, txn, id)?
    {
        let matches = match body_field {
            crate::entity_doc::TextField::Utf8Body => field == "body",
            crate::entity_doc::TextField::MapField(name) => name == field,
        };
        return Ok(matches.then(|| doc.get_text("body")));
    }
    Ok(doc
        .get_map("text_fields")
        .get(field)
        .map(|_| doc.get_text(format!("field:{field}"))))
}

fn cursor_quote(
    doc: &loro::LoroDoc,
    text: Option<loro::LoroText>,
    start: &Cursor,
    end: &Cursor,
) -> Option<String> {
    let text = text?;
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
