//! Explicit memory pins bypass query relevance and render shedding, never read authority.
use super::memories::{MemoriesSection, MemoryRow, MemorySource, MemoryTier};
use super::memories_projection::{finish_projection, foreign_row, memory_asset_ref, memory_slot};
use crate::Result;
use crate::claim::{PointRead, ScopedRead, ScopedReadReceipt, decode_claim_body};
use crate::ports::ShortIdStoreRead;
impl MemoriesSection {
    /// Pins are engine-issued short references already selected by the caller.
    /// Each read still resolves the actor ceiling and returns its mandatory receipt.
    /// No pin selection is inferred from retrieved prose.
    pub fn include_pinned_refs(
        &mut self,
        reader: &ScopedRead<'_>,
        references: &[String],
    ) -> Result<Vec<ScopedReadReceipt>> {
        self.include_pinned_refs_with_disclosure(reader, references, None)
    }

    /// Board callers apply their audience disclosure clamp as well as the
    /// actor's read ceiling. Pins bypass query relevance, never either authority.
    pub fn include_pinned_refs_with_disclosure(
        &mut self,
        reader: &ScopedRead<'_>,
        references: &[String],
        disclosure: Option<&crate::disclosure::DisclosureContext>,
    ) -> Result<Vec<ScopedReadReceipt>> {
        let mut receipts = Vec::with_capacity(references.len());
        let mut pins = std::collections::BTreeSet::<String>::new();
        for reference in references {
            let (short_id, hash) =
                reference
                    .rsplit_once(':')
                    .ok_or(crate::Error::InvalidConfig(
                        "invalid memory pin reference".into(),
                    ))?;
            if hash.len() != 2 {
                return Err(crate::Error::InvalidConfig(
                    "invalid memory pin hash".into(),
                ));
            }
            let hash = u8::from_str_radix(hash, 16)
                .map_err(|_| crate::Error::InvalidConfig("invalid memory pin hash".into()))?;
            let (receipt, row) = pinned_row(
                reader,
                PointRead::short(short_id, hash),
                Some((short_id, hash)),
                disclosure,
            )?;
            receipts.push(receipt);
            if let Some(row) = row.filter(|row| pins.insert(row.id.clone())) {
                self.rows.retain(|old| old.id != row.id);
                self.rows.push(row);
            }
        }
        self.refinish();
        Ok(receipts)
    }

    /// Pins rows by entity id, as a retrieval's result refs name them, under
    /// `reader`'s ceiling and `disclosure`'s clamp, as a short-ref pin reads.
    /// Each id returns its receipt, withheld or missing ones included.
    pub fn include_pinned_ids_with_disclosure(
        &mut self,
        reader: &ScopedRead<'_>,
        ids: &[crate::EntityId],
        disclosure: Option<&crate::disclosure::DisclosureContext>,
    ) -> Result<Vec<ScopedReadReceipt>> {
        let mut receipts = Vec::with_capacity(ids.len());
        let mut pins = std::collections::BTreeSet::<String>::new();
        for id in ids {
            let (receipt, row) = pinned_row(reader, PointRead::id(*id), None, disclosure)?;
            receipts.push(receipt);
            if let Some(row) = row.filter(|row| pins.insert(row.id.clone())) {
                self.rows.retain(|old| old.id != row.id);
                self.rows.push(row);
            }
        }
        self.refinish();
        Ok(receipts)
    }

    /// Re-runs the projection's ordering and budget over the current rows.
    pub(super) fn refinish(&mut self) {
        *self = finish_projection(
            std::mem::take(&mut self.rows),
            self.budget,
            self.companion.clone(),
            self.disclosure.clone(),
        );
    }
}

/// One pin's PINNED row, read under `reader`'s ceiling and `disclosure`'s
/// clamp, or `None` when either withholds it. `short` is the engine-issued
/// reference the pin named; an id pin takes the row's own. The receipt is
/// returned either way.
pub(super) fn pinned_row(
    reader: &ScopedRead<'_>,
    read: PointRead<'_>,
    short: Option<(&str, u8)>,
    disclosure: Option<&crate::disclosure::DisclosureContext>,
) -> Result<(ScopedReadReceipt, Option<MemoryRow>)> {
    // The revision is taken in the read's own snapshot, so a board history
    // records the text this pin served, not a later edit.
    let hydrated = reader.read_projected(&[read], None, |txn, rows| {
        let row = rows.into_iter().next().flatten();
        let Some(found) = &row else {
            return Ok::<_, crate::Error>((None, None, None, None));
        };
        let revision = crate::vault::entity_revision::revision_for_mode_in_txn(
            &reader.vault().store,
            txn,
            &found.id,
            crate::vault::ReadMode::Live,
        )?;
        let short_id = match short {
            Some((short_id, _)) => Some(short_id.to_owned()),
            None => reader
                .vault()
                .store
                .port_short_id_reference(txn, &found.id)?
                .map(|(short_id, _)| short_id),
        };
        let text = pin_text(reader, txn, found)?;
        Ok((row, revision, short_id, text))
    })?;
    let mut receipt = hydrated.receipt;
    let (hydrated, source_revision, short_id, text) = hydrated.value;
    let (Some(hydrated), Some(short_id)) = (hydrated, short_id) else {
        return Ok((receipt, None));
    };
    let Some(body) = &hydrated.body else {
        return Ok((receipt, None));
    };
    let hash = short.map_or(hydrated.content_hash, |(_, hash)| hash);
    let claim = if hydrated.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
        Some(decode_claim_body(body, true)?)
    } else {
        None
    };
    if let Some(disclosure) = disclosure {
        let txn = reader.vault().store.env.read_txn()?;
        if !disclosure.admits(
            &reader.vault().store,
            &txn,
            &hydrated.id,
            hydrated.entity_type,
            claim.as_ref(),
        )? {
            receipt.add_suppressed(1);
            return Ok((receipt, None));
        }
    }
    let mut row = MemoryRow {
        row_index: 0,
        slot: memory_slot(hydrated.entity_type),
        source: MemorySource::Result,
        id: hydrated.id.to_hex(),
        content_hash: format!("{hash:02x}"),
        entity_type: hydrated.entity_type,
        asset_ref: memory_asset_ref(hydrated.entity_type, &short_id, hash),
        short_id,
        score: 0.0,
        claim_source: claim.as_ref().and_then(|c| c.source),
        world: claim.as_ref().and_then(|c| c.world).map(|id| id.to_hex()),
        tier: MemoryTier::Pinned,
        snippet: None,
        hook: None,
        source_revision,
        question: claim
            .as_ref()
            .and_then(crate::context_pack::source_ranking::question_key),
    };
    if !foreign_row(&row)
        && let Some(claim) = claim
    {
        // The MessagePack is read with the claim's other parts, and
        // before and after the projection drops a float's width.
        let value = if crate::batch::export::claim_reads_as_secret(&claim) {
            serde_json::Value::String("[redacted]".to_owned())
        } else {
            crate::batch::export::served_messagepack_json(claim.value)
        };
        row.snippet = Some(value.to_string());
    } else if !foreign_row(&row) {
        row.snippet = text;
    }
    Ok((receipt, Some(row)))
}

/// The words a pinned TURN, MESSAGE, NOTE or SUMMARY shows, read from its
/// admitted body in the read's own snapshot; `None` for another type or a
/// body that shows none. A read by id takes a TURN's row alone, so its words
/// are the messages `reader` may read, one per line in message order
/// (`retrieval_visibility`'s by-id rule).
fn pin_text(
    reader: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    row: &crate::claim::ReadRow,
) -> Result<Option<String>> {
    let Some(body) = &row.body else {
        return Ok(None);
    };
    let text = match row.entity_type {
        crate::registry::ENTITY_TYPE_TURN => {
            let Some(messages) =
                crate::tagging::turn_messages_in_txn(reader.vault(), txn, &row.id)?
            else {
                return Ok(None);
            };
            let mut readable = Vec::with_capacity(messages.len());
            for message in messages {
                let id = crate::EntityId::from_hex(&message.id)?;
                if reader.is_entity_readable_in(txn, &id)? {
                    readable.push((id, message.text));
                }
            }
            crate::embed::joined_turn_text(&readable)
        }
        crate::registry::ENTITY_TYPE_MESSAGE => crate::tagging::shown_message_text(body),
        crate::registry::ENTITY_TYPE_NOTE => {
            crate::note::decode_note_body_in_txn(&reader.vault().store, txn, body)
                .ok()
                .map(|note| note.markdown)
        }
        crate::registry::ENTITY_TYPE_SUMMARY => summary_text(body),
        _ => None,
    };
    Ok(text.filter(|text| !text.is_empty()))
}

/// A SUMMARY's text: an epoch's or a scope's, each by its strict codec, else
/// an ordinary summary's `txt`. A document-backed scope summary's text is
/// already in its live body.
fn summary_text(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Ordinary {
        txt: String,
    }
    crate::compaction::decode_epoch_summary_body(body)
        .map(|summary| summary.text)
        .or_else(|_| {
            crate::scope_summary::decode_scope_summary_body(body).map(|summary| summary.text)
        })
        .ok()
        .or_else(|| {
            rmp_serde::from_slice::<Ordinary>(body)
                .ok()
                .map(|summary| summary.txt)
        })
}
