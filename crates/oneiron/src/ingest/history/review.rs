//! The owner's review of what the Dreamer proposes from one import (ARCH-0027
//! trust tier): imported material never auto-approves. Every claim the
//! Dreamer extracts from an import's words lands Proposed under that import's
//! review id, and the owner approves or declines the whole group in one act at
//! the run-consent door (`oneiron runs`), never claim by claim.
//!
//! An import is its source and the time it ran: every row one import lands is
//! learned at that time (`Vault::import_history`), so the import that last
//! landed words in a TURN is the TURN's source and its newest MESSAGE's
//! learned time.

use super::HistorySource;
use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::claim::ClaimSource;
use crate::dreamer_consolidation::{decode_turn_body, evidence_source_from_row};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EdgeDirection;
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN,
};

/// The review id of the import of `source` that ran at `imported_at`.
#[must_use]
pub fn history_import_review_id(source: HistorySource, imported_at: u64) -> String {
    format!("import:{}:{imported_at}", source.source_id())
}

/// What a claim's evidence says about imports.
pub(crate) struct ImportedEvidence {
    /// Some ref is imported words (an imported TURN, one of its MESSAGEs or
    /// its CONVERSATION) or a CLAIM whose source or taint is imported: the
    /// claim is `Imported`, whatever meet a caller computed for it.
    pub(crate) imported: bool,
    /// The review of the latest import that landed the words the claim cites.
    pub(crate) review: Option<String>,
}

/// Reads `refs` for imported words and claims built on them. The review is
/// the latest import among the cited MESSAGEs (`cited`) of each imported TURN,
/// or among all its MESSAGEs when the citation names none, and the import that
/// learned a MESSAGE cited by its own id; so words one import landed stay in
/// its review after a later import adds more to the same TURN.
pub(crate) fn imported_evidence_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    refs: &[EntityId],
    cited: &[EntityId],
) -> Result<ImportedEvidence> {
    let mut imported = false;
    let mut latest: Option<(u64, HistorySource)> = None;
    for id in refs {
        let Some((header, body)) = row(vault, txn, id)? else {
            continue;
        };
        match header.entity_type {
            ENTITY_TYPE_CLAIM => {
                // A claim built on imported words carries them on; it names no
                // review of its own, so the Dreamer run's review holds it.
                imported |=
                    evidence_source_from_row(ENTITY_TYPE_CLAIM, &body)? == ClaimSource::Imported;
                continue;
            }
            // An imported conversation carries its turns' stamp, and names no
            // review of its own either.
            ENTITY_TYPE_CONVERSATION => {
                imported |= decode_turn_body(&body).imported;
                continue;
            }
            // A message's words were landed by the import that learned it. Its
            // own import provenance or any imported turn it is part of makes it
            // imported; no other parent edge can take that away.
            ENTITY_TYPE_MESSAGE => {
                let mut source = message_import_source(&body);
                let mut stamped = source.is_some();
                for parent in vault.filtered_edge_peers(
                    txn,
                    EdgeDirection::Out,
                    id,
                    EdgeKind::PartOf,
                    Some(ENTITY_TYPE_TURN),
                    "imported message review scan",
                )? {
                    let Some((parent_header, parent_body)) = row(vault, txn, &parent)? else {
                        continue;
                    };
                    let facts = decode_turn_body(&parent_body);
                    if parent_header.entity_type == ENTITY_TYPE_TURN && facts.imported {
                        stamped = true;
                        source = source.or(facts.import_source);
                    }
                }
                imported |= stamped;
                if let Some(source) = source.as_deref().and_then(HistorySource::parse)
                    && latest
                        .as_ref()
                        .is_none_or(|(at, _)| header.learned_at > *at)
                {
                    latest = Some((header.learned_at, source));
                }
                continue;
            }
            ENTITY_TYPE_TURN => {}
            _ => continue,
        }
        let facts = decode_turn_body(&body);
        if !facts.imported {
            continue;
        }
        imported = true;
        // Only a source this module imports names a review.
        let Some(source) = facts
            .import_source
            .as_deref()
            .and_then(HistorySource::parse)
        else {
            continue;
        };
        let messages = vault.filtered_edge_peers(
            txn,
            EdgeDirection::In,
            id,
            EdgeKind::PartOf,
            Some(ENTITY_TYPE_MESSAGE),
            "imported turn review scan",
        )?;
        let named: Vec<_> = messages
            .iter()
            .filter(|message| cited.contains(message))
            .copied()
            .collect();
        let words = if named.is_empty() { messages } else { named };
        let mut imported_at = None;
        for message in &words {
            let learned = vault
                .get_raw_in(txn, message)?
                .as_deref()
                .and_then(EntityMetadataHeader::parse)
                .map(|header| header.learned_at);
            imported_at = imported_at.max(learned);
        }
        let imported_at = imported_at.unwrap_or(header.learned_at);
        if latest.as_ref().is_none_or(|(at, _)| imported_at > *at) {
            latest = Some((imported_at, source));
        }
    }
    Ok(ImportedEvidence {
        imported,
        review: latest.map(|(at, source)| history_import_review_id(source, at)),
    })
}

/// The source an imported MESSAGE's provenance names (`import.source` in its
/// metadata).
fn message_import_source(body: &[u8]) -> Option<String> {
    let field = |value: &rmpv::Value, name: &str| match value {
        rmpv::Value::Map(entries) => entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value.clone()),
        _ => None,
    };
    let message = rmpv::decode::read_value(&mut &body[..]).ok()?;
    let source = field(&field(&field(&message, "metadata")?, "import")?, "source")?;
    source
        .as_str()
        .filter(|source| !source.is_empty())
        .map(str::to_owned)
}

/// A row's header and body.
fn row(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<(EntityMetadataHeader, Vec<u8>)>> {
    let Some(raw) = vault.get_raw_in(txn, id)? else {
        return Ok(None);
    };
    Ok(EntityMetadataHeader::parse(&raw).map(|header| {
        (
            header,
            raw[crate::batch::ENTITY_METADATA_HEADER_LEN..].to_vec(),
        )
    }))
}
