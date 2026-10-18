//! Where the words of one stored revision came from.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::error::{Error, RecordError, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN};
use crate::{EntityId, Vault};
use heed::RoTxn;

/// The origin of one revision's words.
pub(crate) enum WordSources {
    /// The revision's own: it carries no summary's words.
    Own,
    /// A scope summary's, which came from these records and MESSAGEs.
    From(Vec<EntityId>),
    /// A summary's whose sources no longer resolve; a reader refuses it.
    Unresolved,
}

/// The word sources of the stored revision `raw` of `id`: an epoch summary,
/// a scope summary, a TURN that copies one, a claim whose merge header names
/// one, or a `conversation.summary` claim's typed coverage.
pub(crate) fn word_sources_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<WordSources> {
    let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    let names = |needle: &[u8]| body.windows(needle.len()).any(|window| window == needle);
    let epoch = match header.entity_type {
        ENTITY_TYPE_SUMMARY => crate::compaction::stored_epoch_in(&vault.store, txn, id, body)?,
        _ => crate::compaction::StoredEpoch::No,
    };
    let sources = match header.entity_type {
        // A pointer no head stands for may be an epoch summary's, whose
        // sources this read cannot name (Astra 1384e).
        ENTITY_TYPE_SUMMARY if epoch == crate::compaction::StoredEpoch::Unresolved => {
            return Ok(WordSources::Unresolved);
        }
        // An epoch summary's words are those of every record it was written
        // from, its `DerivedFrom` targets (agent-runtime-v1 §d7); a nested
        // epoch among them carries its own. A run that had read and said
        // nothing yet wrote one from its own steps alone.
        ENTITY_TYPE_SUMMARY if epoch == crate::compaction::StoredEpoch::Yes => {
            let sources = vault
                .store
                .port_edges(
                    txn,
                    id,
                    EdgeDirection::Out,
                    Some(EdgeKind::DerivedFrom),
                    None,
                )?
                .map(|edge| edge.map(|edge| edge.target))
                .collect::<Result<Vec<_>>>()?;
            if sources.is_empty() {
                return Ok(WordSources::Own);
            }
            Ok(Some(sources))
        }
        ENTITY_TYPE_SUMMARY => super::body_covers_in_txn(vault, txn, id, header.entity_type, body),
        // A reply carries its summary under the `summary` key, in any
        // string encoding; the decoder below decides. Its words are the
        // summary's as it landed, so the sources its landing registered
        // stay its sources whatever the summary covers now.
        ENTITY_TYPE_TURN if names(b"summary") => {
            super::body_covers_in_txn(vault, txn, id, header.entity_type, body).and_then(|covers| {
                covers
                    .map(|mut covers| {
                        covers.extend(crate::ports::dependency_sources_in(&vault.store, txn, id)?);
                        covers.sort_unstable();
                        covers.dedup();
                        Ok(covers)
                    })
                    .transpose()
            })
        }
        ENTITY_TYPE_CLAIM if names(b"merge.summary") || names(b"conversation.summary") => {
            let claim = crate::claim::decode_claim_body(body, true)?;
            match super::merge_word_sources_in_txn(vault, txn, &claim) {
                Ok(None) => crate::conversation::conversation_summary_covers(&claim),
                merged => merged,
            }
        }
        _ => return Ok(WordSources::Own),
    };
    Ok(match sources {
        Ok(Some(mut sources)) if !sources.is_empty() => {
            if header.entity_type == ENTITY_TYPE_SUMMARY {
                sources.extend(crate::ports::dependency_sources_in(&vault.store, txn, id)?);
                sources.sort_unstable();
                sources.dedup();
            }
            WordSources::From(sources)
        }
        Ok(None) => WordSources::Own,
        Ok(Some(_))
        | Err(
            Error::EntityNotFound
            | Error::Record(
                RecordError::InvalidScopeSummary(_) | RecordError::InvalidConversationDag(_),
            ),
        ) => WordSources::Unresolved,
        Err(error) => return Err(error),
    })
}
