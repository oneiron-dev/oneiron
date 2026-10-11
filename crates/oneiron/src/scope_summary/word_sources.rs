//! Where the words of one stored revision came from.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, RecordError, Result};
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

/// The word sources of the stored revision `raw` of `id`: a scope summary,
/// a TURN that copies one, or a claim whose merge header names one.
pub(crate) fn word_sources_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<WordSources> {
    let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    let names = |needle: &[u8]| body.windows(needle.len()).any(|window| window == needle);
    let sources = match header.entity_type {
        ENTITY_TYPE_SUMMARY => super::body_covers_in_txn(vault, txn, id, header.entity_type, body),
        // A reply carries its summary under the `summary` key, in any
        // string encoding; the decoder below decides.
        ENTITY_TYPE_TURN if names(b"summary") => {
            super::body_covers_in_txn(vault, txn, id, header.entity_type, body)
        }
        ENTITY_TYPE_CLAIM if names(b"merge.summary") => super::merge_word_sources_in_txn(
            vault,
            txn,
            &crate::claim::decode_claim_body(body, true)?,
        ),
        _ => return Ok(WordSources::Own),
    };
    Ok(match sources {
        Ok(Some(sources)) if !sources.is_empty() => WordSources::From(sources),
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
