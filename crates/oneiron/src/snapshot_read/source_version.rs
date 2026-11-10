//! The version of one source row as a scoped read served it, and its recheck
//! in a later transaction.

use serde::{Deserialize, Serialize};

use crate::claim::ScopedRead;
use crate::dreamer_consolidation::{TurnText, scoped_turn_body_text_in};
use crate::registry::ENTITY_TYPE_TURN;
use crate::store::consolidation_evidence::swarm_evidence_content_hash;
use crate::{EntityId, Result};

/// One source row as the caller's scoped read served it: the version a later
/// commit names to prove it cites the same words. It holds no storage
/// snapshot; [`Self::recheck_in_txn`] judges it again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceVersion {
    /// The source row.
    pub entity: EntityId,
    /// Its entity type code.
    pub entity_type: u8,
    /// When the vault learned the revision read.
    pub learned_at: u64,
    /// `blake3:<hex>`: the domain-separated evidence hash of the logical body
    /// read, the hash the Dreamer's decision evidence names a source by.
    pub revision: String,
    /// For a TURN, `blake3:<hex>` over every fact its text was projected
    /// from: its own words, or its MESSAGE rows' versions, bindings, document
    /// frontiers, stream finality and layout. `None` for any other row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection: Option<String>,
}

/// What a recheck of a [`SourceVersion`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceVersionCheck {
    /// The row still reads for the caller, at the same revision.
    Current,
    /// The row still reads for the caller, at another revision.
    Moved,
    /// The caller no longer reads the row, or it is gone. Nothing more is
    /// said, as a scoped read says nothing of a withheld row.
    Withheld,
}

impl SourceVersion {
    /// Judges this version again in `txn` under `read`, the caller's own live
    /// read: the row must still read for the caller (a revoked grant, a
    /// withdrawn or deleted source, or a TURN with a MESSAGE row it may no
    /// longer read answers [`SourceVersionCheck::Withheld`]), and every fact
    /// the version names must be unchanged. A commit that cites the row calls
    /// it in its own write transaction.
    ///
    /// # Errors
    ///
    /// Storage errors, and a TURN whose text no longer projects for a reason
    /// other than a withheld MESSAGE row.
    pub(crate) fn recheck_in_txn(
        &self,
        read: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
    ) -> Result<SourceVersionCheck> {
        Ok(match source_version_in_txn(read, txn, &self.entity)? {
            None => SourceVersionCheck::Withheld,
            Some((current, _)) if current == *self => SourceVersionCheck::Current,
            Some(_) => SourceVersionCheck::Moved,
        })
    }
}

/// The version of `entity` as `read` serves it in `txn`, with a TURN's
/// projected text. `None` when `read` does not read the row, or reads a TURN
/// but not every MESSAGE row its words come from: no partial transcript is
/// ever served.
///
/// # Errors
///
/// Storage errors, and a TURN whose text does not project for a reason other
/// than a withheld MESSAGE row.
pub(crate) fn source_version_in_txn(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
) -> Result<Option<(SourceVersion, Option<TurnText>)>> {
    let Some((entity_type, learned_at, body)) = read
        .get_entities_parts_in_txn(txn, std::slice::from_ref(entity))?
        .pop()
        .flatten()
    else {
        return Ok(None);
    };
    let (projection, text) = if entity_type == ENTITY_TYPE_TURN {
        let mut withheld = 0;
        match scoped_turn_body_text_in(read, txn, entity, &body, &mut withheld) {
            Ok(text) => (Some(blake3_ref(&text.summary_fingerprint()?)), Some(text)),
            Err(_) if withheld != 0 => return Ok(None),
            Err(error) => return Err(error),
        }
    } else {
        (None, None)
    };
    let version = SourceVersion {
        entity: *entity,
        entity_type,
        learned_at,
        revision: blake3_ref(&swarm_evidence_content_hash(&body)),
        projection,
    };
    Ok(Some((version, text)))
}

/// The projected text of TURN `turn` as `memory`'s bound reader reads it, and
/// whether a lifted key was masked in it: for every reader but the owner,
/// each lifted key the TURN's own body or a MESSAGE row its words come from
/// holds reads as its handle (OF-067; review of #6964). `read` is the
/// caller's own read, which served `text`.
///
/// # Errors
///
/// Storage errors.
pub(super) fn served_turn_text_in_txn(
    memory: &crate::memory::Memory<'_>,
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    text: &TurnText,
) -> crate::memory::MemoryResult<(Option<String>, bool)> {
    let Some(words) = text.text() else {
        return Ok((None, false));
    };
    if !memory.reads_lifted_keys_masked_in_txn(txn)? {
        return Ok((Some(words.to_owned()), false));
    }
    let mut sources = vec![*turn];
    sources.extend(text.spans(None)?.into_iter().map(|span| span.message));
    sources.sort_unstable();
    sources.dedup();
    let bodies: Vec<Vec<u8>> = read
        .get_entities_parts_in_txn(txn, &sources)?
        .into_iter()
        .flatten()
        .map(|(_, _, body)| body)
        .collect();
    let (served, masked) = memory.lifted_projection_in_txn(txn, &bodies, words)?;
    Ok((Some(served), masked))
}

/// `blake3:<hex>` for a 32-byte BLAKE3 digest.
pub(super) fn blake3_ref(digest: &[u8; 32]) -> String {
    format!("blake3:{}", blake3::Hash::from(*digest).to_hex())
}
