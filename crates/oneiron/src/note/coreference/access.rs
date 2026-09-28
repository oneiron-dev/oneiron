//! One transaction-bound answer for node and exact-relation diary access.
use super::pair::{DiaryPair, candidate_author_in};
use crate::access_grant::{AccessGrantCapability, AccessGrantScope, AccessGrantStatus};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::error::Result;
use crate::ports::EdgeStoreRead;
use crate::registry::ENTITY_TYPE_NOTE;
use crate::{EntityId, Vault};

/// An exact pair can become readable only through this constructor. Node
/// readability through *another* pair is never proof for this pair's edge.
#[derive(Debug, Clone, Copy)]
pub(super) struct SharedDiaryPair(DiaryPair);

#[derive(Debug, Clone, Copy)]
pub(super) enum DiaryPairAccess {
    Empty,
    Shared(SharedDiaryPair),
}
impl DiaryPairAccess {
    pub(super) fn shared(self) -> Option<SharedDiaryPair> {
        match self {
            Self::Empty => None,
            Self::Shared(proof) => Some(proof),
        }
    }
}

pub(super) fn pair_access_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pair: DiaryPair,
) -> Result<DiaryPairAccess> {
    if !pair.linked_in(vault, txn)? {
        return Ok(DiaryPairAccess::Empty);
    }
    let (Some(left_author), Some(right_author)) = (
        candidate_author_in(vault, txn, pair.left)?,
        candidate_author_in(vault, txn, pair.right)?,
    ) else {
        return Ok(DiaryPairAccess::Empty);
    };
    if left_author == right_author {
        return Ok(DiaryPairAccess::Empty);
    }
    let mut left_granted = false;
    let mut right_granted = false;
    let now = vault.store.clock.now_recorded_at();
    for row in vault
        .store
        .type_index
        .prefix_iter(txn, &[crate::registry::ENTITY_TYPE_ACCESS_GRANT])?
    {
        let (key, _) = row?;
        let id = crate::vault::entity_id_from_type_index_key(&key)?;
        let Some(raw) = vault.store.entities.get(txn, id.as_bytes())? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        if header.entity_type != crate::registry::ENTITY_TYPE_ACCESS_GRANT {
            continue;
        }
        let Ok(grant) =
            crate::access_grant::decode_access_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])
        else {
            continue;
        };
        if grant.scope
            != (AccessGrantScope::DiaryCoreference {
                left_ref: pair.left,
                right_ref: pair.right,
            })
            || grant.capability != AccessGrantCapability::DiaryCoreferenceRead
            || grant.effective_status_at(now) != AccessGrantStatus::Active
        {
            continue;
        }
        left_granted |= grant.principal_ref == left_author;
        right_granted |= grant.principal_ref == right_author;
        if left_granted && right_granted {
            return Ok(DiaryPairAccess::Shared(SharedDiaryPair(pair)));
        }
    }
    Ok(DiaryPairAccess::Empty)
}

pub(crate) fn shared_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    a: EntityId,
    b: EntityId,
) -> Result<bool> {
    let Some(pair) = DiaryPair::new(a, b) else {
        return Ok(false);
    };
    Ok(pair_access_in(vault, txn, pair)?
        .shared()
        .is_some_and(|proof| proof.0 == pair))
}

/// The exact-edge predicate. Unlike `readable_through_link`, this cannot
/// borrow authority from another link joining either endpoint.
pub(crate) fn edge_access_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: EntityId,
    kind: EdgeKind,
    target: EntityId,
) -> Result<bool> {
    if kind != EdgeKind::SameAs {
        return Ok(true);
    }
    let source_note = vault.get_entity_type_in_txn(txn, &source)? == Some(ENTITY_TYPE_NOTE);
    let target_note = vault.get_entity_type_in_txn(txn, &target)? == Some(ENTITY_TYPE_NOTE);
    if source_note || target_note {
        shared_in(vault, txn, source, target)
    } else {
        Ok(true)
    }
}

/// A reader may see the opposite NOTE through ANY shared pair. This does
/// not authorize the other relations of either NOTE.
pub(crate) fn readable_through_link(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    reader: EntityId,
) -> Result<bool> {
    if candidate_author_in(vault, txn, note)?.is_none() {
        return Ok(false);
    }
    for direction in [
        crate::ports::EdgeDirection::Out,
        crate::ports::EdgeDirection::In,
    ] {
        for row in vault
            .store
            .port_edges(txn, &note, direction, Some(EdgeKind::SameAs), None)?
        {
            let other = row?.target;
            if candidate_author_in(vault, txn, other)? == Some(reader)
                && shared_in(vault, txn, note, other)?
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
