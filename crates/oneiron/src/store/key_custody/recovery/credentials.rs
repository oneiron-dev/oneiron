//! A disaster recovery's head keys of erased credentials (FIX 10584 item
//! 4): a key whose credential the head's evidence positively fences never
//! lands live from the head. It lands retired, as the erase left it, before
//! any key is published, so no restored row reads it in the meantime.

use std::collections::BTreeMap;

use crate::entity_id::EntityId;

use super::super::erase_evidence::FenceFact;
use super::super::identity::{CustodyId, CustodyKind};

/// Whether the head key `id` is one of a credential `evidence` fences: its
/// value's, a transition's or a request input's, by the credential's id as
/// the item's first 16 bytes. Every fact is an erase's: none comes of a
/// soft delete, a rotation or a revoke.
pub(super) fn fenced(evidence: &BTreeMap<EntityId, FenceFact>, id: &CustodyId) -> bool {
    matches!(
        id.kind(),
        CustodyKind::CredentialValue
            | CustodyKind::CustodyTransition
            | CustodyKind::CustodyRequestInput
    ) && id
        .subject()
        .item()
        .get(..16)
        .and_then(|parent| <[u8; 16]>::try_from(parent).ok())
        .and_then(|parent| EntityId::from_bytes(parent).ok())
        .is_some_and(|parent| evidence.contains_key(&parent))
}
