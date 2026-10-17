//! Complete authenticated machine-claim history required beside a selected row.

use std::collections::BTreeSet;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::Result;
use crate::{EntityId, Vault};

/// The rows a machine CLAIM's authenticated history needs beside it in an
/// export, read from stored truth: its birth event, each transition event and
/// every handoff of its chain. `None` when that history does not resolve
/// whole (a missing or malformed row, a cycle in the chain).
pub(super) fn machine_history_controls(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<Vec<EntityId>>> {
    let (Ok(rows), Ok(packet)) = (
        crate::claim::history_projection::machine_history_rows(&vault.store, rtxn, id),
        crate::claim::history_projection::trusted_machine_handoff(&vault.store, rtxn, id),
    ) else {
        return Ok(None);
    };
    let mut required = vec![rows.birth.event_id()?];
    for event in &rows.events {
        required.push(crate::claim::transition::machine_claim_transition_event_id(
            event,
        )?);
    }
    let mut next = Some(packet);
    let mut seen = BTreeSet::new();
    while let Some(handoff) = next {
        let hash = handoff
            .content_hash()
            .map_err(|_| crate::Error::InvalidClaimBody("machine handoff hash"))?;
        if !seen.insert(hash) {
            return Ok(None);
        }
        required.push(EntityId::from_bytes(
            hash[..16]
                .try_into()
                .map_err(|_| crate::Error::InvalidClaimBody("machine handoff id"))?,
        )?);
        let Some(parent) = handoff.previous_handoff_hash else {
            break;
        };
        let parent_id = EntityId::from_bytes(
            parent[..16]
                .try_into()
                .map_err(|_| crate::Error::InvalidClaimBody("machine handoff parent id"))?,
        )?;
        let Some(raw) =
            crate::ports::EntityStoreRead::port_entity_raw(&vault.store, rtxn, &parent_id)?
        else {
            return Ok(None);
        };
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|header| header.entity_type != crate::registry::ENTITY_TYPE_CLAIM)
        {
            return Ok(None);
        }
        let Ok(body) = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)
        else {
            return Ok(None);
        };
        let rmpv::Value::Binary(bytes) = body.value else {
            return Ok(None);
        };
        let Ok(parent_packet) = crate::claim::ClaimHistoryHandoff::decode(&bytes) else {
            return Ok(None);
        };
        if parent_packet.content_hash().ok() != Some(parent) {
            return Ok(None);
        }
        next = Some(parent_packet);
    }
    Ok(Some(required))
}
