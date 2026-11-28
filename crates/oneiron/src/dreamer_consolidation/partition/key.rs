use super::super::{resources, watermark::read_turn_facts_in_txn};
use super::{ConsolidationPartitionKey, invalid_consolidation};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Result;

pub(super) fn partition_key_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    conversation_ref: EntityId,
) -> Result<ConsolidationPartitionKey> {
    let turn_facts = read_turn_facts_in_txn(vault, txn, turn)?;
    let conversation_facts = read_turn_facts_in_txn(vault, txn, &conversation_ref)?;
    let project = if let Some(raw) = vault.get_raw_in(txn, turn)? {
        let kind = EntityMetadataHeader::parse(&raw)
            .ok_or_else(|| invalid_consolidation("invalid partition turn header"))?
            .entity_type;
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        // The project axis: one partition per stored project (FIX EXTRACTION-SLICE-VALUE-CROSS-PROJECT).
        resources::stored_project(&vault.store, txn, *turn, kind, body)
            .map(|_| Some(crate::claim::default_project_id()))?
    } else {
        Some(crate::claim::default_project_id())
    };
    Ok(ConsolidationPartitionKey {
        conversation_ref,
        world_ref: turn_facts.world_ref.or(conversation_facts.world_ref),
        facet_ref: turn_facts.facet_ref.or(conversation_facts.facet_ref),
        project,
    })
}
