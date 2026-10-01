//! Published revisions whose vectors an embedding-space swap dropped, waiting
//! to be embedded again at idle.
//!
//! The swap queues what the pending worker embeds (claims, epoch summaries).
//! Every other record that held a vector got it from idle publication or from
//! its writer, and no content edit is coming to make idle publication look at
//! it again. A marker here is that edit's stand-in: idle embeds the published
//! revision as it stands, writes the vector alone, and leaves the revision,
//! its text and its citations exactly as they were.
use crate::ports::EntityStoreRead;
use crate::side_table::{self, Raw, SideTable};
use crate::store::ManifestDbs;
use crate::{EntityId, Result, Vault};

pub(super) const REFILL: SideTable<EntityId, (), Raw> =
    SideTable::new(&side_table::ENTITY_REVISION_VECTOR_REFILL);

/// Marks every record that holds a vector the pending worker will not refill.
///
/// Runs inside the swap, before it drops the vectors. A record the worker
/// embeds is queued by the swap itself, and one whose live body is gone has
/// nothing to embed.
pub(crate) fn schedule_vector_refills(vault: &Vault, wtxn: &mut heed::RwTxn<'_>) -> Result<()> {
    for id in crate::hnsw::collect_vector_ids(&vault.store, wtxn)? {
        let Some(record) = vault.store.port_entity_record(wtxn, &id)? else {
            continue;
        };
        if record.entity_type != crate::registry::ENTITY_TYPE_SECRET_CUSTODY
            && crate::embed::embeddable_payload(record.entity_type, &record.body).is_none()
        {
            REFILL.put(&vault.store, wtxn, &id, &())?;
        }
    }
    Ok(())
}

pub(super) fn clear(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    REFILL.delete(store, txn, id)?;
    Ok(())
}
