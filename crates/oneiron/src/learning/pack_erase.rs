//! The pack context a learning evidence row keeps beside its observation
//! (FIX 8988): an erase that reaches an entity the context names clears the
//! context, as a late-credit receipt's frozen attribution is cleared, since
//! a context cannot keep its execution facts without the erased id. The
//! row's observation, weight, anchor and receipt stay.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::receipt::PackAttributionFields;

use super::evidence::EVIDENCE;

/// Clears the pack context of every learning evidence row whose context
/// names erased `entity`. A row that no longer decodes is deleted and
/// counted.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_learning_pack_context_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    for (key, mut row) in crate::skill_attribution::erase_scan_in_txn(vault, wtxn, EVIDENCE)? {
        if row
            .pack_attribution
            .as_ref()
            .is_some_and(|context| pack_attribution_names(&context.attribution, *entity))
        {
            row.pack_attribution = None;
            EVIDENCE.put(&vault.store, wtxn, &key, &row)?;
        }
    }
    Ok(())
}

/// Whether `fields` names `entity`: as its pattern, decider, project or
/// output, a contributing skill, or an end of a used edge.
pub(crate) fn pack_attribution_names(fields: &PackAttributionFields, entity: EntityId) -> bool {
    fields.pattern == entity
        || fields.decider == entity
        || fields.project == Some(entity)
        || fields.output == Some(entity)
        || fields.contributions.iter().any(|item| item.skill == entity)
        || fields
            .used_edges
            .iter()
            .any(|edge| edge.derived == entity || edge.source == entity)
}
