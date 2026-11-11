//! Owner-edited engine seeds restored only after the import proves a fresh destination.

use super::super::ExportEntity;
use super::{invalid, parse_id};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON};
use crate::temporal::TimeRange;
use crate::vault::{EngineSeedIdentities, live_entity_row_in_txn};

/// Replaces a divergent census AGENT_DEF or PERSON seed in the import writer with
/// the archived native row, through the owner's own edit writer for that kind.
/// `Ok(false)`: not a replaceable seed, so the caller keeps its collision. The caller
/// proved owner + fresh before any import write, and supplies the native archived body.
pub(super) fn replace_edited_seed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    seeds: &EngineSeedIdentities,
    row: &ExportEntity,
    native_body: &[u8],
) -> Result<bool> {
    let id = parse_id(&row.id)?;
    if !matches!(row.entity_type, ENTITY_TYPE_AGENT_DEF | ENTITY_TYPE_PERSON)
        || !seeds.census.contains(row.entity_type, &id)
        || live_entity_row_in_txn(&vault.store, txn, &id)?.live_type() != Some(row.entity_type)
    {
        return Ok(false);
    }
    let occurred = TimeRange {
        start: row.occurred_start,
        end: row.occurred_end,
    };
    if row.entity_type == ENTITY_TYPE_AGENT_DEF {
        let archived = crate::agent_def::decode_agent_definition(native_body)?;
        let existing = vault.read_agent_definition_in_txn(txn, &id)?;
        if archived.version == existing.version && archived != existing {
            return Err(invalid(&format!(
                "archived AGENT_DEF {} differs from the fresh seed at the same version",
                id.to_hex()
            )));
        }
        vault.update_agent_definition_as_owner_in_txn(
            txn,
            owner,
            &id,
            Some(&existing.version),
            &archived,
            occurred,
            row.learned_at,
        )?;
    } else {
        // The owner's in-place PERSON edit (`put_persona_baseline`) is this
        // ordinary put. Like the source's edit, it lands the PERSON's substrate
        // HasFacet at the archived learned_at, so the archived edge compares equal.
        owner.revalidate_as_vault_owner_in_txn(vault, txn)?;
        vault
            .batch_in()
            .put(
                &id,
                ENTITY_TYPE_PERSON,
                occurred,
                row.learned_at,
                native_body,
            )
            .apply(txn)?;
    }
    Ok(true)
}
