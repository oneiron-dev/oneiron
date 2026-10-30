//! Model PERSON mint for imported agent definitions (FIX 1162): one pass over
//! the import's inserted rows, after its own PERSON and anchor rows are in.
use std::io::{Read, Seek};

use super::archive_index::{IndexedArchive, Tag, id_at};
use crate::Vault;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_AGENT_DEF;

/// Mints a model PERSON for each live imported AGENT_DEF in the caller's writer (idempotent).
pub(super) fn ensure_imported_agent_persons_in_txn<R: Read + Seek>(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    archive: &IndexedArchive<'_, R>,
) -> Result<()> {
    for entry in archive.index.entries(Tag::Inserted)? {
        let (key, _) = entry?;
        let id = id_at(key, 0)?;
        let Some(row) =
            crate::ports::EntityStoreRead::port_entity_record(&vault.store, &*wtxn, &id)?
        else {
            continue;
        };
        if row.entity_type != ENTITY_TYPE_AGENT_DEF {
            continue;
        }
        let visibility =
            crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, &*wtxn, &id)?;
        if visibility.deleted || visibility.stale {
            continue;
        }
        let definition = crate::agent_def::decode_agent_definition(&row.body)?;
        let name = definition
            .display_name
            .as_deref()
            .unwrap_or(&definition.agent_id);
        crate::context_board::ensure_agent_person_in_txn(vault, wtxn, id, name, row.learned_at)?;
    }
    Ok(())
}
