//! Project history beside the PROJECT carriers a window document holds
//! (PR 3 decision 9). A retained window keeps a PROJECT carrier after the
//! row's learned time moved to a later month, so closure over the rows
//! learned in range alone would ship that carrier without the revisions
//! learned since (Astra #1434 F2). The export boundary and reverse
//! rematerialization both close over the carriers the document holds.
use loro::LoroDoc;

use super::loro_support::{map_for_each_bytes, map_get_bytes, map_insert_bytes};
use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Writes into `doc` each held, unforged revision of every PROJECT row it
/// carries that the document lacks or holds with other bytes. The caller
/// commits. Returns whether anything was written.
pub(super) fn carry_project_history(vault: &Vault, doc: &LoroDoc) -> Result<bool> {
    let entities = doc.get_map("entities");
    let mut projects = Vec::new();
    map_for_each_bytes(&entities, |key, blob| {
        if EntityMetadataHeader::parse(blob).is_some_and(|header| {
            crate::workspace_roster::is_project_type(&vault.store, header.entity_type)
        }) && let Ok(id) = EntityId::from_hex(key)
        {
            projects.push(id);
        }
    });
    if projects.is_empty() {
        return Ok(false);
    }
    let rtxn = vault.store.env.read_txn()?;
    let mut wrote = false;
    for project in projects {
        for companion in
            crate::workspace_roster::exportable_revisions_in_txn(&vault.store, &rtxn, project)?
        {
            let Some(raw) = vault.get_raw_in(&rtxn, &companion)? else {
                continue;
            };
            let key = companion.to_hex();
            if map_get_bytes(&entities, &key).as_deref() != Some(raw.as_slice()) {
                map_insert_bytes(&entities, &key, &raw)?;
                wrote = true;
            }
        }
    }
    Ok(wrote)
}
