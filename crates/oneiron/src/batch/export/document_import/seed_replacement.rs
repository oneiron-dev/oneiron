//! Owner-edited engine seeds restored only after the import proves a fresh destination.

use std::io::{Read, Seek};

use super::super::{ExportEntity, ExportSkillBundle};
use super::{EntityAt, IndexedArchive, Section, Tag, invalid, parse_id};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON, ENTITY_TYPE_SKILL};
use crate::serialize::ExportSecrets;
use crate::temporal::TimeRange;
use crate::vault::{EngineSeedIdentities, live_entity_row_in_txn};

/// Replaces a divergent census AGENT_DEF, PERSON or SKILL seed in the import writer with
/// the archived native row, through the owner's own edit writer for that kind.
/// `Ok(false)`: not a replaceable seed, so the caller keeps its collision. The caller
/// proved owner + fresh before any import write, and supplies the native archived body.
#[expect(
    clippy::too_many_arguments,
    reason = "seed row and its archived source in the import writer"
)]
pub(super) fn replace_edited_seed_in_txn<R: Read + Seek>(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    seeds: &EngineSeedIdentities,
    row: &ExportEntity,
    native_body: &[u8],
    archive: &mut IndexedArchive<'_, R>,
    at: &EntityAt,
    secrets: ExportSecrets,
) -> Result<bool> {
    let id = parse_id(&row.id)?;
    if !matches!(
        row.entity_type,
        ENTITY_TYPE_AGENT_DEF | ENTITY_TYPE_PERSON | ENTITY_TYPE_SKILL
    ) || !seeds.census.contains(row.entity_type, &id)
        || live_entity_row_in_txn(&vault.store, txn, &id)?.live_type() != Some(row.entity_type)
    {
        return Ok(false);
    }
    let occurred = TimeRange {
        start: row.occurred_start,
        end: row.occurred_end,
    };
    match row.entity_type {
        ENTITY_TYPE_AGENT_DEF => {
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
        }
        ENTITY_TYPE_PERSON => {
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
        ENTITY_TYPE_SKILL => {
            if !seeds.census.skills.contains(&id) || at.section != Section::Skill {
                return Ok(false);
            }
            owner.revalidate_as_vault_owner_in_txn(vault, txn)?;
            let bundle: ExportSkillBundle = archive.hydrated(at.loc)?;
            let record = crate::skill::decode_skill_record(native_body)?;
            let hash = record
                .content_hash
                .ok_or_else(|| invalid("seed skill content hash missing"))?;
            let carrier = crate::store::skill_source_carrier::source_carrier_id(&id, &hash)?;
            let carrier_was_present =
                crate::ports::EntityStoreRead::port_entity_present(&vault.store, txn, &carrier)?;
            let carrier_row = archive.entity(&carrier)?.map(|(_, row)| row);
            let proof =
                crate::skill_hub::HubAdmissionProof::owner_seed_restore(owner, id, native_body);
            vault.restore_owner_seed_skill_in_txn(
                txn,
                seeds,
                &bundle,
                carrier_row.as_ref(),
                &archive.files,
                secrets,
                proof,
            )?;
            if !carrier_was_present
                && crate::ports::EntityStoreRead::port_entity_present(&vault.store, txn, &carrier)?
            {
                // Only the newly created ASSET, never the replaced SKILL, is
                // an import insertion. Its archive row still takes the queue.
                archive.index.put(Tag::Inserted, carrier.as_bytes(), &[])?;
            }
        }
        _ => unreachable!("seed kind checked above"),
    }
    Ok(true)
}
