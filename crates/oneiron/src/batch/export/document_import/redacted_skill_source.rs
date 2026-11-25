//! RULING RESTORE-REDACTED-HUB-SKILL = A (Engine, 14 Nov 2026 16:48): a
//! skill whose source tree an export without secrets redacted has no tree
//! in the archive to restore, and the manifest refuses it
//! (`RedactedSource`). A whole-vault import into a vault that does not hold
//! that skill leaves out its SKILL row, every source carrier that names it
//! as holder and every claim about it, instead of refusing the archive. The
//! receipt's `destination_omissions` names the package (skill id, version,
//! canonical tree hash) under `RedactedSkillSource`, so the owner can
//! reinstall that exact package. A vault that already holds the skill keeps
//! its own rows: `validate_existing_source` compares the stored package with
//! the redacted tree, as before.
use std::collections::BTreeSet;
use std::io::{Read, Seek};

use super::super::archive_index::{IndexedArchive, Tag, id_at};
use super::super::{ExportImportOmission, ImportOmissionReason, OmittedSkillSource};
use crate::Vault;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::serialize::ExportBody;

/// Marks each redacted skill this vault does not hold `Tag::Omitted`, with
/// its source carriers and the claims about each of them, and returns one
/// `RedactedSkillSource` omission per skill, in id order. Runs before the
/// entity pass, so that pass skips every row it marks, and the edge pass
/// skips each link of one.
pub(super) fn omit_redacted_skill_sources<R: Read + Seek>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    archive: &mut IndexedArchive<'_, R>,
) -> Result<Vec<ExportImportOmission>> {
    let mut skills = BTreeSet::new();
    let mut omissions = Vec::new();
    // Archive validation indexed each skill whose source tree it refused.
    let mut after: Option<Vec<u8>> = None;
    while let Some((key, _)) = archive
        .index
        .next(Tag::SourceRefusal, &[], after.as_deref())?
    {
        let id = id_at(&key, 0)?;
        after = Some(key);
        if crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?.is_some() {
            continue;
        }
        let (_, row) = archive
            .entity(&id)?
            .ok_or(Error::InvariantViolation("archive index lost a skill"))?;
        // A record the export nulled names no package; the omission still
        // names the skill's id.
        let skill_source = row
            .body
            .to_bytes()
            .ok()
            .and_then(|bytes| crate::write_envelope::skill_record::decode_skill_record(&bytes).ok())
            .map(|record| OmittedSkillSource {
                skill_id: record.skill_id,
                version: record.version,
                content_hash: record.content_hash.map(|hash| hash.to_hex()),
            });
        omissions.push(ExportImportOmission {
            entity_id: id.to_hex(),
            reason: ImportOmissionReason::RedactedSkillSource,
            skill_source,
        });
        skills.insert(id);
    }
    if skills.is_empty() {
        return Ok(omissions);
    }
    // Each source carrier of a left-out skill: every version's, not only the
    // one its record's tree hash names.
    let mut omitted = skills.clone();
    let mut after: Option<EntityId> = None;
    while let Some(id) = archive.next_of_type(ENTITY_TYPE_ASSET, after.as_ref())? {
        after = Some(id);
        let Some((_, row)) = archive.entity(&id)? else {
            continue;
        };
        if let ExportBody::HubSource(source) = &row.body
            && skills.contains(&source.holder()?)
        {
            omitted.insert(id);
        }
    }
    // The left-out rows, and the claims about each.
    for id in &omitted {
        archive.index.put(Tag::Omitted, id.as_bytes(), &[])?;
        let mut after: Option<Vec<u8>> = None;
        while let Some((key, _)) =
            archive
                .index
                .next(Tag::About, id.as_bytes(), after.as_deref())?
        {
            let claim = id_at(&key, ENTITY_ID_LEN)?;
            archive.index.put(Tag::Omitted, claim.as_bytes(), &[])?;
            after = Some(key);
        }
    }
    Ok(omissions)
}
