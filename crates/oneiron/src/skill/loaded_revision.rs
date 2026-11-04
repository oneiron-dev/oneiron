//! The exact SKILL revision an attempt's pack loaded (FIX 10110).
//!
//! A successful load binds its manifest row to the loaded entity's revision
//! in the entity-revision ledger, which retains that revision's body after an
//! in-place version update. Attribution reads that pin back from the
//! receipt's frozen manifest instead of matching the historical version text
//! against today's mutable record. A row without a pin, or a pinned revision
//! the ledger no longer serves (an erased skill), reads as before: the
//! current record.

use crate::attempt_queue::{ManifestEntry, ManifestKind};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::receipt::ReceiptRecord;
use crate::registry::ENTITY_TYPE_SKILL;
use crate::vault::{ReadMode, RevisionRef};
use crate::{EntityId, Result, Vault};

use super::SkillRecord;
use super::codec::decode_skill_record;

/// `entry` bound to the revision of `entity` this load read, when its live
/// SKILL body is the `record` that loaded. A body read some other way (a
/// proposal through its trial basis) keeps an unpinned row, and a pin never
/// fails a load: an unreadable row is simply left unpinned.
pub(super) fn pin_loaded_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
    record: &SkillRecord,
    entry: ManifestEntry,
) -> Result<ManifestEntry> {
    match vault.get_skill_record_in_txn(txn, entity) {
        Ok(Some(live)) if live == *record => {}
        _ => return Ok(entry),
    }
    // A live revision the ledger does not serve (a source, use-limit or
    // withdrawal exclusion) leaves the row unpinned before any pin write.
    if crate::vault::entity_revision::read_entity_revision_in_txn(
        vault,
        txn,
        entity,
        ReadMode::Live,
    )?
    .is_none()
    {
        return Ok(entry);
    }
    let (revision, _) = crate::vault::entity_revision::ensure_document(vault, txn, entity)?;
    Ok(entry.with_revision(*entity, revision))
}

/// The skill rows `receipt`'s pack pinned, each as its manifest wire form,
/// the entity that loaded and that exact revision's record, in load order.
/// A pin the ledger no longer serves is left out.
pub(crate) fn pinned_skill_revisions(
    vault: &Vault,
    receipt: &ReceiptRecord,
) -> Result<Vec<(String, EntityId, SkillRecord)>> {
    let entries = receipt.pack_manifest_entries().unwrap_or_default();
    let txn = vault.store.env.read_txn()?;
    let mut pinned = Vec::new();
    for entry in entries {
        let Some((entity, revision)) = entry.revision.filter(|_| entry.kind == ManifestKind::Skill)
        else {
            continue;
        };
        if let Some(record) = pinned_record_in_txn(vault, &txn, &entity, revision)? {
            pinned.push((entry.wire_form(), entity, record));
        }
    }
    Ok(pinned)
}

/// The SKILL record `receipt`'s pack loaded as `skill`: the exact revision
/// its last pinned row names, or the current record when no row pins one.
/// `None` when the skill is gone.
pub(crate) fn receipt_skill_record_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt: &ReceiptRecord,
    skill: &EntityId,
) -> Result<Option<SkillRecord>> {
    let pinned = receipt
        .pack_manifest_entries()
        .unwrap_or_default()
        .into_iter()
        .rev()
        .filter(|entry| entry.kind == ManifestKind::Skill)
        .filter_map(|entry| entry.revision)
        .find(|(entity, _)| entity == skill);
    if let Some((_, revision)) = pinned
        && let Some(record) = pinned_record_in_txn(vault, txn, skill, revision)?
    {
        return Ok(Some(record));
    }
    vault.get_skill_record_in_txn(txn, skill)
}

/// [`receipt_skill_record_in_txn`] on a snapshot of its own.
pub(crate) fn receipt_skill_record(
    vault: &Vault,
    receipt: &ReceiptRecord,
    skill: &EntityId,
) -> Result<Option<SkillRecord>> {
    let txn = vault.store.env.read_txn()?;
    receipt_skill_record_in_txn(vault, &txn, receipt, skill)
}

/// One retained SKILL revision, `None` when the ledger no longer serves it
/// (an erased skill) or its body is not a SKILL record. A pin the local
/// FRONTIER table cannot serve while the entity lives fails closed (FIX
/// 10676): falling back to the current record would silently read the wrong
/// revision.
fn pinned_record_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
    revision: RevisionRef,
) -> Result<Option<SkillRecord>> {
    let raw = match crate::vault::entity_revision::read_entity_revision_in_txn(
        vault,
        txn,
        entity,
        ReadMode::Pinned(revision),
    ) {
        Ok(Some(raw)) => raw,
        Ok(None) => return Ok(None),
        Err(error) => return Err(error),
    };
    let skill = EntityMetadataHeader::parse(&raw)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_SKILL);
    if !skill {
        return Ok(None);
    }
    Ok(decode_skill_record(&raw[ENTITY_METADATA_HEADER_LEN..]).ok())
}
