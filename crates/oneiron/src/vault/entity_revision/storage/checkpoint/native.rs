//! Native NOTE revision binding proofs for checkpoint capture and restore.

use heed::RoTxn;

use super::super::RevisionRef;
use super::super::frontier::FrontierEntry;
use super::super::history::{physical_revision_raw, revision_raw};
use super::document::{RAW_REF_CHANGES, SHORT_REF_CHANGES};
use crate::EntityId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, short_id_content_hash};
use crate::error::Result;
use crate::note::checkpoint::split_core_row;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::Unresolved;

/// Reads each new binding through its own namespace. A Native row proves its
/// full tagged ref, actual slot/floor, and physical envelope before rendering.
pub(super) fn binding(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    revision: RevisionRef,
    encoded: &[u8],
) -> Result<Option<Vec<u8>>> {
    match FrontierEntry::decode(encoded)? {
        FrontierEntry::Document(_) => Ok(None),
        FrontierEntry::PhysicalAlias => physical_revision_raw(dbs, txn, id, revision).map(Some),
        FrontierEntry::Note { .. } => revision_raw(dbs, txn, id, revision).map(Some),
    }
}

/// Only the generic DOC's actor projection can change its physical NOTE
/// envelopes. Compare the Native rendered body's own byte, not the physical
/// birth body's byte. NOTE slot actor fills preserve body text operations.
/// DOC-less cores follow the entity getter's unchanged CORE_RAW_REFS rule:
/// live-author cores remain exact under the outer seal, never actor-filled.
pub(super) fn keeps_projected_binding(
    selected: &[u8],
    encoded: &[u8],
) -> std::result::Result<(), Unresolved> {
    let split = split_core_row(selected).map_err(Unresolved::ActorSplit)?;
    if split.actors.is_empty() {
        return Ok(());
    }
    match FrontierEntry::decode(encoded).map_err(|_| Unresolved::Undecodable)? {
        FrontierEntry::PhysicalAlias => Err(Unresolved::ActorSplit(RAW_REF_CHANGES)),
        FrontierEntry::Note { .. } => {
            let short = |row: &[u8]| short_id_content_hash(&row[ENTITY_METADATA_HEADER_LEN..]);
            if short(selected) == short(&split.no_one) {
                Ok(())
            } else {
                Err(Unresolved::ActorSplit(SHORT_REF_CHANGES))
            }
        }
        FrontierEntry::Document(_) => Err(Unresolved::Undecodable),
    }
}

/// Checks the actual binding view supplied by the ledger's capture index.
/// No second durable state or copied physical envelope is created.
pub(super) fn check_without_doc(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    state: Option<&[RevisionRef; 2]>,
    frontiers: &[(RevisionRef, Vec<u8>)],
    identities: &[RevisionRef],
    staged: &[RevisionRef],
) -> Result<()> {
    use super::super::{DOC, IDENTITY, common_binding};
    use crate::store::checkpoint_payload::rows;
    if DOC.contains(dbs, txn, id)?
        || !frontiers.iter().any(|(_, encoded)| {
            matches!(
                FrontierEntry::decode(encoded),
                Ok(FrontierEntry::Note { .. } | FrontierEntry::PhysicalAlias)
            )
        })
    {
        return Ok(());
    }
    let state = state.ok_or_else(rows::bad_part)?;
    let common = crate::entity_doc::record_document(dbs, txn, id, None)?;
    let mut retained = std::collections::BTreeSet::new();
    for (revision, encoded) in frontiers {
        let bound = if binding(dbs, txn, id, *revision, encoded)?.is_some() {
            true
        } else {
            match common.as_ref() {
                Some(common) => common_binding(id, common, *revision, encoded)?,
                None => false,
            }
        };
        if !bound || IDENTITY.get(dbs, txn, &revision.0)? != Some(*id) {
            return Err(rows::bad_part());
        }
        retained.insert(*revision);
    }
    if !state
        .iter()
        .chain(identities)
        .chain(staged)
        .all(|revision| retained.contains(revision))
    {
        return Err(rows::bad_part());
    }
    Ok(())
}
