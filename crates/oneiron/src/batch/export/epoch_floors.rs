//! The epoch floors a whole-vault archive carries (OF-013), one row per
//! lineage (FIX 5029): a SESSION's own log, or one conversation's turns
//! within a SESSION. Export writes each floor whose ids leave this device;
//! validation parses each; import raises each local floor to the archive's
//! and never lowers one. One codec for both directions.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use super::archive_index::ArchiveSpool;
use super::document_import::parse_id;
use super::{ArchiveRecordKind, ExportEpochFloor};
use crate::compaction::EpochScope;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::serialize::DocumentWriter;
use crate::store::Store;

/// Writes every lineage's floor read in `rtxn`, each id it names a source.
/// A floor whose session or conversation a device-local world keeps stays
/// here, as that row does.
pub(super) fn write_epoch_floors_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    device_only: &BTreeSet<EntityId>,
    sources: &mut BTreeSet<EntityId>,
    writer: &mut DocumentWriter<'_>,
) -> Result<()> {
    for (scope, epoch, turn_end) in crate::compaction::epoch_floors_in_txn(store, rtxn)? {
        let ids: Vec<EntityId> = std::iter::once(scope.session)
            .chain(scope.conversation)
            .collect();
        let mut withheld = false;
        for id in &ids {
            withheld |= crate::settings::device_only_withholds(store, rtxn, device_only, id)
                .or_else(|error| match error {
                    Error::CorruptedIndex(_) => Ok(true),
                    error => Err(error),
                })?;
        }
        if withheld {
            continue;
        }
        sources.extend(ids);
        writer.epoch_floor(&ExportEpochFloor {
            session: scope.session.to_hex(),
            conversation: scope.conversation.as_ref().map(EntityId::to_hex),
            epoch,
            turn_end,
        })?;
    }
    Ok(())
}

/// The lineage an archived floor names, its ids canonical hex.
fn floor_scope(floor: &ExportEpochFloor) -> Result<EpochScope> {
    Ok(EpochScope {
        session: parse_id(&floor.session)?,
        conversation: floor.conversation.as_deref().map(parse_id).transpose()?,
    })
}

/// Parses every archived floor, so a malformed one refuses the archive
/// before anything is written.
pub(super) fn validate_epoch_floors(spool: &ArchiveSpool) -> Result<()> {
    let mut floors = spool.rows(ArchiveRecordKind::EpochFloor);
    while let Some((_, floor)) = floors.next_parsed::<ExportEpochFloor>(spool)? {
        floor_scope(&floor)?;
    }
    Ok(())
}

/// Raises each lineage's floor to the archive's in the import's write; a
/// floor only rises, so numbering here never goes back under an epoch a
/// purge removed.
pub(super) fn restore_epoch_floors_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    spool: &ArchiveSpool,
) -> Result<()> {
    let mut floors = spool.rows(ArchiveRecordKind::EpochFloor);
    while let Some((_, floor)) = floors.next_parsed::<ExportEpochFloor>(spool)? {
        crate::compaction::raise_epoch_scope_floor_in_txn(
            store,
            wtxn,
            &floor_scope(&floor)?,
            floor.epoch,
            floor.turn_end,
        )?;
    }
    Ok(())
}
