//! Owner-permitted promotion of retained archive envelopes through their owning modules.

use super::archive_retained_side_rows::retained_side_row_withholds_credential;
use super::{
    ArchiveRetainedSideRow, ArchiveSideFamily, OwnerArchiveRestorePermit,
    RetainedSideHeldBackReason, SideRowBytes,
};
use crate::error::{Error, Result, StoreError};
use crate::side_table::{self, Named, SideCodec, SideKey, SideTable};

/// The live disposition of one source envelope; retained-only rows have no live outcome.
pub(crate) enum ArchivedSideRowOutcome {
    /// The absent live key now holds the source bytes.
    Installed,
    /// The live key already holds the source bytes.
    Unchanged,
    /// Different destination bytes stayed live.
    KeptLive,
    /// Validation left the source envelope inert.
    HeldBack(RetainedSideHeldBackReason),
}

/// The fixed dependency order of the owning landing groups.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ArchivedSideGroup {
    /// Independent settings and customization history.
    Settings,
    /// Grants whose holders have already been restored.
    AgentDef,
    /// Consolidation strength policy.
    DreamerConsolidation,
    /// Projector wake policy.
    DreamerWake,
    /// Description routing policy.
    Llm,
    /// Dependent walk bounds.
    Ports,
    /// Passive housekeeping wake notes.
    HousekeepingWake,
    /// Protective grant withdrawal markers.
    WithdrawnGrant,
}

/// Selects only the tables with a landing group; every other envelope stays retained-only.
pub(crate) fn archived_side_group(source_table: &str) -> Option<ArchivedSideGroup> {
    use ArchivedSideGroup as Group;
    match source_table {
        name if name == side_table::BACKUP_POLICY.name
            || name == side_table::BOARD_LAYOUT_SETTINGS.name
            || name == side_table::CUSTOMIZATION_EVENT.name
            || name == side_table::CUSTOMIZATION_SETTINGS.name
            || name == side_table::NON_BASE_WORLD_CLAIM_FRACTION.name
            || name == side_table::PLUGIN_SUGGESTIONS_ENABLED.name
            || name == side_table::ROOM_THREADS_ADMIN_DELETE.name
            || name == side_table::ROOM_THREADS_ADMIN_WALK_IN.name
            || name == side_table::SNAPSHOT_READ_SETTINGS.name
            || name == side_table::UNDO_SEND_SETTING.name =>
        {
            Some(Group::Settings)
        }
        name if name == side_table::AGENT_DEF_POWER_GRANT.name => Some(Group::AgentDef),
        name if name == side_table::DREAMER_CONSOLIDATION_STRENGTH_POLICY.name => {
            Some(Group::DreamerConsolidation)
        }
        name if name == side_table::DREAMER_PROJECTOR_POLICY.name => Some(Group::DreamerWake),
        name if name == side_table::LLM_DESCRIPTION_POLICY.name => Some(Group::Llm),
        name if name == side_table::PORTS_DEPENDENT_WALK_POLICY.name => Some(Group::Ports),
        name if name == side_table::HOUSEKEEPING_WAKE.name => Some(Group::HousekeepingWake),
        name if name == side_table::AUTHORITY_WITHDRAWN_GRANT.name => Some(Group::WithdrawnGrant),
        _ => None,
    }
}

/// Lands one staged group in input order, without starting any workflow or refreshing caches.
pub(crate) fn land_archived_side_group_in_txn(
    group: ArchivedSideGroup,
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    rows: &[ArchiveRetainedSideRow],
) -> Result<Vec<ArchivedSideRowOutcome>> {
    match group {
        ArchivedSideGroup::Settings => {
            crate::settings::archive_restore::land_archived_settings_rows_in_txn(
                vault, txn, permit, rows,
            )
        }
        ArchivedSideGroup::AgentDef => {
            crate::agent_def::archive_restore::land_archived_agent_def_rows_in_txn(
                vault, txn, permit, rows,
            )
        }
        ArchivedSideGroup::DreamerConsolidation => {
            crate::dreamer_consolidation::strength::land_archived_dreamer_consolidation_rows_in_txn(
                vault, txn, permit, rows,
            )
        }
        ArchivedSideGroup::DreamerWake => {
            crate::dreamer_wake::archive_restore::land_archived_dreamer_wake_rows_in_txn(
                vault, txn, permit, rows,
            )
        }
        ArchivedSideGroup::Llm => {
            crate::llm::archive_restore::land_archived_llm_rows_in_txn(vault, txn, permit, rows)
        }
        ArchivedSideGroup::Ports => {
            crate::ports::land_archived_ports_rows_in_txn(vault, txn, permit, rows)
        }
        ArchivedSideGroup::HousekeepingWake => {
            crate::store::housekeeping_wake::land_archived_housekeeping_wake_rows_in_txn(
                vault, txn, permit, rows,
            )
        }
        ArchivedSideGroup::WithdrawnGrant => {
            crate::authority::land_archived_withdrawn_grant_rows_in_txn(vault, txn, permit, rows)
        }
    }
}

/// Decodes canonical source bytes with the owning table before the existing credential check.
pub(crate) fn decode_archived_row<K: SideKey, V, C: SideCodec<V>>(
    table: &SideTable<K, V, C>,
    row: &ArchiveRetainedSideRow,
) -> std::result::Result<(K, V), RetainedSideHeldBackReason> {
    use RetainedSideHeldBackReason::{Credential, InvalidEncoding};
    if row.source_table != table.decl().name {
        return Err(InvalidEncoding);
    }
    let key = K::decode_key(&row.source_key).ok_or(InvalidEncoding)?;
    let mut encoded_key = Vec::new();
    key.encode_into(&mut encoded_key);
    if encoded_key != row.source_key {
        return Err(InvalidEncoding);
    }
    let value = table
        .decode_value(&row.source_value)
        .map_err(|_| InvalidEncoding)?;
    if table.encode_value(&value).map_err(|_| InvalidEncoding)? != row.source_value {
        return Err(InvalidEncoding);
    }
    let envelope = SideRowBytes {
        family: ArchiveSideFamily::RetainedSideRow,
        key: super::archive_retained_side_rows::retained_side_row_key(row).to_vec(),
        value: <Named as SideCodec<ArchiveRetainedSideRow>>::encode(row)
            .map_err(|_| InvalidEncoding)?,
        owner: None,
        carriers: Vec::new(),
    };
    if retained_side_row_withholds_credential(&envelope) {
        return Err(Credential);
    }
    Ok((key, value))
}

/// Stores a validated row only at an absent physical key, preserving every different live row.
pub(crate) fn install_archived_row<K: SideKey, V, C: SideCodec<V>>(
    table: &SideTable<K, V, C>,
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    key: &K,
    row: &ArchiveRetainedSideRow,
) -> Result<ArchivedSideRowOutcome> {
    match table.get_bytes(vault, txn, key)? {
        Some(stored) if stored == row.source_value => Ok(ArchivedSideRowOutcome::Unchanged),
        Some(_) => Ok(ArchivedSideRowOutcome::KeptLive),
        None => {
            match table.put_archived_as_stored_in_txn(vault, txn, permit, key, &row.source_value) {
                Ok(()) => Ok(ArchivedSideRowOutcome::Installed),
                Err(Error::Store(StoreError::SideTableRow { .. })) => Ok(
                    ArchivedSideRowOutcome::HeldBack(RetainedSideHeldBackReason::InvalidEncoding),
                ),
                Err(error) => Err(error),
            }
        }
    }
}
