//! Owner-permitted promotion of retained archive envelopes through their owning modules.
//! Installed drafter and merge-queue policies queue refreshes that run only after commit.

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

/// Refreshes required by newly installed policies after the import commits.
#[derive(Default)]
pub(crate) struct ArchivedSideRowRefresh {
    /// Serving hosts must observe repaired drafter bindings.
    drafter_serving: bool,
    /// Queue attempts must observe the installed review policy.
    attempt_observers: bool,
}

impl ArchivedSideRowRefresh {
    /// Records refreshes only for groups with an installed source row.
    fn record(&mut self, group: ArchivedSideGroup, outcomes: &[ArchivedSideRowOutcome]) {
        if outcomes
            .iter()
            .any(|outcome| matches!(outcome, ArchivedSideRowOutcome::Installed))
        {
            match group {
                ArchivedSideGroup::Drafter => self.drafter_serving = true,
                ArchivedSideGroup::MergeQueue => self.attempt_observers = true,
                _ => {}
            }
        }
    }

    /// Notifies policy observers after the writer and retrieval guard are released.
    pub(crate) fn after_commit(self, vault: &crate::Vault) {
        if self.drafter_serving {
            vault.notify_drafter_serving();
        }
        if self.attempt_observers {
            vault.store.notify_attempt_observers();
        }
    }
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
    /// Project history budgets.
    ProjectHistory,
    /// Message-stream defaults for new sessions.
    Memory,
    /// Dreamer action-mode policy.
    DreamerRunner,
    /// Served-origin LFS path rules.
    OriginLfs,
    /// Queue review policy.
    MergeQueue,
    /// Owner learning rows before holder rows.
    LearningSetting,
    /// Retrieval pins and local active weights.
    RetrievalPins,
    /// Drafter policy and serving binding repair.
    Drafter,
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
        name if name == side_table::PROJECT_HISTORY_POLICY.name => Some(Group::ProjectHistory),
        name if name == side_table::MESSAGE_STREAM_POLICY.name => Some(Group::Memory),
        name if name == side_table::DREAMER_ACTION_MODE_POLICY.name => Some(Group::DreamerRunner),
        name if name == side_table::ORIGIN_LFS_PATH_POLICY.name => Some(Group::OriginLfs),
        name if name == side_table::MERGE_QUEUE_REVIEW_POLICY.name => Some(Group::MergeQueue),
        name if name == side_table::LEARNING_SETTING.name => Some(Group::LearningSetting),
        name if name == side_table::RETRIEVAL_POLICY_PINS.name => Some(Group::RetrievalPins),
        name if name == side_table::DRAFTER_POLICY.name => Some(Group::Drafter),
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
    refresh: &mut ArchivedSideRowRefresh,
) -> Result<Vec<ArchivedSideRowOutcome>> {
    let outcomes = match group {
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
        ArchivedSideGroup::ProjectHistory => {
            crate::Vault::land_archived_project_history_rows_in_txn(vault, txn, permit, rows)
        }
        ArchivedSideGroup::Memory => {
            crate::memory::archive_restore::land_archived_memory_rows_in_txn(
                vault, txn, permit, rows,
            )
        }
        ArchivedSideGroup::DreamerRunner => {
            crate::dreamer_runner::archive_restore::land_archived_dreamer_runner_rows_in_txn(
                vault, txn, permit, rows,
            )
        }
        ArchivedSideGroup::OriginLfs => {
            crate::Vault::land_archived_origin_lfs_rows_in_txn(vault, txn, permit, rows)
        }
        ArchivedSideGroup::MergeQueue => {
            crate::Vault::land_archived_merge_queue_rows_in_txn(vault, txn, permit, rows)
        }
        ArchivedSideGroup::LearningSetting => {
            crate::learning_setting::land_archived_learning_setting_rows_in_txn(
                vault, txn, permit, rows,
            )
        }
        ArchivedSideGroup::RetrievalPins => {
            crate::store::Store::land_archived_retrieval_pins_rows_in_txn(vault, txn, permit, rows)
        }
        ArchivedSideGroup::Drafter => {
            crate::Vault::land_archived_drafter_rows_in_txn(vault, txn, permit, rows)
        }
    }?;
    refresh.record(group, &outcomes);
    Ok(outcomes)
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
