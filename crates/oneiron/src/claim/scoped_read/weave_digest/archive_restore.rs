//! Owner-only archive landing for digest schedules, owner settings and change history.
//! Restored schedules start at the next cadence boundary, never a missed period.

use super::WeaveDigestReader;
use super::settings::{CHANGES, SCHEDULES, SETTINGS, WeaveDigestSettingChangeStatus as Status};
use super::wire::WireSchedule;
use crate::batch::export::archive_side_install::{
    ArchivedSideRowOutcome, decode_archived_row, install_archived_row,
    install_archived_row_with_rewrite,
};
use crate::batch::export::{
    ArchiveRetainedSideRow, OwnerArchiveRestorePermit, RetainedSideHeldBackReason,
};
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON};
use crate::side_table;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

impl Vault {
    /// Lands one outcome per input row without rendering, saving a digest or issuing a notice.
    pub(crate) fn land_archived_weave_digest_rows_in_txn(
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        permit: &OwnerArchiveRestorePermit,
        rows: &[ArchiveRetainedSideRow],
    ) -> Result<Vec<ArchivedSideRowOutcome>> {
        let mut outcomes = Vec::with_capacity(rows.len());
        for row in rows {
            let outcome = match row.source_table.as_str() {
                name if name == side_table::WEAVE_DIGEST_SCHEDULE.name => {
                    land_archived_weave_digest_schedule_row_in_txn(vault, txn, permit, row)?
                }
                name if name == side_table::WEAVE_DIGEST_SETTINGS.name => {
                    land_archived_weave_digest_settings_row_in_txn(vault, txn, permit, row)?
                }
                name if name == side_table::WEAVE_DIGEST_SETTING_CHANGE.name => {
                    land_archived_weave_digest_setting_change_row_in_txn(vault, txn, permit, row)?
                }
                _ => ArchivedSideRowOutcome::HeldBack(RetainedSideHeldBackReason::InvalidEncoding),
            };
            outcomes.push(outcome);
        }
        Ok(outcomes)
    }
}

fn land_archived_weave_digest_schedule_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    row: &ArchiveRetainedSideRow,
) -> Result<ArchivedSideRowOutcome> {
    use RetainedSideHeldBackReason::{
        InvalidEncoding, InvalidValue, MissingLiveEntity, WrongEntityKind,
    };
    let (key, bytes) = match decode_archived_row(&SCHEDULES, row) {
        Ok(decoded) => decoded,
        Err(reason) => return Ok(ArchivedSideRowOutcome::HeldBack(reason)),
    };
    let wire = match serde_json::from_slice::<WireSchedule>(&bytes) {
        Ok(wire) => wire,
        Err(_) => return Ok(ArchivedSideRowOutcome::HeldBack(InvalidEncoding)),
    };
    let (reader, role) = match key.0[0] {
        b'p' => (WeaveDigestReader::Person(key.1), "person"),
        b'o' => (WeaveDigestReader::Owner(key.1), "owner"),
        b'a' => (WeaveDigestReader::Agent(key.1), "agent"),
        _ => return Ok(ArchivedSideRowOutcome::HeldBack(InvalidValue)),
    };
    match live_entity_row_in_txn(&vault.store, txn, &key.1)? {
        LiveEntityRow::Absent | LiveEntityRow::DeletedShell => {
            return Ok(ArchivedSideRowOutcome::HeldBack(MissingLiveEntity));
        }
        LiveEntityRow::Live { entity_type, .. } => {
            let allowed = entity_type == ENTITY_TYPE_PERSON
                || (role == "agent" && entity_type == ENTITY_TYPE_AGENT_DEF);
            if !allowed {
                return Ok(ArchivedSideRowOutcome::HeldBack(if role == "owner" {
                    MissingLiveEntity
                } else {
                    WrongEntityKind
                }));
            }
        }
    }
    if role == "owner" && !live_owner_in_txn(vault, txn, &key.1)? {
        return Ok(ArchivedSideRowOutcome::HeldBack(MissingLiveEntity));
    }
    let now = vault.store.clock.now_recorded_at();
    let next_due_at = if wire.next_due_at <= now {
        match wire.next_boundary_after(now) {
            Ok(next) => Some(next),
            Err(_) => return Ok(ArchivedSideRowOutcome::HeldBack(InvalidValue)),
        }
    } else {
        None
    };
    let clear_hold = wire.held_until.is_some() || wire.held_because.is_some();
    let mut schedule = match wire.into_row(reader) {
        Ok(schedule) => schedule,
        Err(_) => return Ok(ArchivedSideRowOutcome::HeldBack(InvalidEncoding)),
    };
    let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
    if schedule.recipe.is_empty()
        || super::super::weave_report::validate_weave_recipe_for(
            &policy,
            role,
            key.1,
            &schedule.recipe,
        )
        .is_err()
    {
        return Ok(ArchivedSideRowOutcome::HeldBack(InvalidValue));
    }
    if next_due_at.is_none() && !clear_hold {
        return install_archived_row(&SCHEDULES, vault, txn, permit, &key, row);
    }
    if let Some(next) = next_due_at {
        schedule.next_due_at = next;
    }
    // The writer's conversion clears both timer holds and preserves the recipe and cadence.
    let rewritten = match serde_json::to_vec(&WireSchedule::from_row(&schedule)) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(ArchivedSideRowOutcome::HeldBack(InvalidEncoding)),
    };
    install_archived_row_with_rewrite(&SCHEDULES, vault, txn, permit, &key, row, &rewritten)
}

fn land_archived_weave_digest_settings_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    row: &ArchiveRetainedSideRow,
) -> Result<ArchivedSideRowOutcome> {
    let (key, _) = match decode_archived_row(&SETTINGS, row) {
        Ok(decoded) => decoded,
        Err(reason) => return Ok(ArchivedSideRowOutcome::HeldBack(reason)),
    };
    if !live_owner_in_txn(vault, txn, &key)? {
        return Ok(ArchivedSideRowOutcome::HeldBack(
            RetainedSideHeldBackReason::MissingLiveEntity,
        ));
    }
    install_archived_row(&SETTINGS, vault, txn, permit, &key, row)
}

fn land_archived_weave_digest_setting_change_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    row: &ArchiveRetainedSideRow,
) -> Result<ArchivedSideRowOutcome> {
    use RetainedSideHeldBackReason::{InvalidEncoding, InvalidValue, MissingLiveEntity};
    let (key, value) = match decode_archived_row(&CHANGES, row) {
        Ok(decoded) => decoded,
        Err(reason) => return Ok(ArchivedSideRowOutcome::HeldBack(reason)),
    };
    if value.change_ref != key.1.to_hex() {
        return Ok(ArchivedSideRowOutcome::HeldBack(InvalidEncoding));
    }
    let has_after = matches!(
        value.status,
        Status::Applied | Status::Accepted | Status::Undone
    );
    let is_undone = value.status == Status::Undone;
    if EntityId::from_hex(&value.coach_ref).is_err()
        || value
            .grant_ref
            .as_ref()
            .is_some_and(|id| EntityId::from_hex(id).is_err())
        || value.after_generation.is_some() != has_after
        || value.undone_generation.is_some() != is_undone
        || value.settled_at.is_some() != (value.status != Status::Pending)
        || (value.grant_ref.is_some() && !matches!(value.status, Status::Applied | Status::Undone))
    {
        return Ok(ArchivedSideRowOutcome::HeldBack(InvalidValue));
    }
    if !live_owner_in_txn(vault, txn, &key.0)? {
        return Ok(ArchivedSideRowOutcome::HeldBack(MissingLiveEntity));
    }
    install_archived_row(&CHANGES, vault, txn, permit, &key, row)
}

/// Settings keys name a live PERSON with owner standing on this vault, never mere provenance.
fn live_owner_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, owner: &EntityId) -> Result<bool> {
    if !matches!(
        live_entity_row_in_txn(&vault.store, txn, owner)?,
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_PERSON,
            ..
        }
    ) {
        return Ok(false);
    }
    crate::policy_model::is_live_vault_owner_in_txn(vault, txn, owner)
}
