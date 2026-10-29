//! A project's erase takes the project off the amendment rows that carry it
//! (FIX 6038). An evidence or judgment row whose project is the erased one
//! names one fresh opaque scope instead, as the attempt receipt it came from
//! does (`learning::scope_carriers`): a later pass lands its
//! `learning.edit_cost` rows apart from the vault's and never under the
//! erased id. A row that names the project but no longer decodes is deleted.
//! The worsening notification rows that name it in their packet and their
//! event key are carried to the same fresh scope (FIX 11627); a row keeps
//! the id its old event minted, so a later escalation in the fresh scope
//! mints its own row and the carried one stays until its owner deletes it.

use super::stored::{StoredEvidence, StoredJudgment};
use super::triage::{NOTIFICATION_PRODUCER_WORSENING, TriagePacket};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::inbox::decode_notification_body;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_NOTIFICATION;
use crate::scan_check::{EngineScan, ScanCount};
use crate::side_table::{self, Raw, SideCodec, SideTable};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Amendment evidence rows, by their raw key.
const EVIDENCE_RAW: SideTable<Vec<u8>, StoredEvidence, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_AMENDMENT_EVIDENCE);

/// Amendment judgment rows, by their raw key.
const JUDGMENT_RAW: SideTable<Vec<u8>, StoredJudgment, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_AMENDMENT_JUDGMENT);

/// Re-keys the project of every amendment evidence and judgment row naming
/// erased `entity` to one fresh opaque scope. Registered on both stores; the
/// first call does both, so a judgment keeps its evidence's scope.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_amendment_project_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let named = entity.to_hex();
    let mut scope = None;
    rescope_rows_in_txn(
        vault,
        wtxn,
        EVIDENCE_RAW,
        &named,
        &mut scope,
        evidence_project,
    )?;
    rescope_rows_in_txn(
        vault,
        wtxn,
        JUDGMENT_RAW,
        &named,
        &mut scope,
        judgment_project,
    )?;
    rescope_notifications_in_txn(vault, wtxn, &named, &mut scope)
}

/// Re-keys each row of `table` whose project is `named` to the erase's
/// opaque `scope`, minted on first need.
fn rescope_rows_in_txn<V>(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    table: SideTable<Vec<u8>, V, Raw>,
    named: &str,
    scope: &mut Option<String>,
    project: fn(&mut V) -> &mut Option<String>,
) -> Result<()>
where
    Raw: SideCodec<V>,
{
    let rows = table
        .iter_raw_from(&vault.store, wtxn, &[])?
        .collect::<Result<Vec<_>>>()?;
    for (key, value) in rows {
        if !value
            .windows(named.len())
            .any(|window| window == named.as_bytes())
        {
            continue;
        }
        match table.decode_value(&value) {
            Ok(mut row) => {
                let stamp = project(&mut row);
                if stamp.as_deref() != Some(named) {
                    continue;
                }
                if scope.is_none() {
                    *scope = Some(vault.store.clock.entity_id()?.to_hex());
                }
                stamp.clone_from(scope);
                table.put(&vault.store, wtxn, &key, &row)?;
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    table = table.decl().name,
                    "an amendment row that no longer decodes is deleted"
                );
                table.delete(&vault.store, wtxn, &key)?;
            }
        }
    }
    Ok(())
}

fn evidence_project(row: &mut StoredEvidence) -> &mut Option<String> {
    &mut row.project
}

fn judgment_project(row: &mut StoredJudgment) -> &mut Option<String> {
    &mut row.project
}

/// Re-keys every live worsening escalation whose packet names `named` to the
/// erase's opaque `scope`: the packet's project and the project segment of
/// the event its row keyed on. A worsening packet that no longer decodes is
/// left as it stands: packets written before they carried a project name
/// none, and a corrupt packet is already unreadable everywhere else.
fn rescope_notifications_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    named: &str,
    scope: &mut Option<String>,
) -> Result<()> {
    let mut count = ScanCount::start(
        &vault.store,
        &*wtxn,
        EngineScan::TypeIndexRows,
        &[ENTITY_TYPE_NOTIFICATION],
    )?;
    let mut ids = Vec::new();
    for entry in vault
        .store
        .port_entity_ids_by_type(&*wtxn, ENTITY_TYPE_NOTIFICATION, None)?
    {
        count.row();
        ids.push(entry?);
    }
    count.finish(vault);
    for id in ids {
        let LiveEntityRow::Live { entity_type, body } =
            live_entity_row_in_txn(&vault.store, &*wtxn, &id)?
        else {
            continue;
        };
        if entity_type != ENTITY_TYPE_NOTIFICATION {
            continue;
        }
        let mut body = decode_notification_body(&body)?;
        if body.source.producer != NOTIFICATION_PRODUCER_WORSENING {
            continue;
        }
        let Some(detail) = body.source.detail.as_deref() else {
            continue;
        };
        let Ok(mut packet) = serde_json::from_str::<TriagePacket>(detail) else {
            continue;
        };
        if packet.project.as_deref() != Some(named) {
            continue;
        }
        let fresh = match scope {
            Some(fresh) => fresh.clone(),
            None => {
                let fresh = vault.store.clock.entity_id()?.to_hex();
                *scope = Some(fresh.clone());
                fresh
            }
        };
        packet.project = Some(fresh.clone());
        body.source.detail = Some(
            serde_json::to_string(&packet)
                .map_err(|_| Error::InvariantViolation("triage packet encode"))?,
        );
        let segments: Vec<&str> = body.source.event.splitn(5, ':').collect();
        if segments.len() == 5 && segments[3] == named {
            body.source.event = format!(
                "{}:{}:{}:{fresh}:{}",
                segments[0], segments[1], segments[2], segments[4]
            );
        }
        vault.put_notification_in_txn(wtxn, &id, &body)?;
    }
    Ok(())
}
