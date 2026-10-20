//! Entity pass of forward rematerialization: every window entity blob through the shared
//! ingest entry, one write transaction per entity or TASK component.

use super::super::loro_support::map_for_each_value_bytes_deferring;
#[cfg(any(test, feature = "test-hooks"))]
use super::super::test_hooks;
use super::{RematCtx, RematLedger};

use crate::EntityId;
use crate::error::Result;
use crate::secret_custody::moves_custody_floor;
use crate::sync::ingest::{
    EntityStep, IngestCtx, RefusalRetry, Residence, TaskComponents, authority_parent_order,
    ingest_rows_in_savepoint, is_authority_row, note_born, note_delivered_in_txn,
    waits_for_sibling_row, watches,
};
use loro::{LoroValue, ValueOrContainer};

/// Run the entity pass: iterate the window `entities` map and ingest each value through the
/// shared ingest entry in its own write transaction, which a TASK component's rows share.
///
/// Every LOCAL ingest failure aborts the pass and never reaches the ledger (Trap 1).
pub(super) fn run(ctx: &RematCtx<'_>, ledger: &mut RematLedger) -> Result<()> {
    let vault = ctx.vault;
    let ingest = IngestCtx::new(
        vault,
        ctx.window_key.as_str(),
        ctx.lease_vault_id,
        &ctx.tombstones,
    )
    .with_residence(Residence::Forward {
        doc: ctx.doc,
        trusted: ctx.trusted.is_some(),
    });
    // FIX 5998: TASK rows whose roles change together land in one transaction
    // and one batch.
    let mut components = {
        let mut rows = Vec::new();
        ctx.entities_map.for_each(|key, value| {
            if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value {
                rows.push((key.to_owned(), bytes));
            }
        });
        let rtxn = vault.store.env.read_txn()?;
        let rows = rows.iter().map(|(key, bytes)| (key.as_str(), &bytes[..]));
        TaskComponents::find(vault, &rtxn, rows)?
    };
    let mut entity_error = None;
    let mut visit = |key: &str, value: Option<&[u8]>| {
        if entity_error.is_some() {
            return;
        }
        #[cfg(any(test, feature = "test-hooks"))]
        if let Err(err) = test_hooks::run_receipt_revocation_race(vault) {
            entity_error = Some(err);
            return;
        }
        let component = components.take(key);
        let rows: Vec<(&str, Option<&[u8]>)> = match &component {
            Some(rows) if rows.is_empty() => return,
            Some(rows) => rows
                .iter()
                .map(|(key, blob)| (key.as_str(), Some(&blob[..])))
                .collect(),
            None => vec![(key, value)],
        };
        // A row a federated import watches, written where none was stored, is
        // its birth once this transaction commits.
        let watched: Vec<_> = rows
            .iter()
            .map(|(key, _)| EntityId::from_hex(key).ok().filter(|id| watches(vault, id)))
            .collect();
        let steps = match vault.with_write_txn_grouped(|wtxn| {
            let mut unborn = Vec::with_capacity(rows.len());
            for watched in &watched {
                unborn.push(match watched {
                    Some(id) => {
                        !crate::ports::EntityStoreRead::port_entity_present(&vault.store, wtxn, id)?
                    }
                    None => false,
                });
            }
            let steps = ingest_rows_in_savepoint(&ingest, wtxn, &rows)?;
            for (&(_, value), step) in rows.iter().zip(&steps) {
                if let (Some(id), Some(blob)) = (step.written(), value) {
                    note_delivered_in_txn(vault, wtxn, id, blob)?;
                }
            }
            Ok(steps.into_iter().zip(unborn).collect::<Vec<_>>())
        }) {
            Ok(steps) => steps,
            Err(err) => {
                entity_error = Some(err);
                return;
            }
        };
        for (&(_, value), (step, unborn)) in rows.iter().zip(steps) {
            if unborn && let (Some(id), Some(blob)) = (step.written(), value) {
                note_born(vault, id, blob);
            }
            // FIX 5338: a floor this commit moved re-judges pending custody.
            if step.written().is_some() && value.is_some_and(moves_custody_floor) {
                vault.apply_pending_rebinds_after_commit();
            }
            ledger_step(ledger, step);
        }
    };
    // AUTHORITY_LOG rows land first, parents before children: a signer's
    // enrollment lands before the rows it signs, which its door would
    // otherwise hold until the next pass, and every later row judges
    // against the newest roster.
    let mut authority = Vec::new();
    ctx.entities_map.for_each(|key, value| {
        if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value
            && is_authority_row(&bytes)
        {
            authority.push((key.to_owned(), bytes));
        }
    });
    let rows: Vec<(&str, &[u8])> = authority
        .iter()
        .map(|(key, bytes)| (key.as_str(), &bytes[..]))
        .collect();
    for at in authority_parent_order(&rows) {
        visit(rows[at].0, Some(rows[at].1));
    }
    // Ask facts and project home rooms verify against a sibling row: visit them last.
    let later = waits_for_sibling_row;
    map_for_each_value_bytes_deferring(&ctx.entities_map, later, |key, value| {
        if !value.is_some_and(is_authority_row) {
            visit(key, value);
        }
    });
    if let Some(err) = entity_error {
        return Err(err);
    }
    Ok(())
}

/// What one row's step leaves in the pass's marker ledger.
fn ledger_step(ledger: &mut RematLedger, step: EntityStep) {
    if let EntityStep::Protected { id, .. } = &step {
        ledger.protected_admissions.insert(*id);
    }
    match step {
        EntityStep::Quarantine(refusal) => {
            let Some(id) = refusal.id else {
                return;
            };
            match refusal.retry {
                RefusalRetry::Terminal => ledger.terminal_quarantines.push(id),
                // Still owed: no other outcome at this id in the pass, such as a
                // refused tombstone naming it, may discharge its marker.
                RefusalRetry::Retry | RefusalRetry::DependencyPending => {
                    ledger.pending_entity_dependencies.insert(id);
                }
            }
        }
        // A marked delete-protected row already stored byte for byte: the admission
        // its marker waits for landed (observer B took a later carrier, or a pass
        // committed it and stopped before settling), so it settles as a terminal
        // refusal does, clearing only a proven replay marker.
        EntityStep::Protected { id, wrote: false } if ledger.marked.contains(&id.to_hex()) => {
            ledger.terminal_quarantines.push(id);
        }
        step => {
            if let Some(id) = step.written() {
                ledger.count += 1;
                // ONE-1147: an ACTUAL healing write discharges this entity's
                // needs-remat marker (set by a failed Observer-B batch). A
                // byte-identical skip never writes, so it never discharges.
                if ledger.marked.contains(&id.to_hex()) {
                    ledger.healed.push(id);
                }
            }
        }
    }
}
