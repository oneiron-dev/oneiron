//! Entity pass of forward rematerialization: every window entity blob through the shared
//! ingest entry, one write transaction per entity.

use super::super::loro_support::map_for_each_value_bytes_deferring;
#[cfg(any(test, feature = "test-hooks"))]
use super::super::test_hooks;
use super::{RematCtx, RematLedger};

use crate::EntityId;
use crate::error::Result;
use crate::sync::ingest::{
    EntityStep, IngestCtx, RefusalRetry, Residence, authority_parent_order,
    ingest_entity_in_savepoint, is_authority_row, note_born, waits_for_sibling_row, watches,
};
use loro::{LoroValue, ValueOrContainer};

/// Run the entity pass: iterate the window `entities` map and ingest each value through the
/// shared ingest entry in its own write transaction.
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
        // A row a federated import watches, written where none was stored, is
        // its birth once this transaction commits.
        let watched = EntityId::from_hex(key).ok().filter(|id| watches(vault, id));
        let step = match vault.with_write_txn_grouped(|wtxn| {
            let unborn = match &watched {
                Some(id) => crate::ports::EntityStoreRead::port_entity_with_raw(
                    &vault.store,
                    wtxn,
                    id,
                    |_| Ok(()),
                )?
                .is_none(),
                None => false,
            };
            let step = ingest_entity_in_savepoint(&ingest, wtxn, key, value)?;
            Ok((step, unborn))
        }) {
            Ok((step, unborn)) => {
                if unborn && let (Some(id), Some(blob)) = (step.written(), value) {
                    note_born(vault, id, blob);
                }
                step
            }
            Err(err) => {
                entity_error = Some(err);
                return;
            }
        };
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
