//! Entity pass of forward rematerialization: every window entity blob through the shared
//! ingest entry, one write transaction per entity.

use super::super::bridge::{CompanionCrdtScrub, scrub_local_only_companions_from_crdt};
use super::super::loro_support::map_for_each_value_bytes;
#[cfg(any(test, feature = "test-hooks"))]
use super::super::test_hooks;
use super::{RematCtx, RematLedger};

use crate::error::Result;
use crate::sync::ingest::{EntityStep, IngestCtx, RefusalRetry, ingest_entity_in_savepoint};

/// Run the entity pass: iterate the window `entities` map, ingest each value in its own write
/// transaction, then scrub local-only companion carriers from the document.
///
/// Every LOCAL ingest failure aborts the pass and never reaches the ledger (Trap 1).
pub(super) fn run(ctx: &RematCtx<'_>, ledger: &mut RematLedger) -> Result<()> {
    let vault = ctx.vault;
    let ingest = IngestCtx::new(
        vault,
        ctx.window_key.as_str(),
        ctx.lease_vault_id,
        &ctx.tombstones_map,
    );
    let mut entity_error = None;
    let mut companion_scrubs = Vec::new();
    map_for_each_value_bytes(&ctx.entities_map, |key, value| {
        if entity_error.is_some() {
            return;
        }
        #[cfg(any(test, feature = "test-hooks"))]
        if let Err(err) = test_hooks::run_receipt_revocation_race(vault) {
            entity_error = Some(err);
            return;
        }
        let step = match vault
            .with_write_txn(|wtxn| ingest_entity_in_savepoint(&ingest, wtxn, key, value))
        {
            Ok(step) => step,
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
                    RefusalRetry::Retry => {}
                    RefusalRetry::DependencyPending => {
                        ledger.pending_entity_dependencies.insert(id);
                    }
                }
            }
            EntityStep::LocalOnlyCompanion(id) => {
                companion_scrubs.push(CompanionCrdtScrub::new(key, id));
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
    });
    if let Some(err) = entity_error {
        return Err(err);
    }
    scrub_local_only_companions_from_crdt(ctx.doc, &companion_scrubs)
}
