//! Forward rematerialization of window state into the CRDT doc.
//!
//! The orchestrator below pins the pass order (snapshot markers, entities,
//! edges, tombstones, settle); the three passes live in the child modules.

mod edge_pass;
mod entity_pass;
mod tombstone_pass;

use std::collections::HashSet;

use super::bridge::Materializer;
use super::quarantine;
use super::queue::scrub_receiver_outbox_on_remote_hard_delete_in_txn;
use super::types::WindowKey;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use loro::{LoroDoc, LoroMap};

/// Shared read-only context for the rematerialization passes.
struct RematCtx<'a> {
    vault: &'a Vault,
    doc: &'a LoroDoc,
    window_key: &'a WindowKey,
    lease_vault_id: u64,
    entities_map: LoroMap,
    edges_map: LoroMap,
    tombstones_map: LoroMap,
}

/// Cross-pass mutable ledgers: the `marked` snapshot plus the accumulators
/// every pass reads or extends.
struct RematLedger {
    marked: HashSet<String>,
    healed: Vec<EntityId>,
    terminal_quarantines: Vec<EntityId>,
    pending_subject_model_dependencies: HashSet<EntityId>,
    count: u32,
}

pub fn forward_rematerialize(
    vault: &Vault,
    doc: &LoroDoc,
    materializer: &Materializer,
    window_key: &WindowKey,
) -> Result<u32> {
    let _guard = materializer.lock();
    let lease_vault_id = materializer.lease_vault_id();
    let entities_map = doc.get_map("entities");
    let edges_map = doc.get_map("edges");
    let tombstones_map = doc.get_map("tombstones");

    // Entity-scoped retry markers pending for this window, loaded up front:
    // the entity/edge passes discharge a marker only via an actual healing
    // write (ONE-1147); the tombstone pass only via that entity's own
    // replay success (ONE-1124). Malformed marker rows never match a
    // canonical `to_hex()` and so are never discharged here (fail closed).
    let marked: HashSet<String> = quarantine::pending_remat_entities(vault, window_key.as_str())?
        .into_iter()
        .collect();
    let ctx = RematCtx {
        vault,
        doc,
        window_key,
        lease_vault_id,
        entities_map,
        edges_map,
        tombstones_map,
    };
    let mut ledger = RematLedger {
        marked,
        healed: Vec::new(),
        terminal_quarantines: Vec::new(),
        pending_subject_model_dependencies: HashSet::new(),
        count: 0u32,
    };

    // Pass order is pinned: entities (with companion cleanup), edges,
    // tombstones, then the marker settle below. The tombstone call has no
    // `?`: its error stays deferred past the marker txn (Trap 2).
    entity_pass::run(&ctx, &mut ledger)?;
    edge_pass::run(&ctx, &mut ledger)?;
    let tombstone_outcome = tombstone_pass::run(&ctx, &mut ledger);

    // An edge outcome is not proof that its source claim's missing actor or
    // subject arrived. Keep that replay pending; a successful tombstone purge may
    // still discharge it through `cleared`, with delete-safety precedence.
    ledger
        .healed
        .retain(|id| !ledger.pending_subject_model_dependencies.contains(id));
    ledger
        .terminal_quarantines
        .retain(|id| !ledger.pending_subject_model_dependencies.contains(id));
    if !tombstone_outcome.purge_failures.is_empty()
        || !tombstone_outcome.cleared.is_empty()
        || !ledger.healed.is_empty()
        || !ledger.terminal_quarantines.is_empty()
        || !tombstone_outcome.receiver_scrub_candidates.is_empty()
    {
        let marker_result = vault.with_write_txn(|wtxn| {
            // Clear BEFORE set so set wins: an id that both succeeded and
            // failed in one pass (case-shifted tombstone aliases with
            // divergent reasons) must KEEP its marker — losing it would
            // silently drop a pending hard purge (fail closed). The
            // ONE-1147 `healed` discharges (entity/edge healing writes,
            // structurally disjoint from tombstoned ids — both passes are
            // tombstone-gated). ONE-1167 terminal quarantine may discharge
            // only replay/quarantine-origin markers whose provenance sidecar
            // already proves they are not delete-safety retries; legacy or
            // purge-failure markers stay pending until their own tombstone
            // goal state holds.
            let mut success_seen = HashSet::new();
            // Delete-safety invariant: the `cleared` side has this entity's
            // own tombstone goal state above, while the `healed` side is
            // safe only because tombstone-gating keeps entity/edge healing
            // disjoint from unproven delete-safety `rm:` markers. A
            // tombstoned id cannot reach `healed`; if a refactor weakens
            // that gate or reorders this bookkeeping, the debug assert below
            // catches the healed-clear regression before an unproven purge
            // retry can be silently discharged.
            #[cfg(debug_assertions)]
            for id in &ledger.healed {
                let has_unproven_marker = quarantine::unproven_remat_marker_exists_in_txn(
                    vault,
                    wtxn,
                    window_key.as_str(),
                    id,
                )
                .unwrap_or_else(|err| {
                    panic!("delete-safety invariant: failed to read rm: marker state: {err}")
                });
                debug_assert!(
                    !has_unproven_marker,
                    "delete-safety invariant: healed ids must be disjoint from unproven rm: markers"
                );
            }
            for id in ledger.healed.iter().chain(tombstone_outcome.cleared.iter()) {
                if !success_seen.insert(*id) {
                    continue;
                }
                quarantine::clear_remat_marker_in_txn(vault, wtxn, window_key.as_str(), id)?;
            }
            let mut terminal_seen = HashSet::new();
            for id in &ledger.terminal_quarantines {
                if !terminal_seen.insert(*id) {
                    continue;
                }
                let cleared = quarantine::clear_replay_remat_marker_in_txn(
                    vault,
                    wtxn,
                    window_key.as_str(),
                    id,
                )?;
                if !cleared {
                    tracing::debug!(
                        entity = %id.to_hex(),
                        window = %window_key,
                        "forward remat: terminal quarantine left unproven rm: marker pending"
                    );
                }
            }
            // Delete-safety invariant: `purge_failures` MUST be applied LAST,
            // after healed/cleared clears and terminal-quarantine clears.
            // Tombstone/delete-safety dominance requires a failed purge to win
            // over every clear in this txn: a terminal quarantine may remove
            // replay provenance for non-delete markers, but a simultaneous
            // purge failure must restore the unproven `rm:` retry so the
            // delete-safety provenance is not silently removed.
            for id in &tombstone_outcome.purge_failures {
                quarantine::set_remat_marker_in_txn(vault, wtxn, window_key.as_str(), id)?;
            }
            if !tombstone_outcome.receiver_scrub_candidates.is_empty() {
                scrub_receiver_outbox_on_remote_hard_delete_in_txn(
                    vault,
                    wtxn,
                    window_key.as_str(),
                )?;
            }
            Ok(())
        });
        match marker_result {
            Err(err) if tombstone_outcome.receiver_scrub_candidates.is_empty() => return Err(err),
            Err(err) => {
                tracing::error!(
                    window = %window_key,
                    purge_failures = tombstone_outcome.purge_failures.len(),
                    receiver_scrub_candidates = tombstone_outcome.receiver_scrub_candidates.len(),
                    error = %err,
                    "forward remat: receiver outbox scrub/bookkeeping txn FAILED after hard tombstone replay; flagging entity-scoped rm: markers for durable retry"
                );
                vault.with_write_txn(|wtxn| {
                    for id in tombstone_outcome
                        .purge_failures
                        .iter()
                        .chain(tombstone_outcome.receiver_scrub_candidates.iter())
                    {
                        quarantine::set_remat_marker_in_txn(vault, wtxn, window_key.as_str(), id)?;
                    }
                    Ok(())
                })?;
            }
            Ok(()) => {}
        }
    }
    if let Some(err) = tombstone_outcome.deferred_error {
        return Err(err);
    }
    if quarantine::pending_remat_windows(vault)?
        .iter()
        .any(|window| window == window_key.as_str())
    {
        // Markers survive the pass when a purge failed above, when a
        // flagged entity has neither a healing write nor a proven non-delete
        // terminal x: row in the loaded doc (stale/cross-window state), or
        // when a marker row no longer parses. Clearing any of them here
        // would vacuously discharge a GDPR retry — keep them (fail closed)
        // and keep ERROR-grade visibility.
        tracing::error!(
            window = %window_key,
            "forward remat: rm: markers still pending after tombstone pass — hard-deleted content may be live (GDPR SLA breach signal)"
        );
    }

    Ok(ledger.count)
}
