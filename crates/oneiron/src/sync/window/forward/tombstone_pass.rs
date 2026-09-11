//! Tombstone pass of forward rematerialization: reason-aware replay of window tombstones.

use super::super::bridge;
use super::super::loro_support::{map_for_each_tombstone_value, map_get_bytes};
use super::super::quarantine::{self, QuarantineContainer};
use super::{RematCtx, RematLedger};

use crate::deletion::decode_tombstone_value;
use crate::entity_id::EntityId;
use crate::error::{Error, RegistryError};

/// Outcome of the tombstone pass. The error is DEFERRED past the marker
/// bookkeeping txn (Trap 2): the caller runs that txn first and only then
/// returns `deferred_error`.
pub(super) struct TombstonePassOutcome {
    pub(super) purge_failures: Vec<EntityId>,
    pub(super) cleared: Vec<EntityId>,
    pub(super) receiver_scrub_candidates: Vec<EntityId>,
    pub(super) deferred_error: Option<Error>,
}

/// Run the tombstone pass: replay each tombstone through the shared
/// primitive and collect the marker bookkeeping inputs. Returns the outcome
/// struct instead of falling through — never `?` at the call site.
pub(super) fn run(ctx: &RematCtx<'_>, ledger: &mut RematLedger) -> TombstonePassOutcome {
    let vault = ctx.vault;
    let window_key = ctx.window_key;
    let entities_map = &ctx.entities_map;
    let tombstones_map = &ctx.tombstones_map;
    let marked = &ledger.marked;
    let terminal_quarantines = &mut ledger.terminal_quarantines;
    let mut count = ledger.count;

    // Tombstones — reason-aware replay (ONE-1133 / ARCH-0038): the VALUE
    // decides the effect, routed through the shared primitive, never a
    // bare purge. Known-soft `user_delete` keeps the 25 B shell (SoftErase
    // + D16 refresh); every other shape hard-purges and — when local state
    // was erased — writes the LOCAL REDACTION_AUDIT receipt and `h:` sweep
    // row. The tombstone-aware iterator visits EVERY value: a non-Binary
    // tombstone replays as the empty slice, which decodes HARD — a
    // malformed remote tombstone must never be skipped (it would leave the
    // entity pass's re-materialized body live forever = durable
    // resurrection). The primitive is idempotent (no receipt when nothing
    // local remains), so this every-boot pass cannot multiply receipts.
    //
    // Retry state is ENTITY-scoped (ONE-1124): `rm:w:{window}:{entity_hex}`
    // is written for the specific entity whose replay failed, and cleared
    // ONLY when that entity's own replay succeeds — an unrelated
    // tombstone's success must never discharge another entity's retry.
    // (`marked` is the up-front snapshot loaded before the entity pass.)
    let mut purge_failures: Vec<EntityId> = Vec::new();
    let mut cleared: Vec<EntityId> = Vec::new();
    let mut receiver_scrub_candidates: Vec<EntityId> = Vec::new();
    let mut tombstone_error: Option<Error> = None;
    map_for_each_tombstone_value(tombstones_map, |key, value| {
        if tombstone_error.is_some() {
            return;
        }
        let id = match EntityId::from_hex(key) {
            Ok(id) => id,
            Err(_) => {
                if let Err(err) = quarantine::quarantine_rejected_op(
                    vault,
                    window_key.as_str(),
                    QuarantineContainer::Tombstones,
                    key,
                    &Error::InvalidKey,
                    value,
                ) {
                    tombstone_error = Some(err);
                }
                return;
            }
        };

        // The entity pass may have rejected or not yet materialized a
        // concurrent protected record. Its CRDT envelope is still enough
        // to deny delete authority: quarantine the tombstone before the
        // headerless replay path can mint a permanent `dt:` marker.
        if matches!(vault.read_entity_header(&id), Ok(None))
            && let Some(entity_blob) = map_get_bytes(entities_map, &id.to_hex())
            && let Some(header) = bridge::admitted_concurrent_delete_protected_header(&entity_blob)
        {
            let rejection = Error::Registry(RegistryError::MaintenanceKindNotWritable(
                header.entity_type,
            ));
            if let Err(quarantine_err) = quarantine::quarantine_rejected_op(
                vault,
                window_key.as_str(),
                QuarantineContainer::Tombstones,
                key,
                &rejection,
                value,
            ) {
                tombstone_error = Some(quarantine_err);
            } else {
                terminal_quarantines.push(id);
            }
            return;
        }

        let hard_tombstone = decode_tombstone_value(value).is_hard();
        match quarantine::apply_replayed_tombstone_for_sync(vault, &id, value) {
            Ok(outcome) => {
                if outcome.changed_local_state() {
                    count += 1;
                }
                if hard_tombstone {
                    receiver_scrub_candidates.push(id);
                }
                // The goal state for THIS tombstone's reason holds (purge
                // done, already absent, or soft shell kept) — the entity's
                // own retry marker (if flagged) is discharged.
                if marked.contains(&id.to_hex()) {
                    cleared.push(id);
                }
            }
            Err(err) if quarantine::remote_rejection_reason(&err).is_some() => {
                if let Err(quarantine_err) = quarantine::quarantine_rejected_op(
                    vault,
                    window_key.as_str(),
                    QuarantineContainer::Tombstones,
                    key,
                    &err,
                    value,
                ) {
                    tombstone_error = Some(quarantine_err);
                } else {
                    terminal_quarantines.push(id);
                }
            }
            Err(err) => {
                // Replay failure — the tombstoned content may still be
                // live. Flag THIS entity for durable retry; the pass keeps
                // going so one failure cannot starve other tombstones.
                purge_failures.push(id);
                tracing::error!(
                    entity = %id.to_hex(),
                    error = %err,
                    "forward remat: tombstone replay FAILED — hard-deleted content may still be live (GDPR SLA breach signal)"
                );
            }
        }
    });
    ledger.count = count;
    TombstonePassOutcome {
        purge_failures,
        cleared,
        receiver_scrub_candidates,
        deferred_error: tombstone_error,
    }
}
