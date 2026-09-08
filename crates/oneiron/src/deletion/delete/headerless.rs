//! Headerless-residue delete leg: scope probe, tombstone publish, purge, and conditional receipt.

use uuid::Uuid;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::unix_seconds_now;

use super::super::gate::{GatedDeletion, reverify_deletion_authority_when_unpublished};
use super::super::receipt::{RedactionReceiptInput, RedactionScope};
use super::super::rendezvous::{
    DeleteRendezvous, maybe_fail_after_tombstone_before_purge, signal_delete_rendezvous,
};
use super::super::sweep_queue::HardEraseSweepExtras;
use super::super::tombstone::{
    DeleteReason, TombstoneValueV2, local_hard_delete_key, window_label_from_timestamp,
};
use super::DeleteEntityOutcome;

impl Vault {
    pub(super) fn delete_entity_without_header(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        requested_at: u64,
        gate: Option<&GatedDeletion<'_>>,
    ) -> Result<DeleteEntityOutcome> {
        // Probe first so a fully-missing id stays a strict no-op — deleting
        // a nonexistent entity must not mint tombstones or receipts.
        {
            let rtxn = self.store.env.read_txn()?;
            if !self.active_delete_scope_exists_in_txn(&rtxn, id)? {
                return Ok(DeleteEntityOutcome::missing());
            }
        }
        // ONE-1149: the deletion request UUID is minted only AFTER the probe
        // above says there is something to erase.
        let request_uuid = Uuid::now_v7();

        // ONE-1132: headerless residue previously left NO CRDT record, so
        // the orphan id could re-sync forever. There is no `learned_at` to
        // address a window with, so the tombstone lands under
        // `WindowKey::from_timestamp(now)` — a propagation address, not a
        // truth claim.
        let tombstone = TombstoneValueV2 {
            reason: reason.into(),
            deleted_at: requested_at,
            request_id: *request_uuid.as_bytes(),
        };
        let gate_decision = gate.map(|gate| {
            gate.context
                .decision_record(*request_uuid.as_bytes(), id, reason, requested_at)
        });
        let window_label = window_label_from_timestamp(requested_at);
        let crdt_persisted =
            self.write_crdt_tombstone(id, requested_at, &tombstone, gate_decision.as_ref(), gate)?;
        #[cfg(all(test, feature = "sync"))]
        maybe_fail_after_tombstone_before_purge()?;
        #[cfg(not(all(test, feature = "sync")))]
        maybe_fail_after_tombstone_before_purge();
        // Past the linearization point on the headerless leg too.
        signal_delete_rendezvous(
            DeleteRendezvous::AfterTombstonePublish,
            id,
            gate_decision.as_ref().map(|decision| decision.decision_id),
        );

        let mut wtxn = self.store.env.write_txn()?;
        // Same conditional law on the headerless leg (fix-leg 8). When the
        // publish txn above committed it decided authority and this purge does
        // not re-decide it — the door's pre-publication guards were the scope
        // probe's read txn and that publish txn's re-fold. When NOTHING
        // published, this purge is the headerless door's only durable act and
        // therefore its linearization point: it re-proves the binding against
        // its own view, atomically with the residue tear, the `dt:` marker, the
        // `pt:` propagation intent, the gate record and the receipt.
        reverify_deletion_authority_when_unpublished(gate, crdt_persisted, &wtxn)?;
        let marker_key = local_hard_delete_key(id);
        // ONE-1149 ownership claim: re-probe the FULL delete scope INSIDE
        // the erasing txn (race-free under LMDB's single writer). The read
        // probe above gated the tombstone publish; THIS probe gates the
        // erasure audit. A concurrent delete that raced the residue away
        // between the two means this delete erased nothing: no receipt, no
        // sweep row, no `pt:` marker — only the durable `dt:` marker for
        // hard reasons (hard-once-seen; the CRDT tombstone above is already
        // published), guarded exactly like the receiver-side
        // `apply_replayed_tombstone` nothing-local branch.
        if !self.active_delete_scope_exists_in_txn(&wtxn, id)? {
            if reason.active_store_hard_purge_v1()
                && self.store.sync_state.get(&wtxn, &marker_key)?.is_none()
            {
                self.store
                    .sync_state
                    .put(&mut wtxn, &marker_key, &tombstone.encode())?;
            }
            if crdt_persisted
                && let Some(decision) = gate_decision.as_ref()
                && !self.store.discard_pending_deletion_gate_decision_in_txn(
                    &mut wtxn,
                    decision.decision_id,
                    id.as_bytes(),
                    tombstone.reason.wire_byte(),
                )?
            {
                return Err(Error::CorruptedIndex("pending deletion gate decision"));
            }
            wtxn.commit()?;
            return Ok(DeleteEntityOutcome::missing());
        }
        let existed = self.purge_entity_active_store_in_txn(&mut wtxn, id)?;
        // OWNER-DECISION (cfg-off durability): marker in the SAME purge txn.
        self.put_pending_tombstone_in_txn(&mut wtxn, &window_label, id, &tombstone)?;
        self.append_deletion_gate_decision_in_purge_txn(
            &mut wtxn,
            crdt_persisted,
            gate_decision.as_ref(),
            id,
            tombstone.reason,
        )?;
        if reason.active_store_hard_purge_v1() {
            // `dt:` local hard-delete marker (pinned: presence-only 25 B
            // `[reason:1][deleted_at:8 LE][request_id:16]` value, GLOBAL
            // lowercase key, permanent, no GC), headerless leg — in the
            // SAME txn as the purge, mirroring the receiver-side hard
            // apply. The CRDT tombstone above is mutable remote-facing
            // state; without the local marker a hostile tombstone removal
            // + re-put would resurrect this id through the
            // materialization gates.
            self.store
                .sync_state
                .put(&mut wtxn, &marker_key, &tombstone.encode())?;
        }
        if !reason.writes_receipt() {
            wtxn.commit()?;
            if crdt_persisted {
                self.clear_pending_tombstone(&window_label, id)?;
            }
            return Ok(DeleteEntityOutcome {
                existed,
                receipt_id: None,
                sweep_key: None,
            });
        }

        let receipt_id = EntityId::now();
        let hard_purge_complete_at = unix_seconds_now();
        // A headerless residue has no decodable body, so no provenance
        // capture is possible (ARCH-0038: no body ⇒ no EdgeRef to refresh,
        // no refs for the sweep scope).
        let sweep_key = self.write_redaction_receipt_and_sweep_in_txn(
            &mut wtxn,
            &receipt_id,
            RedactionReceiptInput {
                request_id: request_uuid.to_string(),
                scope: RedactionScope::entity(id),
                reason,
                requested_at,
                soft_complete_at: hard_purge_complete_at,
                hard_purge_complete_at,
                sweep_queued_at: reason
                    .queues_historical_sweep()
                    .then_some(hard_purge_complete_at),
            },
            HardEraseSweepExtras::default(),
        )?;
        wtxn.commit()?;
        if crdt_persisted {
            self.clear_pending_tombstone(&window_label, id)?;
        }
        Ok(DeleteEntityOutcome {
            existed,
            receipt_id: Some(receipt_id),
            sweep_key: Some(sweep_key),
        })
    }
}
