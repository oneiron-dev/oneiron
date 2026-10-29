use uuid::Uuid;

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::HexId;
use crate::store::GateDecisionRecord;
use crate::store::legal_hold::HoldActor;

use super::super::erase::{ProvenanceCapture, sweep_extras};
use super::super::gate::{
    GatedDeletion, claim_in_txn, reverify_deletion_authority_when_unpublished,
    revoke_guest_grants_in_txn,
};
use super::super::receipt::{RedactionReceiptInput, RedactionScope};
use super::super::tombstone::{DeleteReason, HARD_DELETE_MARKER, TombstoneValueV2};
use super::super::topology_delete_intent::{
    TopologyDeletePhase, clear_own_topology_delete_in_txn, reserve_topology_delete_in_txn,
};
use super::{DeleteEntityOutcome, PendingConfirmedErase};

impl Vault {
    /// Purges the active store in one transaction, then writes the hard
    /// delete's receipt and sweep row and publishes what it owes.
    pub(super) fn delete_receipt_phase(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        gate: &Option<GatedDeletion<'_>>,
        allow_replay_test: bool,
        due: Option<&PendingConfirmedErase>,
        requested_at: u64,
        header: EntityMetadataHeader,
        request_uuid: Uuid,
        tombstone: TombstoneValueV2,
        gate_decision: &Option<GateDecisionRecord>,
        turn_program_details: &[String],
        window_label: &str,
        captured: &ProvenanceCapture,
        crdt_persisted: bool,
        authority_settled: bool,
        soft_complete_at: u64,
    ) -> Result<DeleteEntityOutcome> {
        let receipt_id = self.store.clock.entity_id()?;
        let mut scope = RedactionScope::entity(id);
        let mut wtxn = self.store.env.write_txn()?;
        self.require_room_delete_gate(&wtxn, id, gate.as_ref(), allow_replay_test)?;
        // The purge txn: the one that actually tears. It re-checks authority
        // ONLY if nothing has settled this delete yet — i.e. no publish commit
        // AND no earlier destructive commit of this call (fix-leg 8). On
        // `user_hard_delete` with no publish, THIS is the first destructive
        // transaction, so the check lands here and is atomic with the tear, the
        // `dt:` marker, the `pt:` propagation intent, the gate record and the
        // receipt — a revoked owner leaves none of them.
        //
        // Once something HAS settled it, no re-check: fix-5 put an
        // unconditional re-fold here, which made a revocation racing the
        // interval publish→purge produce the rejected-call-publishes shape —
        // FORBIDDEN to the caller with the tombstone already on the wire and
        // peers tearing.
        reverify_deletion_authority_when_unpublished(gate.as_ref(), authority_settled, &wtxn)?;
        // A due confirmed erase nothing has published re-proves here that it
        // still waits, before any marker, scrub or purge (FIX 6337).
        let requester = due
            .map(|due| due.prove_when_unpublished(self, &wtxn, id, authority_settled))
            .transpose()?;
        self.reject_erase_hold_in_txn(&wtxn, id, requester.as_ref())?;
        crate::world_keys::reject_held_pad_world_as_in_txn(
            &self.store,
            &wtxn,
            &[*id],
            requester.as_ref().unwrap_or(&HoldActor::UNATTRIBUTED),
        )?;
        if !authority_settled {
            self.guard_active_merge_hard_delete_in_txn(&wtxn, id)?;
        }
        // A purge nothing published or scrubbed before ends a Connect
        // guest's pacts itself (FIX 3875); otherwise they are gone already.
        revoke_guest_grants_in_txn(self, gate.as_ref(), &mut wtxn, id)?;
        reserve_topology_delete_in_txn(
            &self.store,
            &mut wtxn,
            id,
            &tombstone,
            header.learned_at,
            TopologyDeletePhase::Committed,
        )?;
        let marker_key = HexId(*id);
        // ONE-1149 ownership claim: probe the FULL delete scope INSIDE the
        // erasing txn. LMDB's single writer makes this race-free — if the
        // probe sees state, this txn's purge erases it; if a concurrent
        // delete raced everything away first, this delete must not claim it
        // erased anything (no receipt, no sweep row). Mirrors the
        // receiver-side `apply_replayed_tombstone` nothing-local branch:
        // ONLY the durable `dt:` marker is written (hard-once-seen — the
        // CRDT tombstone above is already published, so the id IS
        // hard-deleted), guarded so an existing marker is never overwritten,
        // and the actor sweep runs, as there.
        if !self.active_delete_scope_exists_in_txn(&wtxn, id)? {
            crate::claim::invalidate_weave_digest_source_in_txn(&self.store, &mut wtxn, id)?;
            if !HARD_DELETE_MARKER.contains(&self.store, &wtxn, &marker_key)? {
                HARD_DELETE_MARKER.put(
                    &self.store,
                    &mut wtxn,
                    &marker_key,
                    &tombstone.encode().to_vec(),
                )?;
            }
            // An actor with no id-local state may still be named in the rows
            // that record it (its turn programs among them), so the purge's
            // actor sweep runs here too, marker or not (FIX 5737). Its code
            // runs' replies retire first, as the provenance door's erase
            // retires them, read before the sweep releases them (FIX 5718).
            #[cfg(unix)]
            crate::code_run::retire_actor_responses_in_txn(&self.store, &mut wtxn, id)?;
            // So do the responses its stamps named, as the provenance
            // door retires them (KS-2B1, KS-2B2, FIX 6530).
            #[cfg(unix)]
            {
                crate::llm::erase_step_state_owner_in_txn(&self.store, &mut wtxn, id)?;
                crate::store::erase_sync_response_owner_in_txn(&self.store, &mut wtxn, id)?;
                crate::store::erase_response_owner_in_txn(&self.store, &mut wtxn, id)?;
            }
            crate::deletion::actor_fields::erase_actor_fields_in_txn(self, &mut wtxn, id)?;
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
            // No id-local purge scope remains (the actor sweep above may still
            // have scrubbed rows naming this id), and there is no cfg-off pt:
            // marker. A published tombstone is durable; an unpublished commit
            // with no purge carries no deletion intent to hold an interlock for.
            clear_own_topology_delete_in_txn(
                &self.store,
                &mut wtxn,
                id,
                &tombstone.request_id,
                false,
            )?;
            self.reconcile_identity_topology_after_delete_in_txn(&mut wtxn, id)?;
            wtxn.commit()?;
            return Ok(DeleteEntityOutcome {
                existed: false,
                receipt_id: None,
                sweep_key: None,
                turn_program_details: turn_program_details.to_vec(),
            });
        }
        // ONE-1122 `dt:` local hard-delete marker: the permanent local truth
        // the Observer-B materialization gate consults when a crafted update
        // REMOVES the CRDT tombstone (nothing else id-keyed survives a hard
        // delete locally — the receipt id is fresh, h: is seq-keyed, pt: is
        // cleared after replay). Written in the SAME txn as the active-store
        // purge. PRESENCE-ONLY for gates; the 25 B value body (the tombstone
        // wire bytes) is informational. Un-cfg'd on every build: `sync_state`
        // is unconditional and the marker is local delete truth, not
        // sync-only state (ONE-1132 cfg-off durability).
        HARD_DELETE_MARKER.put(
            &self.store,
            &mut wtxn,
            &marker_key,
            &tombstone.encode().to_vec(),
        )?;
        // ARCH-0055 §9 (r6): HardErase walks redirects. BEFORE the purge —
        // it deletes the head's incident shell edges, which are the walk's
        // primary witness — and in this same transaction, so a head can
        // never be erased while a shell of it stays readable.
        let mut affected = self.hard_delete_affected_ids_in_txn(&wtxn, id)?;
        let (cascaded_shells, changed_documents) =
            self.cascade_hard_erase_to_redirect_shells_in_txn(&mut wtxn, id)?;
        affected.extend(changed_documents);
        // The shells' historical carriers ride THIS erasure's sweep row:
        // clearing the active store while history keeps the bytes would
        // erase nothing.
        scope
            .entity_ids
            .extend(cascaded_shells.iter().map(EntityId::to_hex));
        // The erased world's pad tombstones publish once this commits
        // (FIX 343); their windows are read before the purge erases the pads.
        let mut pad_windows = self.world_pad_windows_in_txn(&wtxn, id)?;
        // A classified corrupt CLAIM's world does not read: its tombstone goes
        // to its month's world windows too, published with these (FIX 7800).
        pad_windows.extend(self.stage_corrupt_world_tombstones_in_txn(
            &mut wtxn,
            id,
            window_label,
            &tombstone,
        )?);
        let (existed, citing) = self.purge_entity_active_store_in_txn(
            &mut wtxn,
            id,
            Some(&tombstone.request_id),
            true,
        )?;
        affected.extend(citing);

        // ARCH-0038 DELETE: "The derived edge flag follows the Claim" — the
        // subject edge is refreshed in the SAME transaction as the purge.
        // Gated on `existed` (the entity record was erased by THIS txn): a
        // captured Claim whose record was raced away was already refreshed
        // by the racer's own delete txn.
        if existed && let Some(captured) = captured.refs() {
            affected.extend(self.refresh_subject_edge_after_claim_delete_in_txn(
                &mut wtxn,
                id,
                &captured.subject,
            )?);
        }
        if existed && let Some(corrupt) = captured.corrupt() {
            affected.extend(self.scrub_corrupt_capture_in_txn(&mut wtxn, corrupt, false)?);
        }

        // OWNER-DECISION (cfg-off durability): the pending-tombstone marker
        // rides the SAME txn as the active-store purge — on every build.
        //
        // On the non-publishing gdpr/policy arm the scrub txn above already
        // committed this exact key and value (fix-leg 9), so this is an
        // idempotent re-put, not a second intent: `pt:` is keyed by window +
        // entity and the value is this delete's own 25 B tombstone. Every other
        // shape (publishing arms, `user_hard_delete`, a scrub that found
        // nothing) reaches here with no marker on disk and writes the first one.
        self.put_pending_tombstone_in_txn(&mut wtxn, window_label, id, &tombstone)?;
        if window_label.contains('@') {
            self.store.sync_state.put(
                &mut wtxn,
                &format!("m:dw:{}", id.to_hex()),
                window_label.as_bytes(),
            )?;
        }
        self.append_deletion_gate_decision_in_purge_txn(
            &mut wtxn,
            crdt_persisted,
            gate_decision.as_ref(),
            id,
            tombstone.reason,
        )?;

        let hard_purge_complete_at = self.store.clock.now_recorded_at();
        let sweep_key = self.write_redaction_receipt_and_sweep_in_txn(
            &mut wtxn,
            &receipt_id,
            RedactionReceiptInput {
                actor_principal: gate
                    .as_ref()
                    .map(super::super::gate::GatedDeletion::actor_principal),
                room_authority: gate
                    .as_ref()
                    .and_then(super::super::gate::GatedDeletion::room_authority),
                request_id: request_uuid.to_string(),
                scope,
                reason,
                requested_at,
                soft_complete_at,
                hard_purge_complete_at,
                sweep_queued_at: reason
                    .queues_historical_sweep()
                    .then_some(hard_purge_complete_at),
            },
            sweep_extras(captured),
        )?;
        claim_in_txn(gate.as_ref(), &mut wtxn, &tombstone, Some(&receipt_id))?;
        self.reconcile_identity_topology_after_delete_in_txn(&mut wtxn, id)?;

        wtxn.commit()?;
        self.notify_local_delete_materialized(&affected);
        // The CRDT record (tombstone-first, above) is durable — the crash
        // marker has served its purpose. In non-`sync` builds the marker
        // STAYS: it is the deletion's only propagation intent until a
        // sync-enabled boot replays it.
        if crdt_persisted {
            self.finish_published_topology_delete(window_label, id, &tombstone)?;
        }
        self.publish_pad_tombstones_after_commit(&pad_windows);
        Ok(DeleteEntityOutcome {
            existed,
            receipt_id: Some(receipt_id),
            sweep_key: Some(sweep_key),
            turn_program_details: turn_program_details.to_vec(),
        })
    }
}
