use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::GateDecisionRecord;

use super::super::erase::{ProvenanceCapture, stage_sweep_refs_in_txn};
use super::super::gate::{
    GatedDeletion, reverify_deletion_authority_before_publication,
    reverify_deletion_authority_when_unpublished, revoke_guest_grants_in_txn,
};
use super::super::rendezvous::{
    DeleteRendezvous, maybe_fail_after_tombstone_before_purge, signal_delete_rendezvous,
};
use super::super::tombstone::{DeleteReason, TombstoneValueV2};
use super::super::topology_delete_intent::{
    TopologyDeletePhase, clear_own_topology_delete_in_txn, reserve_topology_delete_in_txn,
};
use super::{DeleteEntityOutcome, PendingConfirmedErase};

impl Vault {
    /// Scrubs the body shell of a soft delete, publishes its tombstone, and
    /// returns its outcome; only a soft reason reaches here.
    pub(super) fn delete_soft_arm_phase(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        gate: &Option<GatedDeletion<'_>>,
        allow_replay_test: bool,
        due: Option<&PendingConfirmedErase>,
        header: EntityMetadataHeader,
        tombstone: TombstoneValueV2,
        gate_decision: &Option<GateDecisionRecord>,
        turn_program_details: &[String],
        window_label: &str,
        captured: &ProvenanceCapture,
    ) -> Result<DeleteEntityOutcome> {
            // `user_delete` keeps the local 25 B shell (ARCH-0038 "Tombstone
            // revision (empty content); keep the message shell") but now
            // writes a reason=user_delete CRDT tombstone (ONE-1090 write
            // side): a soft delete with NO cross-device record would leave
            // the deleted body live on every other device.
            let mut wtxn = self.store.env.write_txn()?;
            self.require_room_delete_gate(&wtxn, id, gate.as_ref(), allow_replay_test)?;
            // TOCTOU close: `user_delete` scrubs the body in THIS txn, so the
            // owner authority is re-proven against THIS txn's view. A
            // RevokeActor committed since the gate ran is visible here and
            // refuses before a single byte is scrubbed. PRE-publication: this
            // arm publishes its tombstone after the scrub, so the re-fold below
            // in the publish txn is the decision that binds.
            reverify_deletion_authority_before_publication(gate.as_ref(), &wtxn)?;
            // A due owner delete scrubs only while its request still waits
            // (FIX 1465): this scrub is its first destructive commit.
            if let Some(due) = due {
                due.prove_in(self, &wtxn, id)?;
            }
            // A Connect guest's PERSON leaves its pacts first (FIX 3875).
            revoke_guest_grants_in_txn(self, gate.as_ref(), &mut wtxn, id)?;
            // This scrub is the first destructive commit. The intent rides
            // the same transaction as the pt: propagation marker.
            reserve_topology_delete_in_txn(
                &self.store,
                &mut wtxn,
                id,
                &tombstone,
                header.learned_at,
                TopologyDeletePhase::Committed,
            )?;
            // A deleted world keeps its keys, pads and sealed copies, so it
            // restores from old bundles until they age out (DEC-0006); only
            // an erase destroys them (the hard arm's purge). Its delete time
            // bounds how long a pin change still rewraps them.
            let (existed, had_vector, _ledger_changed) =
                self.soft_erase_active_store_in_txn(&mut wtxn, id, false)?;
            if existed && reason == DeleteReason::UserDelete {
                crate::world_keys::note_world_deleted_in_txn(
                    &self.store,
                    &mut wtxn,
                    *id,
                    tombstone.deleted_at,
                )?;
            }
            if had_vector {
                crate::hnsw::increment_vector_version(&self.store, &mut wtxn)?;
            }
            let mut changed = vec![*id];
            // D16: SoftErase tombstones the Claim, and "the derived edge
            // flag follows the Claim" — refresh in the SAME transaction.
            if existed && let Some(captured) = captured.refs() {
                changed.extend(self.refresh_subject_edge_after_claim_delete_in_txn(
                    &mut wtxn,
                    id,
                    &captured.subject,
                )?);
            }
            if existed {
                if window_label.contains('@') {
                    self.store.sync_state.put(
                        &mut wtxn,
                        &format!("m:dw:{}", id.to_hex()),
                        window_label.as_bytes(),
                    )?;
                }
                if reason.publishes_crdt_tombstone() {
                    // OWNER-DECISION (cfg-off durability): the pending-tombstone
                    // marker rides the SAME txn as the shell scrub.
                    self.put_pending_tombstone_in_txn(&mut wtxn, window_label, id, &tombstone)?;
                } else {
                    // ONE-1931 archive: same "intent rides the scrub txn"
                    // discipline, different marker. `ac:` is GLOBAL and is
                    // never replayed into a window doc, so an archive that
                    // survives a crash is still just a local archive.
                    self.put_archive_tombstone_in_txn(&mut wtxn, id, &tombstone)?;
                }
                if let Some(decision) = gate_decision.as_ref() {
                    self.store
                        .append_gate_decision_in_txn(&mut wtxn, decision)?;
                }
            }
            if !existed || !reason.publishes_crdt_tombstone() {
                clear_own_topology_delete_in_txn(
                    &self.store,
                    &mut wtxn,
                    id,
                    &tombstone.request_id,
                    false,
                )?;
            }
            wtxn.commit()?;
            if existed {
                self.notify_local_delete_materialized(&changed);
                gate.as_ref()
                    .inspect(|gate| gate.note_soft_scrub_committed());
            }
            // An archive publishes nothing (`publishes_crdt_tombstone` is
            // false for exactly one reason): there is no remote-binding act
            // to re-gate, and nothing for a peer to obey, so the local `ac:`
            // marker committed above IS the whole archive.
            if existed && reason.publishes_crdt_tombstone() {
                // fix-leg 7 P1-1: the tombstone publish carries the GATE.
                // The scrub txn's re-fold proved authority for a LOCAL act and
                // then dropped its snapshot; publication is a separate,
                // remote-binding act, and a `RevokeActor` landing in between
                // used to reach peers unchallenged (the soft arm passed no gate
                // at all, so nothing re-checked before `d:w:`/`u:w:`/`q:` were
                // written and the delta routed).
                //
                // The DECISION record stays `None` here on purpose: the scrub
                // txn above already appended it to the real gate ledger, which
                // it must, because that append is the soft arm's only
                // cfg-independent authority record (`write_crdt_tombstone` is a
                // no-op in non-`sync` builds). Passing it again would stage a
                // recovery sidecar for an already-ledgered decision that this
                // path has no TXN3 to consume.
                //
                // A refusal must additionally WITHDRAW the `pt:` marker the
                // scrub txn committed: it holds the verbatim tombstone wire
                // value, so a sync-enabled boot would replay it into exactly
                // the publication the refusal denied. Nothing replayable may
                // survive a refusal — `begin_tombstone_publish_txn` withdraws
                // it in the refusing txn itself.
                let crdt_persisted = self.write_crdt_tombstone(
                    id,
                    header.learned_at,
                    window_label,
                    &tombstone,
                    None,
                    gate.as_ref(),
                )?;
                signal_delete_rendezvous(self, DeleteRendezvous::AfterTombstonePublish, id, None);
                if crdt_persisted {
                    self.finish_published_topology_delete(window_label, id, &tombstone)?;
                }
            }
            return Ok(DeleteEntityOutcome {
                existed,
                receipt_id: None,
                sweep_key: None,
                turn_program_details: turn_program_details.to_vec(),
            });
    }

    /// Publishes the hard delete's tombstone first, then soft-erases the
    /// privacy reasons; reports what settled and when the soft leg completed.
    pub(super) fn delete_hard_setup_phase(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        gate: &Option<GatedDeletion<'_>>,
        allow_replay_test: bool,
        due: Option<&PendingConfirmedErase>,
        header: EntityMetadataHeader,
        tombstone: TombstoneValueV2,
        gate_decision: &Option<GateDecisionRecord>,
        window_label: &str,
        captured: &ProvenanceCapture,
    ) -> Result<DeleteHardSetup> {
        // LOCKED ordering (ARCH-0038): CRDT tombstone FIRST — prevents sync
        // resurrection before the destructive purge touches payloads. That
        // ordering makes the tombstone the FIRST remote-visible act of a hard
        // delete, so the authority behind it is re-proven atomically with the
        // recovery sidecar that stages it (`stage_deletion_gate_recovery`) —
        // a revoked owner must not publish a deletion other devices obey.
        let crdt_persisted = self.write_crdt_tombstone_due(
            id,
            header.learned_at,
            window_label,
            &tombstone,
            gate_decision.as_ref(),
            gate.as_ref(),
            due,
        )?;
        #[cfg(all(test, feature = "sync"))]
        maybe_fail_after_tombstone_before_purge()?;
        #[cfg(not(all(test, feature = "sync")))]
        maybe_fail_after_tombstone_before_purge();
        // Past the linearization point: this delete is decided. The rendezvous
        // lets the regression commit a revocation HERE and prove the delete
        // still completes.
        signal_delete_rendezvous(
            self,
            DeleteRendezvous::AfterTombstonePublish,
            id,
            gate_decision.as_ref().map(|decision| decision.decision_id),
        );
        let tombstone_complete_at = self.store.clock.now_recorded_at();

        // Is there a linearization point BEHIND us? `crdt_persisted` says a
        // publish commit happened; when it did not (the sync-disabled build's
        // no-op writer, or any sync build path that declines to publish) this
        // delete has settled nothing yet, and the FIRST destructive commit below
        // becomes the point instead — so that one transaction re-proves the
        // owner binding. Set from the publish result, then latched by the first
        // destructive txn that actually LINEARIZES this delete (fix-leg 10: an
        // empty commit settles nothing — see the latch below).
        let mut authority_settled = crdt_persisted;

        let soft_complete_at = if matches!(
            reason,
            DeleteReason::GdprDelete | DeleteReason::PolicyDelete
        ) {
            // The SoftErase scrubs the truth-Claim's body — the ONLY carrier
            // of the subject EdgeRef (D12) — so the D16 edge refresh MUST
            // commit atomically with it, mirroring the user_delete branch
            // above. Committing the SoftErase alone first would leave a
            // crash window in which a stale 26 B flag outlives its
            // truth-Claim and a RETRY cannot heal it (capture sees the
            // bodiless shell ⇒ `None`). The purge txn below re-runs the
            // refresh as an idempotent second pass.
            let mut wtxn = self.store.env.write_txn()?;
            self.require_room_delete_gate(&wtxn, id, gate.as_ref(), allow_replay_test)?;
            // Conditional re-fold (fix-leg 7's ruling, refined by fix-leg 8).
            // WHEN THE PUBLISH COMMITTED: no re-fold. That commit is this
            // delete's linearization point; a `RevokeActor` ordered after it did
            // not race the delete — it follows an operation that was authorized
            // when it published. Refusing here would return FORBIDDEN for a
            // deletion peers have already obeyed, and the replayed tombstone
            // tears this replica anyway.
            // WHEN NOTHING PUBLISHED: there is no such commit, so this scrub is
            // the first irreversible act and it re-proves authority against its
            // OWN view — the refusal is actionable (nothing is on the wire) and
            // true (nothing replays back).
            reverify_deletion_authority_when_unpublished(gate.as_ref(), authority_settled, &wtxn)?;
            self.store.reject_legal_hold_in_txn(&wtxn, id.as_bytes())?;
            crate::world_keys::reject_held_pad_world_in_txn(&self.store, &wtxn, &[*id])?;
            self.reject_held_redirect_shells_in_txn(&wtxn, id)?;
            if !authority_settled {
                self.guard_active_merge_hard_delete_in_txn(&wtxn, id)?;
            }
            // With nothing published, this scrub is the first to touch the
            // PERSON: a Connect guest's pacts end here (FIX 3875).
            revoke_guest_grants_in_txn(self, gate.as_ref(), &mut wtxn, id)?;
            reserve_topology_delete_in_txn(
                &self.store,
                &mut wtxn,
                id,
                &tombstone,
                header.learned_at,
                TopologyDeletePhase::Committed,
            )?;
            let scrub_is_the_linearization_point = !authority_settled;
            let mut changed = vec![*id];
            changed.extend(crate::note::erase_citations_in_txn(self, &mut wtxn, id)?);
            let (existed, had_vector, _ledger_changed) =
                self.soft_erase_active_store_in_txn(&mut wtxn, id, true)?;
            if had_vector {
                crate::hnsw::increment_vector_version(&self.store, &mut wtxn)?;
            }
            if existed && let Some(captured) = captured.refs() {
                changed.extend(self.refresh_subject_edge_after_claim_delete_in_txn(
                    &mut wtxn,
                    id,
                    &captured.subject,
                )?);
                stage_sweep_refs_in_txn(self, &mut wtxn, id, captured)?;
            }
            // The audited exception keeps its debt across this scrub (FIX 7800).
            if existed && let Some(corrupt) = captured.corrupt() {
                changed.extend(self.scrub_corrupt_capture_in_txn(&mut wtxn, corrupt, true)?);
            }
            // fix-leg 9 P1: on the NON-PUBLISHING path this txn's re-fold made
            // it the linearization point, so the deletion's propagation intent
            // must commit WITH it. Leaving `pt:` to the purge txn below split
            // one decision across two commits: the scrub is irreversible and
            // local-only, and a crash (or any purge-path error) in between left
            // the body scrubbed here while every peer kept the full data and NO
            // marker existed to propagate the delete — a GDPR/policy erasure
            // silently downgraded to a local-only scrub. Same transaction ⇒
            // re-check + scrub + replayable intent are one atomic act, and the
            // idempotent re-put in the purge txn keeps that path unchanged.
            //
            // PUBLISHING path untouched: there the tombstone is already on the
            // wire, so peers converge from the CRDT record and `pt:` is only the
            // crash marker the purge txn writes and the post-commit
            // `clear_pending_tombstone` retires.
            if existed && scrub_is_the_linearization_point {
                self.put_linearizing_pending_tombstone_in_txn(
                    &mut wtxn,
                    window_label,
                    id,
                    &tombstone,
                )?;
                // fix-leg 10 P1: the latch and the marker are ONE decision, so
                // they share ONE branch — an empty commit settles nothing.
                //
                // fix-8 latched here unconditionally, on the theory that a
                // committed destructive txn is this delete's linearization
                // point. It is, when it erased something. `existed == false` is
                // ONE-1149's raced-to-nothing shape: the scope vanished between
                // the header read and this txn, so the commit below is EMPTY —
                // no body scrubbed, no vector dropped, no marker staged. The
                // unconditional latch declared a linearization point that did
                // not exist and the purge txn below then asked NO authority
                // question: a `RevokeActor` PLUS a same-id re-put landing before
                // it were both ignored, and the purge tore the REPLACEMENT
                // state, wrote `dt:`/`pt:`, and appended the stale `allow`
                // decision. Leaving it unsettled makes the purge re-fold and
                // refuse — actionable (nothing published, nothing torn) and
                // true.
                //
                // The PUBLISHED path never reaches this branch:
                // `scrub_is_the_linearization_point` is `!authority_settled`, so
                // there the flag is already `true` and stays untouched.
                authority_settled = true;
            }
            if existed && window_label.contains('@') {
                // The shell loses its world body in this commit. Preserve the
                // address with the scrub, not in the later hard-purge txn.
                self.store.sync_state.put(
                    &mut wtxn,
                    &format!("m:dw:{}", id.to_hex()),
                    window_label.as_bytes(),
                )?;
            }
            wtxn.commit()?;
            if existed {
                self.notify_local_delete_materialized(&changed);
            }
            self.store.clock.now_recorded_at()
        } else {
            tombstone_complete_at
        };
        // The second post-publication window: soft-erase committed, purge not
        // yet open. Same law, separately pinned.
        signal_delete_rendezvous(
            self,
            DeleteRendezvous::BeforeHardPurge,
            id,
            gate_decision.as_ref().map(|decision| decision.decision_id),
        );
        Ok(DeleteHardSetup {
            crdt_persisted,
            authority_settled,
            soft_complete_at,
        })
    }
}

/// What the hard setup settled: whether the tombstone published, whether any
/// commit linearized the delete, and when the soft leg completed.
pub(super) struct DeleteHardSetup {
    pub(super) crdt_persisted: bool,
    pub(super) authority_settled: bool,
    pub(super) soft_complete_at: u64,
}
