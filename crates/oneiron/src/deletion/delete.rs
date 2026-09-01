use uuid::Uuid;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::GateDecisionRecord;
use crate::unix_seconds_now;

use super::erase::sweep_extras;
use super::gate::{
    GatedDeletion, reverify_deletion_authority_before_publication,
    reverify_deletion_authority_when_unpublished,
};
use super::receipt::{RedactionReceiptInput, RedactionScope};
use super::rendezvous::{
    DeleteRendezvous, maybe_fail_after_tombstone_before_purge,
    maybe_fail_first_txn_pending_tombstone, signal_after_header_read, signal_delete_rendezvous,
};
use super::sweep_queue::HardEraseSweepExtras;
use super::tombstone::{
    DeleteReason, TombstoneReason, TombstoneValueV2, local_hard_delete_key, pending_tombstone_key,
    window_label_from_timestamp,
};

/// Result for a reason-aware delete request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteEntityOutcome {
    pub existed: bool,
    pub receipt_id: Option<EntityId>,
    pub sweep_key: Option<Vec<u8>>,
}

impl DeleteEntityOutcome {
    pub(crate) const fn missing() -> Self {
        Self {
            existed: false,
            receipt_id: None,
            sweep_key: None,
        }
    }
}

impl Vault {
    /// Deletes an entity blob by ID using the destructive user-hard-delete
    /// contract.
    pub fn delete_entity(&self, id: &EntityId) -> Result<bool> {
        Ok(self
            .delete_entity_with_reason(id, DeleteReason::UserHardDelete)?
            .existed)
    }

    /// Deletes an entity according to the pinned ARCH-0038 reason behavior.
    pub fn delete_entity_with_reason(
        &self,
        id: &EntityId,
        reason: DeleteReason,
    ) -> Result<DeleteEntityOutcome> {
        self.delete_entity_with_reason_impl(id, reason, None)
    }

    /// Facade delete seam carrying an owner gate evaluated before TXN1.
    ///
    /// `gate` carries BOTH the decision record and the authority re-check: the
    /// record is minted from a read snapshot this call has already dropped, so
    /// every destructive transaction below re-proves the owner binding against
    /// its OWN view before tearing anything.
    pub(crate) fn delete_entity_with_reason_gated(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        gate: GatedDeletion<'_>,
    ) -> Result<DeleteEntityOutcome> {
        self.delete_entity_with_reason_impl(id, reason, Some(gate))
    }

    fn delete_entity_with_reason_impl(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        gate: Option<GatedDeletion<'_>>,
    ) -> Result<DeleteEntityOutcome> {
        let requested_at = unix_seconds_now();
        let Some(header) = self.read_entity_header(id)? else {
            return self.delete_entity_without_header(id, reason, requested_at, gate.as_ref());
        };
        if crate::registry::is_delete_protected_engine_record(header.entity_type) {
            return Err(Error::MaintenanceKindNotWritable(header.entity_type));
        }
        // ONE-1149 race-test rendezvous: the header is proven `Some` (the
        // lock-free `read_entity_header` read_txn has completed and committed
        // the headerful path) but no write lock is held yet. The deterministic
        // raced-delete harness recv()s here so the eraser commits AFTER this
        // header read, forcing the headerful leg every run. No-op in
        // production.
        signal_after_header_read();
        // ONE-1132: ONE deletion request UUID correlates the CRDT tombstone's
        // `request_id` with the REDACTION_AUDIT receipt's `request_id`.
        // ONE-1149: minted only AFTER the header read proves there is
        // something to erase — a delete that finds nothing must never mint a
        // request id (the headerless leg mints after its own scope probe).
        let request_uuid = Uuid::now_v7();

        let tombstone = TombstoneValueV2 {
            reason: reason.into(),
            deleted_at: requested_at,
            request_id: *request_uuid.as_bytes(),
        };
        let gate_decision = gate.as_ref().map(|gate| {
            gate.context
                .decision_record(*request_uuid.as_bytes(), id, reason, requested_at)
        });
        let window_label = window_label_from_timestamp(header.learned_at);

        // ARCH-0038 DELETE interplay: an `edge.provenance` Claim's subject
        // EdgeRef and sweep refs are only readable PRE-purge (SoftErase
        // truncates the payload to the 25 B header) — capture them now.
        // `None` for every non-Claim / non-provenance entity: zero new
        // behavior on those paths.
        let captured = self.capture_provenance_delete(id)?;

        if !reason.active_store_hard_purge_v1() {
            // `user_delete` keeps the local 25 B shell (ARCH-0038 "Tombstone
            // revision (empty content); keep the message shell") but now
            // writes a reason=user_delete CRDT tombstone (ONE-1090 write
            // side): a soft delete with NO cross-device record would leave
            // the deleted body live on every other device.
            let mut wtxn = self.store.env.write_txn()?;
            // TOCTOU close: `user_delete` scrubs the body in THIS txn, so the
            // owner authority is re-proven against THIS txn's view. A
            // RevokeActor committed since the gate ran is visible here and
            // refuses before a single byte is scrubbed. PRE-publication: this
            // arm publishes its tombstone after the scrub, so the re-fold below
            // in the publish txn is the decision that binds.
            reverify_deletion_authority_before_publication(gate.as_ref(), &wtxn)?;
            let (existed, had_vector) = self.soft_erase_active_store_in_txn(&mut wtxn, id)?;
            if had_vector {
                crate::hnsw::increment_vector_version(&self.store, &mut wtxn)?;
            }
            // D16: SoftErase tombstones the Claim, and "the derived edge
            // flag follows the Claim" — refresh in the SAME transaction.
            if existed && let Some(captured) = &captured {
                self.refresh_subject_edge_after_claim_delete_in_txn(
                    &mut wtxn,
                    id,
                    &captured.subject,
                )?;
            }
            if existed {
                // OWNER-DECISION (cfg-off durability): the pending-tombstone
                // marker rides the SAME txn as the shell scrub.
                self.put_pending_tombstone_in_txn(&mut wtxn, &window_label, id, &tombstone)?;
                if let Some(decision) = gate_decision.as_ref() {
                    self.store
                        .append_gate_decision_in_txn(&mut wtxn, decision)?;
                }
            }
            wtxn.commit()?;
            if existed {
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
                    &tombstone,
                    None,
                    gate.as_ref(),
                )?;
                signal_delete_rendezvous(DeleteRendezvous::AfterTombstonePublish, id, None);
                if crdt_persisted {
                    self.clear_pending_tombstone(&window_label, id)?;
                }
            }
            return Ok(DeleteEntityOutcome {
                existed,
                receipt_id: None,
                sweep_key: None,
            });
        }

        // LOCKED ordering (ARCH-0038): CRDT tombstone FIRST — prevents sync
        // resurrection before the destructive purge touches payloads. That
        // ordering makes the tombstone the FIRST remote-visible act of a hard
        // delete, so the authority behind it is re-proven atomically with the
        // recovery sidecar that stages it (`stage_deletion_gate_recovery`) —
        // a revoked owner must not publish a deletion other devices obey.
        let crdt_persisted = self.write_crdt_tombstone(
            id,
            header.learned_at,
            &tombstone,
            gate_decision.as_ref(),
            gate.as_ref(),
        )?;
        #[cfg(all(test, feature = "sync"))]
        maybe_fail_after_tombstone_before_purge()?;
        #[cfg(not(all(test, feature = "sync")))]
        maybe_fail_after_tombstone_before_purge();
        // Past the linearization point: this delete is decided. The rendezvous
        // lets the regression commit a revocation HERE and prove the delete
        // still completes.
        signal_delete_rendezvous(
            DeleteRendezvous::AfterTombstonePublish,
            id,
            gate_decision.as_ref().map(|decision| decision.decision_id),
        );
        let tombstone_complete_at = unix_seconds_now();

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
            let scrub_is_the_linearization_point = !authority_settled;
            let (existed, had_vector) = self.soft_erase_active_store_in_txn(&mut wtxn, id)?;
            if had_vector {
                crate::hnsw::increment_vector_version(&self.store, &mut wtxn)?;
            }
            if existed && let Some(captured) = &captured {
                self.refresh_subject_edge_after_claim_delete_in_txn(
                    &mut wtxn,
                    id,
                    &captured.subject,
                )?;
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
                    &window_label,
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
            wtxn.commit()?;
            unix_seconds_now()
        } else {
            tombstone_complete_at
        };
        // The second post-publication window: soft-erase committed, purge not
        // yet open. Same law, separately pinned.
        signal_delete_rendezvous(
            DeleteRendezvous::BeforeHardPurge,
            id,
            gate_decision.as_ref().map(|decision| decision.decision_id),
        );

        let receipt_id = EntityId::now();
        let mut scope = RedactionScope::entity(id);
        let mut wtxn = self.store.env.write_txn()?;
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
        let marker_key = local_hard_delete_key(id);
        // ONE-1149 ownership claim: probe the FULL delete scope INSIDE the
        // erasing txn. LMDB's single writer makes this race-free — if the
        // probe sees state, this txn's purge erases it; if a concurrent
        // delete raced everything away first, this delete must not claim it
        // erased anything (no receipt, no sweep row). Mirrors the
        // receiver-side `apply_replayed_tombstone` nothing-local branch:
        // ONLY the durable `dt:` marker is written (hard-once-seen — the
        // CRDT tombstone above is already published, so the id IS
        // hard-deleted), guarded so an existing marker is never overwritten.
        if !self.active_delete_scope_exists_in_txn(&wtxn, id)? {
            if self.store.sync_state.get(&wtxn, &marker_key)?.is_none() {
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
        // ONE-1122 `dt:` local hard-delete marker: the permanent local truth
        // the Observer-B materialization gate consults when a crafted update
        // REMOVES the CRDT tombstone (nothing else id-keyed survives a hard
        // delete locally — the receipt id is fresh, h: is seq-keyed, pt: is
        // cleared after replay). Written in the SAME txn as the active-store
        // purge. PRESENCE-ONLY for gates; the 25 B value body (the tombstone
        // wire bytes) is informational. Un-cfg'd on every build: `sync_state`
        // is unconditional and the marker is local delete truth, not
        // sync-only state (ONE-1132 cfg-off durability).
        self.store
            .sync_state
            .put(&mut wtxn, &marker_key, &tombstone.encode())?;
        // ARCH-0055 §9 (r6): HardErase walks redirects. BEFORE the purge —
        // it deletes the head's incident shell edges, which are the walk's
        // primary witness — and in this same transaction, so a head can
        // never be erased while a shell of it stays readable.
        let cascaded_shells = self.cascade_hard_erase_to_redirect_shells_in_txn(&mut wtxn, id)?;
        // The shells' historical carriers ride THIS erasure's sweep row:
        // clearing the active store while history keeps the bytes would
        // erase nothing.
        scope
            .entity_ids
            .extend(cascaded_shells.iter().map(EntityId::to_hex));
        let existed = self.purge_entity_active_store_in_txn(&mut wtxn, id)?;

        // ARCH-0038 DELETE: "The derived edge flag follows the Claim" — the
        // subject edge is refreshed in the SAME transaction as the purge.
        // Gated on `existed` (the entity record was erased by THIS txn): a
        // captured Claim whose record was raced away was already refreshed
        // by the racer's own delete txn.
        if existed && let Some(captured) = &captured {
            self.refresh_subject_edge_after_claim_delete_in_txn(&mut wtxn, id, &captured.subject)?;
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
        self.put_pending_tombstone_in_txn(&mut wtxn, &window_label, id, &tombstone)?;
        self.append_deletion_gate_decision_in_purge_txn(
            &mut wtxn,
            crdt_persisted,
            gate_decision.as_ref(),
            id,
            tombstone.reason,
        )?;

        let hard_purge_complete_at = unix_seconds_now();
        let sweep_key = self.write_redaction_receipt_and_sweep_in_txn(
            &mut wtxn,
            &receipt_id,
            RedactionReceiptInput {
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
            sweep_extras(captured.as_ref()),
        )?;

        wtxn.commit()?;
        // The CRDT record (tombstone-first, above) is durable — the crash
        // marker has served its purpose. In non-`sync` builds the marker
        // STAYS: it is the deletion's only propagation intent until a
        // sync-enabled boot replays it.
        if crdt_persisted {
            self.clear_pending_tombstone(&window_label, id)?;
        }
        Ok(DeleteEntityOutcome {
            existed,
            receipt_id: Some(receipt_id),
            sweep_key: Some(sweep_key),
        })
    }

    fn delete_entity_without_header(
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

    /// Completes the deletion authority record in the same TXN3 write as the
    /// active-store purge and REDACTION_AUDIT receipt. Sync-enabled deletes
    /// stage recovery data before the tombstone commit; sync-disabled deletes
    /// append the evaluated record directly on their first durable purge.
    fn append_deletion_gate_decision_in_purge_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        crdt_persisted: bool,
        decision: Option<&GateDecisionRecord>,
        id: &EntityId,
        tombstone_reason: TombstoneReason,
    ) -> Result<()> {
        let Some(decision) = decision else {
            return Ok(());
        };
        if crdt_persisted {
            if self
                .store
                .append_pending_deletion_gate_decision_in_txn(
                    wtxn,
                    decision.decision_id,
                    id.as_bytes(),
                    tombstone_reason.wire_byte(),
                )?
                .is_none()
            {
                return Err(Error::CorruptedIndex("pending deletion gate decision"));
            }
        } else {
            self.store.append_gate_decision_in_txn(wtxn, decision)?;
        }
        Ok(())
    }

    /// Writes the CRDT-independent `pt:{window}:{entity_hex}` marker in the
    /// caller's purge / shell-scrub transaction (ONE-1132 OWNER-DECISION:
    /// deletion durability must not depend on the `sync` cargo feature).
    /// Value = the v2 tombstone wire value, so a sync-enabled boot can
    /// replay it verbatim.
    fn put_pending_tombstone_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        window_label: &str,
        id: &EntityId,
        value: &TombstoneValueV2,
    ) -> Result<()> {
        let key = pending_tombstone_key(window_label, id);
        self.store.sync_state.put(wtxn, &key, &value.encode())?;
        Ok(())
    }

    /// Writes the `pt:` marker in a transaction that is ITSELF this delete's
    /// linearization point (fix-leg 9), carrying the crash surrogate that proves
    /// the write is atomic with everything else that transaction did.
    ///
    /// Separate from [`Self::put_pending_tombstone_in_txn`] only so the failure
    /// injection has an exact anchor: the regression arms it, this call fails,
    /// and the caller's `?` drops the whole `RwTxn` un-committed — body and
    /// vector intact, no `pt:`. A future edit that moves the marker back out of
    /// the scrub transaction loses that anchor and the regression goes red.
    fn put_linearizing_pending_tombstone_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        window_label: &str,
        id: &EntityId,
        value: &TombstoneValueV2,
    ) -> Result<()> {
        self.put_pending_tombstone_in_txn(wtxn, window_label, id, value)?;
        #[cfg(all(test, not(feature = "sync")))]
        maybe_fail_first_txn_pending_tombstone()?;
        #[cfg(not(all(test, not(feature = "sync"))))]
        maybe_fail_first_txn_pending_tombstone();
        Ok(())
    }

    /// Clears the pending-tombstone marker. Only called once the CRDT
    /// commit + snapshot persistence have succeeded — never before.
    fn clear_pending_tombstone(&self, window_label: &str, id: &EntityId) -> Result<()> {
        self.with_write_txn(|wtxn| {
            let key = pending_tombstone_key(window_label, id);
            self.store.sync_state.delete(wtxn, &key)?;
            Ok(())
        })
    }
}
