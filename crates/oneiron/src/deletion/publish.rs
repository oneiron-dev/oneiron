use crate::Vault;
use crate::entity_id::EntityId;
// Only the sync arm of `write_crdt_tombstone` inspects a typed error variant;
// the no-feature arm returns `Ok(false)` and needs `Result` alone.
#[cfg(feature = "sync")]
use crate::error::Error;
use crate::error::Result;
use crate::store::GateDecisionRecord;

use super::gate::GatedDeletion;
// Publication-time authority re-verification only exists where there is a
// publication; the no-feature arm publishes nothing.
#[cfg(feature = "sync")]
use super::gate::reverify_deletion_authority_before_publication;
// Both cfg arms of this shim require the `sync` feature, and its only call
// site below is sync-gated with it; the import carries the same gate so a
// no-feature build does not resolve a name that does not exist.
#[cfg(feature = "sync")]
use super::rendezvous::maybe_fail_live_tombstone_persist;
// The publish rendezvous is signalled only from the sync arm below.
#[cfg(feature = "sync")]
use super::rendezvous::{DeleteRendezvous, signal_delete_rendezvous};
use super::tombstone::TombstoneValueV2;
// The `pt:` withdrawal helper is part of the sync persistence transaction.
#[cfg(feature = "sync")]
use super::tombstone::pending_tombstone_key;

/// Inputs committed together by the sync tombstone persistence transaction.
/// Grouping these values makes the TXN1 contract explicit: the request-keyed
/// window snapshot, queue mutation, and scrub commit as one unit after the
/// authority-required marker and recovery sidecar are durably staged.
#[cfg(feature = "sync")]
struct TombstonePersistence<'a> {
    snapshot: &'a [u8],
    version_vector: &'a [u8],
    tombstone: &'a TombstoneValueV2,
    delete_update: Option<&'a crate::sync::window::DeleteBearingUpdate>,
    scrubbed_update_keys: &'a [String],
}

impl Vault {
    /// Writes the ARCH-0038 CRDT tombstone (v2 wire value, ONE-1132) into
    /// the window doc addressed by `window_ts`. In the SAME CRDT commit as
    /// the tombstone insert, the live `entities[id]` copy (an ACTIVE
    /// carrier, not history) and — for hard reasons — the entity's
    /// edges-map keys are removed; op-history bytes remain for the bounded
    /// `h:` sweep (ONE-1091). Returns whether the CRDT record was
    /// persisted: `false` only in non-`sync` builds, where the `pt:`
    /// pending-tombstone marker carries the deletion intent until a
    /// sync-enabled boot replays it.
    ///
    /// ONE-1135 (delete-propagation transport):
    /// - **Live routing**: when the window is OPEN (registry lookup via the
    ///   attached [`crate::sync::WindowManager`]), the tombstone commits
    ///   through the registry-owned live doc. Its synchronous Observer A
    ///   callback is suppressed for this one commit; an authority-required
    ///   marker + complete recovery sidecar are staged first, then the
    ///   deletion TXN1 — the transaction the owner re-fold opens BEFORE the
    ///   live mutation ([`Vault::begin_tombstone_publish_txn`]) — persists
    ///   the snapshot + outbound delta, never through a parallel transient
    ///   copy whose `d:w:` export a live `persist_state` would clobber.
    /// - **Transient path** (window NOT open): the doc is import-merged
    ///   from the persisted snapshot + pending `u:` rows
    ///   ([`crate::sync::window::load_window_from_state`]) — never a blind
    ///   overwrite.
    /// - **Delete-bearing queue row**: the tombstone-commit delta is pushed
    ///   to the offline queue with the `d:{seq}` sidecar marker, so an
    ///   OFFLINE delete is delivered on next connect and survives the
    ///   optimistic clear until VV-confirmed (M4-12).
    /// - **Carrier-15 scrub** (hard reasons): pre-existing `q:` rows for
    ///   this window and the persisted `u:w:` rows the snapshot subsumed
    ///   are dropped, and the `fr:w:{key}` full-resync marker is set
    ///   (ARCH-0038 carriers 13–15; fail-closed — over-drop + full resync,
    ///   never leak).
    ///
    /// OWNER-DECISION (ONE-1601 live-path commit origin): the live-doc
    /// commit is tagged `DELETION_TOMBSTONE_ORIGIN`. Observer B skips it;
    /// Observer A is synchronously suppressed; the recovery sidecar is staged
    /// before the live mutation and TXN1 then persists its snapshot. The local
    /// delete path owns the LMDB purge under the pinned tombstone → purge →
    /// receipt ordering, and a B-side replay here would purge BEFORE the
    /// purge transaction, voiding the local receipt and the
    /// `DeleteEntityOutcome` (mirrors `replay_pending_tombstones`).
    #[cfg(feature = "sync")]
    pub(super) fn write_crdt_tombstone(
        &self,
        id: &EntityId,
        window_ts: u64,
        value: &TombstoneValueV2,
        gate_decision: Option<&GateDecisionRecord>,
        gate: Option<&GatedDeletion<'_>>,
    ) -> Result<bool> {
        use crate::sync::bridge::{
            DELETION_TOMBSTONE_ORIGIN, with_deletion_tombstone_observer_a_suppressed,
        };
        use crate::sync::loro_support::doc_version_vector;
        use crate::sync::schema::create_window_doc;
        use crate::sync::types::WindowKey;
        use crate::sync::window::{
            apply_tombstone_to_window_doc, export_tombstone_commit_delta, load_window_from_state,
            merge_persisted_state_into_doc,
        };
        use loro::CommitOptions;

        let window_key = WindowKey::from_timestamp(window_ts);

        if let Some((window, materializer, manager)) = self.live_window(&window_key) {
            // Live path: merge the on-disk record first (clobber guard —
            // a tombstone persisted transiently while this window was open
            // must survive the snapshot export below), then commit the
            // delete through the SHARED doc.
            //
            // The merge runs OUTSIDE the materializer lock: importing into
            // an observed doc fires Observer B synchronously on this
            // thread, and the callback takes the (non-reentrant) lock
            // itself. The snapshot MODE is resolved here too — its scrub
            // takes its own write txn, which cannot nest inside the publish
            // txn opened below.
            let merged_update_keys =
                merge_persisted_state_into_doc(self, &window.doc, &window_key)?;
            // The snapshot-mode decision, the gate staging, the tombstone
            // commit and the exports all run UNDER the materializer lock:
            // Observer B's tombstone-check + LMDB-materialize is atomic under
            // that lock, so a concurrent remote re-put can no longer check the
            // tombstones map BEFORE this commit and write the deleted body
            // back AFTER the purge txn that follows (resurrection race). The
            // deletion origin skips Observer B; Observer A is synchronously
            // suppressed across the whole doc-mutation region — inside an open
            // LMDB write txn its `persist_window_update` would nest a second
            // writer.
            //
            // The publish txn opens BEFORE the live-doc mutation and re-folds
            // the owner binding against its own view: a `RevokeActor` is
            // therefore ordered strictly before this delete (seen — nothing
            // is published) or strictly after it (LMDB's single writer makes
            // it wait for this commit). The two steps that need their own
            // write txn — the mode scrub and the gate staging — run before it
            // opens, since LMDB admits no nested writer. Lock order
            // materializer → LMDB txn matches every other holder; the registry
            // lock is NOT held here (manager lock-order pin).
            let delete_update = {
                let _guard = materializer.lock();
                let history_free = self.resolve_window_snapshot_mode(&window_key, &window.doc)?;
                self.stage_deletion_gate_recovery(id, value, gate_decision, gate)?;
                signal_delete_rendezvous(
                    DeleteRendezvous::BeforeTombstonePublish,
                    id,
                    gate_decision.map(|decision| decision.decision_id),
                );
                let mut wtxn =
                    self.begin_tombstone_publish_txn(id, &window_key, value, gate_decision, gate)?;
                let vv_before = window.doc.oplog_vv();
                let (delete_update, snapshot, vv) =
                    with_deletion_tombstone_observer_a_suppressed(|| -> Result<_> {
                        apply_tombstone_to_window_doc(&window.doc, id, &value.encode())?;
                        window
                            .doc
                            .commit_with(CommitOptions::new().origin(DELETION_TOMBSTONE_ORIGIN));
                        let delete_update = export_tombstone_commit_delta(&window.doc, &vv_before)?;
                        let snapshot =
                            Self::export_window_snapshot_in_mode(&window.doc, history_free)?;
                        let vv = doc_version_vector(&window.doc);
                        Ok((delete_update, snapshot, vv))
                    })?;
                #[cfg(all(test, feature = "sync"))]
                maybe_fail_live_tombstone_persist()?;
                #[cfg(not(all(test, feature = "sync")))]
                maybe_fail_live_tombstone_persist();
                self.finish_crdt_tombstone_persist_in_txn(
                    &mut wtxn,
                    &window_key,
                    TombstonePersistence {
                        snapshot: &snapshot,
                        version_vector: &vv,
                        tombstone: value,
                        delete_update: delete_update.as_ref(),
                        scrubbed_update_keys: &merged_update_keys,
                    },
                )?;
                wtxn.commit()?;
                delete_update
            };
            // Outbound routing is the LAST act, after the publish txn
            // committed: a refusal or a failed persist must never put the
            // tombstone on the wire.
            if let Some(update) = delete_update.as_ref() {
                manager
                    .outbound()
                    .route_live(window_key.as_str(), update.as_bytes());
            }
            return Ok(true);
        }

        // Transient path (window not open): the loaded doc IS the
        // import-merge of `d:w:` + pending `u:` rows. Both reads and the
        // snapshot-mode scrub run before the publish txn opens.
        let merged_update_keys = self.sync_state_keys_with_prefix(&format!("u:w:{window_key}:"))?;
        let doc = match load_window_from_state(self, "local", &window_key) {
            Ok(doc) => doc,
            Err(Error::WindowNotFound { .. }) => create_window_doc("local", &window_key),
            Err(err) => return Err(err),
        };
        let history_free = self.resolve_window_snapshot_mode(&window_key, &doc)?;
        self.stage_deletion_gate_recovery(id, value, gate_decision, gate)?;
        signal_delete_rendezvous(
            DeleteRendezvous::BeforeTombstonePublish,
            id,
            gate_decision.map(|decision| decision.decision_id),
        );
        // Same authority boundary as the live path: the transient doc is
        // mutated only after this txn's re-fold passes, and its bytes reach
        // `d:w:`/`u:w:`/`q:` in that same txn.
        let mut wtxn =
            self.begin_tombstone_publish_txn(id, &window_key, value, gate_decision, gate)?;
        let vv_before = doc.oplog_vv();
        apply_tombstone_to_window_doc(&doc, id, &value.encode())?;
        doc.commit();
        let delete_update = export_tombstone_commit_delta(&doc, &vv_before)?;

        let snapshot = Self::export_window_snapshot_in_mode(&doc, history_free)?;
        let vv = doc_version_vector(&doc);
        self.finish_crdt_tombstone_persist_in_txn(
            &mut wtxn,
            &window_key,
            TombstonePersistence {
                snapshot: &snapshot,
                version_vector: &vv,
                tombstone: value,
                delete_update: delete_update.as_ref(),
                scrubbed_update_keys: &merged_update_keys,
            },
        )?;
        wtxn.commit()?;
        Ok(true)
    }

    /// Opens the transaction that publishes a gated tombstone, re-proving the
    /// owner binding against ITS view before anything can be published.
    ///
    /// THE LINEARIZATION POINT (fix-leg 7 ruling). This commit is where the
    /// delete becomes real: remote-visible, and locally irreversible in the sense
    /// that any replica that applies the tombstone tears the entity. Authority is
    /// therefore decided HERE, once, and nowhere after. LMDB's single writer
    /// orders a concurrent `RevokeActor` strictly before this fold — seen,
    /// nothing published — or strictly after the commit, in which case the
    /// deletion legitimately precedes the revocation in the serial order and the
    /// steps that follow (soft-erase, purge, headerless purge, receipt) MUST NOT
    /// re-decide it. They finish a committed operation; a FORBIDDEN from them
    /// would be a rejected call that already published, and sync replay of the
    /// published tombstone would purge this replica regardless, so the refusal
    /// would also be false. Later refusals at those sites are FACET-STATE only —
    /// consent conditions evaluated at tear time are a different class of
    /// question from "may this actor delete", and S-DISC2 owns them.
    ///
    /// `stage_deletion_gate_recovery` committed the authority-required marker in
    /// an EARLIER transaction (it has to survive a failed publish, or a crash
    /// would leave an orphan live-doc tombstone that recovery could not tell from
    /// a peer's). That earlier commit drops its snapshot, so re-proving here is
    /// what makes the publish atomic with the binding.
    ///
    /// A refusal is not a plain rollback. Every durable artifact that could be
    /// REDEEMED into this publication later is removed in the refusing txn and
    /// that removal is COMMITTED: the staged authority-required marker and its
    /// recovery sidecar, plus the `pt:` pending-tombstone marker (the soft arm
    /// commits one in its shell-scrub txn, and it carries the verbatim tombstone
    /// wire value a sync-enabled boot would replay into exactly the publication
    /// this refusal denied). Nothing replayable survives a refusal.
    #[cfg(feature = "sync")]
    fn begin_tombstone_publish_txn(
        &self,
        id: &EntityId,
        window_key: &crate::sync::WindowKey,
        value: &TombstoneValueV2,
        gate_decision: Option<&GateDecisionRecord>,
        gate: Option<&GatedDeletion<'_>>,
    ) -> Result<heed::RwTxn<'_>> {
        let mut wtxn = self.store.env.write_txn()?;
        if let Err(refusal) = reverify_deletion_authority_before_publication(gate, &wtxn) {
            self.discard_staged_deletion_gate_recovery_in_txn(&mut wtxn, id, value, gate_decision)?;
            self.withdraw_own_pending_tombstone_in_txn(&mut wtxn, window_key.as_str(), id, value)?;
            wtxn.commit()?;
            return Err(refusal);
        }
        Ok(wtxn)
    }

    /// Deletes the `pt:{window}:{id}` marker IF AND ONLY IF it carries THIS
    /// delete's bytes, called from a refusing publish transaction.
    ///
    /// The value match is the whole point. `pt:` is keyed by window and entity,
    /// not by request, so a blanket delete here would let a refused delete
    /// silently discard the propagation intent of a DIFFERENT, authorized
    /// delete of the same id in the same window — turning a fail-closed refusal
    /// into a fail-open under-delete. The 25 B value embeds the deletion
    /// request UUID, so exact-value equality identifies the marker this call
    /// staged and nothing else. A refusal on an arm that staged no marker
    /// (every hard arm: they publish first and write `pt:` in the later purge
    /// txn) finds no match and leaves the row alone.
    #[cfg(feature = "sync")]
    fn withdraw_own_pending_tombstone_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        window_label: &str,
        id: &EntityId,
        value: &TombstoneValueV2,
    ) -> Result<()> {
        let key = pending_tombstone_key(window_label, id);
        let staged_by_this_delete = self
            .store
            .sync_state
            .get(&*wtxn, &key)?
            .is_some_and(|existing| *existing == value.encode());
        if staged_by_this_delete {
            self.store.sync_state.delete(wtxn, &key)?;
        }
        Ok(())
    }

    /// Decides history-free versus ordinary snapshot bytes for this window
    /// BEFORE the publish transaction opens.
    ///
    /// Hoisted out of the publish txn because the pin it reads
    /// (`require_history_free_window`) is written through its own write
    /// transaction, and LMDB has a single process-wide writer — a nested
    /// writer deadlocks. Resolving first leaves the in-txn export a pure
    /// document operation, which is what lets the owner re-fold span the
    /// live-doc mutation.
    #[cfg(feature = "sync")]
    fn resolve_window_snapshot_mode(
        &self,
        window_key: &crate::sync::WindowKey,
        doc: &loro::LoroDoc,
    ) -> Result<bool> {
        Ok(
            crate::sync::window::history_free_window_required(self, window_key)?
                || doc.is_shallow(),
        )
    }

    /// Exports the window snapshot under a mode already resolved by
    /// [`Self::resolve_window_snapshot_mode`] — a pure document operation,
    /// safe to run inside the publish transaction.
    #[cfg(feature = "sync")]
    fn export_window_snapshot_in_mode(doc: &loro::LoroDoc, history_free: bool) -> Result<Vec<u8>> {
        if history_free {
            crate::sync::window::export_history_free_window_snapshot(doc)
        } else {
            crate::sync::loro_support::export_snapshot(doc)
        }
    }

    /// Removes the authority staging a refused publish transaction must not
    /// leave behind: the required marker plus its recovery sidecar, deleted in
    /// the SAME txn that refused, so a revoked owner leaves no evidence that a
    /// later replay could read as a pending authorized deletion.
    #[cfg(feature = "sync")]
    fn discard_staged_deletion_gate_recovery_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        value: &TombstoneValueV2,
        gate_decision: Option<&GateDecisionRecord>,
    ) -> Result<()> {
        let Some(decision) = gate_decision else {
            return Ok(());
        };
        self.store.discard_pending_deletion_gate_decision_in_txn(
            wtxn,
            decision.decision_id,
            id.as_bytes(),
            value.reason.wire_byte(),
        )?;
        Ok(())
    }

    /// Durably marks a locally gated tombstone as authority-required and
    /// stores its complete recovery sidecar before any shared live document
    /// can commit that tombstone. Remote/ungated tombstones deliberately do
    /// not create this marker and remain valid replay inputs.
    #[cfg(feature = "sync")]
    fn stage_deletion_gate_recovery(
        &self,
        id: &EntityId,
        value: &TombstoneValueV2,
        gate_decision: Option<&GateDecisionRecord>,
        gate: Option<&GatedDeletion<'_>>,
    ) -> Result<()> {
        let Some(decision) = gate_decision else {
            return Ok(());
        };
        self.with_write_txn(|wtxn| {
            // The authority-required marker is what makes the CRDT tombstone
            // binding on every peer, so the owner binding is re-proven in the
            // SAME txn that stages it — a revocation landing since the gate ran
            // stops the deletion before it becomes remote truth.
            reverify_deletion_authority_before_publication(gate, wtxn)?;
            self.store.put_pending_deletion_gate_decision_in_txn(
                wtxn,
                decision,
                id.as_bytes(),
                value.reason.wire_byte(),
            )
        })?;
        // The staging txn has COMMITTED and dropped its snapshot here — the
        // authority it proved is already stale. The publish txn's re-fold is
        // what closes that gap; the `BeforeTombstonePublish` rendezvous the
        // caller fires next lets the regression land a revocation inside it.
        Ok(())
    }

    /// The delete path's sync_state / sync_queue bookkeeping (both DBs share
    /// the LMDB env), inside the caller's PUBLISH transaction: persist the
    /// window-doc snapshot triple, queue the delete-bearing update, and — for
    /// hard reasons — run the carrier-15 scrub + set the `fr:w:{key}`
    /// full-resync marker (consumer lands in M4-12).
    ///
    /// Takes the caller's `wtxn` rather than opening its own so the owner
    /// re-fold in [`Vault::begin_tombstone_publish_txn`] spans the live-doc
    /// mutation AND every durable carrier it produces. A refusal — or any
    /// error below — rolls all of them back together, leaving no `d:w:`
    /// carrier, no `u:w:`/`q:` update, and no pending gate sidecar.
    #[cfg(feature = "sync")]
    fn finish_crdt_tombstone_persist_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        window_key: &crate::sync::WindowKey,
        persistence: TombstonePersistence<'_>,
    ) -> Result<()> {
        let is_hard = persistence.tombstone.reason.is_hard();
        crate::sync::window::persist_window_doc_in_txn(
            self,
            wtxn,
            window_key,
            persistence.snapshot,
            persistence.version_vector,
        )?;
        if is_hard {
            // ARCH-0038 carrier 15: pending `q:` rows for this window
            // may carry the deleted payload — drop them all (fail-closed
            // over-drop; delete-bearing rows are preserved inside the
            // scrub). The `u:w:` rows the snapshot just subsumed are
            // active payload carriers too.
            crate::sync::queue::scrub_window_updates_in_txn(self, wtxn, window_key.as_str())?;
            for update_key in persistence.scrubbed_update_keys {
                self.store.sync_state.delete(wtxn, update_key)?;
            }
            // Carriers 13–14: this window's sync state is no longer a
            // faithful delta source — mark it for a full per-window
            // resync on the next connect.
            let fr_key = format!("fr:w:{window_key}");
            self.store.sync_state.put(wtxn, &fr_key, &[1_u8])?;
        }
        if let Some(update) = persistence.delete_update {
            // The live-doc path suppresses Observer A for the tombstone
            // commit, then writes its ordinary `u:w:` carrier here in the
            // publish txn. Authority recovery was durably staged before the
            // live mutation, so restart replay cannot observe an
            // authority-required tombstone without that requirement.
            crate::sync::bridge::persist_window_update_in_txn(
                self,
                wtxn,
                window_key.as_str(),
                update.as_bytes(),
            )?;
            crate::sync::queue::push_delete_bearing_in_txn(
                self,
                wtxn,
                window_key.as_str(),
                update,
            )?;
        }
        // svf LAST (ONE-1151): the hard branch scrubbed the merged u:w:
        // rows above; the soft branch kept them. Recompute freshness from
        // the FINAL u:w: set so a surviving row reads stale (the
        // fast-reconnect reader then full-opens instead of trusting an
        // sv:w: VV that omits the survivor's ops).
        crate::sync::window::write_window_svf_in_txn(self, wtxn, window_key)
    }

    #[cfg(not(feature = "sync"))]
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn write_crdt_tombstone(
        &self,
        _id: &EntityId,
        _window_ts: u64,
        _value: &TombstoneValueV2,
        _gate_decision: Option<&GateDecisionRecord>,
        _gate: Option<&GatedDeletion<'_>>,
    ) -> Result<bool> {
        // No CRDT in this build — nothing is published, so there is no publish
        // commit and therefore NO linearization point here. `false` is the
        // signal the callers key on: it makes their first destructive
        // transaction re-prove the owner binding
        // ([`reverify_deletion_authority_when_unpublished`]), which is what
        // makes that transaction the linearization point instead. The `pt:`
        // marker it writes is the deletion's durable propagation intent, so a
        // sync-enabled boot that later replays it replays a deletion that WAS
        // authorized when its transaction committed — the value of `false` must
        // never be faked to `true` to "simplify" the callers.
        Ok(false)
    }
}
