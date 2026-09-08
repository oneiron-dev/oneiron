//! Retrieval-run registration door (register/finalize/discard, staged/published arms).

use crate::Vault;
use crate::error::Result;
use crate::session_overlay::{RouteTarget, SessionWriteRoute};

/// The retrieval-run REGISTRATION DOOR a retrieval issued INSIDE a room writes
/// through, minted by [`OffRecordSession::retrieval_telemetry`] (ONE-1570 Arm
/// B). Every telemetry write of an in-room assembly — the registration, the
/// context pack's finalize, and the failure discard — goes through here.
///
/// Crate-private and inert on its own: holding one routes telemetry, never
/// content. Only the retrieval builders consume it.
///
/// It carries the CAPTURED ROUTE rather than a resolved target, and each write
/// revalidates through it. Resolving the target once at the door and handing
/// the arms a bare view was the hole: a `Base` route then collapsed to "no
/// session at all", the assembly took the canonical base door, and that door
/// holds no route to check — so a recall admitted while the room was ON RECORD
/// and flipped OFF RECORD mid-assembly published the room's `result_ids`
/// durably to base, past the K10 boundary. Both targets need the route,
/// because both of them WRITE.
pub(crate) struct SessionRetrievalTelemetry<'session> {
    pub(super) vault: &'session Vault,
    pub(super) route: &'session SessionWriteRoute,
}

impl SessionRetrievalTelemetry<'_> {
    /// Whether this assembly's rows stage into the room's overlay rather than
    /// the base ledger.
    ///
    /// The base-only arms of the retrieval path (K6's embed enqueue) key on
    /// THIS, never on session-boundness: an on-record room's retrieval is an
    /// ordinary base one and takes the ordinary base arms.
    pub(crate) fn stages_in_overlay(&self) -> bool {
        self.route.target() == RouteTarget::Overlay
    }

    /// Registers this assembly's retrieval-run row, provisional or published.
    pub(crate) fn register_run(
        &self,
        record: &crate::store::RetrievalRunRecord,
        provisional: bool,
    ) -> Result<()> {
        if self.stages_in_overlay() {
            return self.staged(|view, wtxn| {
                if provisional {
                    view.record_context_pack_provisional_retrieval_run_in_txn(wtxn, record)
                } else {
                    view.record_retrieval_run_in_txn(wtxn, record)
                }
            });
        }
        self.published(record.run_id, || {
            if provisional {
                self.vault
                    .store
                    .record_context_pack_provisional_retrieval_run(record)
            } else {
                self.vault.store.record_retrieval_run(record)
            }
        })
    }

    /// Clears the provisional marker and publishes the final row, against
    /// whichever target the provisional registered through.
    pub(crate) fn finalize_run(
        &self,
        run_id: crate::store::RetrievalRunId,
        elapsed_us: u64,
        total_in_scope: usize,
        claims_suppressed: usize,
        surfaced_result_ids: &[[u8; 16]],
        empty_reason: Option<String>,
    ) -> Result<()> {
        if self.stages_in_overlay() {
            return self.staged(|view, wtxn| {
                view.finalize_context_pack_retrieval_run_in_txn(
                    wtxn,
                    run_id,
                    elapsed_us,
                    total_in_scope,
                    claims_suppressed,
                    surfaced_result_ids,
                    empty_reason,
                )
            });
        }
        self.published(run_id, || {
            self.vault.store.finalize_context_pack_retrieval_run(
                run_id,
                elapsed_us,
                total_in_scope,
                claims_suppressed,
                surfaced_result_ids,
                empty_reason,
            )
        })
    }

    /// Removes a provisional row whose assembly failed.
    ///
    /// The base arm takes no route check: a REMOVAL publishes nothing, so
    /// refusing it under a replaced route would only strand the residue the
    /// call exists to clear.
    pub(crate) fn discard_run(&self, run_id: crate::store::RetrievalRunId) -> Result<()> {
        if self.stages_in_overlay() {
            return self.staged(|view, wtxn| view.delete_retrieval_run_in_txn(wtxn, run_id));
        }
        self.vault.store.delete_retrieval_run(run_id)
    }

    /// One staged overlay write, under the captured route, revalidated INSIDE
    /// the transaction that publishes it.
    ///
    /// Base writer FIRST, then the segment permit — the overlay's own
    /// documented order, and the only one that cannot deadlock against a
    /// concurrent witness on the same room. The view is built AFTER the
    /// install so it is segment-aware: a [`crate::store::SessionStoreView`]
    /// freezes its overlay snapshot at construction, and the context pack's
    /// finalize READS its provisional row before rewriting it, so a view
    /// frozen before the segment made finalize a silent no-op that left the
    /// provisional marker standing forever.
    fn staged<F>(&self, apply: F) -> Result<()>
    where
        F: FnOnce(&crate::store::SessionStoreView<'_>, &mut heed::RwTxn<'_>) -> Result<()>,
    {
        let overlay = self.route.overlay();
        let segment = self.vault.with_write_txn(|wtxn| {
            let segment = overlay.install_txn_segment()?;
            self.route.revalidate()?;
            let view = self.vault.store.session_view(overlay.clone())?;
            apply(&view, wtxn)?;
            Ok(segment)
        })?;
        segment.commit()
    }

    /// One BASE-ledger telemetry publication, under the captured route.
    ///
    /// The base telemetry door opens its own transaction and refuses to nest,
    /// so the route cannot ride inside the publishing transaction the way
    /// `witness_with_route` puts it. It is therefore checked on BOTH sides:
    /// the pre-check refuses a room that flipped before the write, and a row
    /// that landed under a route the room replaced DURING the write is
    /// withdrawn rather than left standing — the same compensating shape the
    /// settle contract names for a failed registration. Either way the call
    /// returns the stale-route refusal; it never returns success over a row
    /// the room no longer authorizes.
    fn published(
        &self,
        run_id: crate::store::RetrievalRunId,
        write: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.route.revalidate()?;
        write()?;
        if let Err(stale) = self.route.revalidate() {
            self.vault.store.delete_retrieval_run(run_id)?;
            return Err(stale);
        }
        Ok(())
    }
}
