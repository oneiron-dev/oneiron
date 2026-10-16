//! Transactional epoch integration, typed executor coverage, and swap plans.
//!
//! Every door here takes a [`GatedCompaction`]: no summary reaches a mint
//! without passing the pre-swap gate against its own sealed request.

use super::*;
use crate::compaction::gate::GatedCompaction;

impl CompactionDriver {
    /// Commit a compaction and move its covered working outputs to references.
    /// A refused integration leaves the host-owned output context unchanged.
    /// The host retains the `OutputWorkingContext` alongside its message log.
    pub fn integrate_with_outputs(
        &mut self,
        vault: &Vault,
        byline: WriteActor,
        gated: GatedCompaction,
        accumulated: &[CompactionWindowMessage],
        outputs: &mut crate::compaction::output::OutputWorkingContext,
    ) -> Result<SwapPlan> {
        let session_ref = gated.request.session_ref;
        let (turn_start, last) = (
            gated.request.turn_start,
            gated
                .request
                .window
                .last()
                .expect("integrated window is nonempty")
                .turn,
        );
        let plan = self.integrate(vault, &session_ref, byline, gated, accumulated)?;
        outputs.compact_span(turn_start, last);
        Ok(plan)
    }

    /// Commit executor run/span coverage with the actual minted SUMMARY,
    /// born at the run's `placement` in the same transaction.
    /// Read-time views project this record; the driver advances only on commit.
    pub(crate) fn integrate_with_coverage(
        &mut self,
        vault: &Vault,
        byline: WriteActor,
        placement: crate::compaction::EpochPlacement,
        gated: GatedCompaction,
        accumulated: &[CompactionWindowMessage],
        span: &crate::code_run::ExecutorOutputSpan,
    ) -> Result<SwapPlan> {
        let session_ref = gated.request.session_ref;
        self.integrate_inner(gated, accumulated, |request, product| {
            mint_epoch_summary_with(
                vault,
                &session_ref,
                byline,
                request,
                product,
                |txn, mint| {
                    vault.put_code_run_compaction_coverage_in_txn(txn, span, mint)?;
                    placement.settle_in(&vault.store, txn, mint.summary_id())
                },
            )
        })
    }

    /// [`Self::integrate_with_coverage`] for a run in an off-record room: the
    /// summary and the run's coverage land in the room's overlay through
    /// `session`, on the `route` the run captured at entry, and drop with it
    /// at close. Such a summary takes no birth stamp: it is never exported.
    pub(crate) fn integrate_in_overlay(
        &mut self,
        session: &crate::off_record::OffRecordSession<'_>,
        route: &crate::session_overlay::SessionWriteRoute,
        byline: WriteActor,
        gated: GatedCompaction,
        accumulated: &[CompactionWindowMessage],
        span: &crate::code_run::ExecutorOutputSpan,
    ) -> Result<SwapPlan> {
        let session_ref = gated.request.session_ref;
        self.integrate_inner(gated, accumulated, |request, product| {
            mint_epoch_summary_in_overlay(
                session,
                route,
                &session_ref,
                byline,
                request,
                product,
                |view, txn, mint| span.put_coverage_in(view, txn, mint),
            )
        })
    }

    /// A session-bound run's landing, on the `route` it captured at entry
    /// (Docs Q17, agent-runtime-v1 #d7). An off-record room's summary lands
    /// in its overlay ([`Self::integrate_in_overlay`]). A room already on
    /// record at entry lands its summary in base under the room's saver, the
    /// way the run's other base writes land, born at the run's `placement`.
    /// An anonymous room keeps nothing: its route refuses.
    #[expect(
        clippy::too_many_arguments,
        reason = "the overlay landing's arguments plus the base birth placement"
    )]
    pub(crate) fn integrate_in_session(
        &mut self,
        session: &crate::off_record::OffRecordSession<'_>,
        route: &crate::session_overlay::SessionWriteRoute,
        byline: WriteActor,
        placement: crate::compaction::EpochPlacement,
        gated: GatedCompaction,
        accumulated: &[CompactionWindowMessage],
        span: &crate::code_run::ExecutorOutputSpan,
    ) -> Result<SwapPlan> {
        if route.target() == crate::session_overlay::RouteTarget::Overlay {
            return self.integrate_in_overlay(session, route, byline, gated, accumulated, span);
        }
        let session_ref = gated.request.session_ref;
        session.executor_land_base_epoch(route, |vault, landing| {
            self.integrate_inner(gated, accumulated, |request, product| {
                mint_epoch_summary_guarded(
                    vault,
                    &session_ref,
                    byline,
                    request,
                    product,
                    landing,
                    |txn, mint| {
                        vault.put_code_run_compaction_coverage_in_txn(txn, span, mint)?;
                        placement.settle_in(&vault.store, txn, mint.summary_id())
                    },
                )
            })
        })
    }

    /// Integrates a finished compaction: mints the epoch summary and returns
    /// the swap plan.
    ///
    /// THIS is the moment the epoch increments — integration, when the
    /// compaction result is used, not when the work began (owner unification
    /// line). `request` is authoritative for the covered TURN ids and the turn
    /// range; backend-returned range metadata is never accepted.
    ///
    /// One vault write transaction carries the H-S3 probe, the epoch
    /// derivation, the SUMMARY put, its pending-embedding marker and the
    /// capped `DerivedFrom` edge set. The session's message-log splice
    /// (prefix out, summary in, `accumulated` replayed on top) is the caller's
    /// in-memory step: the engine never holds the session's log.
    pub fn integrate(
        &mut self,
        vault: &Vault,
        session_ref: &EntityId,
        byline: WriteActor,
        gated: GatedCompaction,
        accumulated: &[CompactionWindowMessage],
    ) -> Result<SwapPlan> {
        self.integrate_inner(gated, accumulated, |request, product| {
            mint_epoch_summary_with(vault, session_ref, byline, request, product, |_, _| Ok(()))
        })
    }

    /// Checks `gated` is the active flight, then `mint`s its summary.
    fn integrate_inner(
        &mut self,
        gated: GatedCompaction,
        accumulated: &[CompactionWindowMessage],
        mint: impl FnOnce(&CompactionRequest, &CompactionProduct) -> Result<(u64, EntityId)>,
    ) -> Result<SwapPlan> {
        let CompactionState::Compacting {
            request: active, ..
        } = &self.state
        else {
            return Err(Error::InvariantViolation(
                "integrate is legal only while compacting",
            ));
        };
        // Compare both the unique job identity and the sealed input. A stale,
        // duplicate, foreign-driver, or edited request cannot mint or clear
        // the current flight, nor feed its latency into the margin law.
        let GatedCompaction { request, product } = gated;
        let request = &request;
        if active.as_deref() != Some(request) {
            return Err(Error::InvariantViolation(
                "compaction result does not match the active request",
            ));
        }
        let (epoch, summary_id) = mint(request, &product)?;
        self.margin.observe_latency(product.latency);
        self.completed_watermark = Some(request.watermark);
        self.state = CompactionState::Idle;
        Ok(SwapPlan {
            epoch,
            summary_id,
            retained_tail: accumulated.to_vec(),
        })
    }
}
