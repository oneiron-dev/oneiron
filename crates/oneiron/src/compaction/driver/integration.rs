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
    /// A self-written summary (FIX 4465) lands only with its `landing`: its
    /// packet must be the gated request's own, and its receipt rides the
    /// coverage row and the summary's birth.
    #[expect(
        clippy::too_many_arguments,
        reason = "the coverage landing's arguments plus a self-written summary's landing"
    )]
    pub(crate) fn integrate_with_coverage(
        &mut self,
        vault: &Vault,
        byline: WriteActor,
        placement: crate::compaction::EpochPlacement,
        gated: GatedCompaction,
        accumulated: &[CompactionWindowMessage],
        span: &crate::code_run::ExecutorOutputSpan,
        landing: Option<crate::compaction::SelfLanding>,
    ) -> Result<SwapPlan> {
        let session_ref = gated.request.session_ref;
        if let Some(landing) = &landing {
            let WindowLog::Host { run: Some(run), .. } = gated.request.log else {
                return Err(Error::InvariantViolation(
                    "a self-written epoch is cut from no run's log",
                ));
            };
            Self::check_self_landing(&gated, run, byline, landing)?;
        }
        let writer = landing.map(|landing| landing.execution);
        self.integrate_inner(gated, accumulated, |request, product| {
            mint_epoch_summary_with(
                vault,
                &session_ref,
                byline,
                request,
                product,
                writer.as_ref(),
                |txn, mint| {
                    vault.put_code_run_compaction_coverage_in_txn(
                        txn,
                        span,
                        mint,
                        writer.as_ref(),
                    )?;
                    placement.settle_in(&vault.store, txn, mint.summary_id())
                },
            )
        })
    }

    /// A self-written summary's packet belongs to its gated request (FIX
    /// 4465): admitted on `run`'s log for exactly the request's span, in its
    /// session, over its turns, as a digest of exactly the gated prose, with
    /// the snapshot its pass stamped, written by the run's own byline. An
    /// epoch's request must name `run` too; a fold's names none.
    pub(crate) fn check_self_landing(
        gated: &GatedCompaction,
        run: EntityId,
        byline: WriteActor,
        landing: &crate::compaction::SelfLanding,
    ) -> Result<()> {
        let request = &gated.request;
        let last = request
            .window
            .last()
            .ok_or(Error::InvariantViolation(
                "compaction window carries no messages",
            ))?
            .turn;
        let mut turns: Vec<EntityId> = Vec::new();
        for message in &request.window {
            if !turns.contains(&message.turn_id) {
                turns.push(message.turn_id);
            }
        }
        let packet = &landing.packet;
        let same_run = match request.log {
            WindowLog::Host { run: Some(named), .. } => named == run,
            WindowLog::Host { run: None, .. } => true,
            WindowLog::Conversation => false,
        };
        let bound = packet.host_log().is_some_and(|log| {
            log.run_id == run && log.first == request.turn_start && log.last == last
        });
        if !same_run
            || !bound
            || packet.session() != request.session_ref
            || packet.turn_ids() != turns.as_slice()
            || packet.digest_text() != Some(gated.product.summary_text.as_str())
            || landing.execution.snapshot().as_ref() != Some(packet.snapshot())
            || landing.execution.writer != byline.entity_ref()
        {
            return Err(Error::InvariantViolation(
                "a self-written summary's packet is not its gated request's",
            ));
        }
        Ok(())
    }

    /// [`Self::integrate_with_coverage`] for a run in an off-record room: the
    /// summary and the run's coverage land in the room's overlay through
    /// `session`, on the `route` the run captured at entry, and drop with it
    /// at close. Such a summary takes no birth stamp: it is never exported.
    /// The vector its pass embedded, if any, stages with it.
    pub(crate) fn integrate_in_overlay(
        &mut self,
        session: &crate::off_record::OffRecordSession<'_>,
        route: &crate::session_overlay::SessionWriteRoute,
        byline: WriteActor,
        mut gated: GatedCompaction,
        accumulated: &[CompactionWindowMessage],
        span: &crate::code_run::ExecutorOutputSpan,
    ) -> Result<SwapPlan> {
        let session_ref = gated.request.session_ref;
        let vector = gated.vector.take();
        self.integrate_inner(gated, accumulated, |request, product| {
            mint_epoch_summary_in_overlay(
                session,
                route,
                &session_ref,
                byline,
                request,
                product,
                vector.as_ref(),
                |view, txn, mint| span.put_coverage_in(view, txn, mint, None),
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
                    None,
                    landing,
                    |txn, mint| {
                        vault.put_code_run_compaction_coverage_in_txn(txn, span, mint, None)?;
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
    /// `DerivedFrom` edge set. The session's message-log splice
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
            mint_epoch_summary_with(
                vault,
                session_ref,
                byline,
                request,
                product,
                None,
                |_, _| Ok(()),
            )
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
        let GatedCompaction {
            request, product, ..
        } = gated;
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
