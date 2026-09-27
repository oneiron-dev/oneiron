//! Transactional epoch integration, output-marker mint, and swap plans.

use super::*;

impl CompactionDriver {
    /// Commit a compaction and move its covered working outputs to references.
    /// A refused integration leaves the host-owned output context unchanged.
    /// The host retains the `OutputWorkingContext` alongside its message log.
    pub fn integrate_with_outputs(
        &mut self,
        vault: &Vault,
        byline: WriteActor,
        request: &CompactionRequest,
        product: CompactionProduct,
        accumulated: &[CompactionWindowMessage],
        outputs: &mut crate::compaction::output::OutputWorkingContext,
    ) -> Result<SwapPlan> {
        let plan = self.integrate(
            vault,
            &request.session_ref,
            byline,
            request,
            product,
            accumulated,
        )?;
        let last = request
            .window
            .last()
            .expect("integrated window is nonempty")
            .turn;
        outputs.compact_span(request.turn_start, last);
        Ok(plan)
    }

    /// Commit the epoch summary and every executor coverage marker in ONE
    /// transaction. The live views move only after that transaction commits.
    #[expect(
        clippy::too_many_arguments,
        reason = "sealed compaction input and atomic output markers"
    )]
    pub(crate) fn integrate_with_output_markers(
        &mut self,
        vault: &Vault,
        byline: WriteActor,
        request: &CompactionRequest,
        product: CompactionProduct,
        accumulated: &[CompactionWindowMessage],
        outputs: &mut crate::compaction::output::OutputWorkingContext,
        markers: &[(crate::code_run::CodeRunRawOutput, Vec<u8>)],
    ) -> Result<SwapPlan> {
        let (_, last) = validate_window_span(&request.window)?;
        let covered = last
            .checked_sub(request.turn_start)
            .and_then(|span| span.checked_add(1))
            .ok_or(Error::InvariantViolation(
                "compaction output span is invalid",
            ))?;
        if markers.len() as u64 != covered {
            return Err(Error::InvariantViolation(
                "compaction output markers must cover the span",
            ));
        }
        let plan = self.integrate_inner(
            vault,
            &request.session_ref,
            byline,
            request,
            product,
            accumulated,
            |txn| {
                for (marker, raw) in markers {
                    vault.put_code_run_raw_output_in_txn(txn, marker, raw)?;
                }
                Ok(())
            },
        )?;
        let last = request
            .window
            .last()
            .expect("integrated window is nonempty")
            .turn;
        outputs.compact_span(request.turn_start, last);
        Ok(plan)
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
        request: &CompactionRequest,
        product: CompactionProduct,
        accumulated: &[CompactionWindowMessage],
    ) -> Result<SwapPlan> {
        self.integrate_inner(
            vault,
            session_ref,
            byline,
            request,
            product,
            accumulated,
            |_| Ok(()),
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "sealed compaction input and atomic extra write"
    )]
    fn integrate_inner(
        &mut self,
        vault: &Vault,
        session_ref: &EntityId,
        byline: WriteActor,
        request: &CompactionRequest,
        product: CompactionProduct,
        accumulated: &[CompactionWindowMessage],
        extra: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<()>,
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
        if active.as_deref() != Some(request) {
            return Err(Error::InvariantViolation(
                "compaction result does not match the active request",
            ));
        }
        let (epoch, summary_id) =
            mint_epoch_summary_with(vault, session_ref, byline, request, &product, extra)?;
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
