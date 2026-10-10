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


    /// Commit executor run/span coverage with the actual minted SUMMARY.
    /// Read-time views project this record; the driver advances only on commit.
    pub(crate) fn integrate_with_coverage(
        &mut self,
        vault: &Vault,
        byline: WriteActor,
        gated: GatedCompaction,
        accumulated: &[CompactionWindowMessage],
        span: &crate::code_run::ExecutorOutputSpan,
    ) -> Result<SwapPlan> {
        let session_ref = gated.request.session_ref;
        self.integrate_inner(
            vault,
            &session_ref,
            byline,
            gated,
            accumulated,
            |txn, mint| vault.put_code_run_compaction_coverage_in_txn(txn, span, mint),
        )
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
        self.integrate_inner(
            vault,
            session_ref,
            byline,
            gated,
            accumulated,
            |_, _| Ok(()),
        )
    }

    fn integrate_inner(
        &mut self,
        vault: &Vault,
        session_ref: &EntityId,
        byline: WriteActor,
        gated: GatedCompaction,
        accumulated: &[CompactionWindowMessage],
        extra: impl FnOnce(&mut heed::RwTxn<'_>, &crate::compaction::EpochMint) -> Result<()>,
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
