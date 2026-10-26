//! The reconciler's state, built once per vault, its builders, the passes a
//! host worker drives through it, and its staged API (FIX 6755): the claim,
//! the call and the settlement of one marker as phases a host coordinator
//! drives apart, which the synchronous passes compose.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::claim::{ClaimHold, HeldSet, PreparedCall};
use crate::Vault;
use crate::embed::EmbedderLocality;
use crate::error::{Error, Result};
use crate::memory::extraction::{
    EncoderAttempt, EncoderInput, ExtractionCaller, ExtractionEncoder, ExtractionWork,
};
use crate::tagging::marker::TaggingMarkerConfig;
use crate::tagging::trace::{TaggingOutcome, TaggingTrace};

const DEFAULT_LEASE_OWNER: &str = "oneironer-tagging";
const DEFAULT_BATCH_SIZE: usize = 16;

/// Retry backoff for a failed attempt, in store-clock seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaggingBackoff {
    /// Delay before a marker's first retry; every later retry doubles it.
    pub first_secs: u64,
    /// Ceiling on the doubled delay.
    pub max_secs: u64,
}

impl Default for TaggingBackoff {
    fn default() -> Self {
        Self {
            first_secs: 5,
            max_secs: 300,
        }
    }
}

impl TaggingBackoff {
    pub(super) fn delay_secs(self, prior_retries: u32) -> u64 {
        let factor = 1_u64.checked_shl(prior_retries).unwrap_or(u64::MAX);
        self.first_secs.saturating_mul(factor).min(self.max_secs)
    }
}

/// What one pass did.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TaggingPass {
    /// One trace per claimed marker, in claim order.
    pub traces: Vec<TaggingTrace>,
    /// Tagger calls made.
    pub calls: usize,
    /// Calls that returned an error or panicked; a refused answer is not one.
    pub failed_calls: usize,
    /// Whether the host's pause ended the pass before its batch was spent
    /// (FIX 6902): it claimed nothing more, and every marker it did not
    /// claim stays ready.
    pub paused: bool,
}

impl TaggingPass {
    /// The earliest store-clock second a marker this pass failed or
    /// deferred is retried at: when the worker next has a retry to claim,
    /// read from the pass itself rather than from the queue.
    #[must_use]
    pub fn earliest_retry_at(&self) -> Option<u64> {
        self.traces
            .iter()
            .filter_map(|trace| match trace.outcome {
                TaggingOutcome::Failed { retry_at, .. } | TaggingOutcome::Deferred { retry_at } => {
                    Some(retry_at)
                }
                _ => None,
            })
            .min()
    }
}

/// What [`TaggingReconciler::prepare_next`] found in the class it was asked.
#[derive(Debug)]
pub enum TaggingPreparation {
    /// No marker of the class is ready.
    Empty,
    /// Bulk was asked while a live marker is ready: ask again, live first.
    Replan,
    /// The claimed marker settled at once, with no tagger call: its payload
    /// is unreadable, it was rekeyed, its turn is gone or has no text, or a
    /// MESSAGE its saved tags were read from is away from this replica.
    Settled(TaggingTrace),
    /// The claimed marker, owed one call.
    Ready(PreparedTagging),
}

/// One claimed marker between its preparation and its settlement: its lease
/// (the row, its owner and lease generation), its class, the input its call
/// reads, the digests its answer is settled against, its retry depth and the
/// tagger it was prepared for. It holds no transaction, no guard and no
/// borrowed bytes, so it may wait for its call on any task. Dropped
/// unsettled, its marker is handed back by the reconciler's next upkeep.
pub struct PreparedTagging {
    /// The trace its settlement completes.
    pub(super) trace: TaggingTrace,
    pub(super) call: Box<PreparedCall>,
    pub(super) hold: ClaimHold,
}

impl PreparedTagging {
    /// What the call reads.
    #[must_use]
    pub fn input(&self) -> &EncoderInput {
        &self.call.input
    }

    /// The class the call runs at: the marker's effective class when it was
    /// claimed. A live write that promotes it meanwhile makes its next try
    /// live, never this one.
    #[must_use]
    pub fn work(&self) -> ExtractionWork {
        self.call.work
    }
}

impl std::fmt::Debug for PreparedTagging {
    /// The attempt and its class: never the text the call reads.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedTagging")
            .field("attempt", &self.trace.attempt)
            .field("work", &self.call.work)
            .finish_non_exhaustive()
    }
}

/// Drains tagging markers through one host-served tagger.
///
/// Every claimed marker settles inside the pass: completed, retried with
/// backoff, or (for a payload this build cannot read) failed. Each attempt's
/// trace is recorded in the transaction that settles or retries it, and a
/// settled marker leaves the job ledger there, with every try it retried. A
/// marker whose settling write fails stays this reconciler's, as does one a
/// stopped worker left leased, and its next pass hands it back before
/// claiming anything. No marker ever fails the write that committed it.
///
/// A host may drive the same phases one marker at a time instead (FIX 6755):
/// [`Self::ready_class`], [`Self::prepare_next`] and [`Self::settle`], with
/// [`Self::upkeep_until_paused`] between rounds. A marker is this
/// reconciler's from the commit of its claim to the commit that settles it.
pub struct TaggingReconciler {
    pub(super) vault: Arc<Vault>,
    pub(super) encoder: Arc<dyn ExtractionEncoder>,
    /// Who its calls are made for: the vault's own background tagging,
    /// whose calls a host's dispatcher shares its room by (FIX 9519).
    pub(super) caller: ExtractionCaller,
    pub(super) lease_owner: String,
    pub(super) batch_size: usize,
    pub(super) backoff: TaggingBackoff,
    /// The vault's tagging configuration: its mode and label table.
    pub(super) config: TaggingMarkerConfig,
    /// Markers leased under this owner and not settled, each with the reason
    /// it is handed back: a claim, entered before it commits and owned by its
    /// preparation, call or settlement until it settles or its owner lets it
    /// go; and a lease a stopped worker left. No claim, witness or
    /// publication reaches a leased marker, so only this reconciler can
    /// return it.
    pub(super) unsettled: HeldSet,
    /// Whether the scan for stale leases has run; until it has, every pass
    /// starts by running it.
    pub(super) stale_scanned: AtomicBool,
    /// Whether the trace history has been trimmed to the per-turn bound in
    /// force; until it has, every pass starts by trimming the next part.
    pub(super) history_trimmed: AtomicBool,
    /// The turn the next trimming read starts from.
    pub(super) trim_from: Mutex<Option<[u8; 16]>>,
}

impl TaggingReconciler {
    /// A reconciler for an armed vault and an on-device tagger.
    ///
    /// A tagger off the device would carry vault text away, and extraction
    /// leaves the device only behind the host egress predicate, which no
    /// tagger door has yet; so it is refused here.
    pub fn new(vault: Arc<Vault>, encoder: Arc<dyn ExtractionEncoder>) -> Result<Self> {
        let config = vault.config.tagging.clone().ok_or_else(|| {
            Error::InvalidConfig("tagging markers are not armed on this vault".to_owned())
        })?;
        if encoder.locality() != EmbedderLocality::OnDevice {
            return Err(Error::InvalidConfig(
                "a tagger off the device needs the host egress predicate".to_owned(),
            ));
        }
        Ok(Self {
            caller: ExtractionCaller::vault(&vault),
            vault,
            encoder,
            lease_owner: DEFAULT_LEASE_OWNER.to_owned(),
            batch_size: DEFAULT_BATCH_SIZE,
            backoff: TaggingBackoff::default(),
            config,
            unsettled: Arc::new(Mutex::new(Vec::new())),
            stale_scanned: AtomicBool::new(false),
            history_trimmed: AtomicBool::new(false),
            trim_from: Mutex::new(None),
        })
    }

    /// The store clock as this worker reads it, for scheduling its waits:
    /// reading it moves no clock floor of the vault, in memory or on disk, so
    /// a shadow worker leaves every later write's clock as a vault with no
    /// tagger leaves it. A job row is stamped inside its write transaction,
    /// from this or the vault's committed clock floor, whichever is later.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.vault.store.clock.peek_recorded_at()
    }

    /// The stamp a job row this reconciler writes takes, inside its write
    /// transaction: [`Self::now`], or the clock floor the vault has committed
    /// if later. Neither floor moves.
    pub(super) fn stamp_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<u64> {
        crate::ports::job_recorded_at_in_txn(&self.vault.store, txn)
    }

    /// Markers claimed per pass, at least one.
    #[must_use]
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size.max(1);
        self
    }

    #[must_use]
    pub fn with_backoff(mut self, backoff: TaggingBackoff) -> Self {
        self.backoff = backoff;
        self
    }

    /// The lease owner this worker claims under. One worker per vault.
    #[must_use]
    pub fn with_lease_owner(mut self, lease_owner: impl Into<String>) -> Self {
        self.lease_owner = lease_owner.into();
        self
    }

    /// Who its calls are made for, for a host that claims its dispatcher's
    /// room itself ([`Self::prepare_next`], FIX 9519).
    #[must_use]
    pub fn caller(&self) -> &ExtractionCaller {
        &self.caller
    }

    /// Claims and settles up to the batch size of ready markers, after
    /// pruning traces past the history's age.
    ///
    /// A failed attempt ends the pass early: a tagger that is down costs one
    /// attempt per pass, not one per waiting marker, and a refused marker is
    /// never claimed twice in one pass.
    pub fn drain_once(&self) -> Result<TaggingPass> {
        self.drain_once_with(|_| {})
    }

    /// [`Self::drain_once`], handing each trace to `on_trace` the moment its
    /// marker settles.
    ///
    /// An error after a claim leaves that marker leased: the pass keeps it
    /// and returns the error, and the next pass hands it back first.
    pub fn drain_once_with(&self, on_trace: impl FnMut(&TaggingTrace)) -> Result<TaggingPass> {
        self.drain_until_paused(&|| false, on_trace)
    }

    /// [`Self::drain_once_with`], reading `paused` before each marker it
    /// would claim and between the units of its cleanup (FIX 6902). While it
    /// holds, the pass starts nothing more and returns what it did, marked
    /// [`TaggingPass::paused`]: no failure and no backoff, and every marker
    /// it did not claim stays ready. A marker already claimed is tagged and
    /// settled first, under the caller's admission.
    pub fn drain_until_paused(
        &self,
        paused: &dyn Fn() -> bool,
        mut on_trace: impl FnMut(&TaggingTrace),
    ) -> Result<TaggingPass> {
        let mut pass = TaggingPass::default();
        if self.upkeep_until_paused(paused)? {
            pass.paused = true;
            return Ok(pass);
        }
        for _ in 0..self.batch_size {
            if paused() {
                pass.paused = true;
                break;
            }
            // Live first, then bulk, in one claim, which never asks again.
            let trace = match self.prepare(None)? {
                TaggingPreparation::Empty | TaggingPreparation::Replan => break,
                TaggingPreparation::Settled(trace) => trace,
                TaggingPreparation::Ready(mut prepared) => {
                    pass.calls += 1;
                    let called = self.call(&mut prepared);
                    if !matches!(called, Ok(Ok(_))) {
                        pass.failed_calls += 1;
                    }
                    self.settle_called(prepared, called)?
                }
            };
            let failed = matches!(trace.outcome, TaggingOutcome::Failed { .. });
            on_trace(&trace);
            pass.traces.push(trace);
            if failed {
                break;
            }
        }
        Ok(pass)
    }

    /// The upkeep a pass starts with, reading `paused` before each of its
    /// units (FIX 6902): the start scan while it has not run to its end,
    /// else the hand-back of every held marker no preparation, call or
    /// settlement owns; then the trace history's trimming and expiry.
    /// `Ok(true)` when `paused` cut it short: what it did not reach waits for
    /// the next upkeep. A host driving the staged API runs it between its
    /// rounds, under its admission.
    pub fn upkeep_until_paused(&self, paused: &dyn Fn() -> bool) -> Result<bool> {
        let cut_short = if self.stale_scanned.load(Ordering::Acquire) {
            self.return_unsettled(paused)?
        } else {
            // A release the pause cut short leaves the scan not run.
            self.release_stale_leases_until_paused(paused)?;
            !self.stale_scanned.load(Ordering::Acquire)
        };
        // Each later step runs only when the one before it ran to its end.
        if cut_short || self.trim_history(paused)? {
            return Ok(true);
        }
        self.prune_expired_traces(paused)
    }

    /// The class a claim would take now, from one read and no writer: live
    /// when a live marker is ready, else bulk when a bulk one is, else
    /// `None`. A payload this build cannot read counts as live, to be
    /// failed. A readiness entry only waiting for repair is no marker.
    pub fn ready_class(&self) -> Result<Option<ExtractionWork>> {
        self.peek_class()
    }

    /// Claims the next ready marker of class `work` and reads what its call
    /// needs, holding no transaction when it returns. A bulk claim keeps the
    /// live-first fence: it is planned only from a read that found no live
    /// marker ready, and leased only if nothing has committed since or the
    /// writer finds no live marker ready either; otherwise it is
    /// [`TaggingPreparation::Replan`]. A marker owed no call settles here.
    /// From its claim's commit the marker is this reconciler's: an error
    /// before it settles leaves it to the next upkeep's hand-back.
    pub fn prepare_next(&self, work: ExtractionWork) -> Result<TaggingPreparation> {
        self.prepare(Some(work))
    }

    /// Settles `prepared` on its call's `attempt`, which took `timing` from
    /// its submission to its answer. A failed call or a refused answer is a
    /// retry on the failure backoff. An answer that passed is settled against
    /// the turn's text as the settling transaction reads it: saved or
    /// shadowed and the marker completed, or, when the text changed or a
    /// MESSAGE it was read from left this replica, the marker retried in that
    /// same transaction, each with its trace. An error leaves the marker to
    /// the next upkeep's hand-back.
    pub fn settle(
        &self,
        mut prepared: PreparedTagging,
        attempt: EncoderAttempt,
        timing: Duration,
    ) -> Result<TaggingTrace> {
        prepared.trace.call_micros = Some(u64::try_from(timing.as_micros()).unwrap_or(u64::MAX));
        prepared.trace.execution = attempt.execution;
        self.settle_called(prepared, Ok(attempt.result))
    }
}
