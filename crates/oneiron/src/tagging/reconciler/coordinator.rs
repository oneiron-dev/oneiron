//! The reconciler's state, built once per vault, its builders, and the
//! passes a host worker drives through it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use crate::Vault;
use crate::attempt_queue::{AttemptQueue, AttemptRecord};
use crate::embed::EmbedderLocality;
use crate::error::{Error, Result};
use crate::memory::extraction::ExtractionEncoder;
use crate::tagging::marker::TaggingMarkerConfig;
use crate::tagging::trace::{HandBackReason, TaggingOutcome, TaggingTrace};

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

/// Drains tagging markers through one host-served tagger.
///
/// Every claimed marker settles inside the pass: completed, retried with
/// backoff, or (for a payload this build cannot read) failed. Each attempt's
/// trace is recorded in the transaction that settles or retries it, and a
/// settled marker leaves the job ledger there, with every try it retried. A
/// marker whose settling write fails stays this reconciler's, as does one a
/// stopped worker left leased, and its next pass hands it back before
/// claiming anything. No marker ever fails the write that committed it.
pub struct TaggingReconciler {
    pub(super) vault: Arc<Vault>,
    pub(super) encoder: Arc<dyn ExtractionEncoder>,
    pub(super) lease_owner: String,
    pub(super) batch_size: usize,
    pub(super) backoff: TaggingBackoff,
    /// The vault's tagging configuration: its mode and label table.
    pub(super) config: TaggingMarkerConfig,
    /// Markers leased under this owner that no pass is settling, each with
    /// the reason it is handed back: a claim whose settling write failed, or
    /// a lease a stopped worker left. No claim, witness or publication
    /// reaches a leased marker, so only this reconciler can return it.
    pub(super) unsettled: Mutex<Vec<(AttemptRecord, HandBackReason)>>,
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
            vault,
            encoder,
            lease_owner: DEFAULT_LEASE_OWNER.to_owned(),
            batch_size: DEFAULT_BATCH_SIZE,
            backoff: TaggingBackoff::default(),
            config,
            unsettled: Mutex::new(Vec::new()),
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
        let cut_short = if self.stale_scanned.load(Ordering::Acquire) {
            self.return_unsettled(paused)?
        } else {
            // A release the pause cut short leaves the scan not run.
            self.release_stale_leases_until_paused(paused)?;
            !self.stale_scanned.load(Ordering::Acquire)
        };
        // Each later step runs only when the one before it ran to its end.
        if cut_short || self.trim_history(paused)? || self.prune_expired_traces(paused)? {
            pass.paused = true;
            return Ok(pass);
        }
        let queue = AttemptQueue::new(&self.vault);
        for _ in 0..self.batch_size {
            if paused() {
                pass.paused = true;
                break;
            }
            let Some(record) = self.claim()? else {
                break;
            };
            let trace = match self.attempt(&queue, &record, &mut pass) {
                Ok(trace) => trace,
                Err(error) => {
                    self.unsettled
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push((record, HandBackReason::SettlementFailed));
                    return Err(error);
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
}
