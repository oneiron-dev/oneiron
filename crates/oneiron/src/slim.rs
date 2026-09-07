//! SLIM residency (ONE-1933 / OF-447): the engine half of the
//! FULL → SLIM → REAPED ladder.
//!
//! This module owns the shared vocabulary, the in-process residency state and
//! the fixed-order shed transaction. It is deliberately NOT a plugin registry
//! and NOT a scheduler: the transaction calls the three concrete drop
//! producers directly (`WindowManager::drop_rebuildable_windows`
//! under the `sync` feature, `drop_rebuildable_ppr_cache` and
//! `drop_rebuildable_hnsw`), and every dropped structure is
//! rebuilt lazily by its own ordinary first-use path.
//!
//! What this module never does: start a timer, poll, hold an egress slot,
//! observe the outbound wait itself, or write the intent ledger. The long-wait
//! observation is host-side (Hypnos); the engine validates only that
//! `waited_secs` is positive and that exactly one durable `Pending` outbound
//! step exists. No threshold policy lives here.
//!
//! `Reaped` is deliberately absent from [`VaultResidency`]: once the host kills
//! the process no live [`Vault`] value exists, so process absence is the third
//! ladder state.

use std::sync::{Mutex, MutexGuard};

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::error::{Error, Result};
use crate::outbound_intent_ledger::{
    IntentId, IntentLedgerError, IntentState, intent_ledger_records,
};

/// Fail-closed direction for any unreadable outbound-intent ledger row. No
/// `error.rs` edit and no new variant: a damaged journal must never be read as
/// "no pending step" and admit a shed.
const ERR_INTENT_LEDGER_ROW: &str = "outbound intent ledger row is unreadable";

/// Live-process residency. `Reaped` is process absence and remains host-owned.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VaultResidency {
    #[default]
    Full,
    Slim,
}

/// Why the host asked for a shed. Observability only — the engine never
/// compares it, or `waited_secs`, against a policy constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShedCause {
    LongOutboundWait,
    MemoryPressure,
}

/// Stable pointer to the one durable step retained across SLIM.
///
/// It never copies payload, auth material, endpoint or provider text: the full
/// frozen call stays in the durable ledger, and this pointer is used only for
/// admission identity and observability — never to reissue, cancel or rewrite
/// the intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournaledResumeStep {
    pub intent_id: IntentId,
    pub attempt_id: AttemptId,
    pub call_seq: u64,
    /// Observability timestamp from the selected ledger row; never admission
    /// identity.
    pub updated_ms: u64,
}

impl JournaledResumeStep {
    /// Admission identity deliberately excludes `updated_ms`: the landed
    /// ledger may touch a still-Pending row (a retry-begin / non-delivery
    /// marker) without changing the journaled outbound step. Derived
    /// `PartialEq` remains structural only and must never gate shed admission.
    ///
    /// Not a `const fn`: identity compares an `IntentId` array and an
    /// `AttemptId` through `PartialEq`, which is not callable in const
    /// context on stable.
    #[must_use]
    pub(crate) fn same_step(&self, other: &Self) -> bool {
        self.intent_id == other.intent_id
            && self.attempt_id == other.attempt_id
            && self.call_seq == other.call_seq
    }
}

/// What SLIM residency retains: one stable journal pointer and when the vault
/// first entered SLIM for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlimResidue {
    pub step: JournaledResumeStep,
    pub entered_at_ms: u64,
}

/// Counts of concrete work one shed performed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HeapDropReport {
    pub sync_windows: u64,
    pub ppr_cache_rows: u64,
    pub ppr_dependency_rows: u64,
    pub hnsw_nodes: u64,
    /// Lower-bound proxy from persisted snapshot lengths. The heap actually
    /// freed — chiefly Loro op history — is typically much larger and is not
    /// cheaply measurable. Nonzero means the shed did concrete work; it is
    /// never an RSS-delta predictor.
    pub estimated_reclaimed_bytes: u64,
}

impl HeapDropReport {
    /// Field-wise merge of the sync, PPR and HNSW reports. Every count field
    /// is disjoint across producers and sums into its matching output field;
    /// no max/overwrite rule is permitted.
    #[must_use]
    fn merged(self, other: Self) -> Self {
        Self {
            sync_windows: self.sync_windows.saturating_add(other.sync_windows),
            ppr_cache_rows: self.ppr_cache_rows.saturating_add(other.ppr_cache_rows),
            ppr_dependency_rows: self
                .ppr_dependency_rows
                .saturating_add(other.ppr_dependency_rows),
            hnsw_nodes: self.hnsw_nodes.saturating_add(other.hnsw_nodes),
            estimated_reclaimed_bytes: self
                .estimated_reclaimed_bytes
                .saturating_add(other.estimated_reclaimed_bytes),
        }
    }
}

/// Why a shed was refused. Every variant is defined unconditionally so the
/// public outcome shape does not vary by build feature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShedBlocker {
    NoPendingOutboundStep,
    MultiplePendingOutboundSteps {
        count: usize,
    },
    SyncWindowBusy {
        window_key: String,
        outstanding_handles: usize,
    },
    AlreadySlimForDifferentStep,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShedOutcome {
    Entered {
        residue: SlimResidue,
        dropped: HeapDropReport,
    },
    AlreadySlim {
        residue: SlimResidue,
        dropped: HeapDropReport,
    },
    Refused(ShedBlocker),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InboundResumeOutcome {
    AlreadyFull,
    Resumed { residue: SlimResidue },
}

/// Serializes shed/resume TRANSITIONS. It holds state only; the transaction
/// itself lives in the `impl Vault` blocks below.
///
/// The mutex guarantees transition atomicity, nothing more. Slim residency is
/// not an exclusion lock on rebuild/use paths: ordinary component use (window
/// open, PPR recompute, HNSW write) may re-inflate heap while residency is
/// `Slim` — including in the instant between a drop phase and publish. That is
/// by design; the same-step re-shed exists to re-park it.
#[derive(Debug, Default)]
pub(crate) struct SlimController {
    state: Mutex<SlimState>,
}

impl SlimController {
    /// Poison-recovering lock, matching the vault's other state mutexes: the
    /// state is only ever replaced wholesale after a fully successful
    /// transition, so a panicked holder cannot leave it half-updated.
    fn lock_state(&self) -> MutexGuard<'_, SlimState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum SlimState {
    #[default]
    Full,
    Slim(SlimResidue),
}

/// Result of step 0 (journaled-step selection). A hard read failure is an
/// `Err` on the enclosing `Result` and never a blocker.
enum StepSelection {
    Selected(JournaledResumeStep),
    Blocked(ShedBlocker),
}

impl Vault {
    /// The vault's current live-process residency.
    #[must_use]
    pub fn residency(&self) -> VaultResidency {
        match &*self.slim.lock_state() {
            SlimState::Full => VaultResidency::Full,
            SlimState::Slim(_) => VaultResidency::Slim,
        }
    }

    /// Drops every rebuildable heap structure and parks the vault in SLIM.
    ///
    /// Called by the vault-side ctl adapter. No timer path calls this, and the
    /// engine never observes the wait itself: `cause` and `waited_secs` are the
    /// host's observation, ride the shed log, and are validated only for
    /// positivity. Policy lives in the host scheduler.
    ///
    /// The transaction runs in exactly this order:
    ///
    /// 0. **Journaled step first** — exactly one `IntentState::Pending` row
    ///    read through the existing read-only `intent_ledger_records` API.
    /// 1. **Admission second**, with the controller mutex held through publish.
    /// 2. **Sync** — persist and deregister every manager-owned live window. A
    ///    busy external window handle refuses before any registry mutation.
    /// 3. **Derived indexes** — one LMDB write transaction clears the PPR
    ///    cache and marks/drops the HNSW graph shape, committing once.
    /// 4. **Publish/return.**
    ///
    /// A drop-phase failure preserves the residency admitted at entry: a
    /// first-entry failure leaves `Full`, a re-drop failure leaves the existing
    /// `Slim(residue)` unchanged including its previous `updated_ms`. Already
    /// dropped derived state is safe because each component's ordinary
    /// first-use path rebuilds it.
    ///
    /// # Errors
    ///
    /// Returns the existing invalid-config error when `waited_secs == 0`, and
    /// propagates storage/ledger failures. Refusals are `Ok(Refused(..))`.
    pub fn shed_rebuildable_heap(
        &self,
        cause: ShedCause,
        waited_secs: u64,
        now_ms: u64,
    ) -> Result<ShedOutcome> {
        // Defense in depth with the ctl request validator; neither layer
        // compares the duration to a policy constant.
        if waited_secs == 0 {
            return Err(Error::InvalidConfig(
                "shed requires a positive waited_secs".to_owned(),
            ));
        }

        // Serialize selection through publish with inbound resume. Selecting
        // before this lock could admit stale journal evidence after a resume.
        let mut state = self.slim.lock_state();
        let selection = self.select_journaled_resume_step()?;

        // Step 1 — admission. The guard remains held through publish.
        let admitted_residue = match &*state {
            SlimState::Full => None,
            SlimState::Slim(residue) => Some(residue.clone()),
        };
        let step = match (&admitted_residue, selection) {
            (None, StepSelection::Blocked(blocker)) => return Ok(ShedOutcome::Refused(blocker)),
            // The pending row may simply have completed. No identity remains
            // to re-drop against, so report the existing residue unchanged.
            (Some(residue), StepSelection::Blocked(_)) => {
                return Ok(ShedOutcome::AlreadySlim {
                    residue: residue.clone(),
                    dropped: HeapDropReport::default(),
                });
            }
            (Some(residue), StepSelection::Selected(step)) => {
                if !residue.step.same_step(&step) {
                    return Ok(ShedOutcome::Refused(
                        ShedBlocker::AlreadySlimForDifferentStep,
                    ));
                }
                step
            }
            (None, StepSelection::Selected(step)) => step,
        };

        // Step 2 — sync windows.
        #[cfg(feature = "sync")]
        let dropped = match self.drop_rebuildable_sync_windows()? {
            Ok(report) => report,
            Err(blocker) => return Ok(ShedOutcome::Refused(blocker)),
        };
        #[cfg(not(feature = "sync"))]
        let dropped = HeapDropReport::default();

        // Step 3 — derived indexes, one write transaction, committed once. Any
        // failure aborts it and leaves every derived row unchanged.
        let derived = self.with_write_txn(|wtxn| {
            // Heal-mode maintenance can leave malformed source rows outside
            // the usable graph. Validate without healing in this SAME write
            // snapshot before dropping anything: lazy rebuild must be able
            // to recover every source row, not just the healed subset.
            for entry in self.store.vectors.iter(&*wtxn)? {
                let (id_bytes, vector_bytes) = entry?;
                crate::maintain::validate_rebuild_vector(self, &id_bytes, &vector_bytes)?;
            }
            let ppr = crate::ppr::drop_rebuildable_ppr_cache(&self.store, wtxn)?;
            let hnsw = crate::hnsw::drop_rebuildable_hnsw(&self.store, wtxn)?;
            Ok(ppr.merged(hnsw))
        })?;
        let dropped = dropped.merged(derived);

        tracing::info!(
            ?cause,
            waited_secs,
            sync_windows = dropped.sync_windows,
            ppr_cache_rows = dropped.ppr_cache_rows,
            ppr_dependency_rows = dropped.ppr_dependency_rows,
            hnsw_nodes = dropped.hnsw_nodes,
            estimated_reclaimed_bytes = dropped.estimated_reclaimed_bytes,
            re_shed = admitted_residue.is_some(),
            "slim: shed the rebuildable heap"
        );

        // Step 4 — publish.
        match admitted_residue {
            None => {
                let residue = SlimResidue {
                    step,
                    entered_at_ms: now_ms,
                };
                *state = SlimState::Slim(residue.clone());
                Ok(ShedOutcome::Entered { residue, dropped })
            }
            Some(mut residue) => {
                // Same-step re-drop: refresh ONLY the observability timestamp,
                // preserve `entered_at_ms`, keep residency.
                residue.step.updated_ms = step.updated_ms;
                *state = SlimState::Slim(residue.clone());
                Ok(ShedOutcome::AlreadySlim { residue, dropped })
            }
        }
    }

    /// Ingress hook for the provider reply or any other next inbound.
    ///
    /// Changes LOGICAL residency only: it opens no window, recomputes no PPR,
    /// rebuilds no HNSW graph, writes no ledger row and schedules no wake.
    /// Rehydrate is lazy by construction — each missing component rebuilds on
    /// its own first use, and the journaled step's send continues through the
    /// existing outbound machinery untouched.
    ///
    /// Production wiring is DECLARED DEFERRED (blueprint §9): this lane ships
    /// the hook uncalled and direct-call tested, without claiming an ingress
    /// caller.
    ///
    /// # Errors
    ///
    /// Infallible today; the `Result` is the pinned handler-entry-point shape
    /// the ctl adapter binds to.
    pub fn resume_from_slim_on_inbound(&self) -> Result<InboundResumeOutcome> {
        let mut state = self.slim.lock_state();
        // `take` restores the `Full` default, which is exactly the transition.
        match std::mem::take(&mut *state) {
            SlimState::Full => Ok(InboundResumeOutcome::AlreadyFull),
            SlimState::Slim(residue) => Ok(InboundResumeOutcome::Resumed { residue }),
        }
    }

    /// Engine truth at shed time: exactly one durable `Pending` outbound step,
    /// read through the existing public read-only ledger API.
    fn select_journaled_resume_step(&self) -> Result<StepSelection> {
        let listing = intent_ledger_records(self).map_err(map_intent_ledger_error)?;
        if let Some(corrupt) = listing.corrupt.into_iter().next() {
            // Fail closed: an unreadable row must never be read as "no pending
            // step" and admit a shed against an unknown journal.
            return Err(map_intent_ledger_error(corrupt.error));
        }

        let pending: Vec<_> = listing
            .records
            .into_iter()
            .filter(|record| record.state == IntentState::Pending)
            .collect();
        match pending.len() {
            0 => Ok(StepSelection::Blocked(ShedBlocker::NoPendingOutboundStep)),
            1 => {
                let record = &pending[0];
                Ok(StepSelection::Selected(JournaledResumeStep {
                    intent_id: record.id,
                    attempt_id: record.attempt_id,
                    call_seq: record.call_seq,
                    updated_ms: record.updated_ms,
                }))
            }
            count => Ok(StepSelection::Blocked(
                ShedBlocker::MultiplePendingOutboundSteps { count },
            )),
        }
    }

    /// Persists and deregisters every manager-owned live window.
    ///
    /// `live_window_manager_attached` is consulted as a read-only fast path and
    /// never written — attach/detach own the flag. A false flag, no manager, or
    /// a true flag whose weak upgrade is dead all mean zero windows dropped,
    /// which is success and not a failure.
    #[cfg(feature = "sync")]
    fn drop_rebuildable_sync_windows(
        &self,
    ) -> Result<std::result::Result<HeapDropReport, ShedBlocker>> {
        if !self
            .live_window_manager_attached
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Ok(Ok(HeapDropReport::default()));
        }
        let manager = self
            .live_window_manager
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .upgrade();
        let Some(manager) = manager else {
            return Ok(Ok(HeapDropReport::default()));
        };
        match manager.drop_rebuildable_windows() {
            Ok(report) => Ok(Ok(report)),
            Err(Error::WindowBusy {
                window_key,
                outstanding_handles,
            }) => Ok(Err(ShedBlocker::SyncWindowBusy {
                window_key,
                outstanding_handles,
            })),
            Err(other) => Err(other),
        }
    }
}

/// Maps the ledger's typed failures onto the engine error surface without
/// touching `error.rs`: engine failures pass through, and every decode/
/// transition failure takes the existing fail-closed `CorruptedIndex`
/// direction.
fn map_intent_ledger_error(error: IntentLedgerError) -> Error {
    match error {
        IntentLedgerError::Engine(engine) => engine,
        IntentLedgerError::InvalidRecord(_)
        | IntentLedgerError::InvalidTransition { .. }
        | IntentLedgerError::InvalidInput(_)
        | IntentLedgerError::InvalidBoundActor => Error::CorruptedIndex(ERR_INTENT_LEDGER_ROW),
    }
}

#[cfg(test)]
mod tests;
