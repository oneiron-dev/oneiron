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
//! The host supplies the long-wait timer. The engine keeps a scoped pointer
//! to a live, journaled model step and polls the same provider future while
//! that timer runs. Shed admission requires exactly one journaled outbound
//! step (a live model wait or a `Pending` effect intent). No threshold policy,
//! outbound reissue or intent-ledger write lives here.
//!
//! Each live outbound wait, a model call or an admitted effect send, also
//! carries a monotonic start and an opaque process-local id, so a supervisor
//! can read how long the selected step has waited and guard its shed with
//! that observation ([`supervisor`], FIX 5186).
//!
//! `Reaped` is deliberately absent from [`VaultResidency`]: once the host kills
//! the process no live [`Vault`] value exists, so process absence is the third
//! ladder state.

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

mod outbound_wait;
mod owner_admission;
pub mod public;
pub mod supervisor;
pub use outbound_wait::OutboundWaitHost;
pub use owner_admission::{OwnerShedAttempt, OwnerShedStep};

use crate::Vault;
use crate::attempt_queue::AttemptId;
#[cfg(feature = "sync")]
use crate::error::SyncError;
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
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ShedCause {
    LongOutboundWait,
    MemoryPressure,
}

/// Stable pointer to the one durable step retained across SLIM.
///
/// Payloads, credentials and responses stay in their existing journals. These
/// identities are resume points, never instructions to reissue an outbound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournaledResumeStep {
    OutboundIntent {
        intent_id: IntentId,
        attempt_id: AttemptId,
        call_seq: u64,
        updated_ms: u64,
    },
    Model {
        attempt_id: AttemptId,
        step_hash: [u8; 32],
        updated_ms: u64,
    },
}

impl JournaledResumeStep {
    /// The journal may refresh a timestamp without changing step identity.
    #[must_use]
    pub(crate) fn same_step(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::OutboundIntent {
                    intent_id,
                    attempt_id,
                    call_seq,
                    ..
                },
                Self::OutboundIntent {
                    intent_id: other_intent,
                    attempt_id: other_attempt,
                    call_seq: other_seq,
                    ..
                },
            ) => intent_id == other_intent && attempt_id == other_attempt && call_seq == other_seq,
            (
                Self::Model {
                    attempt_id,
                    step_hash,
                    ..
                },
                Self::Model {
                    attempt_id: other_attempt,
                    step_hash: other_hash,
                    ..
                },
            ) => attempt_id == other_attempt && step_hash == other_hash,
            _ => false,
        }
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
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
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
#[derive(
    Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(tag = "kind", rename_all = "snake_case")]
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
    /// Live model waits and admitted effect sends. Model waits count toward
    /// selection and change only while holding `state`, so a completed wait
    /// cannot race selection and leave the process parked on a stale step.
    /// An effect send's `Pending` row is what selection counts, so its live
    /// wait changes under this lock alone.
    live_waits: Mutex<Vec<LiveWait>>,
    /// The last [`LiveWait::wait_id`] handed out. Process-local and never
    /// persisted.
    last_wait_id: AtomicU64,
    wait_host: Mutex<Option<Arc<dyn OutboundWaitHost>>>,
    /// The owner's own shed requests, in turn (FIX 10157).
    owner_line: owner_admission::OwnerShedLine,
}

/// One live outbound wait: a journaled model call the engine is polling, or
/// an admitted effect send on the wire. Nothing of its payload is kept.
#[derive(Clone, Copy, Debug)]
struct LiveWait {
    step: JournaledResumeStep,
    /// Opaque and process-local: names this one wait, never a step.
    wait_id: u64,
    /// Monotonic, so a wall-clock jump never stretches or shrinks a wait.
    started: Instant,
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

    /// Poison-recovering, like [`Self::lock_state`]. When both are taken,
    /// `state` comes first.
    fn lock_live_waits(&self) -> MutexGuard<'_, Vec<LiveWait>> {
        self.live_waits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The one live wait on `step`, or `None` when none or more than one is
    /// registered for it.
    fn live_wait_on(&self, step: &JournaledResumeStep) -> Option<LiveWait> {
        let waits = self.lock_live_waits();
        let mut on_step = waits.iter().filter(|wait| wait.step.same_step(step));
        match (on_step.next(), on_step.next()) {
            (Some(wait), None) => Some(*wait),
            _ => None,
        }
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

/// Result of steps 0 and 1, taken with the transition lock held: the shed's
/// outcome is already decided, or `step` goes on to the drop phases.
enum ShedAdmission {
    Decided(ShedOutcome),
    Admitted {
        step: JournaledResumeStep,
        admitted_residue: Option<SlimResidue>,
    },
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
    /// Called by the vault-side ctl adapter or the host's long-wait hook.
    /// `cause` and `waited_secs` are the host's observation, ride the shed log,
    /// and are validated only for positivity. Policy lives in the host.
    ///
    /// The transaction runs in exactly this order:
    ///
    /// 0. **Journaled step first** — exactly one live model wait or
    ///    `IntentState::Pending` row read through `intent_ledger_records`.
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
        require_positive_wait(waited_secs)?;

        // Serialize selection through publish with inbound resume. Selecting
        // before this lock could admit stale journal evidence after a resume.
        let mut state = self.slim.lock_state();
        match self.admit_shed(&state)? {
            ShedAdmission::Decided(outcome) => Ok(outcome),
            ShedAdmission::Admitted {
                step,
                admitted_residue,
            } => self.drop_rebuildable_heap(
                &mut state,
                step,
                admitted_residue,
                cause,
                waited_secs,
                now_ms,
            ),
        }
    }

    /// Steps 0 and 1 of [`Self::shed_rebuildable_heap`]. The caller holds the
    /// transition lock and keeps it through publish.
    fn admit_shed(&self, state: &SlimState) -> Result<ShedAdmission> {
        let selection = self.select_journaled_resume_step()?;

        // Step 1 — admission. The guard remains held through publish.
        let admitted_residue = match state {
            SlimState::Full => None,
            SlimState::Slim(residue) => Some(residue.clone()),
        };
        let step = match (&admitted_residue, selection) {
            (None, StepSelection::Blocked(blocker)) => {
                return Ok(ShedAdmission::Decided(ShedOutcome::Refused(blocker)));
            }
            // The pending row may simply have completed. No identity remains
            // to re-drop against, so report the existing residue unchanged.
            (Some(residue), StepSelection::Blocked(_)) => {
                return Ok(ShedAdmission::Decided(ShedOutcome::AlreadySlim {
                    residue: residue.clone(),
                    dropped: HeapDropReport::default(),
                }));
            }
            (Some(residue), StepSelection::Selected(step)) => {
                if !residue.step.same_step(&step) {
                    return Ok(ShedAdmission::Decided(ShedOutcome::Refused(
                        ShedBlocker::AlreadySlimForDifferentStep,
                    )));
                }
                step
            }
            (None, StepSelection::Selected(step)) => step,
        };
        Ok(ShedAdmission::Admitted {
            step,
            admitted_residue,
        })
    }

    /// Steps 2 to 4 of [`Self::shed_rebuildable_heap`] for an admitted step:
    /// the one fixed-order drop transaction every shed runs. The caller still
    /// holds the transition lock `state` came from.
    fn drop_rebuildable_heap(
        &self,
        state: &mut SlimState,
        step: JournaledResumeStep,
        admitted_residue: Option<SlimResidue>,
        cause: ShedCause,
        waited_secs: u64,
        now_ms: u64,
    ) -> Result<ShedOutcome> {
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
        let derived = self.with_write_txn_grouped(|wtxn| {
            // Heal-mode maintenance can leave malformed source rows outside
            // the usable graph. Validate without healing in this SAME write
            // snapshot before dropping anything: lazy rebuild must be able
            // to recover every source row, not just the healed subset.
            crate::ports::RetrievalIndexMaintenance::port_retrieval_validate_rebuild(self, &*wtxn)?;
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
                residue.step = step;
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
    /// Called on managed HTTP ingress, outbound transport completion, and
    /// durable LLM provider replies. Rebuilding remains a first-use operation.
    ///
    /// # Errors
    ///
    /// Infallible today; the `Result` is the pinned handler-entry-point shape
    /// the ctl adapter binds to.
    pub fn resume_from_slim_on_inbound(&self) -> Result<InboundResumeOutcome> {
        let mut state = self.slim.lock_state();
        // `take` restores the `Full` default, which is exactly the transition.
        let outcome = match std::mem::take(&mut *state) {
            SlimState::Full => InboundResumeOutcome::AlreadyFull,
            SlimState::Slim(residue) => InboundResumeOutcome::Resumed { residue },
        };
        drop(state);
        // The owner's waiting shed looks again, woken outside the lock.
        self.wake_owner_shed();
        Ok(outcome)
    }

    /// Engine truth at shed time, with the transition lock held: one live
    /// model step whose Started row precedes its wait, or one Pending intent.
    fn select_journaled_resume_step(&self) -> Result<StepSelection> {
        let listing = intent_ledger_records(self).map_err(map_intent_ledger_error)?;
        if let Some(corrupt) = listing.corrupt.into_iter().next() {
            return Err(map_intent_ledger_error(corrupt.error));
        }

        let mut pending: Vec<_> = listing
            .records
            .into_iter()
            // A Deferred send still waits on its provider's remote task (FIX
            // 7960): it is an open step, as a Pending one is.
            .filter(|record| matches!(record.state, IntentState::Pending | IntentState::Deferred))
            .map(|record| JournaledResumeStep::OutboundIntent {
                intent_id: record.id,
                attempt_id: record.attempt_id,
                call_seq: record.call_seq,
                updated_ms: record.updated_ms,
            })
            .collect();
        // A live effect send is already counted by its Pending row above.
        pending.extend(
            self.slim
                .lock_live_waits()
                .iter()
                .map(|wait| wait.step)
                .filter(|step| matches!(step, JournaledResumeStep::Model { .. })),
        );
        match pending.as_slice() {
            [] => Ok(StepSelection::Blocked(ShedBlocker::NoPendingOutboundStep)),
            [step] => Ok(StepSelection::Selected(*step)),
            steps => Ok(StepSelection::Blocked(
                ShedBlocker::MultiplePendingOutboundSteps { count: steps.len() },
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
            Err(Error::Sync(SyncError::WindowBusy {
                window_key,
                outstanding_handles,
            })) => Ok(Err(ShedBlocker::SyncWindowBusy {
                window_key,
                outstanding_handles,
            })),
            Err(other) => Err(other),
        }
    }
}

/// Defense in depth with the ctl request validator; neither layer compares
/// the duration to a policy constant.
fn require_positive_wait(waited_secs: u64) -> Result<()> {
    if waited_secs == 0 {
        return Err(Error::InvalidConfig(
            "shed requires a positive waited_secs".to_owned(),
        ));
    }
    Ok(())
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
        | IntentLedgerError::InvalidBoundActor
        | IntentLedgerError::FailureResultIneligible
        | IntentLedgerError::Step(_) => Error::CorruptedIndex(ERR_INTENT_LEDGER_ROW),
    }
}

#[cfg(test)]
mod tests;
