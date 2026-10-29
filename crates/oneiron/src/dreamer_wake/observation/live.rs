//! The live half of the wake observation: the passes and admitted calls
//! running on one open vault. The registry holds them weakly; a pass's root
//! holds its own through its deadline, and each call's observer its call.
//! Nothing here is persisted, restored or shared across vaults, and no
//! registry lock is held across a vault write or a guard read.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError, Weak};

use super::read::{WakeLiveCall, WakeLiveState};
use super::{
    AdmittedCall, CallKey, StepTerminal, WakeCallState, WakeObservedCallEnd, WakeRef,
    bind_call_in_txn, record_call_closed, skipped,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::dreamer_wake::WakePassDeadline;
use crate::entity_id::EntityId;
use crate::llm::{BudgetGuard, BudgetLease, BudgetLeaseState};

/// The wake passes running on one open vault, by wake ref (DOOR-144).
pub(crate) struct ActiveWakes {
    wakes: Mutex<BTreeMap<WakeRef, Weak<ActiveWake>>>,
    /// Sixteen random bytes minted once with the vault handle: the boot an
    /// owed wake call names, so a reconcile tells a live call of this process
    /// from what a dead boot left (FIX 11450).
    boot: [u8; 16],
}

impl Default for ActiveWakes {
    fn default() -> Self {
        let mut boot = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut boot);
        Self {
            wakes: Mutex::default(),
            boot,
        }
    }
}

impl ActiveWakes {
    /// This handle's boot nonce.
    pub(crate) fn boot(&self) -> [u8; 16] {
        self.boot
    }

    /// Registers one pass before its header is visible, and returns the hold
    /// its deadline carries. Passes no root holds any more leave here.
    pub(super) fn register(&self, wake: WakeRef, deadline: &WakePassDeadline) -> WakeBinding {
        let live = Arc::new(ActiveWake {
            clock: deadline.unbound(),
            calls: Mutex::default(),
            attempt_lines: Mutex::default(),
        });
        let mut wakes = self.wakes.lock().unwrap_or_else(PoisonError::into_inner);
        wakes.retain(|_, pass| pass.strong_count() > 0);
        wakes.insert(wake, Arc::downgrade(&live));
        drop(wakes);
        WakeBinding { wake, live }
    }

    /// The pass `wake` names, while a root on this handle still runs it.
    pub(super) fn get(&self, wake: WakeRef) -> Option<Arc<ActiveWake>> {
        self.wakes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&wake)
            .and_then(Weak::upgrade)
    }

    /// Records the runner line `attempt` reserved on in `wake`: the line an
    /// owed wake call of that attempt charges (FIX 11450). Nothing when the
    /// pass no longer runs.
    pub(crate) fn record_attempt_line(&self, wake: WakeRef, attempt: AttemptId, line: &str) {
        if let Some(live) = self.get(wake) {
            live.record_attempt_line(attempt, line);
        }
    }
}

/// One running pass: the clock it runs on, and its admitted calls.
pub(crate) struct ActiveWake {
    clock: WakePassDeadline,
    calls: Mutex<BTreeMap<EntityId, Weak<ActiveCall>>>,
    attempt_lines: Mutex<BTreeMap<AttemptId, String>>,
}

impl ActiveWake {
    /// Records the runner line `attempt` reserved on: the line an owed wake
    /// call of that attempt charges (FIX 11450).
    pub(crate) fn record_attempt_line(&self, attempt: AttemptId, line: &str) {
        self.attempt_lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(attempt, line.to_owned());
    }

    /// The runner line `attempt` reserved on, while this pass runs it.
    pub(crate) fn attempt_line(&self, attempt: AttemptId) -> Option<String> {
        self.attempt_lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&attempt)
            .cloned()
    }

    /// Registers one admitted call before its row is visible. Calls no
    /// observer holds any more leave here.
    fn register_call(
        &self,
        call: EntityId,
        guard: &BudgetGuard,
        lease: &BudgetLease,
    ) -> Arc<ActiveCall> {
        let live = Arc::new(ActiveCall {
            call,
            guard: guard.clone(),
            lease_id: lease.id().to_owned(),
        });
        let mut calls = self.calls.lock().unwrap_or_else(PoisonError::into_inner);
        calls.retain(|_, held| held.strong_count() > 0);
        calls.insert(call, Arc::downgrade(&live));
        drop(calls);
        live
    }

    /// The pass's clock and its calls still running, read now. The registry
    /// lock is released before any guard is read.
    pub(super) fn sample(&self) -> WakeLiveState {
        let running: Vec<Arc<ActiveCall>> = self
            .calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        let mut calls = Vec::with_capacity(running.len());
        for call in &running {
            calls.push(WakeLiveCall {
                call: call.call,
                lease_id: call.lease_id.clone(),
                lease: call.guard.lease_observation(&call.lease_id),
            });
        }
        WakeLiveState {
            elapsed_ms: self.clock.elapsed_ms(),
            remaining_ms: self.clock.remaining_ms(),
            calls,
        }
    }
}

/// One admitted call: the guard that issued its lease, and the lease's id.
pub(crate) struct ActiveCall {
    call: EntityId,
    guard: BudgetGuard,
    lease_id: String,
}

/// What a bound deadline carries to its clones: the committed wake, and the
/// hold that keeps the pass live while any clone runs.
#[derive(Clone)]
pub(crate) struct WakeBinding {
    wake: WakeRef,
    live: Arc<ActiveWake>,
}

impl WakeBinding {
    pub(crate) const fn wake(&self) -> WakeRef {
        self.wake
    }
}

/// A durable step's model calls, as its wake binds them.
#[derive(Clone, Copy)]
pub(crate) struct StepCalls<'a> {
    pub(crate) vault: &'a Vault,
    pub(crate) deadline: Option<&'a WakePassDeadline>,
    pub(crate) attempt_id: AttemptId,
    pub(crate) step_hash: [u8; 32],
}

impl<'a> StepCalls<'a> {
    /// Binds a call `guard` just admitted under `lease` to its wake: live
    /// first, then its row in one short write, before anything is sent.
    /// Best-effort: outside an observed pass, or when either fails (logged),
    /// the call runs exactly as it would unobserved.
    pub(crate) fn admitted(
        &self,
        guard: &BudgetGuard,
        lease: &BudgetLease,
        ordinal: u32,
    ) -> ObservedCall<'a> {
        ObservedCall {
            vault: self.vault,
            bound: self.bind(guard, lease, ordinal),
            stated_reset: None,
        }
    }

    fn bind(&self, guard: &BudgetGuard, lease: &BudgetLease, ordinal: u32) -> Option<BoundCall> {
        let deadline = self.deadline?;
        let binding = deadline.wake_binding()?;
        // Sampled just after the guard returned: an upper bound on when it
        // allocated, on the pass's own clock.
        let admitted_elapsed_ms = deadline.elapsed_ms();
        let call = match self.vault.store.clock.entity_id() {
            Ok(call) => call,
            Err(error) => {
                skipped(&error, "admitted call");
                return None;
            }
        };
        let key = CallKey {
            wake: binding.wake,
            attempt: self.attempt_id,
            call,
        };
        // Live before visible: whoever reads the row finds the call.
        let live = binding.live.register_call(call, guard, lease);
        let admitted = AdmittedCall {
            key,
            step_hash: self.step_hash,
            ordinal,
            lease_id: lease.id().to_owned(),
            admitted_elapsed_ms,
        };
        match self.vault.with_write_txn_grouped(|wtxn| {
            let bound = bind_call_in_txn(self.vault, wtxn, &admitted)?;
            // The owed row for this send, beside its call row (FIX 11450): a
            // crash before the attempt settles still charges it. None when the
            // attempt reserved on no recorded line.
            if let Some(line) = binding.live.attempt_line(self.attempt_id) {
                let reserved_units = match guard.lease_observation(lease.id()) {
                    Some(BudgetLeaseState::Open { reserve_units, .. }) => reserve_units,
                    Some(BudgetLeaseState::Settled { .. })
                    | Some(BudgetLeaseState::Aborted)
                    | None => 0,
                };
                let owed = crate::dreamer_wake::owed::WakeOwedCall {
                    boot: self.vault.active_wakes.boot(),
                    line,
                    lease: lease.id().to_owned(),
                    reserved_units,
                    at: crate::unix_seconds_now(),
                };
                crate::dreamer_wake::owed::put_owed_call_in_txn(
                    self.vault,
                    wtxn,
                    self.attempt_id,
                    &self.step_hash,
                    &owed,
                )?;
            }
            Ok(bound)
        }) {
            Ok(true) => Some(BoundCall {
                key,
                live,
                armed: true,
            }),
            Ok(false) => None,
            Err(error) => {
                skipped(&error, "admitted call");
                None
            }
        }
    }
}

/// One admitted call's observation, closed when it drops.
pub(crate) struct ObservedCall<'a> {
    vault: &'a Vault,
    bound: Option<BoundCall>,
    /// The reset the provider limit that refused the call stated.
    stated_reset: Option<u64>,
}

struct BoundCall {
    key: CallKey,
    live: Arc<ActiveCall>,
    armed: bool,
}

impl ObservedCall<'_> {
    /// Which call this step's terminal claim closes.
    pub(crate) fn terminal(&self) -> StepTerminal {
        StepTerminal::Fresh {
            bound: self.bound.is_some(),
        }
    }

    /// A provider limit refused the call and stated it resets at `at`, in
    /// Unix seconds: its end row keeps it, so a Retry park its try makes is
    /// due then (FIX 11226).
    pub(crate) fn refused_until(&mut self, at: u64) {
        self.stated_reset = Some(at);
    }

    /// The step's terminal claim recorded this call's end in its own write:
    /// nothing is left to close.
    pub(crate) fn claimed(&mut self) {
        if let Some(bound) = &mut self.bound {
            bound.armed = false;
        }
    }
}

impl Drop for ObservedCall<'_> {
    /// Records how the call closed, as its guard holds the lease once
    /// whatever settled or aborted it on the way out has run.
    fn drop(&mut self) {
        let Some(bound) = self.bound.take() else {
            return;
        };
        if !bound.armed || std::thread::panicking() {
            return;
        }
        let (state, used_units) = match bound.live.guard.lease_observation(&bound.live.lease_id) {
            Some(BudgetLeaseState::Settled { used_units }) => {
                (WakeCallState::Settled, Some(used_units))
            }
            Some(BudgetLeaseState::Aborted) => (WakeCallState::Aborted, None),
            Some(BudgetLeaseState::Open { .. }) | None => (WakeCallState::Unsettled, None),
        };
        let end = WakeObservedCallEnd {
            state,
            at_unix_ms: crate::unix_millis_now(),
            used_units,
            claim: None,
            stated_reset: self.stated_reset,
        };
        record_call_closed(self.vault, bound.key, end);
    }
}
