//! The reap freeze's write admission (FIX 6902): what a served write and a
//! background pass take, held until their last write.
//!
//! One short lock holds the freeze and the writes admitted in flight,
//! counted by kind. A write is counted in the same hold that reads the
//! freeze, so a freeze either counts it or refuses it, and what a freeze
//! reads is exactly the writes it let in; a refused write is never counted.
//! Each admission is released as it drops, wherever that is, and the lock is
//! never held across an await or a storage call.
//!
//! The freeze is also the Dreamer's pause (FIX 6909), as one watch per
//! epoch: `true` once frozen. A thaw starts a fresh epoch and leaves the
//! last one `true`, closed, so a pass that read it stays paused and its
//! next pass reads the new one.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use oneiron_vault_contract::{IdleReapInFlight, REAP_PAUSE_REFUSAL};
use tokio::sync::watch;

use super::{ManagedState, WRITES_FROZEN_TAG};
use crate::ai_host::DreamerControl;
use crate::managed::ManagedError;
use crate::server::{HousekeepingAdmission, PassControl};

/// What an admitted write is, as a reap's freeze counts it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WriteKind {
    /// The owner's foreground work: a served request other than a read, a
    /// held MCP socket's receipt, a voice call or live voice session, a
    /// device sync connection, a relay delete, a mutating ctl request, or an
    /// agent run.
    OwnerWrite,
    /// A tagging pass.
    BackgroundTagging,
    /// A Dreamer pass, and the home timer, drafts and fallback timers its
    /// gate admits.
    Dreamer,
    /// Every other background pass.
    BackgroundOther,
    /// A backup before an idle reap, counted from its start under the
    /// freeze until it ends.
    Backup,
}

impl WriteKind {
    /// Whether it is a background pass, which an idle reap's preparation
    /// waits for before it judges the vault quiet.
    fn background(self) -> bool {
        matches!(
            self,
            Self::BackgroundTagging | Self::Dreamer | Self::BackgroundOther
        )
    }
}

/// The admitted writes in flight, by kind.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct InFlightCounts {
    pub(super) owner_write: u64,
    pub(super) background_tagging: u64,
    pub(super) dreamer: u64,
    pub(super) background_other: u64,
    pub(super) backup: u64,
}

impl InFlightCounts {
    fn of(&mut self, kind: WriteKind) -> &mut u64 {
        match kind {
            WriteKind::OwnerWrite => &mut self.owner_write,
            WriteKind::BackgroundTagging => &mut self.background_tagging,
            WriteKind::Dreamer => &mut self.dreamer,
            WriteKind::BackgroundOther => &mut self.background_other,
            WriteKind::Backup => &mut self.backup,
        }
    }

    /// Every write in flight.
    pub(super) fn total(&self) -> u64 {
        self.owner_write + self.background() + self.backup
    }

    /// The background passes in flight.
    pub(super) fn background(&self) -> u64 {
        self.background_tagging + self.dreamer + self.background_other
    }

    /// As an idle reap's answer carries them: backups among the other.
    pub(super) fn wire(&self) -> IdleReapInFlight {
        IdleReapInFlight {
            owner_write: self.owner_write,
            background_tagging: self.background_tagging,
            dreamer: self.dreamer,
            other: self.background_other + self.backup,
        }
    }
}

/// The freeze and the writes in flight, under one lock.
struct Gate {
    /// The current epoch of the freeze: `true` while frozen.
    frozen: watch::Sender<bool>,
    in_flight: InFlightCounts,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            frozen: watch::channel(false).0,
            in_flight: InFlightCounts::default(),
        }
    }
}

/// A managed vault's write admission.
pub(super) struct Admission {
    gate: Mutex<Gate>,
    /// Bumped as each background pass's admission drops, so a wait for
    /// them looks again.
    ended: watch::Sender<u64>,
}

impl Default for Admission {
    fn default() -> Self {
        Self {
            gate: Mutex::default(),
            ended: watch::channel(0).0,
        }
    }
}

/// One admitted write's place among those in flight, released as it drops.
pub(super) struct Admitted {
    admission: Arc<Admission>,
    kind: WriteKind,
}

impl Drop for Admitted {
    fn drop(&mut self) {
        let mut gate = self.admission.gate();
        let count = gate.in_flight.of(self.kind);
        *count = count.saturating_sub(1);
        drop(gate);
        if self.kind.background() {
            self.admission
                .ended
                .send_modify(|ended| *ended = ended.wrapping_add(1));
        }
    }
}

impl Admission {
    fn gate(&self) -> MutexGuard<'_, Gate> {
        self.gate.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn is_frozen(&self) -> bool {
        *self.gate().frozen.borrow()
    }

    /// Freezes: no write is admitted after, and the epoch's passes read
    /// their pause. Returns the writes in flight at that moment, read in the
    /// same hold.
    pub(super) fn freeze(&self) -> InFlightCounts {
        let gate = self.gate();
        gate.frozen.send_replace(true);
        gate.in_flight
    }

    /// Lifts the freeze with a fresh epoch. The last one keeps its `true`
    /// and closes. Unfrozen, nothing changes.
    pub(super) fn thaw(&self) {
        let mut gate = self.gate();
        let frozen = *gate.frozen.borrow();
        if frozen {
            gate.frozen = watch::channel(false).0;
        }
    }

    /// The freeze's current epoch, as a Dreamer pass reads its pause.
    pub(super) fn pass_pause(&self) -> watch::Receiver<bool> {
        self.gate().frozen.subscribe()
    }

    /// The writes in flight now.
    pub(super) fn in_flight(&self) -> InFlightCounts {
        self.gate().in_flight
    }

    /// Changes as each background pass's admission drops.
    pub(super) fn ended(&self) -> watch::Receiver<u64> {
        self.ended.subscribe()
    }

    /// Counts a `kind` write in flight, unless frozen: then `None`, and
    /// nothing is counted.
    fn admit(self: &Arc<Self>, kind: WriteKind) -> Option<Admitted> {
        let mut gate = self.gate();
        if *gate.frozen.borrow() {
            return None;
        }
        *gate.in_flight.of(kind) += 1;
        drop(gate);
        Some(Admitted {
            admission: Arc::clone(self),
            kind,
        })
    }

    /// Counts a `kind` write in flight, frozen or not: a backup before an
    /// idle reap, which starts under the freeze.
    pub(super) fn hold(self: &Arc<Self>, kind: WriteKind) -> Admitted {
        *self.gate().in_flight.of(kind) += 1;
        Admitted {
            admission: Arc::clone(self),
            kind,
        }
    }
}

/// The Dreamer's control (FIX 6909), made before the managed state exists:
/// a pass is admitted as a Dreamer write once `state` holds that state, and
/// refused until then, and reads `admission`'s current epoch as its pause.
pub(super) fn dreamer_control(
    admission: &Arc<Admission>,
    state: &Arc<OnceLock<Arc<ManagedState>>>,
) -> DreamerControl {
    let state = Arc::clone(state);
    let epochs = Arc::clone(admission);
    DreamerControl {
        admission: Arc::new(move || state.get()?.admit_background(WriteKind::Dreamer)),
        pause: Arc::new(move || epochs.pass_pause()),
    }
}

impl ManagedState {
    /// This state over `admission`, the reap freeze the Dreamer's control
    /// was made on before the state existed (FIX 6909).
    #[must_use]
    pub(super) fn with_admission(mut self, admission: Arc<Admission>) -> Self {
        self.admission = admission;
        self
    }

    /// Admits a `kind` write, counted until it drops. While the vault is
    /// frozen for reap it is refused, as [`Self::guard_write`] refuses, and
    /// not counted.
    pub(super) fn admit(&self, kind: WriteKind) -> Result<Admitted, ManagedError> {
        self.admission.admit(kind).ok_or(ManagedError::WritesFrozen)
    }

    /// A worker's admission, counted as `kind` and held on the pass's own
    /// thread until its last write. A refused pass logs the pause's typed
    /// reason, once per freeze, and asks again later.
    pub(super) fn admit_background(&self, kind: WriteKind) -> Option<Box<dyn Send>> {
        match self.admit(kind) {
            Ok(admission) => Some(Box::new(admission)),
            Err(_) => {
                if !self.background_waiting.swap(true, Ordering::SeqCst) {
                    tracing::info!(
                        reason = WRITES_FROZEN_TAG,
                        bound_kind = REAP_PAUSE_REFUSAL.bound.kind.as_str(),
                        bound_resource = REAP_PAUSE_REFUSAL.bound.resource.as_str(),
                        bound_phase = REAP_PAUSE_REFUSAL.bound.phase.as_str(),
                        "background passes wait: the vault is paused for reap preparation until the reap is aborted or the vault wakes again"
                    );
                }
                None
            }
        }
    }

    /// [`Self::admit_background`] as the admission a worker takes.
    pub(super) fn background_admission(self: &Arc<Self>, kind: WriteKind) -> HousekeepingAdmission {
        let state = Arc::clone(self);
        Arc::new(move || state.admit_background(kind))
    }

    /// [`Self::background_admission`] with the reap freeze as the pause
    /// the worker reads between its units.
    pub(super) fn pass_control(self: &Arc<Self>, kind: WriteKind) -> PassControl {
        let admission = Arc::clone(&self.admission);
        PassControl::new(
            self.background_admission(kind),
            Arc::new(move || admission.is_frozen()),
        )
    }
}
