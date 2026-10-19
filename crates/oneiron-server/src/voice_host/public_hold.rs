//! A public live voice session's hold on its host's write gate: one
//! admission, taken when the session starts and dropped for good when its
//! task ends, so a session in flight keeps a managed vault from reading
//! quiescent and a frozen one opens none. On a host whose gate can refuse
//! (managed serve's reap freeze) a session no door named for
//! [`IDLE_RELEASE`] releases it once it rests, so a client that went away
//! keeps no vault from its reap; the session stays open, and the next door
//! that names it takes an admission again. While released nothing the
//! session owns runs: its loop waits, and its media worker and credential
//! recheck are not polled ([`while_held`]), so no write of its lands outside
//! an admission. A host with no freeze never releases one.

use std::future::Future;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use oneiron::memory::{MemoryError, MemoryResult};
use tokio::sync::watch;
use tokio::time::Instant;

/// How long a session may go with no door naming it before it releases its
/// admission, on a host whose gate can refuse.
const IDLE_RELEASE: Duration = Duration::from_secs(60);

/// The typed pause a vault frozen for reap answers a session's admission
/// with, as its served writes are answered.
pub(super) fn writes_frozen() -> MemoryError {
    MemoryError::new(
        crate::managed::WRITES_FROZEN_TAG,
        crate::managed::ManagedError::WritesFrozen.to_string(),
        &[],
    )
}

/// One session's hold on its admission.
pub(super) struct SessionHold {
    state: Mutex<HoldState>,
    /// `true` while the admission is held.
    held: watch::Sender<bool>,
    /// Whether the host's gate can refuse; on one that cannot, the session
    /// never releases its admission.
    releases: bool,
}

struct HoldState {
    /// When a door last named the session.
    seen: Instant,
    admission: Admission,
}

enum Admission {
    /// Held: the guard the gate handed over, dropped on release.
    Held {
        _guard: Box<dyn Send>,
    },
    Released,
    /// The session's task ended: nothing takes an admission for it again.
    Ended,
}

impl SessionHold {
    /// A hold on `admission`, which an idle session releases when
    /// `releases`.
    pub(super) fn new(admission: Box<dyn Send>, releases: bool) -> Self {
        Self {
            state: Mutex::new(HoldState {
                seen: Instant::now(),
                admission: Admission::Held { _guard: admission },
            }),
            held: watch::Sender::new(true),
            releases,
        }
    }

    fn lock(&self) -> MutexGuard<'_, HoldState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A door named the session: its idle clock starts again, and a released
    /// one takes an admission again from `admit`, before the door's call
    /// reaches it. A vault frozen for reap refuses with the typed pause.
    pub(super) fn named(&self, admit: impl FnOnce() -> Option<Box<dyn Send>>) -> MemoryResult<()> {
        let mut state = self.lock();
        state.seen = Instant::now();
        if matches!(state.admission, Admission::Released) {
            state.admission = Admission::Held {
                _guard: admit().ok_or_else(writes_frozen)?,
            };
            // Under the lock, so a release and a readmission are seen in order.
            self.held.send_replace(true);
        }
        Ok(())
    }

    /// When the session's idle release falls due, or `None` on a host whose
    /// gate cannot refuse.
    pub(super) fn release_at(&self) -> Option<Instant> {
        self.releases.then(|| self.lock().seen + IDLE_RELEASE)
    }

    /// Releases the held admission when no door named the session for
    /// [`IDLE_RELEASE`]; whether it did. The caller has checked that the
    /// session rests.
    pub(super) fn release_if_idle(&self) -> bool {
        let mut state = self.lock();
        if !self.releases
            || !matches!(state.admission, Admission::Held { .. })
            || Instant::now() < state.seen + IDLE_RELEASE
        {
            return false;
        }
        state.admission = Admission::Released;
        self.held.send_replace(false);
        true
    }

    /// The hold as a watch: `true` while the admission is held.
    pub(super) fn watch(&self) -> watch::Receiver<bool> {
        self.held.subscribe()
    }

    /// The session's task ended, its work dropped: the admission drops for
    /// good.
    pub(super) fn end(&self) {
        self.lock().admission = Admission::Ended;
    }
}

/// Runs `work` only while `held` says the admission is held: released, it is
/// not polled, so nothing it does lands outside an admission. Ends with
/// `work`.
pub(super) async fn while_held<T>(
    work: impl Future<Output = T>,
    mut held: watch::Receiver<bool>,
) -> T {
    tokio::pin!(work);
    loop {
        // The sender lives as long as the session's task; with it gone,
        // nothing holds the work back.
        if held.wait_for(|held| *held).await.is_err() {
            return work.await;
        }
        let closed = tokio::select! {
            output = &mut work => return output,
            released = held.wait_for(|held| !*held) => released.is_err(),
        };
        if closed {
            return work.await;
        }
    }
}
