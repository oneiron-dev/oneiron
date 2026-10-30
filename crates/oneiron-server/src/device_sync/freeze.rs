//! The reap freeze a managed vault's device sync works under (WILL-PLAN L14
//! row 14, FIX 5127). The connection holds no admission for its life: each
//! run between freezes takes one, and so does each model catalog refresh
//! and each candidacy write a catch-up starts. A freeze does not count them
//! among its writes in flight, as a live connection is always running; it
//! pauses the run, which ends as a stop ends it, and a reap waits for its
//! end before it judges the vault quiet. After the thaw the same connection
//! runs again on a fresh admission. Self-hosted serve has no reap: its runs
//! are always admitted and never paused.

use tokio::sync::watch;

use crate::server::HousekeepingAdmission;

/// One run's, refresh's or write's admission, released as it drops.
pub(super) type Admitted = Box<dyn Send>;

/// What device sync takes for each run, refresh and write, and the freeze
/// that pauses a run.
#[derive(Clone)]
#[cfg_attr(not(feature = "mesh"), allow(dead_code))]
pub(crate) struct ReapFreeze {
    /// One admission, `None` while the vault is frozen for reap.
    admit: HousekeepingAdmission,
    /// `true` while the vault is frozen for reap.
    frozen: watch::Receiver<bool>,
}

impl ReapFreeze {
    /// A managed vault's: `admit` refuses while `frozen` reads `true`.
    pub(crate) fn new(admit: HousekeepingAdmission, frozen: watch::Receiver<bool>) -> Self {
        Self { admit, frozen }
    }

    /// Self-hosted serve's: every run admitted, never frozen.
    pub(super) fn never() -> Self {
        Self::new(crate::server::admit_every_pass(), watch::channel(false).1)
    }

    /// One admission now, or `None` while frozen.
    pub(super) fn admit(&self) -> Option<Admitted> {
        (self.admit)()
    }

    /// The admission alone, for a refresh or write beside the run.
    #[cfg(feature = "mesh")]
    pub(super) fn admission(&self) -> HousekeepingAdmission {
        std::sync::Arc::clone(&self.admit)
    }

    /// Resolves once the vault is frozen for reap; never where no freeze
    /// can come (serve's freeze, whose sender is gone).
    #[cfg(feature = "mesh")]
    pub(super) async fn frozen(&mut self) {
        let closed = self.frozen.wait_for(|frozen| *frozen).await.is_err();
        if closed {
            std::future::pending::<()>().await;
        }
    }

    /// Waits out a freeze: the first admission after the thaw, or `None`
    /// once `stop` is sent (or the freeze is gone). A vault frozen again
    /// before the admission is waited out again.
    #[cfg(feature = "mesh")]
    pub(super) async fn resumed(
        &mut self,
        stop: &mut tokio::sync::oneshot::Receiver<()>,
    ) -> Option<Admitted> {
        loop {
            let thawed = tokio::select! {
                biased;
                _ = &mut *stop => return None,
                thawed = self.frozen.wait_for(|frozen| !*frozen) => thawed.is_ok(),
            };
            if !thawed {
                return None;
            }
            if let Some(admitted) = self.admit() {
                return Some(admitted);
            }
        }
    }
}
