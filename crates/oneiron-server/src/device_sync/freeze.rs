//! The reap freeze a managed vault's device sync works under (WILL-PLAN L14
//! row 14, FIX 5127). The connection holds no admission for its life: each
//! batch it applies or sends takes one (FIX 12036), and so does each model
//! catalog refresh, each candidacy write a catch-up starts and each removal
//! archive import (FIX 12038). A freeze does not count them among its writes
//! in flight, as a live connection is always running; it pauses the
//! connection with its socket open, and a reap waits for the batches in
//! flight to end before it judges the vault quiet. After the thaw the same
//! connection runs on. Self-hosted serve has no reap: its batches are always
//! admitted and never paused.

use tokio::sync::watch;

use crate::server::HousekeepingAdmission;

/// One batch's, refresh's, write's or import's admission, released as it
/// drops.
pub(super) type Admitted = Box<dyn Send>;

/// What device sync takes for each batch, refresh, write and import, and the
/// freeze that pauses the connection.
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

    /// Self-hosted serve's: every batch admitted, never frozen.
    pub(super) fn never() -> Self {
        Self::new(crate::server::admit_every_pass(), watch::channel(false).1)
    }

    /// One admission now, or `None` while frozen.
    pub(super) fn admit(&self) -> Option<Admitted> {
        (self.admit)()
    }

    /// The admission alone, for a refresh, write or import beside the
    /// connection.
    #[cfg_attr(not(feature = "mesh"), allow(dead_code))]
    pub(super) fn admission(&self) -> HousekeepingAdmission {
        std::sync::Arc::clone(&self.admit)
    }

    /// Resolves once the vault is not frozen for reap: at once while it is
    /// not, and at the thaw while it is (FIX 12036, FIX 12154); never if the
    /// freeze goes while frozen.
    #[cfg_attr(not(feature = "mesh"), allow(dead_code))]
    pub(super) async fn thawed(&mut self) {
        let closed = self.frozen.wait_for(|frozen| !*frozen).await.is_err();
        if closed {
            std::future::pending::<()>().await;
        }
    }

    /// Waits out a freeze: the first admission after the thaw, or `None`
    /// once `stop` is sent (or the freeze is gone). A vault frozen again
    /// before the admission is waited out again. The archive receiver waits
    /// on it too, so it runs without the `mesh` feature as well.
    #[cfg_attr(not(feature = "mesh"), allow(dead_code))]
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
