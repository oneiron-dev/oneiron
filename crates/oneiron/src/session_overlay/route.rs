use std::sync::Arc;

use crate::error::{Error, Result};

use super::overlay::SessionOverlay;

/// Which store a session write lands in for the session's CURRENT mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteTarget {
    /// `OffRecord` — rows stage into the overlay and evaporate at close.
    Overlay,
    /// `OnRecord` (post-flip) — rows take the ordinary base apply under the
    /// session's on-record continuation shell.
    Base,
}

/// The mode-aware write route (ARCH-0052 D5, K10).
///
/// Minted by `OffRecordSession::write_route()` under the session state lock, so
/// the target and the mode generation it records are the same publication.
/// Every apply route on the session write path carries the route it was
/// constructed with and revalidates it before staging or committing.
///
/// Fields are private to this module: `batch.rs` receives a route and NEVER
/// reads its fields — the route revalidates itself. That is why `revalidate`
/// lives here, in the fields' owner module, rather than at the call site.
pub(crate) struct SessionWriteRoute {
    overlay: Arc<SessionOverlay>,
    target: RouteTarget,
    mode_generation: u64,
}

impl SessionWriteRoute {
    /// Mints a route recording the overlay's currently published mode
    /// generation. Callers hold the session state lock across mint + the mode
    /// read so target and generation cannot disagree.
    pub(crate) fn mint(overlay: &Arc<SessionOverlay>, target: RouteTarget) -> Result<Self> {
        Ok(Self {
            overlay: overlay.clone(),
            target,
            mode_generation: overlay.mode_generation()?,
        })
    }

    /// Refuses with the typed stale-route family if this route was minted
    /// before the most recent mode publication (flip to `OnRecord`, or the
    /// K10 flip-back rearm). Read under the overlay's own state lock against
    /// freshly published state, so a route that survives this check is the
    /// route the current mode authorizes.
    ///
    /// The refusal reuses [`Error::OffRecordOverlayLeaseClosed`], carrying the
    /// route's recorded mode generation: a stale route names a mode epoch that
    /// no longer accepts writes, exactly as a stale lease names a closed
    /// overlay generation.
    pub(crate) fn revalidate(&self) -> Result<()> {
        if self.overlay.mode_generation()? == self.mode_generation {
            return Ok(());
        }
        Err(Error::OffRecordOverlayLeaseClosed {
            generation: self.mode_generation,
        })
    }

    /// Narrow query arm: which store this route resolves to. `batch.rs` may
    /// branch through this method, never through a field read.
    pub(crate) const fn target(&self) -> RouteTarget {
        self.target
    }

    /// The overlay this route stages into. Crate-private and used only by the
    /// session apply entry, which must stage through the same overlay the
    /// route was minted against.
    pub(crate) const fn overlay(&self) -> &Arc<SessionOverlay> {
        &self.overlay
    }
}
