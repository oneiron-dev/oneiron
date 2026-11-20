//! The window a tombstone publication commits to: the registered window, or a
//! closed window's persisted state, held closed while the publication
//! rewrites it.

use std::sync::Arc;

use super::WindowManager;
use crate::sync::WindowKey;
use crate::sync::bridge::Materializer;
use crate::sync::window::LoadedWindow;

/// What a tombstone publication to a window commits to
/// ([`crate::Vault::publication_window`]).
pub(crate) enum PublicationWindow {
    /// The registered window: the publication commits through its document,
    /// in the live-window turn of `materializer`.
    Live {
        window: Arc<LoadedWindow>,
        materializer: Arc<Materializer>,
        manager: Arc<WindowManager>,
    },
    /// No registered window: the publication rewrites the window's persisted
    /// state. The hold keeps the window closed until it drops; with no
    /// manager attached there is none, as then nothing opens or replaces it.
    Closed { _hold: Option<ClosedWindowHold> },
}

/// A closed window a publication holds closed: an open or a replacement of it
/// waits until the hold drops, as for a sweep's mark.
pub(crate) struct ClosedWindowHold {
    manager: Arc<WindowManager>,
    key: WindowKey,
}

impl Drop for ClosedWindowHold {
    fn drop(&mut self) {
        self.manager.sweep_fence.release(&self.key);
    }
}

impl WindowManager {
    /// [`Self::window`] for a tombstone publication to `key`: the registered
    /// window, or else `key` held closed until the returned hold drops.
    ///
    /// A publication to a closed window loads its persisted state, commits
    /// the tombstone to that copy and writes it back. A replacement reads the
    /// same state under the registry lock and installs a document built from
    /// it, deleting the window's pending updates; one that read before the
    /// publication's write and installed after it would put back the state
    /// from before the tombstone. The hold is taken under the registry lock,
    /// which a replacement holds from its read through its install, and
    /// replacements and opens wait for it: each either ends before the
    /// publication looks the window up, or reads the state the publication
    /// wrote. The holder itself waits for no mark, so a publication inside a
    /// sweep of the same window joins the sweep's.
    pub(crate) fn publication_window(self: &Arc<Self>, key: &WindowKey) -> PublicationWindow {
        let registry = self.lock_registry_settled(key);
        if let Some(window) = registry.get(key).map(Arc::clone) {
            #[cfg(test)]
            self.maybe_pause_handle_issue();
            self.track_issued_handle(key, &window);
            drop(registry);
            return PublicationWindow::Live {
                window,
                materializer: Arc::clone(&self.materializer),
                manager: Arc::clone(self),
            };
        }
        self.sweep_fence.hold(key);
        drop(registry);
        PublicationWindow::Closed {
            _hold: Some(ClosedWindowHold {
                manager: Arc::clone(self),
                key: key.clone(),
            }),
        }
    }
}
