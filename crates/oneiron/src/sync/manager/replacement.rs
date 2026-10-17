//! Installing a peer's window replacement in place of the live window.

use std::collections::HashMap;
use std::sync::Arc;

use super::WindowManager;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError, SyncProtocolValidation};
use crate::sync::WindowKey;
use crate::sync::schema::create_window_doc;
use crate::sync::window::{self, LoadedWindow, ReplacementConflict};

impl WindowManager {
    /// Replaces window `key` with a peer's history-free `snapshot`
    /// ([`window::prepare_replacement`]), then attaches observers to the new document and
    /// registers it in place of the old one, whose observers drop with it. Returns the keys whose
    /// local value the replacement could not keep, with that value.
    ///
    /// Refused with [`SyncProtocolValidation::ReplacementBusy`], and nothing changes, while any
    /// handle other than the registry's holds the window, or a discarded window's handle is
    /// still alive: such a holder could write the old document, or persist it over the
    /// replacement. The registry lock is held throughout, so no handle can be issued and no
    /// delete can route to the old document meanwhile; the caller retries later.
    pub fn replace_window(
        self: &Arc<Self>,
        key: &WindowKey,
        snapshot: &[u8],
        evidence: &HashMap<EntityId, (WindowKey, Vec<u8>)>,
    ) -> Result<(Arc<LoadedWindow>, Vec<ReplacementConflict>)> {
        self.replace_window_admitted(key, snapshot, evidence, || true)
    }

    /// [`Self::replace_window`] once `admitted` holds. It is judged after any sweep holding the
    /// window closed is done (a residence demotion among them) and under the registry lock, so
    /// no sweep starts between the check and the replacement. Refused with
    /// [`SyncProtocolValidation::ReplacementRejected`] when it does not hold.
    pub fn replace_window_admitted(
        self: &Arc<Self>,
        key: &WindowKey,
        snapshot: &[u8],
        evidence: &HashMap<EntityId, (WindowKey, Vec<u8>)>,
        admitted: impl FnOnce() -> bool,
    ) -> Result<(Arc<LoadedWindow>, Vec<ReplacementConflict>)> {
        self.attach_to_vault();
        let mut registry = self.lock_registry();
        // A window a sweep holds closed is replaced once the sweep is done.
        while self.sweep_fence.holds(key) {
            drop(registry);
            self.sweep_fence.wait_until_open(key);
            registry = self.lock_registry();
        }
        if !admitted() {
            return Err(Error::Sync(SyncError::SyncProtocolError {
                context: SyncProtocolValidation::ReplacementRejected,
            }));
        }
        let current = registry.get(key).map(Arc::clone);
        if current
            .as_ref()
            .is_some_and(|window| Arc::strong_count(window) > 2)
            || self.holds_other_handles(key, current.as_ref())
        {
            return Err(Error::Sync(SyncError::SyncProtocolError {
                context: SyncProtocolValidation::ReplacementBusy,
            }));
        }
        let old = match &current {
            Some(window) => window.doc.clone(),
            None => match window::load_window_from_state(&self.vault, &self.user_id, key) {
                Ok(doc) => doc,
                Err(Error::Sync(SyncError::WindowNotFound { .. })) => {
                    let doc = create_window_doc(&self.user_id, key);
                    window::apply_pending_window_updates(&self.vault, &doc, key)?;
                    doc
                }
                Err(error) => return Err(error),
            },
        };
        let prepared = window::prepare_replacement(
            &self.vault,
            &self.materializer,
            key,
            &old,
            snapshot,
            evidence,
        )?;
        drop(old);
        drop(current);
        let window = Arc::new(LoadedWindow::from_doc_with_outbound(
            prepared.doc,
            key.clone(),
            &self.vault,
            &self.materializer,
            Some(Arc::clone(&self.outbound)),
        ));
        registry.insert(key.clone(), Arc::clone(&window));
        self.track_issued_handle(key, &window);
        drop(registry);
        Ok((window, prepared.conflicts))
    }

    /// Whether a handle this manager issued for `key` is alive and is not `current`.
    fn holds_other_handles(&self, key: &WindowKey, current: Option<&Arc<LoadedWindow>>) -> bool {
        let mut issued = self
            .issued_handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(handles) = issued.get_mut(key) else {
            return false;
        };
        handles.retain(|handle| handle.strong_count() > 0);
        handles.iter().any(|handle| {
            current.is_none_or(|current| !std::ptr::eq(handle.as_ptr(), Arc::as_ptr(current)))
        })
    }
}
