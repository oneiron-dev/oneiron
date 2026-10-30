//! A federation socket's admitted window copies (FIX 12118): the filtered
//! copy of each window it fetched, with the selector that admitted it, whose
//! rows' by-reference bodies it is served while that selector stands. At most
//! [`FEDERATION_ADMITTED_WINDOW_COPIES`] copies stay held, the least recently
//! used dropped first. The selector of every window fetched stays for the
//! socket's life, and a dropped copy is rebuilt on its next use exactly as on
//! first use: the home's window filtered by that selector for the socket's
//! peer ([`rebuild`]). No copy is built but through its selector.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use loro::LoroDoc;
use oneiron::authority::PeerMachine;
use oneiron::sync::{SyncSelector, WindowKey, WindowManager, filtered_window_doc_for_peer};

use super::window_sync::selector_grant_scope;

/// How many filtered window copies one federation socket holds at once
/// (CALLS: FEDERATION_ADMITTED_WINDOW_COPIES). A memory bound, never a
/// refusal: a window past it is filtered again on its next use.
pub(super) const FEDERATION_ADMITTED_WINDOW_COPIES: usize = 16;

/// One socket's admitted windows, their held copies in the order last used.
#[derive(Default)]
pub(super) struct AdmittedWindows {
    /// Every window this socket fetched, by key.
    windows: HashMap<WindowKey, Admitted>,
    /// The held copies by use stamp, oldest first.
    order: BTreeMap<u64, WindowKey>,
    next: u64,
}

/// One fetched window: the selector that admitted it, and its copy with the
/// copy's use stamp while held.
struct Admitted {
    selector: SyncSelector,
    copy: Option<(u64, LoroDoc)>,
}

/// One admitted window as a body frame or poll reads it: its held copy, or,
/// once dropped, the selector its next use filters it again by.
pub(super) enum AdmittedCopy {
    Held(LoroDoc),
    Dropped(SyncSelector),
}

impl AdmittedWindows {
    /// Keeps `copy`, the filtered `key` this socket was just sent under
    /// `selector`, as its latest use, in place of what `key` held before.
    pub(super) fn keep(&mut self, key: WindowKey, selector: SyncSelector, copy: LoroDoc) {
        if let Some((earlier, _)) = self.windows.remove(&key).and_then(|admitted| admitted.copy) {
            self.order.remove(&earlier);
        }
        self.windows.insert(
            key.clone(),
            Admitted {
                selector,
                copy: None,
            },
        );
        self.used(&key, copy);
    }

    /// Holds `copy` of `key`, held or rebuilt for a use just done, as its
    /// latest use; past [`FEDERATION_ADMITTED_WINDOW_COPIES`] the least
    /// recently used copy is dropped. A window no longer admitted holds none.
    pub(super) fn used(&mut self, key: &WindowKey, copy: LoroDoc) {
        let Some(admitted) = self.windows.get_mut(key) else {
            return;
        };
        self.next += 1;
        if let Some((earlier, _)) = admitted.copy.replace((self.next, copy)) {
            self.order.remove(&earlier);
        }
        self.order.insert(self.next, key.clone());
        while self.order.len() > FEDERATION_ADMITTED_WINDOW_COPIES {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            if let Some(admitted) = self.windows.get_mut(&oldest) {
                admitted.copy = None;
            }
        }
    }

    /// Each admitted window whose selector `admits`, as a read sees it.
    pub(super) fn read(
        &self,
        mut admits: impl FnMut(&SyncSelector) -> bool,
    ) -> Vec<(WindowKey, AdmittedCopy)> {
        self.windows
            .iter()
            .filter(|(_, admitted)| admits(&admitted.selector))
            .map(|(key, admitted)| {
                let copy = match &admitted.copy {
                    Some((_, doc)) => AdmittedCopy::Held(doc.clone()),
                    None => AdmittedCopy::Dropped(admitted.selector.clone()),
                };
                (key.clone(), copy)
            })
            .collect()
    }
}

/// `key`'s window on the home filtered by `selector` for `peer`, as the fetch
/// that admitted it filtered it (`federation::handle_selector_fetch`); `None`,
/// logged, when the window does not open or filter, as for a window this
/// socket moves no body for.
pub(super) fn rebuild(
    vault: &oneiron::Vault,
    manager: &Arc<WindowManager>,
    key: &WindowKey,
    selector: &SyncSelector,
    peer: PeerMachine,
) -> Option<LoroDoc> {
    let rebuilt = manager.open_window(key).and_then(|window| {
        filtered_window_doc_for_peer(
            vault,
            &window.doc,
            key,
            selector_grant_scope(),
            selector,
            peer,
        )
    });
    match rebuilt {
        Ok(copy) => Some(copy),
        Err(error) => {
            tracing::warn!(
                window = %key,
                kind = ?error.kind(),
                "a federation socket's dropped window copy was not rebuilt; its bodies wait"
            );
            None
        }
    }
}
