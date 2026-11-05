//! Optional derived copies carried through a synchronous canonical import.
//! This context neither admits source writes nor proves a durable receipt.

use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::Arc;

use super::retained::PreparedHomeClaimResponse;
use crate::sync::types::WindowKey;
use crate::{EntityId, Vault};

thread_local! {
    static COPIES: RefCell<Option<CopyScope>> = const { RefCell::new(None) };
}

struct CopyScope {
    vault: PathBuf,
    window: String,
    copies: Vec<Arc<PreparedHomeClaimResponse>>,
}

struct Restore(Option<CopyScope>);

impl Drop for Restore {
    fn drop(&mut self) {
        let outer = self.0.take();
        COPIES.with(|slot| *slot.borrow_mut() = outer);
    }
}

/// Keeps the actual copies and native key leases alive while `land` runs on
/// this thread. The caller encloses the real outer canonical writer's commit,
/// not just a callback or savepoint. An empty inner scope masks any outer one.
/// This does not retain copies across a process exit or asynchronous work.
pub(crate) fn with_copies<T>(
    vault: &Vault,
    window: &WindowKey,
    copies: &[Arc<PreparedHomeClaimResponse>],
    land: impl FnOnce() -> T,
) -> T {
    let scope = (!copies.is_empty()).then(|| CopyScope {
        vault: vault.store.env.path().to_path_buf(),
        window: window.as_str().to_owned(),
        copies: copies.to_vec(),
    });
    let _restore = Restore(COPIES.with(|slot| std::mem::replace(&mut *slot.borrow_mut(), scope)));
    land()
}

/// Selects the actual in-memory holders, not a permission or a serialized
/// instance id. Their retainer still checks the current peer, exact canonical
/// source and native response obligations in the real writer.
pub(crate) fn copies_for(
    vault: &Vault,
    window: &WindowKey,
    id: &EntityId,
) -> Vec<Arc<PreparedHomeClaimResponse>> {
    COPIES.with(|slot| {
        let borrowed = slot.borrow();
        let Some(scope) = borrowed.as_ref().filter(|scope| {
            scope.vault == vault.store.env.path() && scope.window == window.as_str()
        }) else {
            return Vec::new();
        };
        scope
            .copies
            .iter()
            .filter(|copy| copy.entity_id() == *id)
            .cloned()
            .collect()
    })
}
