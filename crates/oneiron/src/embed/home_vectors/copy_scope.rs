//! Optional derived copies carried through a synchronous canonical import.
//! This context neither admits source writes nor proves a durable receipt.

use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::Arc;

use heed::RwTxn;

use super::retained::{PreparedHomeClaimResponse, RetainedHomeClaimResponseState};
use crate::sync::types::WindowKey;
use crate::{EntityId, Result, Vault};

thread_local! {
    static COPIES: RefCell<Option<CopyScope>> = const { RefCell::new(None) };
}

struct CopyScope {
    vault: PathBuf,
    window: String,
    copies: Vec<Arc<PreparedHomeClaimResponse>>,
    attempts: Vec<HomeClaimCopyAttempt>,
}

/// The derived operation only. Even an `Ok` was staged in the caller's writer,
/// not certified as durable. A later outer error may follow a real commit;
/// neither this report nor its errors undo Loro or custody-journal effects.
pub(crate) struct HomeClaimCopyAttempt {
    pub(crate) entity_id: EntityId,
    pub(crate) result: Result<RetainedHomeClaimResponseState>,
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
) -> (T, Vec<HomeClaimCopyAttempt>) {
    let scope = (!copies.is_empty()).then(|| CopyScope {
        vault: vault.store.env.path().to_path_buf(),
        window: window.as_str().to_owned(),
        copies: copies.to_vec(),
        attempts: Vec::new(),
    });
    let _restore = Restore(COPIES.with(|slot| std::mem::replace(&mut *slot.borrow_mut(), scope)));
    let landed = land();
    let attempts = COPIES.with(|slot| {
        slot.borrow_mut()
            .as_mut()
            .map(|scope| std::mem::take(&mut scope.attempts))
            .unwrap_or_default()
    });
    (landed, attempts)
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

/// Runs only after the native canonical admission. Each optional copy gets a
/// child savepoint: a derived error is reported, not turned into a canonical
/// admission error. The native outer writer still owns its commit and errors.
/// A child commit is not the outer writer's durability receipt.
pub(crate) fn retain_copies_in_txn(
    vault: &Vault,
    parent: &mut RwTxn<'_>,
    window: &WindowKey,
    id: &EntityId,
) {
    for copy in copies_for(vault, window, id) {
        let result = (|| {
            let mut savepoint = vault.store.env.nested_write_txn(parent)?;
            let state = copy.retain_in_txn(vault, &mut savepoint)?;
            savepoint.commit()?;
            Ok(state)
        })();
        COPIES.with(|slot| {
            if let Some(scope) = slot.borrow_mut().as_mut() {
                scope.attempts.push(HomeClaimCopyAttempt {
                    entity_id: *id,
                    result,
                });
            }
        });
    }
}
