//! Optional derived copies carried through a synchronous canonical import.
//! This context neither admits source writes nor proves a durable receipt.

use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::Arc;

use heed::RwTxn;

use super::retained::RetainedHomeClaimState;
use super::retained_copy::PreparedHomeClaimCopy;
use crate::sync::types::WindowKey;
use crate::{EntityId, Result, Vault};

thread_local! {
    static COPIES: RefCell<Option<CopyScope>> = const { RefCell::new(None) };
}

struct CopyScope {
    vault: PathBuf,
    windows: Vec<CopyWindow>,
}

struct CopyWindow {
    window: String,
    copies: Vec<Arc<PreparedHomeClaimCopy>>,
    attempts: Vec<HomeClaimCopyAttempt>,
}

/// The derived operation only. Even an `Ok` was staged in the caller's writer,
/// not certified as durable. A later outer error may follow a real commit;
/// neither this report nor its errors undo Loro or custody-journal effects.
pub(crate) struct HomeClaimCopyAttempt {
    pub(crate) entity_id: EntityId,
    pub(crate) result: Result<RetainedHomeClaimState>,
    /// The actual outer writer's returned result, not proof of rollback on Err.
    pub(crate) writer_result: Option<std::result::Result<(), crate::error::ErrorKind>>,
}

/// Associates only the attempts made during this actual writer call.
/// This holds references and an index, not a transaction or custody guard.
pub(crate) struct CopyWriterObservation<'a> {
    vault: &'a Vault,
    window: &'a str,
    first: usize,
}

pub(crate) fn observe_writer<'a>(
    vault: &'a Vault,
    window: &'a str,
) -> Option<CopyWriterObservation<'a>> {
    COPIES.with(|slot| {
        slot.borrow()
            .as_ref()
            .filter(|scope| scope.vault == vault.store.env.path())
            .and_then(|scope| scope.windows.iter().find(|entry| entry.window == window))
            .map(|scope| CopyWriterObservation {
                vault,
                window,
                first: scope.attempts.len(),
            })
    })
}

impl CopyWriterObservation<'_> {
    /// Observe the native API after it returns, keeping its original result
    /// and error ownership. A postcommit error does not mean nothing landed.
    pub(crate) fn finish<T>(self, result: &Result<T>) {
        COPIES.with(|slot| {
            if let Some(scope) = slot
                .borrow_mut()
                .as_mut()
                .filter(|scope| scope.vault == self.vault.store.env.path())
                .and_then(|scope| {
                    scope
                        .windows
                        .iter_mut()
                        .find(|entry| entry.window == self.window)
                })
            {
                for attempt in &mut scope.attempts[self.first..] {
                    attempt.writer_result = Some(result.as_ref().map(|_| ()).map_err(|e| e.kind()));
                }
            }
        });
    }
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
    copies: &[Arc<PreparedHomeClaimCopy>],
    land: impl FnOnce() -> T,
) -> (T, Vec<HomeClaimCopyAttempt>) {
    with_copy_batch(vault, &[(window, copies)], land)
}

fn with_copy_batch<T>(
    vault: &Vault,
    windows: &[(&WindowKey, &[Arc<PreparedHomeClaimCopy>])],
    land: impl FnOnce() -> T,
) -> (T, Vec<HomeClaimCopyAttempt>) {
    let windows: Vec<_> = windows
        .iter()
        .filter(|(_, copies)| !copies.is_empty())
        .map(|(window, copies)| CopyWindow {
            window: window.as_str().to_owned(),
            copies: copies.to_vec(),
            attempts: Vec::new(),
        })
        .collect();
    let scope = (!windows.is_empty()).then(|| CopyScope {
        vault: vault.store.env.path().to_path_buf(),
        windows,
    });
    let _restore = Restore(COPIES.with(|slot| std::mem::replace(&mut *slot.borrow_mut(), scope)));
    let landed = land();
    let attempts = COPIES.with(|slot| {
        slot.borrow_mut()
            .as_mut()
            .map(|scope| {
                scope
                    .windows
                    .iter_mut()
                    .flat_map(|window| std::mem::take(&mut window.attempts))
                    .collect()
            })
            .unwrap_or_default()
    });
    (landed, attempts)
}

pub(crate) fn with_home_claim_copies<T>(
    vault: &Vault,
    key: &WindowKey,
    copies: &[Arc<PreparedHomeClaimCopy>],
    land: impl FnOnce() -> T,
) -> T {
    with_home_claim_copy_batch(vault, &[(key, copies)], land)
}

/// Keeps every window's native holders and observations around one real root
/// writer. The batch caller supplies distinct window keys.
pub(crate) fn with_home_claim_copy_batch<T>(
    vault: &Vault,
    windows: &[(&WindowKey, &[Arc<PreparedHomeClaimCopy>])],
    land: impl FnOnce() -> T,
) -> T {
    let (landed, attempts) = with_copy_batch(vault, windows, land);
    let mut retained = std::collections::BTreeSet::new();
    for attempt in attempts {
        if matches!(attempt.result.as_ref(), Ok(RetainedHomeClaimState::Stored)) {
            retained.insert(attempt.entity_id);
        }
        tracing::debug!(
            entity = %attempt.entity_id.to_hex(),
            error = ?attempt.result.as_ref().err().map(|error| error.kind()),
            writer_result = ?attempt.writer_result,
            "derived home CLAIM copy attempt; not a durable receipt"
        );
    }
    for id in retained {
        if let Err(error) = vault.complete_pending_retained_home_claim(&id) {
            tracing::debug!(
                entity = %id.to_hex(),
                error = ?error.kind(),
                "immediate retained home CLAIM completion returned an error"
            );
        }
    }
    landed
}

/// A late optional tail can fill only an already-admitted native pending
/// job. Each holder rechecks its exact canonical source and native custody
/// in this same writer. No raw delivery is replayed and no job is created.
pub(crate) fn retain_pending_copies(
    vault: &Vault,
    window: &WindowKey,
    copies: &[Arc<PreparedHomeClaimCopy>],
) {
    if copies.is_empty() {
        return;
    }
    let ids: std::collections::BTreeSet<_> = copies.iter().map(|copy| copy.entity_id()).collect();
    with_home_claim_copies(vault, window, copies, || {
        let observation = observe_writer(vault, window.as_str());
        let result = vault.with_write_txn_grouped(|txn| {
            for id in &ids {
                if crate::sync::queue::has_pending_embed_job_in_txn(&vault.store, txn, id)? {
                    retain_copies_in_txn(vault, txn, window.as_str(), id);
                }
            }
            Ok(())
        });
        if let Some(observation) = observation {
            observation.finish(&result);
        }
        if let Err(error) = result {
            tracing::debug!(
                error = ?error.kind(),
                "late derived home CLAIM writer returned an error; not a rollback receipt"
            );
        }
    });
}

/// Selects the actual in-memory holders, not a permission or a serialized
/// instance id. Their retainer still checks the current peer, exact canonical
/// source and native response obligations in the real writer.
pub(crate) fn copies_for(
    vault: &Vault,
    window: &str,
    id: &EntityId,
) -> Vec<Arc<PreparedHomeClaimCopy>> {
    COPIES.with(|slot| {
        let borrowed = slot.borrow();
        let Some(scope) = borrowed
            .as_ref()
            .filter(|scope| scope.vault == vault.store.env.path())
            .and_then(|scope| scope.windows.iter().find(|entry| entry.window == window))
        else {
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
    window: &str,
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
            if let Some(scope) = slot.borrow_mut().as_mut().and_then(|scope| {
                scope
                    .windows
                    .iter_mut()
                    .find(|entry| entry.window == window)
            }) {
                scope.attempts.push(HomeClaimCopyAttempt {
                    entity_id: *id,
                    result,
                    writer_result: None,
                });
            }
        });
    }
}
