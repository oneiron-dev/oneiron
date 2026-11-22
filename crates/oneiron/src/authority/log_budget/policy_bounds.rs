//! The bounds the authority observation policy's rows set: the signer
//! bound, the fold headroom rows and the fold's memory floor, with the
//! per-thread overrides tests scale them by.

use super::*;

/// The least the memory floor's default reaches, however small the machine.
const FOLD_MEMORY_FLOOR_MIN_BYTES: u64 = 1024 * 1024 * 1024;

/// Runs `body` with the signer bound and the row and pair headroom rows
/// scaled to `rows` per signer on this thread, so a test crosses them in a
/// few rows.
#[cfg(test)]
pub(crate) fn with_rows_per_signer_for_test<T>(rows: usize, body: impl FnOnce() -> T) -> T {
    ROWS_PER_SIGNER_FOR_TEST.with(|bound| bound.set(Some(rows)));
    let result = body();
    ROWS_PER_SIGNER_FOR_TEST.with(|bound| bound.set(None));
    result
}

/// Runs `body` with every fold on this thread under a memory floor of
/// `bytes`, the policy row's or the default's.
#[cfg(test)]
pub(crate) fn with_fold_memory_floor_for_test<T>(bytes: u64, body: impl FnOnce() -> T) -> T {
    FOLD_MEMORY_FLOOR_FOR_TEST.with(|floor| floor.set(Some(bytes)));
    let result = body();
    FOLD_MEMORY_FLOOR_FOR_TEST.with(|floor| floor.set(None));
    result
}

/// Runs `body` on this thread as on a machine with `bytes` of physical
/// memory.
#[cfg(test)]
pub(crate) fn with_physical_memory_for_test<T>(bytes: u64, body: impl FnOnce() -> T) -> T {
    PHYSICAL_MEMORY_FOR_TEST.with(|memory| memory.set(Some(bytes)));
    let result = body();
    PHYSICAL_MEMORY_FOR_TEST.with(|memory| memory.set(None));
    result
}

/// The rows a signer stores before the rest wait, unless a slip issuer
/// signed or cosigned them: the policy row, or a test's scaled bound.
pub(super) fn signer_bound(store: &Store, txn: &heed::RoTxn<'_>) -> crate::error::Result<usize> {
    #[cfg(test)]
    if let Some(rows) = ROWS_PER_SIGNER_FOR_TEST.with(std::cell::Cell::get) {
        return Ok(rows);
    }
    let bound = authority_observation_policy_in_txn(store, txn)?.log_signer_bound;
    Ok(usize::try_from(bound).unwrap_or(usize::MAX))
}

/// The counted rows, slip-issuer handoffs and counted ancestor pairs at
/// which the log raises its headroom checks: the policy rows, or a test's
/// scaled bound for rows and pairs.
pub(super) fn headroom(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> crate::error::Result<(u64, u64, u64)> {
    let policy = authority_observation_policy_in_txn(store, txn)?;
    #[cfg(test)]
    if let Some(rows) = ROWS_PER_SIGNER_FOR_TEST.with(std::cell::Cell::get) {
        let rows = rows as u64;
        return Ok((rows, policy.log_headroom_handoffs, 2 * rows * rows));
    }
    Ok((
        policy.log_headroom_rows,
        policy.log_headroom_handoffs,
        policy.log_headroom_ancestor_pairs,
    ))
}

/// The bytes a fold may project to hold at its peak: the policy row, else a
/// quarter of this machine's physical memory between 1 GiB and
/// [`DEFAULT_AUTHORITY_LOG_FOLD_MEMORY_FLOOR_BYTES`] (the cap when the
/// platform does not say), or a test's floor.
pub(in crate::authority) fn fold_memory_floor(policy: Option<&AuthorityObservationPolicy>) -> u64 {
    #[cfg(test)]
    if let Some(bytes) = FOLD_MEMORY_FLOOR_FOR_TEST.with(std::cell::Cell::get) {
        return bytes;
    }
    policy
        .and_then(|policy| policy.log_fold_memory_floor_bytes)
        .unwrap_or_else(|| {
            physical_memory_bytes().map_or(DEFAULT_AUTHORITY_LOG_FOLD_MEMORY_FLOOR_BYTES, |bytes| {
                (bytes / 4).clamp(
                    FOLD_MEMORY_FLOOR_MIN_BYTES,
                    DEFAULT_AUTHORITY_LOG_FOLD_MEMORY_FLOOR_BYTES,
                )
            })
        })
}

/// The fold of a log past its memory floor: no root, no roster, one typed
/// issue naming the floor.
pub(in crate::authority) fn memory_floor_fold(floor_bytes: u64) -> AuthorityFold {
    let mut fold = fold_authority_log(&[]);
    fold.issues
        .push(AuthorityFoldIssue::FoldMemoryFloor { floor_bytes });
    fold
}
