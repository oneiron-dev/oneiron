//! A replayed search answers under its caller's read scope now (SCAN C025,
//! FIX 5989). An action's replay record keeps a search's hits as the first
//! call's key read them, and a later call under the same idempotency key may
//! hold a narrower key. Each cached hit is point-read again under the current
//! principal's key: only the hits that key admits stay, in their cached order
//! and with their cached scores, and the answer carries that read's receipt.
//! Nothing runs again (no search, rerank or refill), and the stored replay
//! record is not rewritten.
use super::super::SelfDispatchOutcome;
use crate::claim::{PointRead, ScopedReadActorKey, ScopedReadReceipt};
use crate::{Result, Vault};

/// `outcome` as `key` reads it now, beside the receipt it answers under: a
/// replayed search keeps the hits `key` admits, under that read's receipt;
/// any other outcome keeps `receipt` and is returned as it was.
pub(super) fn rescoped(
    vault: &Vault,
    key: &ScopedReadActorKey,
    outcome: SelfDispatchOutcome,
    receipt: ScopedReadReceipt,
) -> Result<(SelfDispatchOutcome, ScopedReadReceipt)> {
    let SelfDispatchOutcome::MemorySearch(mut search) = outcome else {
        return Ok((outcome, receipt));
    };
    let reads: Vec<_> = search
        .results
        .iter()
        .map(|hit| PointRead::id(hit.id))
        .collect();
    let read = vault.scoped_read(key.clone()).read(&reads, None)?;
    let admitted: Vec<bool> = read.value.iter().map(Option::is_some).collect();
    let mut kept = admitted.into_iter();
    search.results.retain(|_| kept.next().unwrap_or(false));
    Ok((SelfDispatchOutcome::MemorySearch(search), read.receipt))
}
