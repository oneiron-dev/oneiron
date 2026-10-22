//! The keyed fingerprint of a signal's exact intent (FIX 10066), kept beside
//! a signal the side-row wall masked, so its identical retry still matches
//! and a changed one does not. Only the fingerprint is stored, under a key
//! derived from the vault's known-value master; the raw intent never is.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::RunSignalInput;
use crate::Vault;
use crate::attempt_queue::AttemptRecord;

/// One masked signal's intent fingerprint, by the signal's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SignalIntent {
    pub(crate) key: String,
    pub(crate) fingerprint: [u8; 32],
}

/// The exact intent `input` states, as the bytes its fingerprint keys: its
/// branch, run, key, actor and kind, as given. Wiped when dropped. `None`
/// when it does not encode: then no fingerprint is kept.
pub(super) fn intent_bytes(input: &RunSignalInput) -> Option<Zeroizing<Vec<u8>>> {
    rmp_serde::to_vec(&(
        input.branch.as_bytes(),
        &input.run_id,
        &input.key,
        &input.actor,
        &input.kind,
    ))
    .ok()
    .map(Zeroizing::new)
}

/// The keyed fingerprint of `bytes`, in the caller's writer. `None` while no
/// master exists, and when custody faults: the fault is logged without any
/// input byte, and plain equality decides as before. Nothing refuses.
pub(super) fn fingerprint_in(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    bytes: &[u8],
) -> Option<[u8; 32]> {
    match vault.store.intent_fingerprint_in_writer(txn, bytes) {
        Ok(fingerprint) => fingerprint,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a signal's intent fingerprint did not read; plain equality decides"
            );
            None
        }
    }
}

/// Whether `input` repeats the masked signal `record` holds under its key:
/// the fingerprint kept beside it equals `input`'s. `false` when none was
/// kept or none reads now.
pub(super) fn retry_matches(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    record: &AttemptRecord,
    input: &RunSignalInput,
) -> bool {
    let kept: Vec<[u8; 32]> = record
        .signal_intents
        .iter()
        .filter(|intent| intent.key == input.key)
        .map(|intent| intent.fingerprint)
        .collect();
    if kept.is_empty() {
        return false;
    }
    intent_bytes(input)
        .and_then(|bytes| fingerprint_in(vault, txn, &bytes))
        .is_some_and(|fingerprint| kept.contains(&fingerprint))
}
