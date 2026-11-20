//! The keyed fingerprint of a signal's exact intent (FIX 10066), kept beside
//! a signal the side-row wall masked, so its identical retry still matches
//! and a changed one does not. Only the fingerprint is stored, under a key
//! derived from the vault's known-value master; the raw intent never is.

use zeroize::Zeroizing;

use super::{RunSignalInput, RunSignalKind};
use crate::Vault;
use crate::attempt_queue::AttemptRecord;

pub(crate) use crate::attempt_queue::run_signal::SignalIntent;

/// The exact intent `input` states, as the bytes its fingerprint keys: its
/// branch, run, key, actor and kind, as given. Wiped when dropped. `None`
/// when it does not encode: then no fingerprint is kept.
pub(super) fn intent_bytes(input: &RunSignalInput) -> Option<Zeroizing<Vec<u8>>> {
    intent_bytes_under(input, &input.key, &input.actor)
}

/// The exact intent `input` states, restated under `key` and `actor`.
fn intent_bytes_under(
    input: &RunSignalInput,
    key: &str,
    actor: &str,
) -> Option<Zeroizing<Vec<u8>>> {
    rmp_serde::to_vec(&(
        input.branch.as_bytes(),
        &input.run_id,
        key,
        actor,
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
    kept_matches(vault, txn, record, &input.key, || intent_bytes(input))
}

/// Whether a fingerprint `record` keeps beside the signal under `key`
/// equals the fingerprint of the intent `bytes` gives. `false` when none
/// was kept or none reads now.
fn kept_matches(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    record: &AttemptRecord,
    key: &str,
    bytes: impl FnOnce() -> Option<Zeroizing<Vec<u8>>>,
) -> bool {
    let kept: Vec<[u8; 32]> = record
        .signal_intents
        .iter()
        .filter(|intent| intent.key == key)
        .map(|intent| intent.fingerprint)
        .collect();
    if kept.is_empty() {
        return false;
    }
    bytes()
        .and_then(|bytes| fingerprint_in(vault, txn, &bytes))
        .is_some_and(|fingerprint| kept.contains(&fingerprint))
}

/// Whether the ask answer `input` gives repeats, exactly as given, an
/// answer a masked signal `record` holds gave to the same ask for the same
/// person: the fingerprint kept beside that signal equals `input`'s intent
/// restated under that signal's key and actor. So an answer given again
/// under a new key meets the first answer as it was given, never as the
/// side-row wall stored it (blind review round 2 of #9531). `false` when
/// `input` is no ask answer, when no such signal kept a fingerprint, and
/// when none reads now: the answer then refuses, as before FIX
/// SIGNAL-NEW-KEY-MASKED-ANSWER.
pub(super) fn answer_repeats(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    record: &AttemptRecord,
    input: &RunSignalInput,
) -> bool {
    let RunSignalKind::AskAnswer { handle, who, .. } = &input.kind else {
        return false;
    };
    record
        .signals
        .iter()
        .filter(|signal| {
            matches!(
                &signal.kind,
                RunSignalKind::AskAnswer {
                    handle: answered,
                    who: answering,
                    ..
                } if answered == handle && answering == who
            )
        })
        .any(|signal| {
            kept_matches(vault, txn, record, &signal.key, || {
                intent_bytes_under(input, &signal.key, &signal.actor)
            })
        })
}
