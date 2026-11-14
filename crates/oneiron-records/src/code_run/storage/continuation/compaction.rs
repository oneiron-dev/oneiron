//! Moved from `crates/oneiron/src/code_run/storage/continuation/compaction.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_store::result_manifest::invalid_code_run_replay;
use oneiron_verb_wire::compaction::folds::FoldReply;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::BTreeSet;

/// A fold verb's typed answer in `answer`, the JSON its call recorded, or
/// `None` for the ledger's refusal, which gave out no handle.
///
/// # Errors
///
/// An answer that decodes as neither.
pub fn fold_answer<T: DeserializeOwned>(answer: &str) -> Result<Option<T>> {
    match serde_json::from_str::<FoldReply<T>>(answer) {
        Ok(FoldReply::Answer(answer)) => Ok(Some(answer)),
        Ok(FoldReply::Refused { .. }) => Ok(None),
        Err(_) => Err(undecoded_fold_answer()),
    }
}

/// The storage error for a copied fold call that does not decode.
pub fn undecoded_fold_answer() -> Error {
    invalid_code_run_replay("a copied fold answer does not decode")
}
