//! What a run's guest gets in place of an answer the side-row wall could
//! not admit (FIX 5718 part 3, Engine ruling 4): a secret in it no handle
//! can stand for kept it from being stored, so the guest reads its size, its
//! kind and the door's reason, in the shape a withheld read answers, and
//! none of its content. The call ran, and its row keeps that it did.

use serde_json::{Value, json};

use super::taint_word;
use crate::secret_rotation::ArtifactTaintState;

/// Why the answer reads as withheld.
const UNPLACED_REASON: &str = "this answer holds a secret the vault cannot keep as a handle, \
     so it was not stored and no read shows it; the call ran, and this is not a size limit";

/// The withheld answer: `bytes` long, `text` or binary, held back for the
/// door's `reason`. It names no result.
pub(crate) fn unplaced_answer(bytes: u64, text: bool, reason: &str) -> Value {
    let state = taint_word(ArtifactTaintState::TaintedLive);
    json!({
        "withheld": state,
        "bytes": bytes,
        "kind": if text { "text" } else { "binary" },
        "taint": {"state": state, "secret": reason},
        "reason": UNPLACED_REASON,
    })
}
