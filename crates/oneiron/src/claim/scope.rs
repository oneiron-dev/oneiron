//! The engine-RECOGNIZED entries inside a claim's otherwise opaque `scope`
//! map, and their fail-closed structural checks.
//!
//! The `scope` body key stays opaque by design: the crate stores whatever a
//! writer put there and preserves unknown entries losslessly. A recognized
//! entry is different — once the engine reads an entry to make a retrieval
//! decision, an ambiguous or malformed one must never reach that decision
//! point. [`validate_known_claim_scope_entries`] is the chokepoint that keeps
//! those two properties compatible: it inspects ONLY the entries this crate
//! interprets and leaves every sibling untouched.
//!
//! Today that is exactly one entry — the corpus id
//! ([`crate::corpus::CLAIM_SCOPE_CORPUS_ID_KEY`]).

use rmpv::Value;

use super::ClaimBody;
use crate::corpus::{CorpusId, corpus_id_from_scope};
use crate::error::Result;

/// Reads the corpus a claim is scoped to.
///
/// `None` means unscoped/core — the claim belongs to every corpus, so corpus
/// selection keeps it. A malformed or duplicated corpus entry is a
/// fail-closed [`crate::Error::InvalidClaimBody`], never a silent `None`.
pub(crate) fn claim_corpus_id(body: &ClaimBody) -> Result<Option<CorpusId>> {
    corpus_id_from_scope(body.scope.as_ref())
}

/// Structural check for the recognized entries of a claim's `scope` map, run
/// from the body decoder so a duplicate or malformed corpus id can never be
/// written and can never be read back into a retrieval decision.
///
/// Scope of the check is deliberately narrow: an entry this crate does not
/// interpret is not validated, not reshaped and not rejected, and a `scope`
/// value that is not a map carries no recognized entry at all. Widening the
/// opaque contract is not a side effect of adding a recognized entry to it.
pub(crate) fn validate_known_claim_scope_entries(scope: Option<&Value>) -> Result<()> {
    corpus_id_from_scope(scope).map(|_| ())
}
