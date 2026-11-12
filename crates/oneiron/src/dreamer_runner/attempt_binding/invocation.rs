//! A bound client's verb calls: the strength facet's two operations, each
//! through its row's one verb-hook boundary, with the binding proved before
//! the hooks and again in the call's own transaction.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::{DreamerAttemptBinding, facet_refused, strength_batch};
use crate::derive::DeriveCommitInput;
use crate::memory::{MemoryError, MemoryResult};
use crate::runtime_hooks::InvocationId;
use crate::snapshot_read::StrengthObservationsPageRequest;
use crate::task_verb::verb_hook_boundary::{typed_row, typed_row_validated};
use crate::verbs::VERB_TABLE;

/// The observations page a strength attempt reads.
const STRENGTH_PAGE_VERB: &str = "vault.consolidation.strength.observations.page";
/// The commit a strength attempt lands its Archive items with.
const DERIVE_COMMIT_VERB: &str = "vault.derive.commit";

impl DreamerAttemptBinding {
    /// Runs `verb` on `input` as the Dreamer under this binding; with
    /// `invocation`, as the retry of a call a verb hook stopped on an ask.
    ///
    /// The facet admits two verbs. `vault.consolidation.strength.observations.page`
    /// takes its usual request. `vault.derive.commit` takes the batch itself,
    /// `{"items": [...], "sources": [...]}`, Archive items only: the binding
    /// is the live run, so no `live_run` attachment wraps it.
    ///
    /// # Errors
    ///
    /// `FORBIDDEN` for another verb or a non-Archive item; the binding's
    /// refusals ([`Vault::bind_dreamer_attempt`](crate::Vault::bind_dreamer_attempt));
    /// a bad request for input the verb does not decode; the verb's own errors.
    pub fn invoke(
        &self,
        verb: &str,
        input: Value,
        invocation: Option<InvocationId>,
    ) -> MemoryResult<Value> {
        if verb != STRENGTH_PAGE_VERB && verb != DERIVE_COMMIT_VERB {
            return Err(facet_refused());
        }
        let memory = self
            .vault
            .memory(self.stamp.actor, self.actor().actor_class());
        let memory = match invocation {
            Some(invocation) => memory.with_invocation(invocation),
            None => memory,
        };
        if verb == STRENGTH_PAGE_VERB {
            let input: StrengthObservationsPageRequest = decode(verb, input)?;
            encode(&typed_row(&memory, &VERB_TABLE, verb, input, |input| {
                crate::snapshot_read::strength_observations_page_bound(&memory, &input, self)
            })?)
        } else {
            let input: DeriveCommitInput = decode(verb, input)?;
            encode(&typed_row_validated(
                &memory,
                &VERB_TABLE,
                verb,
                input,
                validate_strength_commit,
                |input| self.commit(input),
            )?)
        }
    }
}

/// The check a hook's rewrite of a bound commit must pass: the batch itself,
/// Archive items only.
fn validate_strength_commit(verb: &str, value: &Value) -> MemoryResult<()> {
    strength_batch(decode(verb, value.clone())?).map(drop)
}

fn decode<T: DeserializeOwned>(verb: &str, value: Value) -> MemoryResult<T> {
    serde_json::from_value(value)
        .map_err(|error| MemoryError::bad_request(format!("invalid {verb} input: {error}")))
}

fn encode<T: Serialize>(output: &T) -> MemoryResult<Value> {
    serde_json::to_value(output)
        .map_err(|error| MemoryError::bad_request(format!("the result did not encode: {error}")))
}
