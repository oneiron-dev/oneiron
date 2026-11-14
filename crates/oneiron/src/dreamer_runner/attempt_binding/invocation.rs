//! A bound client's verb calls, limited to its admitted maintenance facet.
//! Each call crosses its row's one verb-hook boundary, with the binding
//! proved before the hooks and again in the call's own transaction.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::{BoundFacet, DreamerAttemptBinding, facet_batch, facet_refused};
use crate::derive::DeriveCommitInput;
use crate::memory::{MemoryError, MemoryResult};
use crate::runtime_hooks::InvocationId;
use crate::snapshot_read::{ConflictsPageRequest, StrengthObservationsPageRequest};
use crate::task_verb::verb_hook_boundary::{typed_row, typed_row_validated};
use crate::verbs::{AiVerdictRequest, VERB_TABLE};

/// The observations page a strength attempt reads.
const STRENGTH_PAGE_VERB: &str = "vault.consolidation.strength.observations.page";
/// The conflicts page a conflict-settlement attempt reads.
const CONFLICTS_PAGE_VERB: &str = "vault.consolidation.conflicts.page";
/// The typed question a conflict-settlement attempt asks the host's ladder.
const AI_VERDICT_VERB: &str = "ai.verdict";
/// The commit that lands items admitted by the bound facet.
const DERIVE_COMMIT_VERB: &str = "vault.derive.commit";

impl DreamerAttemptBinding {
    /// Runs `verb` on `input` as the Dreamer under this binding; with
    /// `invocation`, as the retry of a call a verb hook stopped on an ask.
    ///
    /// Strength admits its observations page and Archive commits. Conflict
    /// settlement admits its conflicts page, typed verdicts on the host's
    /// lent ladder and Settle commits. A commit takes the batch itself,
    /// `{"items": [...], "sources": [...]}`: the binding is the live run,
    /// so no `live_run` attachment wraps it.
    ///
    /// # Errors
    ///
    /// `FORBIDDEN` for another verb or item kind; the binding's refusals
    /// ([`Vault::bind_dreamer_attempt`](crate::Vault::bind_dreamer_attempt));
    /// a bad request for input the verb does not decode; the verb's own errors.
    pub fn invoke(
        &self,
        verb: &str,
        input: Value,
        invocation: Option<InvocationId>,
    ) -> MemoryResult<Value> {
        let admitted = match self.facet {
            BoundFacet::Strength => matches!(verb, STRENGTH_PAGE_VERB | DERIVE_COMMIT_VERB),
            BoundFacet::ConflictSettle => {
                matches!(
                    verb,
                    CONFLICTS_PAGE_VERB | AI_VERDICT_VERB | DERIVE_COMMIT_VERB
                )
            }
        };
        if !admitted {
            return Err(facet_refused(self.facet));
        }
        self.check()?;
        let memory = self
            .vault
            .memory(self.stamp.actor, self.actor().actor_class());
        let memory = match invocation {
            Some(invocation) => memory.with_invocation(invocation),
            None => memory,
        };
        match verb {
            STRENGTH_PAGE_VERB => {
                let input: StrengthObservationsPageRequest = decode(verb, input)?;
                encode(&typed_row(&memory, &VERB_TABLE, verb, input, |input| {
                    crate::snapshot_read::strength_observations_page_bound(&memory, &input, self)
                })?)
            }
            CONFLICTS_PAGE_VERB => {
                let input: ConflictsPageRequest = decode(verb, input)?;
                encode(&typed_row(&memory, &VERB_TABLE, verb, input, |input| {
                    crate::snapshot_read::conflicts_page_bound(&memory, &input, self)
                })?)
            }
            AI_VERDICT_VERB => {
                let input: AiVerdictRequest = decode(verb, input)?;
                encode(&typed_row(&memory, &VERB_TABLE, verb, input, |input| {
                    self.verdict(input)
                })?)
            }
            _ => {
                let input: DeriveCommitInput = decode(verb, input)?;
                let validate = match self.facet {
                    BoundFacet::Strength => validate_strength_commit,
                    BoundFacet::ConflictSettle => validate_conflict_settle_commit,
                };
                encode(&typed_row_validated(
                    &memory,
                    &VERB_TABLE,
                    verb,
                    input,
                    validate,
                    |input| self.commit(input),
                )?)
            }
        }
    }
}

/// The check a hook's rewrite of a strength commit must pass.
fn validate_strength_commit(verb: &str, value: &Value) -> MemoryResult<()> {
    facet_batch(decode(verb, value.clone())?, BoundFacet::Strength).map(drop)
}

/// The check a hook's rewrite of a conflict-settlement commit must pass.
fn validate_conflict_settle_commit(verb: &str, value: &Value) -> MemoryResult<()> {
    facet_batch(decode(verb, value.clone())?, BoundFacet::ConflictSettle).map(drop)
}

fn decode<T: DeserializeOwned>(verb: &str, value: Value) -> MemoryResult<T> {
    serde_json::from_value(value)
        .map_err(|error| MemoryError::bad_request(format!("invalid {verb} input: {error}")))
}

fn encode<T: Serialize>(output: &T) -> MemoryResult<Value> {
    serde_json::to_value(output)
        .map_err(|error| MemoryError::bad_request(format!("the result did not encode: {error}")))
}
