//! One bound merged-value generation over a rebuilt conflict set.
//!
//! A bound job sends only the decided resolution with the set's references.
//! The binding rebuilds the set, and this module runs native's resolved-value
//! request for it as one durable verdict-role generation on the attempt's
//! borrowed role. The render is native's own renderer; the call, the terminal
//! charge and the failure-rules rule below mirror native's `merged_value`.
//! Failure rules load after the checks closed, in execution, so a retracted
//! rule never shapes a prepared input. A reply the rules refuse, or one that
//! names no value, answers `{"value": null}` as a finished, memoized step.

use super::executor::{ConsolidationExecutor, decode_merged_value};
use super::failure_rules::{self, Stage};
use super::roles::{DREAMER_VERDICT_ROLE, bind_reasoning};
use super::step_charge::charge_borrowed_slice_outcome;
use super::{ConflictIdentity, PriorHead, PromotionCandidate, rmpv_to_json};
use crate::dreamer_runner::{MergedValueResolution, MergedValueStepLoan};
use crate::entity_id::EntityId;
use crate::memory::MemoryResult;
use crate::store::model_step_submission::ModelStepResult;
use oneiron_model::llm::{LlmResponse, Scope};

/// One bound merged-value step's checked input, snapshotted in validation.
///
/// The members are the selected set's proposals in `candidate_indexes`
/// order, the priors are the set's prior heads in order, and the identity
/// and scope are the set's and the bound scope. Native's renderer reads
/// exactly these, so the bound request renders what native's would for the
/// same set.
pub(crate) struct PreparedMergedValueStep {
    /// Holds the decided resolution the request renders: merge or supersede.
    pub(crate) resolution: MergedValueResolution,
    /// Holds the kept member's claim id, when the decision named one.
    pub(crate) kept: Option<EntityId>,
    /// Holds the selected set's proposals in `candidate_indexes` order.
    pub(crate) members: Vec<PromotionCandidate>,
    /// Holds the set's prior heads in order.
    pub(crate) priors: Vec<PriorHead>,
    /// Holds the conflict identity the request renders.
    pub(crate) identity: ConflictIdentity,
    /// Holds the bound scope the call asks under.
    pub(crate) scope: Scope,
}

/// Runs `prepared` as one durable merged-value generation on the borrowed role.
///
/// The request is native's resolved-value request over the prepared members,
/// priors, kept identity and scope, then the Conflict rules, then the final
/// verdict-role authorization and reasoning binding. The call sends on the
/// role's own backend, as native's does, and the durable execution keeps the
/// standard three transport retries with the original attempt context and
/// guard. The outcome is accounted into the shared tally through the borrowed
/// native helper before the original outcome moves into the shared
/// request-hash receipt converter, so the receipt reads back by the same key.
/// A refused or valueless reply is a finished step: it answers
/// `{"value": null}` and a replay answers it again.
///
/// # Errors
///
/// The render's candidate or locality failures, the role authorization or
/// reasoning binding refusals, the request hash's bad spelling, the tally
/// lock or charge failures, and the shared receipt converter's own failures.
pub(crate) async fn execute_merged_value_step(
    ctx: &crate::model_step_context::DurableStepContext<'_>,
    prepared: &PreparedMergedValueStep,
    loan: &MergedValueStepLoan<'_>,
) -> MemoryResult<crate::llm::model_step::ModelStepReceipt> {
    let members: Vec<&PromotionCandidate> = prepared.members.iter().collect();
    let mut request = ConsolidationExecutor::value_request(
        &loan.call,
        prepared.resolution.as_str(),
        prepared.kept,
        &prepared.identity,
        &members,
        &prepared.priors,
        &prepared.scope,
    )?;
    if let Some(rules) = failure_rules::load(ctx.vault)? {
        rules.bind(Stage::Conflict, &mut request);
    }
    let mut request = ctx
        .vault
        .authorize_model_role(DREAMER_VERDICT_ROLE, request, &loan.call.inference)?
        .into_request();
    bind_reasoning(ctx.vault, loan.call.backend, &mut request)?;
    let execution_request = request.clone();
    let outcome =
        crate::llm::call_as_step(ctx, loan.call.backend, loan.guard, execution_request).await;
    {
        let mut charges = loan.charges.lock().map_err(|_| {
            crate::error::Error::InvariantViolation("merged value charge tally lock")
        })?;
        charge_borrowed_slice_outcome(ctx.vault, &outcome, None, &mut charges)?;
    }
    let mut receipt =
        crate::llm::request_hash_submit_receipt(ctx.vault, ctx.attempt_id, &request, outcome)?;
    if let Some(ModelStepResult::Finished { response, json, .. }) = receipt.result.as_mut() {
        *json = Some(merged_value_receipt_json(ctx.vault, response)?);
    }
    Ok(receipt)
}

/// The checked reply the receipt carries: the decoded value under `value`,
/// or null when the failure rules refuse the reply or it names no value.
///
/// # Errors
///
/// The failure-rules load's own failures.
fn merged_value_receipt_json(
    vault: &crate::Vault,
    response: &LlmResponse,
) -> MemoryResult<serde_json::Value> {
    let rules = failure_rules::load(vault)?;
    if rules.is_some_and(|rules| !rules.accepts(Stage::Conflict, response)) {
        return Ok(serde_json::json!({"value": null}));
    }
    let value = decode_merged_value(response)
        .map_or(serde_json::Value::Null, |decoded| rmpv_to_json(&decoded));
    Ok(serde_json::json!({"value": value}))
}
