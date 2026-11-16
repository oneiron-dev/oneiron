//! Runs the one typed pack execution every verdict read shares: the verdict shell, the
//! role seal, the scoped ladder read and the spent prefix tally.
//!
//! Native [`ConsolidationExecutor::decide`](super::super::ConsolidationExecutor) and the bound
//! extraction read both execute through [`decide_pack_with_charges`]: the same request
//! bytes, the same seal, the same first read and the same paid-prefix accounting. The
//! bound path reaches it through the extraction pack facade, which builds its questions,
//! labels and state with the lent wording; it never builds a shell, a seal or a tally of
//! its own.

use std::collections::BTreeMap;
use std::sync::Mutex;

use super::super::super::roles::{DREAMER_VERDICT_ROLE, RoleCall};
use super::{Decider, ScopedRead, VERDICT_CEILING};
use crate::Vault;
use crate::dreamer_consolidation::call_labels::CallLabelMap;
use crate::dreamer_consolidation::provenance::KeptDecision;
#[cfg(oneiron_test_support)]
use crate::dreamer_consolidation::step_charge::SpentObservation;
use crate::dreamer_consolidation::step_charge::StepChargeTally;
use crate::dreamer_wake::WakePassDeadline;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::decision::AskTo;
use crate::model_decision::{DecisionQuestion, DecisionRung, EvidenceVersion};
use crate::model_step_context::{DurableStepContext, StepEffectBinding};
use crate::model_step_error::{DurableStepError, DurableStepResult};
use oneiron_model::llm::{
    CallClass, CallEnvelope, CallPurpose, LlmRequest, LlmUsage, ModelTierRef, ResponseFormat,
    Scope, TierPrecedence,
};

/// Carries one typed pack read into the shared execution: the step and pass clock, the
/// decider and role call, the request scope and pinned versions, the route and
/// correlation, the evidence, state and labels, the source rows, and the optional
/// request lowerings. Native fills every field from its branch; the bound facade fills
/// them from its checked preparation with the lent decisions.
pub(in crate::dreamer_consolidation) struct VerdictRead<'a> {
    /// Holds the durable step the read spends on.
    pub(in crate::dreamer_consolidation) step: &'a DurableStepContext<'a>,
    /// Holds the pass clock bounding the read.
    pub(in crate::dreamer_consolidation) pass: &'a WakePassDeadline,
    /// Holds the ladder, actor and guard the read decides with.
    pub(in crate::dreamer_consolidation) decider: Decider<'a>,
    /// Holds the verdict role call the shell and seal bind.
    pub(in crate::dreamer_consolidation) call: &'a RoleCall<'a>,
    /// Holds the exact scope the request shell carries.
    pub(in crate::dreamer_consolidation) scope: &'a Scope,
    /// Holds the body version of each evidence source the caller pinned.
    pub(in crate::dreamer_consolidation) versions: &'a [EvidenceVersion],
    /// Names where an ask goes when the read climbs.
    pub(in crate::dreamer_consolidation) to: &'a AskTo,
    /// Names the work the read decides, for ask reuse.
    pub(in crate::dreamer_consolidation) correlation: EntityId,
    /// Holds the evidence identifiers the read shows, in native order.
    pub(in crate::dreamer_consolidation) evidence: &'a [EntityId],
    /// Holds the state the questions read over.
    pub(in crate::dreamer_consolidation) state: &'a serde_json::Value,
    /// Holds the call labels the read shows and answers through.
    pub(in crate::dreamer_consolidation) labels: &'a CallLabelMap,
    /// Holds the complete rows the read was rendered from, or none when unknown.
    pub(in crate::dreamer_consolidation) sources: Option<Vec<EntityId>>,
    /// Holds a request lowering of the ladder deadline in milliseconds, or none for the pass time.
    pub(in crate::dreamer_consolidation) deadline_ms: Option<u64>,
    /// Holds a request lowering of the read ceiling, or none for the verdict ceiling.
    pub(in crate::dreamer_consolidation) ceiling: Option<DecisionRung>,
}

/// Names where the shared execution tallies a pack's spent generations: the native
/// pass's own tally, or the bound attempt's shared tally. The shared lock is taken
/// only around the accounting after the model await, never across it.
pub(in crate::dreamer_consolidation) enum ChargeSink<'a> {
    /// Borrows the native pass's tally for this read.
    Borrowed(&'a mut StepChargeTally),
    /// Shares the bound attempt's tally across every pack invocation.
    Shared(&'a Mutex<StepChargeTally>),
}

/// Decides `questions` over `read`'s state through the shared verdict execution: the
/// verdict shell, the role seal, the scoped ladder read and the spent prefix tally.
/// Each generation that finished joins the sink, even when a later one traps or fails.
/// Returns none when the step trapped: the attempt is parked.
pub(in crate::dreamer_consolidation) async fn decide_pack_with_charges(
    read: VerdictRead<'_>,
    questions: &[DecisionQuestion],
    sink: ChargeSink<'_>,
) -> DurableStepResult<Option<Vec<KeptDecision>>> {
    let vault = read.step.vault;
    let seal = |request: LlmRequest| -> Result<LlmRequest> {
        let mut request = vault
            .authorize_model_role(DREAMER_VERDICT_ROLE, request, &read.call.inference)?
            .into_request();
        super::super::super::roles::bind_reasoning(vault, read.call.backend, &mut request)?;
        Ok(request)
    };
    let mut spent = Vec::new();
    let ceiling = read
        .ceiling
        .map_or(VERDICT_CEILING, |cap| VERDICT_CEILING.min(cap));
    let scoped = ScopedRead {
        step: read.step,
        pass: read.pass,
        call: read.call,
        shell: verdict_shell(read.call, read.scope)?,
        seal: &seal,
        versions: read.versions,
        to: read.to,
        correlation: read.correlation,
        evidence: read.evidence,
        state: read.state,
        ceiling,
        sources: read.sources,
    };
    let decided = match read.deadline_ms {
        None => {
            read.decider
                .decide_scoped(scoped, questions, read.labels, &mut spent)
                .await
        }
        Some(cap) => {
            read.decider
                .decide_scoped_with_deadline_cap(
                    scoped,
                    questions,
                    read.labels,
                    &mut spent,
                    Some(cap),
                )
                .await
        }
    };
    match sink {
        ChargeSink::Borrowed(charges) => {
            settle_spent_prefix(vault, &spent, &decided, charges)?;
        }
        ChargeSink::Shared(shared) => {
            let mut charges = shared
                .lock()
                .map_err(|_| crate::Error::InvariantViolation("extraction charge tally lock"))?;
            settle_spent_prefix(vault, &spent, &decided, &mut charges)?;
        }
    }
    decided
}

/// Accounts `spent` onto `charges`: every generation that finished is spent, whatever the
/// pack's outcome, so a later step that traps or fails leaves the prefix on the tally. A
/// terminal binding already tallied or checkpoint-paid is skipped; a charge-record
/// failure falls back to the paid prefix of raw usage plus the failed step's own usage.
fn settle_spent_prefix(
    vault: &Vault,
    spent: &[([u8; 32], LlmUsage, Option<StepEffectBinding>, bool)],
    decided: &DurableStepResult<Option<Vec<KeptDecision>>>,
    charges: &mut StepChargeTally,
) -> Result<()> {
    #[cfg(oneiron_test_support)]
    charges
        .spent_observations
        .extend(
            spent
                .iter()
                .map(|(hash, usage, binding, memoized)| SpentObservation {
                    hash: *hash,
                    usage: usage.clone(),
                    binding: *binding,
                    memoized: *memoized,
                }),
        );
    // Every generation that finished is spent, whatever the pack's outcome: a later
    // step that traps or fails leaves the prefix on the tally.
    for (index, (_, usage, binding, _)) in spent.iter().enumerate() {
        if let Some(binding) = binding {
            if let Err(error) =
                charges.record_terminal(vault, binding.attempt_id, binding.step_hash, usage)
            {
                for (_, usage, _, memoized) in &spent[index..] {
                    if !*memoized {
                        charges.record_usage(usage);
                    }
                }
                if let Some(usage) = decided
                    .as_ref()
                    .err()
                    .and_then(DurableStepError::spent_usage)
                {
                    charges.record_usage(usage);
                }
                return Err(error);
            }
        } else {
            charges.record_usage(usage);
        }
    }
    Ok(())
}

/// Builds the verdict role's request for a typed read: its model, scope and binding,
/// with no messages yet.
fn verdict_shell(call: &RoleCall<'_>, scope: &Scope) -> Result<LlmRequest> {
    let keyless = call.inference.selected_keyless();
    let paid = call.inference.selected_paid();
    Ok(LlmRequest {
        model: call.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: scope.clone(),
            purpose: CallPurpose::Consolidation,
            class: CallClass::Durable {
                fallback: oneiron_model::llm::DeterministicFallback {
                    name: "json_rules_v1".into(),
                    config: None,
                },
            },
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Consolidation,
                ModelTierRef("consolidation".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: call.inference.selected_locality().ok_or_else(|| {
                crate::Error::InvalidConfig("consolidation host binding needs locality".into())
            })?,
            host_keyless: keyless,
            host_paid: paid,
        }
        .with_purpose_defaults(),
        messages: Vec::new(),
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    })
}

/// Computes the receipt version of the row `id` read as `body`: the plain BLAKE3 of
/// the logical row bytes. This is the native receipt hash, never a domain-separated pin
/// digest.
pub(crate) fn evidence_version_for_row(id: EntityId, body: &[u8]) -> EvidenceVersion {
    EvidenceVersion {
        id,
        body_hash: *blake3::hash(body).as_bytes(),
    }
}
