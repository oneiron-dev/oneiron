//! The Dreamer's model roles, and the backend each one calls out on.
//!
//! Extraction, the typed conflict verdict and narrative generation are three
//! manifest roles (ARCH-0036; ARCH-0026's two verbs, verdict and generate,
//! beside extraction). A vault's manifest may bind each role to its own model
//! and route, so a host may serve each on its own backend, under its own run.
//! A role the host routes nowhere calls the executor's own backend, as a
//! one-model host does.
//!
//! Every call of a role names its reasoning level, never "no level": a local
//! server reads an absent level as its own default, its highest.
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::Vault;
use crate::error::Result;
use crate::llm::manifest::ModelRole;
use crate::llm::seat::PurposeEffort;
use crate::llm::{
    ExtractionEgressPredicate, HostInferenceBinding, HostInferenceContext, LlmBackend,
    LlmCapability, LlmRequest, ModelId, REASONING_BUDGET_PARAM, ReasoningEffort,
};

/// Transcript extraction.
pub const DREAMER_EXTRACTION_ROLE: ModelRole = ModelRole::ExtractionTeacher;
/// The typed conflict verdict: merge, supersede, accumulate or escalate.
pub const DREAMER_VERDICT_ROLE: ModelRole = ModelRole::GenerativeReasoner;
/// Narrative generation: declared scope summaries.
pub const DREAMER_NARRATIVE_ROLE: ModelRole = ModelRole::DreamerCurrent;
/// Every role a consolidation pass calls.
pub const DREAMER_ROLES: [ModelRole; 3] = [
    DREAMER_EXTRACTION_ROLE,
    DREAMER_VERDICT_ROLE,
    DREAMER_NARRATIVE_ROLE,
];

/// One role's backend and the host's attestation of the model it serves.
#[derive(Clone)]
pub struct RoleBackend {
    pub backend: Arc<dyn LlmBackend>,
    pub model: ModelId,
    pub binding: HostInferenceBinding,
}

/// The backends a host routes the Dreamer's roles to.
#[derive(Clone, Default)]
pub struct RoleBackends(BTreeMap<ModelRole, RoleBackend>);

impl RoleBackends {
    #[must_use]
    pub fn with(mut self, role: ModelRole, backend: RoleBackend) -> Self {
        self.0.insert(role, backend);
        self
    }

    #[must_use]
    pub fn get(&self, role: ModelRole) -> Option<&RoleBackend> {
        self.0.get(&role)
    }
}

/// Where one role's calls go: its backend, the model the request names, and
/// the host context its admission binds against.
pub struct RoleCall<'r> {
    pub backend: &'r dyn LlmBackend,
    pub model: &'r ModelId,
    pub inference: HostInferenceContext<'r>,
}

impl<'r> RoleCall<'r> {
    /// `role`'s routed backend, else the caller's own `backend` serving
    /// `model` under `binding`. Every role passes the same egress decision.
    #[must_use]
    pub fn resolve(
        roles: &'r RoleBackends,
        role: ModelRole,
        backend: &'r dyn LlmBackend,
        model: &'r ModelId,
        binding: &HostInferenceBinding,
        extraction_egress: Option<&'r dyn ExtractionEgressPredicate>,
    ) -> Self {
        let (backend, model, binding) = match roles.get(role) {
            Some(routed) => (routed.backend.as_ref(), &routed.model, &routed.binding),
            None => (backend, model, binding),
        };
        Self {
            backend,
            model,
            inference: HostInferenceContext {
                binding: binding.clone(),
                extraction_egress,
            },
        }
    }
}

/// The level a Dreamer call carries when the vault authors none, and the
/// thinking budget that goes with it: the pair measured best for extraction.
const DEFAULT_EFFORT: ReasoningEffort = ReasoningEffort::Medium;
const DEFAULT_BUDGET_TOKENS: u64 = 4_096;

/// Pins `request`'s reasoning level, for the backend that will serve it: the
/// vault's authored level for the call's purpose, else medium with its
/// thinking budget, each within what the model's ladder takes. A backend
/// that takes no reasoning controls for the model is pinned to `none`, the
/// only level it can be sent.
pub(super) fn bind_reasoning(
    vault: &Vault,
    backend: &dyn LlmBackend,
    request: &mut LlmRequest,
) -> Result<()> {
    let takes_reasoning = backend.supports(&request.model, LlmCapability::Reasoning);
    bind_reasoning_for(vault, takes_reasoning, request)
}

/// [`bind_reasoning`] for a host that calls its route itself and says
/// whether the model takes reasoning controls.
pub(super) fn bind_reasoning_for(
    vault: &Vault,
    takes_reasoning: bool,
    request: &mut LlmRequest,
) -> Result<()> {
    request.params.remove(REASONING_BUDGET_PARAM);
    if !takes_reasoning {
        request.envelope.seat_effort = Some(ReasoningEffort::None);
        return Ok(());
    }
    match vault.purpose_effort(
        &request.envelope.purpose,
        &request.model,
        true,
        DEFAULT_EFFORT,
    )? {
        PurposeEffort::Authored(effort) => request.envelope.seat_effort = Some(effort),
        PurposeEffort::Fallback(effort) => {
            request.envelope.seat_effort = Some(effort);
            request
                .params
                .insert(REASONING_BUDGET_PARAM.into(), DEFAULT_BUDGET_TOKENS.into());
        }
    }
    Ok(())
}
