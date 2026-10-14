//! The Dreamer's model roles, and the backend each one calls out on.
//!
//! Extraction, the typed conflict verdict and narrative generation are three
//! manifest roles (ARCH-0036; ARCH-0026's two verbs, verdict and generate,
//! beside extraction). A vault's manifest may bind each role to its own model
//! and route, so a host may serve each on its own backend, under its own run.
//! A role the host routes nowhere calls the executor's own backend, as a
//! one-model host does.
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::llm::manifest::ModelRole;
use crate::llm::{
    ExtractionEgressPredicate, HostInferenceBinding, HostInferenceContext, LlmBackend, ModelId,
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
