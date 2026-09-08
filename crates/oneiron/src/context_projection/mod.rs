//! Typed context projection (`ContextSpec`) and the referenced panel-spec
//! codec/planner a recursive task lead composes over existing primitives.
//!
//! Two generic mechanisms live here, both consumer-neutral despite their
//! EIRI-ARCH-0013 canon source:
//!
//! 1. **`ContextSpec` — a descriptor, not context data.** `self.context(spec)`
//!    returns the descriptor unchanged; RESOLUTION happens later, at agent
//!    dispatch, so a sub-agent reads fresh state rather than a create-time
//!    snapshot. Resolution follows one fixed order — Layers → Memory → Chat →
//!    Briefing — and the dev-only `_annotation` never reaches a resolved
//!    projection.
//!
//! 2. **`LeadPanelSpec` — a typed spec entity, referenced by a consult.** The
//!    consult wire stays exactly `{question_ref, context_refs, correlation_ref}`:
//!    free-form question text, member instructions, judge rubric, and synthesis
//!    instructions live only in referenced durable entities, never inline in a
//!    TASK payload. [`plan_lead_panel_tasks`] returns typed task INPUTS; the
//!    lead mints the actual TASKs with ordinary `tasks.create` calls. This is
//!    not a workflow executor and it pre-allocates no entity ids.
//!
//! ## The narrowing law
//!
//! Context can only narrow, never widen. That is enforced twice, on two
//! different axes, because they answer different questions:
//!
//! * [`validate_spec_narrows`] compares two DECLARED bounds — the parent's
//!   stored spec against the child's requested one. A child cannot ask for a
//!   domain its parent did not scope, nor raise a limit.
//! * [`validate_context_narrows`] compares the child's request against what the
//!   parent ACTUALLY RESOLVED. A child cannot name a layer the parent did not
//!   project, and an explicit `Scoped`/`Recent` request against an empty parent
//!   projection is the "excluded → included" widening the law forbids.
//!   `Default` inherits and is therefore always admissible.
//!
//! Resolution additionally INTERSECTS a child's sections with its parent's, so
//! narrowing holds structurally even where neither declarative check bites.

mod narrowing;
mod panel_spec;
mod resolution;
mod spec;

pub use self::narrowing::{validate_context_narrows, validate_spec_narrows};
pub use self::panel_spec::{
    LEAD_PANEL_MAX_MEMBERS, LEAD_PANEL_SPEC_ROLE, LEAD_PANEL_SPEC_SCHEMA_VERSION,
    LeadPanelExecutionPlan, LeadPanelSpec, LeadPanelTaskInputSpec, PanelJudgeSpec, PanelMemberSpec,
    PanelResultInputs, PanelSynthesisSpec, decode_lead_panel_spec, encode_lead_panel_spec,
    load_lead_panel_spec, persist_lead_panel_spec, plan_lead_panel_tasks, validate_lead_panel_spec,
};
pub use self::resolution::{
    CONTEXT_PROJECTION_MAX_ANCESTORS, CONTEXT_SPEC_MEMORY_SCAN_LIMIT, ContextResolutionRequest,
    ResolvedContextProjection, resolve_context_spec,
};
pub use self::spec::{
    CONTEXT_SPEC_DEFAULT_CHAT_LAST_N, CONTEXT_SPEC_DEFAULT_MEMORY_LIMIT,
    CONTEXT_SPEC_MAX_CHAT_LAST_N, CONTEXT_SPEC_MAX_DOMAINS, CONTEXT_SPEC_MAX_LABEL_BYTES,
    CONTEXT_SPEC_MAX_LAYERS, CONTEXT_SPEC_MAX_MEMORY_LIMIT, CONTEXT_SPEC_MAX_TEXT_BYTES,
    ChatProjection, ContextSpec, MemoryProjection, context, normalize_context_spec,
    validate_context_spec,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
use self::resolution::is_conversational_turn_body;
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::VaultConfig;
#[cfg(test)]
use crate::edge::EdgeKind;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::pipeline::WorldScope;
#[cfg(test)]
use crate::registry::ENTITY_TYPE_TURN;
#[cfg(test)]
use crate::task_verb::{ConsultPayloadRef, TaskAssignee};
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use crate::test_util::{entity, open_test_vault_with, put_policy_manifest_bytes};
