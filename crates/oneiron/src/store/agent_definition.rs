//! The stored agent definition record (AGENT_DEF): a saved, host-agnostic
//! agent composition and the shared lifecycle block it carries.

use oneiron_contracts::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron_model::llm::{ModelId, ModelTierRef};
use oneiron_store::write_envelope::skill_record::SkillDependency;
use rmpv::Value;

use crate::entity_id::EntityId;
use crate::store::agent_memory_profile::MemoryProfile;
use crate::store::agent_model::AgentModel;
use crate::store::agent_record::{AgentCeiling, AgentWakeCadence, DreamingMode, McpRef};
use crate::store::agent_refusal::RefusalDial;
use crate::store::agent_scope::AgentScope;

/// A saved, host-agnostic agent composition record.
///
/// The lifecycle block (`approval_status` … `provenance`) is the shared
/// `SkillRecord` machinery, field-for-field. `generated`/`human_authored` are a
/// mutually-exclusive authorship pair and `generated` tracks
/// `source == ClaimSource::Generated`; both invariants are frozen on update.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct AgentDefinition {
    pub agent_id: String,
    pub desc: String,
    pub version: String,
    pub instructions: Option<String>,
    pub skills: Vec<SkillDependency>,
    pub connectors: Vec<String>,
    pub code_mode_mcps: Vec<McpRef>,
    pub model_tier: Option<ModelTierRef>,
    pub scope: AgentScope,
    pub ceiling: AgentCeiling,
    /// The fork parent's stored row id. Frozen on update.
    pub forked_from: Option<EntityId>,
    pub approval_status: ClaimApprovalStatus,
    pub lifecycle_status: ClaimLifecycleStatus,
    pub source: ClaimSource,
    pub confidence: f32,
    pub generated: bool,
    pub human_authored: bool,
    pub provenance: Value,
    /// Stable lookup key for a seeded row (`sys.*`). User-created definitions
    /// carry `None`; once `Some`, it is frozen on update.
    pub logical_id: Option<String>,
    /// Whether this definition may be dispatched. Row state, not absence —
    /// reseeding never resurrects a user's "off".
    pub enabled: bool,
    /// Runtime-editable display name; deliberately NOT in the freeze-set.
    pub display_name: Option<String>,
    /// Per-agent context-window memory profile (RT-05, ONE-1687). A dial, not
    /// identity: it may change on update under the ordinary version-bump rule,
    /// so it is deliberately NOT in the freeze-set.
    pub memory_profile: Option<MemoryProfile>,
    /// Absent means enabled and inheriting the vault weaver model and window.
    pub dreaming: Option<DreamingMode>,
    /// Optional per-resident model slot for `Own` dreaming. Host-resolved.
    pub dreaming_model: Option<ModelTierRef>,
    /// An absent role follows the owner-editable wake-policy absent-role row.
    pub wake_cadence: Option<AgentWakeCadence>,
    /// Her refusal dial (OF-533). Absent, or a domain left unset, takes the
    /// vault-kind default; resolve through [`crate::agent_def::resolve_refusal`]. A
    /// dial, not identity: deliberately NOT in the freeze-set.
    pub refusal: Option<RefusalDial>,
    /// The models the agent may run on, in its owner's order, each with the
    /// owner's words on when (FIX 4472). Empty: its one house-routed model.
    /// A dial, not identity: deliberately NOT in the freeze-set.
    pub models: Vec<AgentModel>,
    /// The model that compacts the agent's window; absent takes the default
    /// its host supplies (for a `self` writer, the self-compaction row's
    /// cheap model, FIX 6029). It need not be listed; resolve through
    /// [`crate::agent_def::resolve_compaction_model`].
    pub compaction_model: Option<ModelId>,
}
