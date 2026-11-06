//! The per-agent context-window memory profile (RT-05, ONE-1687) an agent
//! definition stores: its window budget and split, who compacts it, its hot
//! window, output decay, verbatim pins and optional recall.

use oneiron_model::llm::ModelTierRef;

use crate::store::agent_optional_memory::OptionalMemoryProfile;
use crate::store::agent_record::{CompactionOwnership, ContextBudgetSplit};
use crate::store::output_decay::OutputDecayPolicy;

/// The per-agent context-window memory profile (RT-05, ONE-1687).
///
/// Additive and optional: an `AgentDefinition` carrying `None` reproduces
/// today's behavior byte-for-byte, so the record grew without moving any
/// existing agent's assembly.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct MemoryProfile {
    /// Context-window token budget for this agent — the lift of
    /// `context_pack`'s builder-constant default.
    pub window_token_budget: u64,
    /// Optional per-entity-class split; absent = the engine default split.
    pub budget_split: Option<ContextBudgetSplit>,
    /// Host-registered compaction backend key. Resolved against the
    /// compaction registry at drive time; never a frontier tier. The ban is
    /// enforced at registration, not by sniffing this string.
    pub compaction_backend: ModelTierRef,
    /// Who compacts this agent's context WINDOW.
    pub compaction: CompactionOwnership,
    /// How many recent steps stay raw past a compaction (agent-runtime-v1
    /// #d7 hot window, Docs Q13); absent = the host's configured hot window.
    pub hot_steps: Option<u64>,
    /// When a stored output decays to its overview, then to a stub, in turns
    /// (#d7 decay thresholds); absent = the executor's default decay.
    pub output_decay: Option<OutputDecayPolicy>,
    /// Literal text every summary of this agent's window keeps verbatim when
    /// the span holds it (#d7 verbatim pins). User messages and failure lines
    /// stay pinned regardless; these are added, never a replacement.
    pub verbatim_pins: Vec<String>,
    /// The optional recall this reader takes per task family; absent = the
    /// caller's request as sent. Separate from the window above.
    pub optional_memory: Option<OptionalMemoryProfile>,
}
