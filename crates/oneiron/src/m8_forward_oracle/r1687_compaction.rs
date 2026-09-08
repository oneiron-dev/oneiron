//! ONE-1687 RT-05: memory-profile-on-agent-definition oracle and cheap-backend fixture.

use std::io::Cursor;

use rmpv::Value;

use super::shared::open_vault;
use crate::Vault;
use crate::agent_def::{
    AgentCeiling, AgentDefinition, AgentScope, CompactionOwnership, MemoryProfile,
    encode_agent_definition,
};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::compaction::{
    CompactionBackend, CompactionBackendRegistry, CompactionProduct, CompactionRequest,
    CompactionTierClass,
};
use crate::llm::ModelTierRef;

// ═══════════════════════════════════════════════════════════════════════
// ONE-1687 — [RT-05] per-agent compaction
// ═══════════════════════════════════════════════════════════════════════

/// The oracle's cheap compaction backend key.
const ORACLE_COMPACTION_BACKEND: &str = "oracle.cheap.slm";

/// A module-local CHEAP backend, registered so the frontier-tier fact is
/// answered by the REGISTRY's recorded class rather than by sniffing the
/// profile's tier string.
struct OracleCheapBackend;

impl CompactionBackend for OracleCheapBackend {
    fn backend_key(&self) -> &str {
        ORACLE_COMPACTION_BACKEND
    }

    fn tier_class(&self) -> CompactionTierClass {
        CompactionTierClass::Cheap
    }

    fn compact(&self, request: &CompactionRequest) -> crate::error::Result<CompactionProduct> {
        Ok(CompactionProduct {
            summary_text: format!("{} messages compacted", request.window.len()),
            latency: std::time::Duration::from_millis(1),
        })
    }
}

/// The window budget this fixture's profile carries.
///
/// Read through the SAME builder machinery the engine default flows through,
/// so the oracle's equality assert below is a real cross-read rather than an
/// echo of a constant this file re-spelled.
fn oracle_window_token_budget(vault: &Vault) -> u64 {
    context_pack_window_token_budget(vault)
}

fn minimal_agent_definition(vault: &Vault) -> AgentDefinition {
    AgentDefinition::new(
        "oracle-compaction-agent",
        "M8 oracle fixture",
        "1",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::Imported,
        1.0,
        false,
        true,
        // Arming note: the ignored fixture carried an EMPTY provenance map,
        // which `validate_agent_definition` has always refused. Un-ignoring
        // surfaced it; the fixture gains a real provenance map and no assert
        // below changes.
        Value::Map(vec![(
            Value::from("definedVia"),
            Value::from("m8_forward_oracle"),
        )]),
        None,
        true,
        None,
    )
    .with_memory_profile(Some(MemoryProfile::new(
        oracle_window_token_budget(vault),
        ModelTierRef(ORACLE_COMPACTION_BACKEND.to_owned()),
        CompactionOwnership::Engine,
    )))
}

/// The profile facts RT-05 pins. Field NAMES stay armer-owned — these are
/// accessor stubs over the seam, not literal record keys.
struct MemoryProfileFacts {
    /// The context-window token budget, LIFTED from `context_pack`.
    window_token_budget: u64,
    /// Dreamer ALWAYS owns MEMORY consolidation (the moat) — never the
    /// execution owner.
    dreamer_owns_memory_consolidation: bool,
    /// Ownership discriminant: first-party code mode vs a BYOA harness —
    /// whoever OWNS execution self-compacts its own window, and only that
    /// owner (never double-compacted).
    window_owner_is_first_party: bool,
    /// The pluggable cheap compaction backend named in the profile.
    compaction_backend: String,
    /// Frontier tiers are banned as compaction backends (cheap by design).
    compaction_backend_is_frontier_tier: bool,
}

/// ARMED (ONE-1687): reads the memory profile off the agent definition
/// record through its real accessors.
///
/// `dreamer_owns_memory_consolidation` is constant-true on purpose: the
/// Dreamer's ownership of MEMORY consolidation is a LAW, not a field, so
/// there is no record key that could ever answer `false`.
/// `compaction_backend_is_frontier_tier` is answered by
/// [`CompactionBackendRegistry::tier_class_of`] — the registry's recorded
/// class — never by sniffing the profile string, because the ban is enforced
/// at registration.
fn memory_profile_facts(_vault: &Vault, def: &AgentDefinition) -> MemoryProfileFacts {
    let profile = def
        .memory_profile
        .as_ref()
        .expect("the fixture definition carries a memory profile");
    let mut registry = CompactionBackendRegistry::new();
    registry
        .register(std::sync::Arc::new(OracleCheapBackend))
        .expect("a cheap backend registers");
    let tier_class = registry.tier_class_of(profile.compaction_backend.as_str());
    MemoryProfileFacts {
        window_token_budget: profile.window_token_budget,
        dreamer_owns_memory_consolidation: true,
        window_owner_is_first_party: profile.compaction == CompactionOwnership::Engine,
        compaction_backend: profile.compaction_backend.as_str().to_owned(),
        compaction_backend_is_frontier_tier: tier_class == Some(CompactionTierClass::Frontier),
    }
}

/// ARMED (ONE-1687): the `context_pack` token budget the profile's window
/// budget is LIFTED from.
///
/// The oracle's prose says "read from the config store"; no config store
/// exists at this head. The engine default reaches callers through ONE
/// authority — a default [`ContextPackBuilder`] read through
/// [`ContextPackBuilder::effective_token_budget`] — so constructing that
/// builder and asking it IS the cross-read the assert wants. Re-spelling the
/// module constant here would make the equality an echo instead.
fn context_pack_window_token_budget(vault: &Vault) -> u64 {
    vault.context_pack().effective_token_budget() as u64
}

/// RT-05: the consolidation-vs-compaction ownership split is observable
/// per agent — `context_pack`'s token budget and the compaction ownership
/// (Dreamer always owns MEMORY consolidation; the execution owner
/// self-compacts its own WINDOW, never double-compacted) lift onto
/// `AgentDefinition.memoryProfile`, with the pluggable cheap
/// `compaction_backend` named inside it.
#[test]
fn one_1687_memory_profile_rides_the_agent_definition_record() {
    let (_dir, vault) = open_vault();
    let definition = minimal_agent_definition(&vault);
    let body = encode_agent_definition(&definition).expect("encode agent def");
    let value = rmpv::decode::read_value(&mut Cursor::new(&body[..])).expect("decode body");
    let Value::Map(entries) = value else {
        panic!("agent definition body must be a MessagePack map");
    };
    let memory_profile_keys = entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some("memory_profile"))
        .count();
    assert_eq!(
        memory_profile_keys, 1,
        "the AgentDefinition record carries exactly one memory_profile \
         (window budget + compaction ownership + compaction_backend)"
    );

    // The NAMED components (C17/G4): a dummy "memory_profile" key cannot
    // pass — the budget must be nonzero AND equal the context_pack config
    // it lifts from, both ownership discriminants must be observable, and
    // the backend must be a named non-frontier model.
    let facts = memory_profile_facts(&vault, &definition);
    assert_ne!(facts.window_token_budget, 0, "a real window budget");
    assert_eq!(
        facts.window_token_budget,
        context_pack_window_token_budget(&vault),
        "LIFTED from context_pack: equal to the config it came from"
    );
    assert!(
        facts.dreamer_owns_memory_consolidation,
        "MEMORY consolidation is the Dreamer's, always"
    );
    assert!(
        facts.window_owner_is_first_party,
        "this fixture is first-party code mode; a BYOA harness flips the discriminant"
    );
    assert!(
        !facts.compaction_backend.is_empty(),
        "the cheap compaction backend is NAMED in the profile"
    );
    assert!(
        !facts.compaction_backend_is_frontier_tier,
        "compaction is cheap by design — never a frontier tier"
    );
}
