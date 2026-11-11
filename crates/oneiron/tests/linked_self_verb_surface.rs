//! The verb table is closed over the linked `self.*` operations (F2.1): each
//! operation a code-mode guest can link or call under `self.`, and each
//! agent-authoring import, is a verb row or an exact-name exemption with its
//! reason. An agent-authoring import never takes an exemption.

use std::collections::{BTreeMap, BTreeSet};

use oneiron::store::sandbox_contract::{
    LINKED_SELF_OPERATION_EXEMPTIONS, SandboxBoundaryContract, SandboxGuestTier,
};
use oneiron::store::sandbox_import::SandboxImportClass;
use oneiron::task_verb::sdk::{AgentVerb, RunVerb, code_mode_verb_names};

#[test]
fn linked_self_operations_have_verb_rows_or_named_exemptions() {
    let row_names: BTreeSet<&str> = AgentVerb::ALL
        .iter()
        .map(|verb| verb.as_str())
        .chain(RunVerb::ALL.iter().map(|verb| verb.as_str()))
        .collect();

    let mut linked: BTreeSet<&str> = code_mode_verb_names()
        .filter(|name| name.starts_with("self."))
        .collect();
    let mut authoring: BTreeSet<&str> = BTreeSet::new();
    for tier in [
        SandboxGuestTier::FirstPartyDreamer,
        SandboxGuestTier::Foreign,
        SandboxGuestTier::Untrusted,
    ] {
        for import in SandboxBoundaryContract::for_tier(tier).linked_imports() {
            if matches!(import.class(), SandboxImportClass::AgentAuthoring) {
                authoring.insert(import.name());
                linked.insert(import.name());
            } else if import.name().starts_with("self.") {
                linked.insert(import.name());
            }
        }
    }

    let mut exemptions = BTreeMap::new();
    for &(name, reason) in LINKED_SELF_OPERATION_EXEMPTIONS {
        assert!(name.starts_with("self."), "non-self exemption: {name}");
        assert!(!reason.trim().is_empty(), "exemption has no reason: {name}");
        assert!(
            exemptions.insert(name, reason).is_none(),
            "duplicate exemption: {name}"
        );
        assert!(
            linked.contains(name),
            "stale exemption is not linked: {name}"
        );
        assert!(
            !authoring.contains(name),
            "an agent-authoring import takes a row, not an exemption: {name}"
        );
        assert!(
            !row_names.contains(name),
            "exemption also has a verb row; remove the exemption: {name}"
        );
    }

    let missing: Vec<&str> = linked
        .iter()
        .copied()
        .filter(|name| !row_names.contains(*name) && !exemptions.contains_key(*name))
        .collect();
    assert!(
        missing.is_empty(),
        "linked code-mode operations have no verb row or named exemption: {}. \
         Add scripts/sdk/verbs/<operation>.json or an exact-name reason in \
         store::sandbox_contract::LINKED_SELF_OPERATION_EXEMPTIONS; \
         agent-authoring imports take rows, not exemptions.",
        missing.join(", ")
    );
}
