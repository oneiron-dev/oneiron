use std::collections::BTreeMap;

use oneiron::{
    code_run::SelfEffect, code_sandbox::SANDBOX_WIT_WORLD_NAME,
    code_sandbox::SandboxBoundaryContract, code_sandbox::SandboxGuestTier,
    code_sandbox::SandboxImportClass, code_sandbox::SandboxLinkedImportEffects,
    task_verb::sdk::RunVerb,
};

#[test]
fn of060_p3_code_mode_guest_surface_links_named_verbs_only() {
    let first_party = SandboxBoundaryContract::for_tier(SandboxGuestTier::FirstPartyDreamer);
    assert_eq!(first_party.wit_world(), SANDBOX_WIT_WORLD_NAME);

    let mut write_imports = BTreeMap::new();
    for import in first_party
        .linked_imports()
        .iter()
        .filter(|import| import.class() == SandboxImportClass::WriteTrap)
    {
        assert!(
            write_imports
                .insert(
                    import.name().to_owned(),
                    import.write_trap_effect().expect("named write trap"),
                )
                .is_none(),
            "write-import names must be unique",
        );
    }
    // The memory writes reach the guest as verb-table rows the run answers
    // itself, each its own named, gated effect: the same closed set.
    for verb in RunVerb::ALL.iter().filter(|verb| verb.writes()) {
        assert!(
            write_imports
                .insert(format!("self.memory.{}", verb.as_str()), verb.effect())
                .is_none(),
            "write-import names must be unique",
        );
    }
    assert_eq!(
        write_imports,
        BTreeMap::from([
            (
                "self.memory.put_claim".to_owned(),
                SelfEffect::MemoryPutClaim
            ),
            (
                "self.memory.supersede_claim".to_owned(),
                SelfEffect::MemorySupersedeClaim,
            ),
            ("self.memory.put_edge".to_owned(), SelfEffect::MemoryPutEdge),
            ("self.report_blocked".to_owned(), SelfEffect::ReportBlocked),
        ]),
        "OF-060 P3: write imports must map exactly to authorized memory effects and the blocked-report receipt",
    );
    for verb in RunVerb::ALL {
        assert_ne!(
            verb.effect(),
            SelfEffect::MemoryWriteFixture,
            "OF-060 P3: a run row must not expose the fixture write effect",
        );
    }

    for tier in [
        SandboxGuestTier::FirstPartyDreamer,
        SandboxGuestTier::Foreign,
        SandboxGuestTier::Untrusted,
    ] {
        let contract = SandboxBoundaryContract::for_tier(tier);
        for import in contract.linked_imports() {
            assert!(
                !matches!(
                    import.write_trap_effect(),
                    Some(SelfEffect::MemoryWriteFixture),
                ),
                "OF-060 P3: {tier:?} must not expose the fixture write effect",
            );
            for forbidden in [
                "batch",
                "bulk",
                "raw",
                "delete",
                "put_entity",
                "put_replicated",
                "set_edge_weight",
                "write_fixture",
            ] {
                assert!(
                    !import.name().contains(forbidden),
                    "OF-060 P3: {tier:?} code-mode WIT import {} exposes raw escape hatch fragment {forbidden}",
                    import.name()
                );
            }
        }
    }
}
