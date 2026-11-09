//! The Coach tunes the Dreamer's maintenance rows through `engine.controls`
//! (untangle 6.6b, the A1 family; S66-MAP = A). Through its minted default
//! grant the Coach sets the strength policy, the selection timing and the
//! projector policy; each change is in force, a field-level change keeps the
//! row's other fields, and each writes a receipt naming the Coach in the
//! maintenance class. An agent without the grant changes nothing. On the
//! base there is no holder door.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test coach_maintenance_rows`.
#![cfg(oneiron_test_support)]

use oneiron::EntityId;
use oneiron::dreamer_consolidation::strength::ConsolidationStrengthPolicy;
use oneiron::dreamer_wake::ProjectorPolicy;
use oneiron::federation::EngineControlClass;
use oneiron::test_doors::coach::coach;
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};

#[test]
fn the_coach_tunes_the_dreamers_maintenance_rows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    let coach = coach(&vault).expect("the Coach");
    vault.provision_system_agent_grants().expect("first mint");

    // The strength policy, whole.
    let strength = ConsolidationStrengthPolicy {
        archive_below: 0.2,
        quiet_ms: 86_400_000,
    };
    vault
        .set_consolidation_strength_policy_as_holder(coach, &strength)
        .expect("strength policy");
    assert_eq!(
        vault.consolidation_strength_policy().expect("strength"),
        strength
    );

    // The selection timing; every other field stays.
    let before = vault.consolidation_selection().expect("selection");
    vault
        .set_consolidation_selection_timing_as_holder(coach, 60_000, before.recency_window_ms * 2)
        .expect("selection timing");
    let after = vault.consolidation_selection().expect("selection");
    assert_eq!(after.soak_ms, 60_000);
    assert_eq!(after.recency_window_ms, before.recency_window_ms * 2);
    let mut expected = before.clone();
    expected.soak_ms = 60_000;
    expected.recency_window_ms = before.recency_window_ms * 2;
    assert_eq!(after, expected, "only the timing moved");

    // The projector policy.
    let projector = ProjectorPolicy {
        min_new_statements: 3,
    };
    vault
        .set_dreamer_projector_policy_as_holder(coach, projector)
        .expect("projector policy");
    assert_eq!(
        vault.dreamer_projector_policy().expect("projector"),
        projector
    );

    // Three receipts, each naming the Coach in the maintenance class.
    let changes = vault.engine_control_changes(&owner).expect("receipts");
    let knobs: Vec<&str> = changes
        .iter()
        .map(|(_, change)| change.knob.as_str())
        .collect();
    assert_eq!(
        knobs,
        vec![
            "DREAMER_CONSOLIDATION_STRENGTH_POLICY",
            "DREAMER_CONSOLIDATION_SELECTION",
            "DREAMER_PROJECTOR_POLICY",
        ]
    );
    assert!(changes.iter().all(|(_, change)| change.by == coach
        && !change.owner
        && change.class == EngineControlClass::MaintenanceCadence));

    // An agent without the grant changes nothing.
    assert!(
        vault
            .set_dreamer_projector_policy_as_holder(
                EntityId::now(),
                ProjectorPolicy {
                    min_new_statements: 9
                }
            )
            .is_err()
    );
    assert_eq!(
        vault.dreamer_projector_policy().expect("projector"),
        projector
    );
}

/// The C1 family: the Coach sets the Dreamer's wake policy, in force, with a
/// receipt in the wake-cadence class.
#[test]
fn the_coach_tunes_the_dreamers_wake_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    let coach = coach(&vault).expect("the Coach");
    vault.provision_system_agent_grants().expect("first mint");

    let mut policy = vault.dreamer_wake_policy().expect("wake policy");
    policy.longest_wait_secs += 60;
    vault
        .set_dreamer_wake_policy_as_holder(coach, policy)
        .expect("wake policy");
    assert_eq!(vault.dreamer_wake_policy().expect("wake policy"), policy);
    let changes = vault.engine_control_changes(&owner).expect("receipts");
    let [(_, change)] = changes.as_slice() else {
        panic!("one receipt, found {}", changes.len());
    };
    assert_eq!(change.knob, "DREAMER_WAKE_POLICY");
    assert_eq!(change.class, EngineControlClass::WakeCadence);
    assert_eq!(change.by, coach);
}
