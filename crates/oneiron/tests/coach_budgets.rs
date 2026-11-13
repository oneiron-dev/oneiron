//! The Coach's work-budget changes stay inside the owner's caps (untangle
//! 6.6b, the B1 and B2 families; S66B-BUDGETS = A, A). A holder of
//! `engine.controls` lowers the sieve's per-pass budgets and is refused a
//! raise; it moves the schedule of a free-time policy that stands, keeping
//! the owner's `total_units` and the authority of the set it moves, while the
//! engine-control receipt records the act as the holder's (FABLE-6918-2); it
//! never creates or clears a policy. A move delays the next cycle and never
//! brings it forward, so no move opens a second cycle, with a second whole
//! allowance, on the day one already opened (FABLE-6918-1). On the base there
//! is no holder door.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test coach_budgets`.
#![cfg(oneiron_test_support)]

use oneiron::dreamer_runner::{
    DreamerRunnerStore, FreeTimeCadence, FreeTimePolicyInput, FreeTimeSchedule,
};
use oneiron::dreamer_wake::SievePassBudgets;
use oneiron::federation::EngineControlClass;
use oneiron::test_doors::coach::{coach, define_agent};
use oneiron::test_doors::steward::{GrantMark, grant_mark, open_owner_carrier_vault, owner};

#[test]
fn the_coach_lowers_the_sieve_budgets_and_never_raises_them() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    let coach = coach(&vault).expect("the Coach");
    vault.provision_system_agent_grants().expect("first mint");
    let held = vault.dreamer_sieve_policy().expect("sieve policy");

    let lower = SievePassBudgets {
        max_turns_per_pass: held.max_turns_per_pass / 2,
        max_scan_per_pass: held.max_scan_per_pass,
        max_text_bytes_per_pass: held.max_text_bytes_per_pass,
    };
    vault
        .lower_dreamer_sieve_budgets_as_holder(coach, lower)
        .expect("a lower budget");
    let after = vault.dreamer_sieve_policy().expect("sieve policy");
    assert_eq!(after.max_turns_per_pass, held.max_turns_per_pass / 2);
    assert_eq!(after.date_interest, held.date_interest, "scoring stays");

    let raise = SievePassBudgets {
        max_turns_per_pass: held.max_turns_per_pass,
        ..lower
    };
    assert!(
        vault
            .lower_dreamer_sieve_budgets_as_holder(coach, raise)
            .is_err(),
        "raising is the owner's act"
    );
    assert_eq!(vault.dreamer_sieve_policy().expect("sieve policy"), after);

    let changes = vault.engine_control_changes(&owner).expect("receipts");
    let [(_, change)] = changes.as_slice() else {
        panic!("one receipt, found {}", changes.len());
    };
    assert_eq!(change.knob, "DREAMER_SIEVE_POLICY");
    assert_eq!(change.class, EngineControlClass::WorkBudget);
    assert_eq!(change.by, coach);
}

fn schedule(hour: u8) -> FreeTimeSchedule {
    schedule_at(hour, 0)
}

fn schedule_at(hour: u8, minute: u8) -> FreeTimeSchedule {
    FreeTimeSchedule {
        cadence: FreeTimeCadence::Nightly,
        hour,
        minute,
        zone: "Asia/Tokyo".to_owned(),
    }
}

/// The owner's policy for an agent: 50,000 units a night at `hour` o'clock.
fn owners_policy(hour: u8) -> FreeTimePolicyInput {
    FreeTimePolicyInput {
        total_units: 50_000,
        schedule: schedule(hour),
        pinned_split: None,
        cap_shown_at_ms: 1_000,
    }
}

const MINUTE: u64 = 60;
/// One night apart in Asia/Tokyo, which keeps no summer time.
const DAY: u64 = 24 * 60 * MINUTE;

#[test]
fn the_coach_moves_a_free_time_schedule_and_keeps_the_owners_cap() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    let coach = coach(&vault).expect("the Coach");
    vault.provision_system_agent_grants().expect("first mint");
    let Some(GrantMark::Minted { .. }) = grant_mark(&vault, coach).expect("mark") else {
        panic!("the Coach holds its grant");
    };
    let agent = define_agent(&vault).expect("an agent");

    // No policy stands: the Coach creates none.
    assert!(
        vault
            .set_free_time_schedule_as_holder(coach, agent, 0, schedule(2))
            .is_err(),
        "creating a policy is the owner's act"
    );
    assert_eq!(vault.free_time_policy(agent).expect("policy"), None);

    // The owner sets one; the Coach moves its schedule only.
    let set = vault
        .set_free_time_policy(&owner, None, agent, 0, owners_policy(2))
        .expect("the owner's policy");
    let (_, moved) = vault
        .set_free_time_schedule_as_holder(coach, agent, set.revision, schedule(4))
        .expect("the Coach's schedule");
    assert_eq!(moved.schedule, schedule(4));
    assert_eq!(moved.revision, set.revision + 1);
    assert_eq!(moved.total_units, 50_000, "the owner's cap stays");
    assert_eq!(moved.cap_shown_at_ms, 1_000);
    assert_eq!(moved.pinned_split, None);
    // The set it moved keeps its authority: the owner's, at the owner's time.
    assert_eq!(moved.set_by, set.set_by, "the owner's set stands");
    assert_eq!(moved.set_by_agent, None);
    assert_eq!(
        moved.set_grant, None,
        "no grant is judged for the owner's set"
    );
    assert_eq!(moved.set_at, set.set_at);
    assert_eq!(moved.surface, set.surface);
    assert_eq!(
        vault.free_time_policy(agent).expect("policy"),
        Some(moved.clone())
    );

    // A stale revision is refused, and the receipt names the Coach.
    assert!(
        vault
            .set_free_time_schedule_as_holder(coach, agent, set.revision, schedule(5))
            .is_err()
    );
    let changes = vault.engine_control_changes(&owner).expect("receipts");
    let [(_, change)] = changes.as_slice() else {
        panic!("one receipt, found {}", changes.len());
    };
    assert_eq!(change.knob, "DREAMER_FREE_TIME_POLICY");
    assert_eq!(change.class, EngineControlClass::WakeCadence);
    assert_eq!(change.by, coach, "the move is the holder's act");
    assert!(!change.owner);
}

#[test]
fn holder_schedule_move_does_not_reopen_today() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    let coach = coach(&vault).expect("the Coach");
    vault.provision_system_agent_grants().expect("first mint");
    let agent = define_agent(&vault).expect("an agent");
    let set = vault
        .set_free_time_policy(&owner, None, agent, 0, owners_policy(3))
        .expect("the owner's policy");
    // Today's boundary: the policy's first, 03:00 in Tokyo.
    let today = vault
        .next_free_time_due_at()
        .expect("due")
        .expect("the owner's first boundary");
    let store = DreamerRunnerStore::new(&vault);
    let candidate = store
        .local_home_node_candidate(true, true, true)
        .expect("candidate");
    let node = store
        .elect_home_node(&[candidate], today)
        .expect("election")
        .expect("the vault's node is elected home")
        .node_id;
    assert_eq!(
        vault
            .enqueue_due_free_time_cycles(today, node)
            .expect("enqueue"),
        1,
        "the owner's boundary opens today's cycle"
    );

    // The Coach moves the schedule to a minute still ahead today.
    let (_, moved) = vault
        .set_free_time_schedule_as_holder(coach, agent, set.revision, schedule_at(3, 31))
        .expect("the Coach's move");
    assert_eq!(
        vault
            .enqueue_due_free_time_cycles(today + 31 * MINUTE, node)
            .expect("enqueue"),
        0,
        "a holder schedule move must not open a second cycle in the same day"
    );
    // A second move gains no cycle either.
    let (_, moved) = vault
        .set_free_time_schedule_as_holder(coach, agent, moved.revision, schedule_at(3, 32))
        .expect("the Coach's second move");
    assert_eq!(
        vault
            .enqueue_due_free_time_cycles(today + 32 * MINUTE, node)
            .expect("enqueue"),
        0,
        "nor does a second move"
    );
    assert_eq!(moved.total_units, 50_000, "the owner's cap stays");
    assert_eq!(
        vault
            .free_time_cycles(agent, None, 10)
            .expect("cycles")
            .len(),
        1,
        "one cycle, one allowance, today"
    );
    // Tomorrow's cycle opens at the moved minute.
    let tomorrow = today + DAY + 32 * MINUTE;
    assert_eq!(vault.next_free_time_due_at().expect("due"), Some(tomorrow));
    assert_eq!(
        vault
            .enqueue_due_free_time_cycles(tomorrow, node)
            .expect("enqueue"),
        1,
        "tomorrow's cycle opens"
    );
}

#[test]
fn a_holder_schedule_move_before_the_days_cycle_still_opens_it_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    let coach = coach(&vault).expect("the Coach");
    vault.provision_system_agent_grants().expect("first mint");
    let agent = define_agent(&vault).expect("an agent");
    let set = vault
        .set_free_time_policy(&owner, None, agent, 0, owners_policy(3))
        .expect("the owner's policy");
    let first = vault
        .next_free_time_due_at()
        .expect("due")
        .expect("the owner's first boundary");
    let store = DreamerRunnerStore::new(&vault);
    let candidate = store
        .local_home_node_candidate(true, true, true)
        .expect("candidate");
    let node = store
        .elect_home_node(&[candidate], first)
        .expect("election")
        .expect("the vault's node is elected home")
        .node_id;

    // Before that boundary, the Coach moves the night's cycle an hour later.
    vault
        .set_free_time_schedule_as_holder(coach, agent, set.revision, schedule(4))
        .expect("the Coach's move");
    assert_eq!(
        vault
            .enqueue_due_free_time_cycles(first + 60 * MINUTE, node)
            .expect("enqueue"),
        1,
        "the night's cycle opens at the moved time"
    );
    assert_eq!(
        vault
            .enqueue_due_free_time_cycles(first + 61 * MINUTE, node)
            .expect("enqueue"),
        0,
        "and only once"
    );
}
