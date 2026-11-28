//! Pass 34 row P2 (`34-compute-general/DESIGN.md` sections 4.1, 4.3 step 2 and 10): warm keys
//! on the issuer's side. The PLACE rule prefers the machine that already holds what the order
//! reads after its role and before its headroom; an input a machine's template maps but does
//! not hold blocks the order there, under the node's own code; and a list of warm keys is
//! refused when it is malformed, repeats a key or passes its bound.
//!
//! The machines' facts are what the test says they reported; nothing is stored.
//!
//! `cargo test --locked -p oneiron --all-features --test work_order_warm`

use oneiron::EntityId;
use oneiron::job_workload::ResourceRequest;
use oneiron::warm_key::{WarmKeyInvalid, check_warm_keys};
use oneiron::work_order::{
    Blocker, MachineFacts, MachineReach, OrderCharge, OrderClass, OrderLimits, OrderState,
    OrderWishes, OrderedBy, Room, TemplateFact, WaitRule, WorkOrder, fit, place,
};

const NOW: u64 = 1_800_000_000_000;
const TEMPLATE: &str = "builds";
const TEMPLATE_DIGEST: &str = "2222222222222222222222222222222222222222222222222222222222222222";

/// A CPU-only order that reads `warm`.
fn order(warm: &[&str]) -> WorkOrder {
    WorkOrder {
        id: EntityId::now(),
        ordered_by: OrderedBy::Owner {
            owner: Some(EntityId::now()),
        },
        workload: "workload-digest".to_owned(),
        request: ResourceRequest {
            cpu_threads: 4,
            memory_mib: 4_096,
            disk_mib: 1_024,
            devices: Vec::new(),
            maximum_secs: 600,
        },
        charge: OrderCharge::Offer {
            name: "builds".to_owned(),
        },
        limits: OrderLimits::default(),
        wishes: OrderWishes {
            warm: warm.iter().map(|key| (*key).to_owned()).collect(),
            machine: None,
        },
        class: OrderClass::default(),
        wait: WaitRule::Open,
        retry_on: Vec::new(),
        state: OrderState::Open {
            blocked: Vec::new(),
            looked_at_ms: NOW,
            earliest_ms: None,
        },
        cancel: None,
        retry_not_before_ms: None,
        attempts: Vec::new(),
        result: None,
        intent_key: None,
        after: None,
        group: None,
        ordered_at_ms: NOW,
        updated_at_ms: NOW,
        revision: 0,
    }
}

/// A machine with the work roles `roles` and the warm keys `warm`, whose free threads and
/// memory are `free_tenths` tenths of its totals.
fn machine(roles: &[&str], warm: &[&str], free_tenths: u32) -> MachineFacts {
    MachineFacts {
        machine: EntityId::now(),
        reach: MachineReach::Answered { at_ms: NOW },
        enabled: true,
        refusal: None,
        paused: None,
        drained: None,
        templates: Some(vec![TemplateFact {
            name: TEMPLATE.to_owned(),
            digest: TEMPLATE_DIGEST.to_owned(),
        }]),
        room: Room {
            threads_total: Some(40),
            threads_free: Some(4 * free_tenths),
            memory_total_mib: Some(81_920),
            memory_free_mib: Some(8_192 * u64::from(free_tenths)),
            disk_free_mib: Some(100_000),
            frees_at_ms: None,
        },
        devices: None,
        window: None,
        keep_headroom_pct: None,
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        warm: warm.iter().map(|key| (*key).to_owned()).collect(),
        warm_absent: Vec::new(),
    }
}

#[test]
fn a_warm_machine_is_preferred_after_role_and_before_headroom() {
    let keys = ["weights:aa", "env:open-models"];
    let warm_tight = machine(&["builds"], &keys, 3);
    let some_roomy = machine(&["builds"], &keys[..1], 10);
    let cold_roomy = machine(&["builds"], &[], 10);
    let other_role_warm = machine(&["experiments"], &keys, 10);
    let candidates = [&cold_roomy, &other_role_warm, &some_roomy, &warm_tight];

    let (picked, decision) = place(&order(&keys), &candidates).expect("a machine fits");
    assert_eq!(picked.machine, warm_tight.machine);
    assert_eq!(decision.why, "already holds weights:aa, env:open-models");
    // The role first; then all of the keys, some, none; the roomiest only breaks those ties.
    let expected: Vec<String> = [&warm_tight, &some_roomy, &cold_roomy, &other_role_warm]
        .iter()
        .map(|facts| facts.machine.to_hex())
        .collect();
    assert_eq!(decision.options, expected);

    // With no warm wish the same machines go by headroom.
    let (picked, decision) = place(&order(&[]), &candidates).expect("a machine fits");
    assert!(
        picked.machine == cold_roomy.machine || picked.machine == some_roomy.machine,
        "{decision:?}"
    );
    assert_eq!(decision.why, "tie");
}

#[test]
fn the_warm_reason_names_only_the_keys_the_picked_machine_holds() {
    let holds_a = machine(&["builds"], &["env:a"], 10);
    let holds_none = machine(&["builds"], &[], 10);
    let (picked, decision) =
        place(&order(&["env:a", "env:b"]), &[&holds_none, &holds_a]).expect("a machine fits");
    assert_eq!(picked.machine, holds_a.machine);
    assert_eq!(decision.why, "already holds env:a");
}

#[test]
fn an_order_listing_a_missing_input_is_blocked_on_that_machine_as_warm_key_missing() {
    let mut lacking = machine(&[], &["env:open-models"], 10);
    lacking.warm_absent = vec!["weights:aa".to_owned()];
    let holding = machine(&[], &["weights:aa"], 10);
    let wanting = order(&["weights:aa"]);

    let blocked = fit(&wanting, (TEMPLATE, TEMPLATE_DIGEST), &lacking);
    let missing = Blocker::WarmKeyMissing {
        key: "weights:aa".to_owned(),
    };
    assert_eq!(blocked, [missing.clone()]);
    assert_eq!(missing.code(), "warm_key_missing");
    assert!(!missing.clears_by_waiting(), "no wait fetches an input");
    // The node's launch refusal names the same blocker.
    assert_eq!(
        Blocker::of_node_reason("warm_key_missing:weights:aa"),
        missing
    );
    assert!(fit(&wanting, (TEMPLATE, TEMPLATE_DIGEST), &holding).is_empty());
    // An order that does not list the key is not blocked by it.
    assert!(fit(&order(&[]), (TEMPLATE, TEMPLATE_DIGEST), &lacking).is_empty());
}

#[test]
fn a_warm_key_list_is_refused_when_malformed_repeated_or_over_its_bound() {
    let keys =
        |list: &[&str]| -> Vec<String> { list.iter().map(|key| (*key).to_owned()).collect() };
    assert_eq!(
        check_warm_keys(&keys(&["weights:aa", "worktree:oneiron@1f2e"]), 2),
        Ok(())
    );
    for malformed in ["weights", ":aa", "Weights:aa", "weights:a a", "weights:"] {
        assert_eq!(
            check_warm_keys(&keys(&[malformed]), 2),
            Err(WarmKeyInvalid::Form(malformed.to_owned())),
            "{malformed}"
        );
    }
    let long = format!("dataset:{}", "a".repeat(128));
    assert!(matches!(
        check_warm_keys(&keys(&[long.as_str()]), 2),
        Err(WarmKeyInvalid::Form(_))
    ));
    assert_eq!(
        check_warm_keys(&keys(&["env:x", "env:x"]), 2),
        Err(WarmKeyInvalid::Repeated("env:x".to_owned()))
    );
    assert_eq!(
        check_warm_keys(&keys(&["env:x", "env:y", "env:z"]), 2),
        Err(WarmKeyInvalid::TooMany { count: 3, max: 2 })
    );
}
