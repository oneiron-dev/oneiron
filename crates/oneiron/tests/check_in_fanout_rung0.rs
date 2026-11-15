//! ROLES-CHECKIN PR 3, P3.4 (CHECKIN-PR1-SHAPE Q2 = A; ARCH-0082 #ladder):
//! fan-out's standing row is check-in's rung 0. An accepted standing approval
//! that covers a plan answers before the mode, so it clears the plan under
//! `manual` as under `auto`, and no classifier is asked. With no such row the
//! mode and the classifier decide as before, `full-access` still goes before
//! rung 0, and a pathology still pauses first.
//!
//! The admission arms run through the PR 1 door; the last test runs the
//! public consult fan-out doors end to end: a manual vault's owner answers
//! "approve and remember" once, and the next fan-out as wide goes.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test check_in_fanout_rung0`.
#![cfg(oneiron_test_support)]
// RED PIN: main plus the end-to-end test alone (the door arms need the PR door).

use oneiron::check_in::CheckInMode;
use oneiron::config::VaultConfig;
use oneiron::edge::EdgeActorClass;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::{
    ConsultFanOutChoice, ConsultFanOutPolicy, ConsultFanOutSpec, ConsultPayloadRef,
};
use oneiron::{EntityId, TimeRange, Vault};

fn person(vault: &Vault, seed: u8) -> EntityId {
    let id = EntityId::from_bytes([seed; 16]).expect("actor id");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"actor",
        )
        .expect("put actor");
    id
}

fn question(vault: &Vault, seed: u8) -> ConsultPayloadRef {
    let turn_ref = EntityId::from_bytes([seed; 16]).expect("turn id");
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("role"),
            rmpv::Value::from("question"),
        )]),
    )
    .expect("encode turn body");
    vault
        .put_entity(
            &turn_ref,
            ENTITY_TYPE_TURN,
            TimeRange { start: 1, end: 1 },
            1,
            &body,
        )
        .expect("put turn");
    ConsultPayloadRef::parse(vault, &format!("tn_{}", turn_ref.to_hex()))
        .expect("turn parses as a consult ref")
}

fn spec(vault: &Vault, question: ConsultPayloadRef, peers: &[u8]) -> ConsultFanOutSpec {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs();
    ConsultFanOutSpec {
        question_ref: question,
        context_refs: Vec::new(),
        assignees: peers.iter().map(|seed| person(vault, *seed)).collect(),
        deadline_at: now + 3_600,
        label: Some("consult".into()),
        now: None,
    }
}

#[test]
fn a_remembered_approval_lets_the_next_manual_fan_out_go() {
    let dir = tempfile::tempdir().expect("vault dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    // The seeded first-party agent the default manifest grants an Auto ceiling.
    let asker = person(&vault, 0xE1);
    let owner_actor = vault.ensure_embedded_owner_actor().expect("owner actor");
    let owner = vault
        .authenticate_owner(owner_actor, "principal:owner", true, GateDecisionId::now())
        .expect("owner proof");
    let facade = vault.memory(asker, EdgeActorClass::Agent);
    facade
        .set_consult_fanout_policy(
            &owner,
            &ConsultFanOutPolicy {
                mode: CheckInMode::AlwaysAsk,
                ..Default::default()
            },
        )
        .expect("manual fan-out");
    let asked = question(&vault, 0x7A);

    // `manual` pauses the first fan-out. The owner approves it and remembers:
    // "stop asking" writes the standing row, bounded at three consults.
    let first = facade
        .fan_out_consults(&spec(&vault, asked, &[0xE2, 0xE3, 0xE4]))
        .expect("first fan-out");
    assert!(first.paused.is_some(), "manual pauses the first fan-out");
    assert!(first.task_refs.is_empty());
    let resumed = facade
        .resume_fan_out_consults(
            first.correlation_ref,
            first.meter.plan_digest,
            ConsultFanOutChoice::ApproveAndRemember,
            &owner,
        )
        .expect("approve and remember");
    assert_eq!(resumed.task_refs.len(), 3);

    // The next fan-out of the same question, as wide: the remembered row is
    // its rung 0, so it goes and nobody is asked.
    let second = facade
        .fan_out_consults(&spec(&vault, asked, &[0xE5, 0xE6, 0xE7]))
        .expect("second fan-out");
    assert!(
        second.paused.is_none(),
        "a covered fan-out goes under manual: {:?}",
        second.paused
    );
    assert_eq!(second.task_refs.len(), 3);

    // A wider one is not covered by a row bounded at three: manual pauses it.
    let wider = facade
        .fan_out_consults(&spec(&vault, asked, &[0xE8, 0xE9, 0xEA, 0xEB]))
        .expect("wider fan-out");
    assert!(wider.paused.is_some(), "an uncovered fan-out still pauses");
    assert!(wider.task_refs.is_empty());
}
