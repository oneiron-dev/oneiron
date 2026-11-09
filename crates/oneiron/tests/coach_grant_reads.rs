//! The Coach reads through its grant (untangle 6.6c): the agent health,
//! failure-evidence and retrieval-run reads answer the vault owner or a
//! holder of a Steward grant naming `read`, and the learning dials read a
//! holder of any `engine.controls` class, each checked at the call. They are general
//! verbs: any agent the owner grants reads them, the Coach by default. An
//! agent without the grant is refused, and a narrowed grant reads nothing
//! from its next call on.
//!
//! The verbs run by name through the SDK, as a code-mode or SDK caller runs
//! them. On the base the three new verbs are unknown and the three widened
//! ones answer the owner alone.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test coach_grant_reads`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::attempt_queue::AttemptId;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::{
    ENGINE_CONTROLS_VERBS, ENGINE_CONTROLS_WORK_BUDGET_VERB, coach, define_agent,
    read_and_engine_controls,
};
use oneiron::test_doors::steward::{STEWARD_READ_VERB, stand_steward_grant};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

fn open(dir: &tempfile::TempDir) -> Vault {
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    oneiron::test_support::provision_engine_machines(&vault);
    vault
}

/// Each evidence read, by verb and input.
fn evidence_reads(agent: EntityId) -> Vec<(&'static str, Value)> {
    vec![
        (
            "vault.agent_health.cards",
            json!({ "from": 0, "to": u64::MAX }),
        ),
        (
            "vault.agent_health.calls",
            json!({ "agent_ref": agent.to_hex(), "since": 0 }),
        ),
        (
            "vault.diagnostics.evidence",
            json!({ "attempt": AttemptId::now() }),
        ),
        ("vault.retrieval.runs", json!({})),
    ]
}

fn read(
    vault: &Vault,
    actor: EntityId,
    class: EdgeActorClass,
    verb: &str,
    input: Value,
) -> MemoryResult<Value> {
    invoke(&vault.memory(actor, class), verb, input)
}

fn assert_refused(answer: MemoryResult<Value>, verb: &str) {
    let error = answer.expect_err(&format!("{verb}: an ungranted reader is refused"));
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{verb}: {error:?}");
}

#[test]
fn a_steward_reader_reads_agent_health_and_an_ungranted_agent_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open(&dir);
    let agent = define_agent(&vault).expect("an agent");

    for (verb, input) in evidence_reads(agent) {
        assert_refused(
            read(&vault, agent, EdgeActorClass::Agent, verb, input),
            verb,
        );
    }

    stand_steward_grant(&vault, agent, &[STEWARD_READ_VERB]).expect("a read grant");
    for (verb, input) in evidence_reads(agent) {
        read(&vault, agent, EdgeActorClass::Agent, verb, input)
            .unwrap_or_else(|error| panic!("{verb}: a Steward `read` holder reads: {error:?}"));
    }

    // The verb is the grant's own: an agent holding only `engine.controls`
    // reads no evidence.
    let controls_only = define_agent(&vault).expect("a second agent");
    stand_steward_grant(&vault, controls_only, &ENGINE_CONTROLS_VERBS).expect("a controls grant");
    for (verb, input) in evidence_reads(agent) {
        assert_refused(
            read(&vault, controls_only, EdgeActorClass::Agent, verb, input),
            verb,
        );
    }
}

#[test]
fn the_dials_read_needs_engine_controls() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open(&dir);
    let agent = define_agent(&vault).expect("an agent");
    let dials = |actor, class| read(&vault, actor, class, "vault.settings.learning", json!({}));

    assert_refused(
        dials(agent, EdgeActorClass::Agent),
        "vault.settings.learning",
    );
    stand_steward_grant(&vault, agent, &[STEWARD_READ_VERB]).expect("a read grant");
    assert_refused(
        dials(agent, EdgeActorClass::Agent),
        "vault.settings.learning",
    );
    stand_steward_grant(&vault, agent, &[ENGINE_CONTROLS_WORK_BUDGET_VERB])
        .expect("a one-class controls grant");
    dials(agent, EdgeActorClass::Agent).expect("any engine.controls class reads the dials");

    // The Coach with its default grant reads the dials and agent health.
    let coach = coach(&vault).expect("the Coach");
    stand_steward_grant(&vault, coach, &read_and_engine_controls())
        .expect("the Coach's default grant");
    dials(coach, EdgeActorClass::System).expect("the Coach reads the dials");
    for (verb, input) in evidence_reads(agent) {
        read(&vault, coach, EdgeActorClass::System, verb, input)
            .unwrap_or_else(|error| panic!("{verb}: the Coach reads: {error:?}"));
    }

    // The grant is checked at each call: the Coach narrowed off `read` reads
    // no evidence from its next call on, and still reads the dials.
    stand_steward_grant(&vault, coach, &ENGINE_CONTROLS_VERBS).expect("the Coach narrowed");
    for (verb, input) in evidence_reads(agent) {
        assert_refused(
            read(&vault, coach, EdgeActorClass::System, verb, input),
            verb,
        );
    }
    dials(coach, EdgeActorClass::System).expect("the narrowed Coach still reads the dials");
}

#[test]
fn the_owner_reads_without_a_grant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open(&dir);
    let agent = define_agent(&vault).expect("an agent");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    for (verb, input) in evidence_reads(agent) {
        read(&vault, owner, EdgeActorClass::Human, verb, input)
            .unwrap_or_else(|error| panic!("{verb}: the owner reads: {error:?}"));
    }
    read(
        &vault,
        owner,
        EdgeActorClass::Human,
        "vault.settings.learning",
        json!({}),
    )
    .expect("the owner reads the dials");
}
