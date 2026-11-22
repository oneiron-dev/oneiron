//! One extraction selection flow over a real vault without a model.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-driver --all-features --test extraction_selection_flow`.
//! Two identical operands citing distinct TURNs group to one union; with
//! `evidence_minimum = 2` the singletons hold and the union readies.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::dreamer_consolidation::selection::SelectionConfig;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::extraction_inputs::{
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{AttemptId, EntityId, Vault, VaultConfig};
use oneiron_dreamer::extraction_observations::read_observations;
use oneiron_dreamer::extraction_selection::{
    ExtractionSelectionConfig, group_candidates, observe_and_select, select, union_operands,
};
use oneiron_remote::OneironClient;
use serde_json::{Value, json};

type FlowTestResult<T> = Result<T, Box<dyn std::error::Error>>;

const QUEUE_NOW: u64 = 1_000;
const INPUTS_PAGE_VERB: &str = "vault.consolidation.extraction.inputs.page";

fn attempt_hex(attempt: AttemptId) -> String {
    attempt
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn flow_operands(subject: &str, turns: &[Value]) -> Vec<Value> {
    vec![
        json!({
            "subject": subject,
            "predicate": "preference.food",
            "value": "green tea",
            "evidence": [{"turn": turns[0]["turn"], "version": turns[0]["version"]}],
        }),
        json!({
            "subject": subject,
            "predicate": "preference.food",
            "value": "green tea",
            "evidence": [{"turn": turns[1]["turn"], "version": turns[1]["version"]}],
        }),
    ]
}

#[test]
fn duplicate_operands_group_to_one_union_and_ready() -> FlowTestResult<()> {
    let directory = tempfile::tempdir()?;
    drop(open_dreamer_vault(directory.path(), "owen")?);
    let vault = Vault::open_owned(directory.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    let vault = Arc::new(vault);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let updated = SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 2,
        ..vault.consolidation_selection()?
    };
    vault.set_consolidation_selection(&updated)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed =
        witness_extraction_turns(&vault, &["owen savors green tea", "owen cooks daily"])?;
    let (attempt, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let attempt_hex = attempt_hex(attempt);
    let binding = vault.bind_dreamer_attempt(&admitted)?;
    let client = OneironClient::for_dreamer_attempt(binding);
    let now_ms = vault.now_recorded_at().saturating_add(1) * 1_000;
    let inputs = client.agent_verb(INPUTS_PAGE_VERB, json!({"attempt": attempt_hex}))?;
    let policy_pin = inputs["value"]["policy_pin"]
        .as_str()
        .ok_or("the inputs page serves its policy pin")?
        .to_owned();
    let selection_value = inputs["value"]["policy"]["selection"].clone();
    let config = ExtractionSelectionConfig::from_selection(selection_value, &policy_pin)?;
    let turns = inputs["value"]["turns"]
        .as_array()
        .ok_or("the inputs page serves its turns")?;
    assert_eq!(turns.len(), 2, "both witnessed turns are served");
    let operands = flow_operands(&subject.to_hex(), turns);
    let first = read_observations(&client, &attempt_hex, now_ms, &operands)?;
    assert_eq!(first.candidates.len(), 2, "one row per operand");
    assert_eq!(first.candidates[0].evidence_count, 1);
    assert_eq!(first.candidates[1].evidence_count, 1);
    assert_eq!(first.policy_pin, policy_pin);
    let rows: Vec<Option<_>> = first.candidates.into_iter().map(Some).collect();
    let groups = group_candidates(&rows);
    assert!(groups.pending_bindings.is_empty(), "no declared subjects");
    assert_eq!(
        groups.groups.len(),
        1,
        "identical operands fold to one group"
    );
    assert_eq!(groups.groups[0].representative_index, 0);
    assert_eq!(groups.groups[0].member_indexes, vec![0, 1]);
    let union = union_operands(&operands, &groups);
    assert_eq!(union.len(), 1, "one union operand per group");
    assert_eq!(
        union[0]["evidence"]
            .as_array()
            .ok_or("the union carries its evidence")?
            .len(),
        2,
        "member evidence unions in member order"
    );
    let union_observations = read_observations(&client, &attempt_hex, now_ms, &union)?;
    assert_eq!(union_observations.candidates.len(), 1);
    assert_eq!(union_observations.candidates[0].index, 0);
    assert_eq!(union_observations.candidates[0].evidence_count, 2);
    let plan = select(&groups, &union_observations, now_ms, &config)?;
    assert_eq!(plan.ready, vec![0], "the union meets its minimum");
    assert!(plan.held.is_empty(), "nothing is held");
    assert_eq!(plan.groups.len(), 1);
    let auto = observe_and_select(
        &client,
        &attempt_hex,
        now_ms,
        &operands,
        &config,
        &policy_pin,
    )?;
    assert_eq!(auto.ready, vec![0]);
    assert!(auto.held.is_empty());
    assert_eq!(auto.groups.len(), 1);
    assert_eq!(auto.groups[0].representative_index, 0);
    assert_eq!(auto.groups[0].member_indexes, vec![0, 1]);
    assert_eq!(plan.policy_pin, union_observations.policy_pin);
    assert_eq!(plan.facts_pin, union_observations.facts_pin);
    Ok(())
}
