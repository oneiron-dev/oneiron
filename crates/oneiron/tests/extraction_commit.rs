//! Extraction binding commits Candidate items with attempt outputs (T1-T3).
//!
//! T1 lands one green-tea candidate via the binding with every field the
//! stamp-door fixture checks (run `EXTRACTION_RUN`), then proves Settle and
//! Claim batches are refused as facet kinds with batches and outputs
//! unchanged. T2 compares attempt outputs: the binding records its claim
//! while a stamp-door fresh fixture records nothing. T3 ends the lease and
//! proves no derivation is written (nearest honest form, explicitly not a
//! metric test).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test extraction_commit`.
#![cfg(oneiron_test_support)]

#[allow(dead_code)]
#[path = "extraction_verdict/support.rs"]
mod verdict_support;

#[allow(dead_code)]
#[path = "extraction_commit/support.rs"]
mod support;

use oneiron::dreamer_consolidation::selection::SelectionConfig;
use oneiron::dreamer_runner::{
    CompleteDreamerAttempt, CompleteDreamerAttemptOutcome, DreamerRunnerStore,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_LEASE_REQUIRED};
use oneiron::test_doors::derive::{batches_of, claim_lifecycle, derive_item_receipts};
use oneiron::test_doors::derive_conflict;
use oneiron::test_doors::extraction_inputs::{
    EXTRACTION_LEASE_OWNER, enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::extraction_outputs::recorded_outputs;
use oneiron::test_doors::open_candidate::build_native_candidate;
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{EdgeActorClass, EntityId};
use serde_json::json;
use std::sync::Arc;
use support::{
    DERIVE_COMMIT_VERB, FOOD, TestResult, candidate_spec, land_green_tea_via_binding, member,
    operand_for,
};
use verdict_support::{
    QUEUE_NOW, bind_extraction, extraction_attempt_hex, open_extraction_verdict_vault,
    page_turns_with_versions, read_bound_extraction_page,
};

/// One candidate lands via the binding as native prepares it, then Settle
/// and Claim batches are refused as facet kinds with batches and outputs
/// unchanged.
#[test]
fn an_extraction_binding_commits_a_candidate() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    vault.set_consolidation_selection(&SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 1,
        ..vault.consolidation_selection()?
    })?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, &["owen chooses green tea"])?;
    let (attempt_id, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt_id))?;
    let turns = page_turns_with_versions(&page);
    let landed = land_green_tea_via_binding(&vault, attempt_id, &binding, &turns, &subject)?;
    let dreamer_id = dreamer(&vault)?;
    let batches_before = batches_of(&vault, dreamer_id)?;
    assert_eq!(batches_before.len(), 1);
    assert_eq!(batches_before[0], landed.batch);
    let outputs_before = recorded_outputs(&vault, attempt_id)?;
    assert_eq!(outputs_before, vec![landed.claim]);
    // A well-formed Settle batch names any stored ref; the existing subject
    // proves facet refusal before the stager reads a marker.
    let settle = json!({
        "items": [{
            "kind": "settle",
            "spec": {
                "local": "refused-settle",
                "marker": {"stored": subject.to_hex()},
                "settlement": "dismiss",
            },
        }],
        "sources": [],
    });
    let Err(refused_settle) = binding.invoke(DERIVE_COMMIT_VERB, settle, None) else {
        panic!("a Settle batch is refused as a facet kind");
    };
    assert_eq!(refused_settle.code, MEMORY_CODE_FORBIDDEN);
    assert!(
        refused_settle
            .message
            .contains("extraction facet does not admit"),
        "unexpected refusal: {refused_settle:?}"
    );
    assert_eq!(batches_of(&vault, dreamer_id)?, batches_before);
    assert_eq!(recorded_outputs(&vault, attempt_id)?, outputs_before);
    // A well-formed Claim batch cites its evidence turn with the served
    // version; the subject needs no version (batch `cited` is evidence
    // only, the stager reads the subject itself).
    let turn = &turns[0];
    let claim = json!({
        "items": [{
            "kind": "claim",
            "spec": {
                "local": "refused-claim",
                "predicate": FOOD,
                "subject": {"stored": subject.to_hex()},
                "value": json!("green tea"),
                "confidence": 0.9,
                "evidence": [{"stored": turn.0}],
            },
        }],
        "sources": [turn.1.clone()],
    });
    let Err(refused_claim) = binding.invoke(DERIVE_COMMIT_VERB, claim, None) else {
        panic!("a Claim batch is refused as a facet kind");
    };
    assert_eq!(refused_claim.code, MEMORY_CODE_FORBIDDEN);
    assert!(
        refused_claim
            .message
            .contains("extraction facet does not admit"),
        "unexpected refusal: {refused_claim:?}"
    );
    assert_eq!(batches_of(&vault, dreamer_id)?, batches_before);
    assert_eq!(recorded_outputs(&vault, attempt_id)?, outputs_before);
    Ok(())
}

/// The binding records its landed claim as the attempt's output, while a
/// stamp-door fresh fixture with the same green-tea candidate records
/// nothing.
#[test]
fn a_binding_s_commit_records_the_attempt_s_outputs() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    vault.set_consolidation_selection(&SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 1,
        ..vault.consolidation_selection()?
    })?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, &["owen chooses green tea"])?;
    let (attempt_id, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt_id))?;
    let turns = page_turns_with_versions(&page);
    let landed = land_green_tea_via_binding(&vault, attempt_id, &binding, &turns, &subject)?;
    assert_eq!(recorded_outputs(&vault, attempt_id)?, vec![landed.claim]);
    let stamp_dir = tempfile::tempdir()?;
    let (stamp_vault, stamp_attempt, stamp_turns, stamp_subject) =
        verdict_support::extraction_attempt_with_turns(
            &stamp_dir,
            "owen",
            &["owen chooses green tea"],
        )?;
    assert_eq!(stamp_turns.len(), 1);
    let operand = operand_for(&stamp_subject.to_hex(), json!("green tea"), &stamp_turns[0]);
    let green = member(operand, 0.0, vec![]);
    let request = json!({"items": [candidate_spec("first", green)], "sources": []});
    let stamp_actor = dreamer(&stamp_vault)?;
    let answer = derive_conflict::commit(
        &stamp_vault,
        stamp_actor,
        EdgeActorClass::System,
        "run",
        Some(stamp_attempt),
        request,
    )?;
    assert_eq!(answer["items"][0]["landed"], true, "{answer}");
    assert_eq!(batches_of(&stamp_vault, stamp_actor)?.len(), 1);
    assert!(
        recorded_outputs(&stamp_vault, stamp_attempt)?.is_empty(),
        "a stamp door records no attempt outputs"
    );
    Ok(())
}

/// A binding whose lease ended writes no derivation: the commit is refused
/// with lease required and no batch, receipt, claim or output stands.
/// Nearest honest form over existing readers; explicitly not a metric test.
#[test]
fn a_binding_whose_lease_ended_writes_no_derivation() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    vault.set_consolidation_selection(&SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 1,
        ..vault.consolidation_selection()?
    })?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, &["owen chooses green tea"])?;
    let (attempt_id, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt_id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 1);
    let operand = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
    let now_ms = vault.now_recorded_at().saturating_mul(1_000);
    let hex = extraction_attempt_hex(attempt_id);
    let door = build_native_candidate(&vault, &hex, now_ms, &operand)?;
    let predicted = EntityId::from_hex(door["claim"].as_str().ok_or("the predicted claim")?)?;
    let completed = DreamerRunnerStore::new(&vault).complete(CompleteDreamerAttempt {
        id: attempt_id,
        lease_owner: EXTRACTION_LEASE_OWNER.to_owned(),
        attempt_count: admitted.status.attempt.attempt_count,
        now: admitted.status.attempt.updated_at,
    })?;
    assert!(
        matches!(completed, CompleteDreamerAttemptOutcome::Completed(_)),
        "the extraction lease ended: {completed:?}"
    );
    let green = member(operand, 0.0, vec![]);
    let request = json!({"items": [candidate_spec("first", green)], "sources": []});
    let Err(ended) = binding.invoke(DERIVE_COMMIT_VERB, request, None) else {
        panic!("a commit after the lease ended is refused");
    };
    assert_eq!(ended.code, MEMORY_CODE_LEASE_REQUIRED);
    assert!(
        ended.message.contains("lease no longer holds"),
        "unexpected refusal: {ended:?}"
    );
    let dreamer_id = dreamer(&vault)?;
    assert!(batches_of(&vault, dreamer_id)?.is_empty());
    assert!(recorded_outputs(&vault, attempt_id)?.is_empty());
    assert!(vault.get_claim(&predicted)?.is_none());
    assert_eq!(claim_lifecycle(&vault, predicted)?, None);
    assert!(derive_item_receipts(&vault, &predicted)?.is_empty());
    Ok(())
}
