//! Extraction binding commits Candidate items with attempt outputs (T1-T3)
//! and a Person item (T4).
//!
//! T1 lands one green-tea candidate via the binding with every field the
//! stamp-door fixture checks (run `EXTRACTION_RUN`), then proves Settle and
//! Claim batches are refused as facet kinds with batches and outputs
//! unchanged. T2 compares attempt outputs: the binding records its claim
//! while a stamp-door fresh fixture records nothing. T3 ends the lease and
//! proves no derivation is written (nearest honest form, explicitly not a
//! metric test). T4 lands a Person item through the binding from the
//! attempt's own TURN: a PERSON and no output of the attempt.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test extraction_commit`.
#![cfg(oneiron_test_support)]

#[allow(dead_code)]
#[path = "extraction_verdict/support.rs"]
mod verdict_support;

#[allow(dead_code)]
#[path = "extraction_commit/support.rs"]
mod support;

#[allow(dead_code)]
#[path = "extraction_commit/checker.rs"]
mod checker;

use checker::{FixedChoiceProvider, TestAutoCheckerLender, bounded, name_checker};
use oneiron::dreamer_consolidation::selection::SelectionConfig;
use oneiron::dreamer_runner::{
    CompleteDreamerAttempt, CompleteDreamerAttemptOutcome, DreamerRunnerStore,
};
use oneiron::inbox::{InboxReviewDial, UnifiedInboxGroup};
use oneiron::ingest::history::{HistorySource, history_import_review_id};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_LEASE_REQUIRED};
use oneiron::test_doors::derive::{
    batches_of, claim_lifecycle, derive_item_receipts, source_version, supports,
};
use oneiron::test_doors::derive_conflict;
use oneiron::test_doors::derive_person::person_body;
use oneiron::test_doors::derive_verbs::revert_as_owner;
use oneiron::test_doors::extraction_inputs::{
    EXTRACTION_LEASE_OWNER, EXTRACTION_RUN, enqueue_admitted_extraction_attempt,
    witness_extraction_turns,
};
use oneiron::test_doors::extraction_outputs::recorded_outputs;
use oneiron::test_doors::extraction_single_valued::seed_extraction_single_valued_predicates;
use oneiron::test_doors::open_candidate::build_native_candidate;
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{ClaimApprovalStatus, ClaimSource, EdgeActorClass, EdgeKind, EntityId, Vault};
use serde_json::json;
use std::sync::Arc;
use support::{
    DERIVE_COMMIT_VERB, FOOD, IMPORTED_AT, TestResult, candidate_spec, conflict_spec,
    import_green_tea_history, land_green_tea_via_binding, land_head, member, operand_for,
    open_for, sibling_pair,
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

/// A Person item lands through the binding, named in the one TURN the
/// attempt queues and cited at the version the attempt's page serves. It
/// lands a PERSON and no claim, so the attempt records no output.
#[test]
fn an_extraction_binding_commits_a_person() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    let witnessed = witness_extraction_turns(&vault, &["Owen chooses green tea"])?;
    let (attempt_id, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt_id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 1);
    let (turn, version) = &turns[0];
    let spec = json!({"local": "owen", "name": "Owen", "evidence": [{"stored": turn}]});
    let request = json!({"items": [{"kind": "person", "spec": spec}], "sources": [version]});
    let answer = binding.invoke(DERIVE_COMMIT_VERB, request, None)?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    assert_eq!(item["kind"], "person");
    let person = EntityId::from_hex(item["rows"][0].as_str().ok_or("the row")?)?;
    let body = person_body(&vault, person)?.ok_or("the PERSON")?;
    assert_eq!(body.name.as_deref(), Some("Owen"));
    assert!(recorded_outputs(&vault, attempt_id)?.is_empty());
    let batch = EntityId::from_hex(answer["batch"].as_str().ok_or("the batch")?)?;
    assert_eq!(batches_of(&vault, dreamer(&vault)?)?, vec![batch]);
    Ok(())
}

/// An equal candidate attaches through the binding and records the head as
/// the attempt's output: the item lands with no approval and one support
/// record, the head's bytes stand, the cited TURN supports the head, no new
/// claim stands for the subject, and the recorded outputs hold the head. If
/// Part C still refused equal restatements the item would refuse with
/// `candidate_restates_head`; if the binding did not record outputs the head
/// would be absent from them.
#[test]
fn a_binding_s_attachment_records_the_head_as_an_output() -> TestResult<()> {
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
    let witnessed = witness_extraction_turns(&vault, &["owen chooses black coffee"])?;
    let (attempt_id, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt_id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 1);
    let head = land_head(&vault, subject, "green tea")?;
    let before = vault.get(&head)?.ok_or("the head stands")?;
    let operand = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
    let green = member(operand, 0.0, vec![]);
    let request = json!({"items": [candidate_spec("first", green)], "sources": []});
    let answer = binding.invoke(DERIVE_COMMIT_VERB, request, None)?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    assert_eq!(item["kind"], "candidate");
    assert!(
        item.get("approval").is_none(),
        "an attach lands no claim, so no approval: {answer}"
    );
    assert!(
        item["receipt"].is_string(),
        "an attach keeps its receipt: {answer}"
    );
    let rows = item["rows"].as_array().ok_or("the support rows")?;
    assert_eq!(rows.len(), 1, "{answer}");
    let record = EntityId::from_hex(rows[0].as_str().ok_or("the record")?)?;
    assert_ne!(record, head);
    assert_eq!(vault.get(&head)?.ok_or("the head still stands")?, before);
    let turn = EntityId::from_hex(&turns[0].0)?;
    assert!(
        supports(&vault, turn, head)?,
        "the head now has the cited TURN as support"
    );
    assert!(
        vault.sources(&head, EdgeKind::Supports, None)?.contains(&turn),
        "the public supports read names the TURN"
    );
    assert_eq!(vault.claims_for_subject(&subject)?, vec![head]);
    assert_eq!(recorded_outputs(&vault, attempt_id)?, vec![head]);
    let receipts = derive_item_receipts(&vault, &head)?;
    let attached = receipts.iter().any(|receipt| {
        receipt.outcome == "approved"
            && receipt.reasons == vec!["gate.allow.derive.candidate_attached".to_owned()]
    });
    assert!(attached, "the allowance receipt names the head: {receipts:?}");
    Ok(())
}

/// Two conflict markers land Proposed through one binding commit and wait in
/// the attempt's run review, sharing one tray group; the same sibling
/// conflict through the stamp door on a fresh vault waits with no group. If
/// Part A did not mark the binding's rows the pending rows would show no
/// `dreamer_run_id` and the tray would list no Dreamer group; if the stamp
/// door grouped, its pending row would name a run.
#[test]
fn a_binding_s_held_rows_wait_in_the_run_s_review() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    vault.set_consolidation_selection(&SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 1,
        ..vault.consolidation_selection()?
    })?;
    let owen = EntityId::now();
    let yuki = EntityId::now();
    seed_named_person(&vault, &owen, "owen", vault.now_recorded_at())?;
    seed_named_person(&vault, &yuki, "yuki", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(
        &vault,
        &[
            "owen chooses green tea",
            "owen chooses black coffee",
            "yuki chooses green tea",
            "yuki chooses black coffee",
        ],
    )?;
    let (attempt_id, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt_id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 4);
    let served = |index: usize| {
        let wanted = witnessed.turns[index].to_hex();
        turns.iter().find(|pair| pair.0 == wanted).cloned().ok_or("the served turn")
    };
    let owen_pair = [served(0)?, served(1)?];
    let yuki_pair = [served(2)?, served(3)?];
    let owen_members = sibling_pair(&owen, &owen_pair);
    let yuki_members = sibling_pair(&yuki, &yuki_pair);
    let request = json!({
        "items": [
            conflict_spec("open-owen", owen_members, vec![]),
            conflict_spec("open-yuki", yuki_members, vec![]),
        ],
        "sources": [],
    });
    let answer = binding.invoke(DERIVE_COMMIT_VERB, request, None)?;
    assert_eq!(answer["items"][0]["landed"], true, "{answer}");
    assert_eq!(answer["items"][1]["landed"], true, "{answer}");
    let owen_marker = EntityId::from_hex(
        answer["items"][0]["rows"][0].as_str().ok_or("the owen row")?,
    )?;
    let yuki_marker = EntityId::from_hex(
        answer["items"][1]["rows"][0].as_str().ok_or("the yuki row")?,
    )?;
    for marker in [&owen_marker, &yuki_marker] {
        let stored = vault.get_claim(marker)?.ok_or("the marker stands")?;
        assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);
    }
    let owen_open = open_for(&vault, owen)?;
    assert_eq!(owen_open.len(), 1);
    assert_eq!(owen_open[0].marker, owen_marker);
    let yuki_open = open_for(&vault, yuki)?;
    assert_eq!(yuki_open.len(), 1);
    assert_eq!(yuki_open[0].marker, yuki_marker);
    let owner = vault.ensure_embedded_owner_actor()?;
    let pending = vault.memory(owner, EdgeActorClass::Human).pending_writes(64)?;
    for marker in [&owen_marker, &yuki_marker] {
        let row = pending
            .iter()
            .find(|row| row.claim_ref == marker.to_hex())
            .ok_or("the held row waits")?;
        assert_eq!(row.dreamer_run_id.as_deref(), Some(EXTRACTION_RUN));
    }
    let groups = vault.pending_gate_consent_groups(64)?;
    let group = groups
        .iter()
        .find(|group| group.dreamer_run_id.as_deref() == Some(EXTRACTION_RUN))
        .ok_or("the run group")?;
    for marker in [&owen_marker, &yuki_marker] {
        assert!(
            group.records.iter().any(|record| record.claim_id == *marker.as_bytes()),
            "the group holds the marker"
        );
    }
    vault.set_inbox_review_dial(InboxReviewDial::ReviewEverything)?;
    let page = vault.inbox_groups_unified(1_000_000, 64, None)?;
    let owen_hex = owen_marker.to_hex();
    let yuki_hex = yuki_marker.to_hex();
    let mut seen = std::collections::BTreeMap::new();
    for group in page.groups {
        let UnifiedInboxGroup::Dreamer { group } = group else {
            continue;
        };
        for member in &group.members {
            let ids = std::iter::once(member.claim_id.clone())
                .chain(member.duplicate_claim_ids.iter().cloned());
            for id in ids {
                if id == owen_hex || id == yuki_hex {
                    seen.insert(id, (group.group_key.clone(), group.run_id.clone()));
                }
            }
        }
    }
    let owen_group = seen.get(&owen_hex).ok_or("the owen tray row")?;
    let yuki_group = seen.get(&yuki_hex).ok_or("the yuki tray row")?;
    assert_eq!(owen_group, yuki_group, "two held rows share one group");
    assert_eq!(owen_group.1, EXTRACTION_RUN);
    let stamp_dir = tempfile::tempdir()?;
    let (stamp_vault, stamp_attempt, stamp_turns, stamp_subject) =
        verdict_support::extraction_attempt_with_turns(
            &stamp_dir,
            "owen",
            &["owen chooses green tea", "owen chooses black coffee"],
        )?;
    assert_eq!(stamp_turns.len(), 2);
    let members = sibling_pair(&stamp_subject, &stamp_turns);
    let request = json!({"items": [conflict_spec("open", members, vec![])], "sources": []});
    let stamp_actor = dreamer(&stamp_vault)?;
    let stamp_answer = derive_conflict::commit(
        &stamp_vault,
        stamp_actor,
        EdgeActorClass::System,
        "run",
        Some(stamp_attempt),
        request,
    )?;
    assert_eq!(stamp_answer["items"][0]["landed"], true, "{stamp_answer}");
    let stamp_marker = EntityId::from_hex(
        stamp_answer["items"][0]["rows"][0].as_str().ok_or("the row")?,
    )?;
    let stored = stamp_vault.get_claim(&stamp_marker)?.ok_or("the marker")?;
    assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);
    let tray = stamp_vault.pending_gate_consents(64)?;
    let row = tray
        .iter()
        .find(|row| row.claim_id == *stamp_marker.as_bytes())
        .ok_or("the stamp tray row")?;
    assert_eq!(row.dreamer_run_id, None);
    Ok(())
}

/// A candidate from imported words lands Proposed through the binding in its
/// import's review, records the attempt's output, and reverts clean; the same
/// candidate through the stamp door is refused with
/// `candidate_imported_evidence`. If Part B still refused imported evidence
/// under a binding the item would refuse; if the review key were missing the
/// pending row would group under the run instead of the import; if the revert
/// left the pending row it would still list.
#[test]
fn a_binding_lands_an_imported_candidate_in_its_import_s_review() -> TestResult<()> {
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
    let imported = import_green_tea_history(&vault)?;
    let (attempt_id, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &[imported.turn], QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt_id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 1);
    let operand = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
    let green = member(operand, 0.0, vec![]);
    let request = json!({"items": [candidate_spec("first", green)], "sources": []});
    let answer = binding.invoke(DERIVE_COMMIT_VERB, request, None)?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    assert_eq!(item["kind"], "candidate");
    assert_eq!(item["approval"], json!("proposed"), "{answer}");
    let claim = EntityId::from_hex(item["rows"][0].as_str().ok_or("the row")?)?;
    let stored = vault.get_claim(&claim)?.ok_or("the stored claim")?;
    assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(stored.source, Some(ClaimSource::Imported));
    let expected = history_import_review_id(HistorySource::Chatgpt, IMPORTED_AT);
    let pending = vault
        .memory(dreamer(&vault)?, EdgeActorClass::System)
        .pending_writes(64)?;
    let row = pending
        .iter()
        .find(|row| row.claim_ref == claim.to_hex())
        .ok_or("the held row waits")?;
    assert_eq!(row.dreamer_run_id.as_deref(), Some(expected.as_str()));
    assert_eq!(recorded_outputs(&vault, attempt_id)?, vec![claim]);
    let batch = EntityId::from_hex(answer["batch"].as_str().ok_or("the batch")?)?;
    let reverted = revert_as_owner(&vault, batch)?;
    assert_eq!(reverted["reverted"], json!(["first"]));
    assert_eq!(reverted["left"], json!([]));
    assert_ne!(
        claim_lifecycle(&vault, claim)?,
        Some("active".to_owned()),
        "the claim no longer stands"
    );
    let after = vault
        .memory(dreamer(&vault)?, EdgeActorClass::System)
        .pending_writes(64)?;
    assert!(
        after.iter().all(|row| row.claim_ref != claim.to_hex()),
        "the revert takes the pending row"
    );
    let stamp_dir = tempfile::tempdir()?;
    let stamp_vault = Arc::new(open_extraction_verdict_vault(&stamp_dir)?);
    stand_steward_grant(&stamp_vault, dreamer(&stamp_vault)?, &STEWARD_VERBS)?;
    stamp_vault.set_consolidation_selection(&SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 1,
        ..stamp_vault.consolidation_selection()?
    })?;
    let stamp_subject = EntityId::now();
    seed_named_person(
        &stamp_vault,
        &stamp_subject,
        "owen",
        stamp_vault.now_recorded_at(),
    )?;
    let stamp_imported = import_green_tea_history(&stamp_vault)?;
    let (stamp_attempt, stamp_admitted) = enqueue_admitted_extraction_attempt(
        &stamp_vault,
        &[stamp_imported.turn],
        QUEUE_NOW,
    )?;
    let stamp_binding = bind_extraction(&stamp_vault, &stamp_admitted)?;
    let stamp_page =
        read_bound_extraction_page(&stamp_binding, &extraction_attempt_hex(stamp_attempt))?;
    let stamp_turns = page_turns_with_versions(&stamp_page);
    assert_eq!(stamp_turns.len(), 1);
    let stamp_operand =
        operand_for(&stamp_subject.to_hex(), json!("green tea"), &stamp_turns[0]);
    let stamp_green = member(stamp_operand, 0.0, vec![]);
    let stamp_request =
        json!({"items": [candidate_spec("first", stamp_green)], "sources": []});
    let stamp_actor = dreamer(&stamp_vault)?;
    let stamp_answer = derive_conflict::commit(
        &stamp_vault,
        stamp_actor,
        EdgeActorClass::System,
        "run",
        Some(stamp_attempt),
        stamp_request,
    )?;
    assert_eq!(stamp_answer["items"][0]["landed"], false, "{stamp_answer}");
    assert_eq!(stamp_answer["items"][0]["rows"], json!([]));
    assert_eq!(
        stamp_answer["items"][0]["reasons"],
        json!(["gate.deny.derive.candidate_imported_evidence"])
    );
    Ok(())
}

// --- The lent checker (e2i.1d) ---

/// One skip resolution over `members` against `heads`.
fn skip_spec(
    local: &str,
    members: Vec<serde_json::Value>,
    heads: Vec<serde_json::Value>,
) -> serde_json::Value {
    json!({"kind": "conflict_resolution", "spec": {"local": local, "members": members, "heads": heads, "outcome": "skip"}})
}

/// The version of `entity` as the Dreamer reads it now, as JSON.
fn served_version(vault: &Vault, entity: EntityId) -> TestResult<serde_json::Value> {
    let actor = dreamer(vault)?;
    let version = source_version(vault, actor, EdgeActorClass::System, entity)?.ok_or("unread")?;
    Ok(serde_json::to_value(version)?)
}

/// Lands one Generated food preference about `subject` and returns its id.
/// A replacement of it is granted with no owner.
fn land_generated_head(vault: &Vault, subject: EntityId, value: &str) -> TestResult<EntityId> {
    let head = EntityId::now();
    let mut body = oneiron::claim::ClaimBody::new(
        FOOD,
        oneiron::claim::ClaimSubject::Entity(subject),
        rmpv::Value::from(value),
        1.0,
        ClaimApprovalStatus::Auto,
        oneiron::claim::ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::Generated);
    body.scope_facet = vault.default_facet()?;
    let now = vault.now_recorded_at();
    let at = oneiron::TimeRange {
        start: now,
        end: now,
    };
    vault.put_claim(&head, &body, at, now)?;
    Ok(head)
}

/// T1 allow: on a vault whose policy names a checker, a lender whose checker allows lands one
/// plain candidate Auto with exactly one consult, the claim recorded as the attempt's output,
/// and exactly one claim gate decision naming the claim. Without the loan (Part 4) the item
/// would refuse checker-unavailable; without the terminal (Part 1) the gate would never see
/// the checker.
#[test]
fn a_lent_checker_allows_a_plain_candidate() -> TestResult<()> {
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
    name_checker(&vault)?;
    let provider = Arc::new(FixedChoiceProvider::allow());
    let lender = Arc::new(TestAutoCheckerLender::lending(Some(bounded(
        provider.clone(),
    ))));
    let binding = binding.lend_decisions(lender);
    let landed = land_green_tea_via_binding(&vault, attempt_id, &binding, &turns, &subject)?;
    assert_eq!(provider.calls(), 1, "the checker is consulted once");
    assert_eq!(recorded_outputs(&vault, attempt_id)?, vec![landed.claim]);
    let claim_decisions: Vec<_> = vault
        .gate_decisions(64)?
        .into_iter()
        .filter(|record| {
            record.claim_id == Some(*landed.claim.as_bytes()) && record.content_kind == "claim"
        })
        .collect();
    assert_eq!(
        claim_decisions.len(),
        1,
        "exactly one gate decision names the claim"
    );
    assert_eq!(claim_decisions[0].outcome, "allow");
    Ok(())
}

/// T2 hold: the same with a checker that holds. The item is refused with the gate's own
/// hold token, no claim row stands at the candidate's id, no pending-consent row waits,
/// nothing is recorded as an output, and the checker was consulted once.
#[test]
fn a_lent_checker_holds_a_plain_candidate() -> TestResult<()> {
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
    name_checker(&vault)?;
    let operand = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
    let now_ms = vault.now_recorded_at().saturating_mul(1_000);
    let hex = extraction_attempt_hex(attempt_id);
    let door = build_native_candidate(&vault, &hex, now_ms, &operand)?;
    let predicted = EntityId::from_hex(door["claim"].as_str().ok_or("the predicted claim")?)?;
    let provider = Arc::new(FixedChoiceProvider::hold());
    let lender = Arc::new(TestAutoCheckerLender::lending(Some(bounded(
        provider.clone(),
    ))));
    let binding = binding.lend_decisions(lender);
    let green = member(operand, 0.0, vec![]);
    let request = json!({"items": [candidate_spec("first", green)], "sources": []});
    let answer = binding.invoke(DERIVE_COMMIT_VERB, request, None)?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], false, "{answer}");
    assert_eq!(item["reasons"], json!(["gate.pending.checker"]), "{answer}");
    assert_eq!(provider.calls(), 1, "the checker is consulted once");
    assert!(
        vault.get_claim(&predicted)?.is_none(),
        "no claim row stands at the candidate's id"
    );
    let pending: Vec<_> = vault
        .pending_gate_consents(64)?
        .into_iter()
        .filter(|row| row.claim_id == *predicted.as_bytes())
        .collect();
    assert!(pending.is_empty(), "no pending-consent row waits");
    assert!(
        recorded_outputs(&vault, attempt_id)?.is_empty(),
        "nothing is recorded as an output"
    );
    Ok(())
}

/// T3 no loan, as before: the same vault with a binding with no lender, and with a lender
/// that lends none. Both refuse with the checker-unavailable token. This is the behaviour
/// the leaf replaces only when a checker is lent.
#[test]
fn a_commit_without_a_loan_is_refused_checker_unavailable() -> TestResult<()> {
    for (what, lend_none) in [("no lender", false), ("a lender that lends none", true)] {
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
        name_checker(&vault)?;
        let binding = if lend_none {
            binding.lend_decisions(Arc::new(TestAutoCheckerLender::lending(None)))
        } else {
            binding
        };
        let operand = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
        let green = member(operand, 0.0, vec![]);
        let request = json!({"items": [candidate_spec("first", green)], "sources": []});
        let answer = binding.invoke(DERIVE_COMMIT_VERB, request, None)?;
        let item = &answer["items"][0];
        assert_eq!(item["landed"], false, "{what}: {answer}");
        assert_eq!(
            item["reasons"],
            json!(["gate.pending.checker.unavailable"]),
            "{what}: {answer}"
        );
    }
    Ok(())
}

/// T4 a vault that names no checker: a lender that lends an allowing checker, but the vault
/// has no checker knob. The candidate lands as in e2i.1a's first test and the provider is
/// never consulted (`admit_for_writes` takes no turn).
#[test]
fn a_loan_on_a_vault_that_names_no_checker_lands_unconsulted() -> TestResult<()> {
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
    let provider = Arc::new(FixedChoiceProvider::allow());
    let lender = Arc::new(TestAutoCheckerLender::lending(Some(bounded(
        provider.clone(),
    ))));
    let binding = binding.lend_decisions(lender);
    let landed = land_green_tea_via_binding(&vault, attempt_id, &binding, &turns, &subject)?;
    assert_eq!(
        provider.calls(),
        0,
        "no turn is taken, so nothing is consulted"
    );
    assert_eq!(recorded_outputs(&vault, attempt_id)?, vec![landed.claim]);
    Ok(())
}

/// A commit with no checked item asks for no loan: on a checker vault, a binding whose lender
/// would lend an allowing checker commits one Person item. The PERSON lands, the lender is
/// never asked and the checker is never consulted. The fixture is
/// `an_extraction_binding_commits_a_person`. If the commit asked for every extraction batch,
/// the lender would count one request and the commit would take a turn it never uses.
#[test]
fn a_commit_with_no_checked_item_asks_for_no_loan() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    let witnessed = witness_extraction_turns(&vault, &["Owen chooses green tea"])?;
    let (attempt_id, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt_id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 1);
    name_checker(&vault)?;
    let provider = Arc::new(FixedChoiceProvider::allow());
    let lender = Arc::new(TestAutoCheckerLender::lending(Some(bounded(
        provider.clone(),
    ))));
    let binding = binding.lend_decisions(lender.clone());
    let (turn, version) = &turns[0];
    let spec = json!({"local": "owen", "name": "Owen", "evidence": [{"stored": turn}]});
    let request = json!({"items": [{"kind": "person", "spec": spec}], "sources": [version]});
    let answer = binding.invoke(DERIVE_COMMIT_VERB, request, None)?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    assert_eq!(item["kind"], "person");
    let person = EntityId::from_hex(item["rows"][0].as_str().ok_or("the row")?)?;
    let body = person_body(&vault, person)?.ok_or("the PERSON")?;
    assert_eq!(body.name.as_deref(), Some("Owen"));
    assert_eq!(lender.asked(), 0, "a Person commit asks for no loan");
    assert_eq!(provider.calls(), 0, "and consults nothing");
    Ok(())
}

/// T5 two candidates, one turn: one commit with two plain candidates of different subjects
/// on a checker vault, allowing checker. Both land Auto with two consults, proving the one
/// turn serves the whole commit.
#[test]
fn one_turn_serves_two_candidates_in_one_commit() -> TestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    vault.set_consolidation_selection(&SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 1,
        ..vault.consolidation_selection()?
    })?;
    let owen = EntityId::now();
    let yuki = EntityId::now();
    seed_named_person(&vault, &owen, "owen", vault.now_recorded_at())?;
    seed_named_person(&vault, &yuki, "yuki", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(
        &vault,
        &["owen chooses green tea", "yuki chooses black coffee"],
    )?;
    let (attempt_id, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt_id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 2);
    let served = |index: usize| {
        let wanted = witnessed.turns[index].to_hex();
        turns
            .iter()
            .find(|pair| pair.0 == wanted)
            .cloned()
            .ok_or("the served turn")
    };
    name_checker(&vault)?;
    let provider = Arc::new(FixedChoiceProvider::allow());
    let lender = Arc::new(TestAutoCheckerLender::lending(Some(bounded(
        provider.clone(),
    ))));
    let binding = binding.lend_decisions(lender);
    let green = member(
        operand_for(&owen.to_hex(), json!("green tea"), &served(0)?),
        0.0,
        vec![],
    );
    let black = member(
        operand_for(&yuki.to_hex(), json!("black coffee"), &served(1)?),
        0.0,
        vec![],
    );
    let request = json!({
        "items": [candidate_spec("first", green), candidate_spec("second", black)],
        "sources": [],
    });
    let answer = binding.invoke(DERIVE_COMMIT_VERB, request, None)?;
    assert_eq!(answer["items"][0]["landed"], true, "{answer}");
    assert_eq!(answer["items"][0]["approval"], json!("auto"), "{answer}");
    assert_eq!(answer["items"][1]["landed"], true, "{answer}");
    assert_eq!(answer["items"][1]["approval"], json!("auto"), "{answer}");
    assert_eq!(
        provider.calls(),
        2,
        "one turn serves the commit's two consults"
    );
    let first = EntityId::from_hex(answer["items"][0]["rows"][0].as_str().ok_or("the row")?)?;
    let second = EntityId::from_hex(answer["items"][1]["rows"][0].as_str().ok_or("the row")?)?;
    let mut got: Vec<String> = recorded_outputs(&vault, attempt_id)?
        .iter()
        .map(EntityId::to_hex)
        .collect();
    got.sort();
    let mut want = vec![first.to_hex(), second.to_hex()];
    want.sort();
    assert_eq!(got, want, "both claims are recorded as outputs");
    Ok(())
}

/// T6 the grant: a skip resolution whose replacement closes a standing Generated head, on a
/// checker vault, for a set whose attempt parked no first-try marker. With the allowing lender
/// the replacement is granted Auto and the prior is closed, with exactly one consult: the
/// landing's preflight does not put a Proposed request to the checker and the closure is a
/// stored-value close, so only the grant consults. With no lender the replacement stays
/// Proposed and the prior stays Active.
#[test]
fn a_lent_checker_grants_a_skip_replacement() -> TestResult<()> {
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
    let witnessed = witness_extraction_turns(&vault, &["owen chooses black coffee"])?;
    let (attempt_id, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt_id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 1);
    let head = land_generated_head(&vault, subject, "green tea")?;
    seed_extraction_single_valued_predicates(&vault, &[FOOD])?;
    name_checker(&vault)?;
    let provider = Arc::new(FixedChoiceProvider::allow());
    let lender = Arc::new(TestAutoCheckerLender::lending(Some(bounded(
        provider.clone(),
    ))));
    let binding = binding.lend_decisions(lender);
    let operand = operand_for(&subject.to_hex(), json!("black coffee"), &turns[0]);
    let black = member(operand, 0.7, vec![]);
    let pin = json!({"claim": head.to_hex(), "version": served_version(&vault, head)?});
    let spec = skip_spec("resolve", vec![black], vec![pin]);
    let answer = binding.invoke(
        DERIVE_COMMIT_VERB,
        json!({"items": [spec], "sources": []}),
        None,
    )?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    assert_eq!(item["approval"], json!("auto"), "{answer}");
    let replacement = EntityId::from_hex(item["rows"][0].as_str().ok_or("the row")?)?;
    let stored = vault
        .get_claim(&replacement)?
        .ok_or("the stored replacement")?;
    assert_eq!(stored.approval, ClaimApprovalStatus::Auto);
    assert_eq!(stored.confidence, 0.7);
    assert!(
        vault
            .edges_out(&replacement)?
            .iter()
            .any(|edge| { edge.kind == EdgeKind::Supersedes && edge.target == head }),
        "the stored replacement names the replaced head"
    );
    assert_eq!(
        claim_lifecycle(&vault, head)?,
        Some("superseded".to_owned()),
        "the prior is closed"
    );
    assert_eq!(provider.calls(), 1, "only the grant consults");
    let held_dir = tempfile::tempdir()?;
    let held_vault = Arc::new(open_extraction_verdict_vault(&held_dir)?);
    stand_steward_grant(&held_vault, dreamer(&held_vault)?, &STEWARD_VERBS)?;
    held_vault.set_consolidation_selection(&SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 1,
        ..held_vault.consolidation_selection()?
    })?;
    let held_subject = EntityId::now();
    seed_named_person(
        &held_vault,
        &held_subject,
        "owen",
        held_vault.now_recorded_at(),
    )?;
    let held_witnessed = witness_extraction_turns(&held_vault, &["owen chooses black coffee"])?;
    let (held_attempt, held_admitted) =
        enqueue_admitted_extraction_attempt(&held_vault, &held_witnessed.turns, QUEUE_NOW)?;
    let held_binding = bind_extraction(&held_vault, &held_admitted)?;
    let held_page =
        read_bound_extraction_page(&held_binding, &extraction_attempt_hex(held_attempt))?;
    let held_turns = page_turns_with_versions(&held_page);
    assert_eq!(held_turns.len(), 1);
    let held_head = land_generated_head(&held_vault, held_subject, "green tea")?;
    seed_extraction_single_valued_predicates(&held_vault, &[FOOD])?;
    name_checker(&held_vault)?;
    let held_operand = operand_for(
        &held_subject.to_hex(),
        json!("black coffee"),
        &held_turns[0],
    );
    let held_black = member(held_operand, 0.7, vec![]);
    let held_pin =
        json!({"claim": held_head.to_hex(), "version": served_version(&held_vault, held_head)?});
    let held_spec = skip_spec("resolve", vec![held_black], vec![held_pin]);
    let held_answer = held_binding.invoke(
        DERIVE_COMMIT_VERB,
        json!({"items": [held_spec], "sources": []}),
        None,
    )?;
    let held_item = &held_answer["items"][0];
    assert_eq!(held_item["landed"], true, "{held_answer}");
    assert_eq!(held_item["approval"], json!("proposed"), "{held_answer}");
    let held_replacement = EntityId::from_hex(held_item["rows"][0].as_str().ok_or("the row")?)?;
    let held_stored = held_vault
        .get_claim(&held_replacement)?
        .ok_or("the stored replacement")?;
    assert_eq!(held_stored.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(
        claim_lifecycle(&held_vault, held_head)?,
        Some("active".to_owned()),
        "the prior stays Active"
    );
    assert_eq!(
        held_vault.pending_claim_supersession(&held_replacement)?,
        Some(held_head),
        "the staged supersession names the prior for the owner"
    );
    Ok(())
}

/// T7 the attach: an equal restatement of a standing head, on a checker vault. The fixture's
/// evidence meets at Generated, so the attach's gate consults: with the allowing lender the
/// item lands and names the head, with one consult; with no lender it is refused with the
/// checker-unavailable token.
#[test]
fn a_lent_checker_attaches_an_equal_restatement() -> TestResult<()> {
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
    let witnessed = witness_extraction_turns(&vault, &["owen chooses black coffee"])?;
    let (attempt_id, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt_id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 1);
    let head = land_head(&vault, subject, "green tea")?;
    let before = vault.get(&head)?.ok_or("the head stands")?;
    name_checker(&vault)?;
    let provider = Arc::new(FixedChoiceProvider::allow());
    let lender = Arc::new(TestAutoCheckerLender::lending(Some(bounded(
        provider.clone(),
    ))));
    let binding = binding.lend_decisions(lender);
    let operand = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
    let green = member(operand, 0.0, vec![]);
    let request = json!({"items": [candidate_spec("first", green)], "sources": []});
    let answer = binding.invoke(DERIVE_COMMIT_VERB, request, None)?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    assert_eq!(item["kind"], "candidate");
    assert!(
        item.get("approval").is_none(),
        "an attach lands no claim, so no approval: {answer}"
    );
    let rows = item["rows"].as_array().ok_or("the support rows")?;
    assert_eq!(rows.len(), 1, "{answer}");
    let record = EntityId::from_hex(rows[0].as_str().ok_or("the record")?)?;
    assert_ne!(record, head);
    assert_eq!(provider.calls(), 1, "the attach consults once");
    assert_eq!(vault.get(&head)?.ok_or("the head still stands")?, before);
    let turn = EntityId::from_hex(&turns[0].0)?;
    assert!(
        supports(&vault, turn, head)?,
        "the head now has the cited TURN as support"
    );
    assert_eq!(vault.claims_for_subject(&subject)?, vec![head]);
    assert_eq!(recorded_outputs(&vault, attempt_id)?, vec![head]);
    let refused_dir = tempfile::tempdir()?;
    let refused_vault = Arc::new(open_extraction_verdict_vault(&refused_dir)?);
    stand_steward_grant(&refused_vault, dreamer(&refused_vault)?, &STEWARD_VERBS)?;
    refused_vault.set_consolidation_selection(&SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 1,
        ..refused_vault.consolidation_selection()?
    })?;
    let refused_subject = EntityId::now();
    seed_named_person(
        &refused_vault,
        &refused_subject,
        "owen",
        refused_vault.now_recorded_at(),
    )?;
    let refused_witnessed =
        witness_extraction_turns(&refused_vault, &["owen chooses black coffee"])?;
    let (refused_attempt, refused_admitted) =
        enqueue_admitted_extraction_attempt(&refused_vault, &refused_witnessed.turns, QUEUE_NOW)?;
    let refused_binding = bind_extraction(&refused_vault, &refused_admitted)?;
    let refused_page =
        read_bound_extraction_page(&refused_binding, &extraction_attempt_hex(refused_attempt))?;
    let refused_turns = page_turns_with_versions(&refused_page);
    assert_eq!(refused_turns.len(), 1);
    let refused_head = land_head(&refused_vault, refused_subject, "green tea")?;
    name_checker(&refused_vault)?;
    let refused_operand = operand_for(
        &refused_subject.to_hex(),
        json!("green tea"),
        &refused_turns[0],
    );
    let refused_green = member(refused_operand, 0.0, vec![]);
    let refused_request = json!({"items": [candidate_spec("first", refused_green)], "sources": []});
    let refused_answer = refused_binding.invoke(DERIVE_COMMIT_VERB, refused_request, None)?;
    let refused_item = &refused_answer["items"][0];
    assert_eq!(refused_item["landed"], false, "{refused_answer}");
    assert_eq!(
        refused_item["reasons"],
        json!(["gate.pending.checker.unavailable"]),
        "{refused_answer}"
    );
    let refused_turn = EntityId::from_hex(&refused_turns[0].0)?;
    assert!(
        !supports(&refused_vault, refused_turn, refused_head)?,
        "nothing was attached"
    );
    assert!(
        recorded_outputs(&refused_vault, refused_attempt)?.is_empty(),
        "nothing is recorded as an output"
    );
    Ok(())
}
