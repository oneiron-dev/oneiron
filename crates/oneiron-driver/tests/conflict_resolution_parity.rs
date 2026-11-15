//! Parity of the crate policy against native builds over lent fixtures.
//!
//! Each test copies one `extraction_decisions.rs` fixture without varying it,
//! runs `run`, plans with a second client lending the merged-value step, and
//! commits the planned items in one batch as the attempt's Dreamer.

#![cfg(oneiron_test_support)]

#[path = "conflict_resolution_parity/support.rs"]
mod parity;
// This binary uses a part of the decision tests' support.
#[allow(dead_code)]
#[path = "extraction_decisions/support.rs"]
mod support;

use oneiron::EdgeActorClass;
use oneiron::EntityId;
use oneiron::Vault;
use oneiron::claim::ClaimApprovalStatus;
use oneiron::claim::ClaimSubject;
use oneiron::dreamer_consolidation::OpenConflict;
use oneiron::test_doors::derive::claim_lifecycle;
use oneiron::test_doors::derive_conflict;
use oneiron::test_doors::derive_conflict_resolution::build_native_merge;
use oneiron::test_doors::derive_conflict_resolution::build_native_skip;
use oneiron::test_doors::open_conflict_marker::build_native_open_conflict;
use oneiron::test_doors::steward::dreamer;
use oneiron_dreamer::conflict_decisions::Resolution;
use oneiron_dreamer::conflict_resolution::Input;
use oneiron_dreamer::conflict_resolution::OpenCause;
use oneiron_dreamer::conflict_resolution::ResolvedOutcome;
use oneiron_dreamer::conflict_resolution::SetPlan;
use oneiron_dreamer::conflict_resolution::plan;
use oneiron_dreamer::conflict_resolution::step_request;
use oneiron_dreamer::extraction_decisions::SetOutcome;
use oneiron_dreamer::extraction_decisions::SkipRule;
use parity::TestResult;
use parity::accumulate_script;
use parity::escalate_script;
use parity::merge_script;
use parity::none_script;
use parity::run_case_two;
use rmpv::Value as RmpValue;
use serde_json::Value;
use serde_json::json;

/// Commits `request` as the Dreamer in `attempt`.
fn commit_dreamer(
    vault: &Vault,
    attempt: Option<oneiron::AttemptId>,
    request: Value,
) -> TestResult<Value> {
    let actor = dreamer(vault)?;
    Ok(derive_conflict::commit(
        vault,
        actor,
        EdgeActorClass::System,
        "run",
        attempt,
        request,
    )?)
}

/// Returns the Dreamer's open conflicts about `subject`.
fn open_for(vault: &Vault, subject: EntityId) -> TestResult<Vec<OpenConflict>> {
    let memory = vault.memory(dreamer(vault)?, EdgeActorClass::System);
    Ok(memory.open_conflicts(None, Some(subject), usize::MAX)?)
}

/// Returns the marker `operands` would natively park at the clock of `answer`'s batch.
fn built_for(
    vault: &Vault,
    answer: &Value,
    attempt: &str,
    operands: &[Value],
) -> TestResult<Value> {
    let batch = EntityId::from_hex(answer["batch"].as_str().ok_or("the batch")?)?;
    let record = vault.derive_batch(batch)?.ok_or("the batch record")?;
    let now_ms = record.committed_at.saturating_mul(1_000);
    Ok(build_native_open_conflict(
        vault, attempt, now_ms, operands,
    )?)
}

/// Returns the map entry `key` of `value`, when it is a map holding one.
fn map_at<'v>(value: &'v RmpValue, key: &str) -> Option<&'v RmpValue> {
    let RmpValue::Map(rows) = value else {
        return None;
    };
    rows.iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, found)| found)
}

/// Returns `value`'s encoded bytes as lowercase hex.
fn hex_of(value: &RmpValue) -> TestResult<String> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).map_err(|_| "the value encodes")?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Fast-path skip lands as native builds it and asks no step.
#[test]
fn fast_path_skip_lands_as_native_builds_it() -> TestResult<()> {
    let run = run_case_two(
        &[("profile.name", "Owen")],
        &["owen is called Alex"],
        &[("profile.name", json!("Alex"))],
        none_script(),
        &["profile.name"],
        Vec::new(),
    )?;
    assert_eq!(run.outcome.sets.len(), 1);
    assert!(matches!(
        &run.outcome.sets[0],
        SetOutcome::Skipped {
            rule: SkipRule::FastPath,
            ..
        }
    ));
    assert_eq!((run.counts.correction(), run.counts.resolution()), (1, 0));
    let planned = plan(Input {
        client: &run.step_client,
        reply: &run.reply,
        outcome: &run.outcome,
    })?;
    assert_eq!(planned.sets.len(), 1);
    let SetPlan::Resolved { outcome, item } = &planned.sets[0] else {
        panic!("a fast-path skip resolves");
    };
    assert_eq!(*outcome, ResolvedOutcome::Skip);
    assert_eq!(item["spec"]["outcome"], json!("skip"));
    assert_eq!(run.step_backend.call_count(), 0);
    let head = run.outcome.route.judge_sets[0]
        .prior_head
        .as_ref()
        .ok_or("the skipped set names its head")?;
    // The build-only door first: once the commit replaces the head, native
    // no longer forms this conflict. No compared field carries time.
    let door = build_native_skip(
        &run.vault,
        &run.attempt,
        run.now_ms,
        &run.outcome.set_operands[0].candidates,
        0.9,
    )?;
    let answer = commit_dreamer(
        &run.vault,
        Some(run.attempt_id),
        json!({"items": planned.items(), "sources": []}),
    )?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    assert_eq!(item["approval"], json!("auto"), "{answer}");
    assert_eq!(door["claim"], item["rows"][0]);
    assert_eq!(door["supersedes"], json!(head));
    let claim = EntityId::from_hex(item["rows"][0].as_str().ok_or("the row")?)?;
    let stored = run.vault.get_claim(&claim)?.ok_or("the stored claim")?;
    assert_eq!(door["predicate"].as_str().ok_or("p")?, stored.predicate);
    let ClaimSubject::Entity(subject) = stored.subject else {
        return Err("the claim names an entity subject".into());
    };
    assert_eq!(door["subject"].as_str().ok_or("s")?, subject.to_hex());
    assert_eq!(
        door["value_hex"].as_str().ok_or("v")?,
        hex_of(&stored.value)?
    );
    let stored_scope = stored.scope.as_ref().ok_or("scope")?;
    assert_eq!(
        door["scope_hex"].as_str().ok_or("sc")?,
        hex_of(stored_scope)?
    );
    assert_eq!(
        door["source"].as_str().ok_or("src")?,
        stored.source.ok_or("source")?.as_str()
    );
    assert_eq!(
        door["confidence"].as_f64().ok_or("c")?,
        f64::from(stored.confidence)
    );
    assert_eq!(stored.confidence, 0.9);
    assert_eq!(
        door["world"].as_str(),
        stored.world.map(|world| world.to_hex()).as_deref()
    );
    let stored_rel: Option<Vec<String>> = stored
        .rel
        .as_ref()
        .map(|rel| rel.iter().map(EntityId::to_hex).collect());
    assert_eq!(
        door["relationship"],
        stored_rel.map_or(json!(null), |rel| json!(rel))
    );
    assert_eq!(
        door["facet"].as_str().ok_or("f")?,
        stored.scope_facet.to_hex()
    );
    assert_eq!(
        door["project"].as_str().ok_or("pr")?,
        stored.scope_project.to_hex()
    );
    let stored_evidence = stored.evidence.as_ref().ok_or("e")?;
    let candidate_evidence = map_at(stored_evidence, "candidate_evidence").ok_or("ce")?;
    assert_eq!(
        door["candidate_evidence_hex"].as_str().ok_or("ee")?,
        hex_of(candidate_evidence)?
    );
    let provenance = map_at(stored_evidence, "provenance").ok_or("p")?;
    let at = |key: &str| map_at(provenance, key).and_then(RmpValue::as_str);
    assert_eq!(at("surface"), Some("vault.derive"));
    assert_eq!(at("batch"), answer["batch"].as_str());
    assert_eq!(at("item"), Some("conflict-set-0"));
    assert_eq!(at("run"), Some("run"));
    assert!(map_at(provenance, "job_id").is_none());
    assert!(map_at(provenance, "decisions").is_none());
    assert_eq!(
        claim_lifecycle(&run.vault, EntityId::from_hex(head)?)?,
        Some("superseded".to_owned()),
        "the head is superseded"
    );
    Ok(())
}

/// Bound-correction skip lands and its operand names the corrected head.
#[test]
fn bound_correction_skip_lands_and_names_head() -> TestResult<()> {
    let run = run_case_two(
        &[("preference.food", "green tea")],
        &["owen chooses black coffee"],
        &[("preference.food", json!("black coffee"))],
        merge_script(),
        &[],
        Vec::new(),
    )?;
    assert!(matches!(
        &run.outcome.sets[0],
        SetOutcome::Skipped {
            rule: SkipRule::BoundCorrection,
            ..
        }
    ));
    assert_eq!((run.counts.correction(), run.counts.resolution()), (1, 0));
    let planned = plan(Input {
        client: &run.step_client,
        reply: &run.reply,
        outcome: &run.outcome,
    })?;
    assert_eq!(run.step_backend.call_count(), 0);
    let items = planned.items();
    assert_eq!(items.len(), 1);
    let head = run.outcome.route.judge_sets[0]
        .prior_head
        .as_ref()
        .ok_or("the skipped set names its head")?;
    assert_eq!(
        items[0]["spec"]["members"][0]["candidate"]["corrects"],
        json!(head)
    );
    let answer = commit_dreamer(
        &run.vault,
        Some(run.attempt_id),
        json!({"items": items, "sources": []}),
    )?;
    assert_eq!(answer["items"][0]["landed"], true, "{answer}");
    assert_eq!(
        claim_lifecycle(&run.vault, EntityId::from_hex(head)?)?,
        Some("superseded".to_owned()),
        "the corrected head is superseded"
    );
    Ok(())
}

/// Merge asks once with the kept position and lands as native builds it.
#[test]
fn merge_lands_as_native_builds_it() -> TestResult<()> {
    let merged = json!("oolong tea");
    let run = run_case_two(
        &[],
        &["owen chooses green tea", "owen chooses black coffee"],
        &[
            ("preference.food", json!("green tea")),
            ("preference.food", json!("black coffee")),
        ],
        merge_script(),
        &[],
        vec![json!({"value": merged.clone()}).to_string()],
    )?;
    let SetOutcome::Decided(decision) = &run.outcome.sets[0] else {
        panic!("the merge decides");
    };
    assert_eq!(decision.resolution, Resolution::Merge);
    assert_eq!(
        decision.identity,
        Some(run.outcome.route.judge_sets[0].component_indexes[0])
    );
    assert_eq!((run.counts.correction(), run.counts.resolution()), (0, 1));
    let request = step_request(&run.outcome.set_operands[0], &run.outcome.sets[0], 0)?
        .ok_or("a kept merge asks")?;
    assert_eq!(request["resolution"], json!("merge"));
    assert_eq!(request["kept"], json!(0));
    let planned = plan(Input {
        client: &run.step_client,
        reply: &run.reply,
        outcome: &run.outcome,
    })?;
    assert_eq!(run.step_backend.call_count(), 1);
    let SetPlan::Resolved { outcome, item } = &planned.sets[0] else {
        panic!("a valued merge resolves");
    };
    assert_eq!(*outcome, ResolvedOutcome::Merge);
    assert_eq!(item["spec"]["kept"], json!(0));
    assert_eq!(item["spec"]["value"], merged);
    // The build-only door first: once the merged claim lands, native lists
    // it as a head of this subject.
    let door = build_native_merge(
        &run.vault,
        &run.attempt,
        run.now_ms,
        &run.outcome.set_operands[0].candidates,
        0,
        &merged,
    )?;
    assert_eq!(door["supersedes"], json!(null), "{door}");
    let answer = commit_dreamer(
        &run.vault,
        Some(run.attempt_id),
        json!({"items": planned.items(), "sources": []}),
    )?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    assert_eq!(item["approval"], json!("auto"), "{answer}");
    assert_eq!(door["claim"], item["rows"][0]);
    let claim = EntityId::from_hex(item["rows"][0].as_str().ok_or("the row")?)?;
    let stored = run.vault.get_claim(&claim)?.ok_or("the stored claim")?;
    assert_eq!(stored.value, RmpValue::from("oolong tea"));
    assert_eq!(stored.predicate, "preference.food");
    assert_eq!(stored.confidence, 0.5);
    assert_eq!(stored.approval, ClaimApprovalStatus::Auto);
    assert!(
        !run.vault
            .edges_out(&claim)?
            .iter()
            .any(|edge| edge.kind == oneiron::EdgeKind::Supersedes),
        "a merge with no head replaces nothing"
    );
    let stored_evidence = stored.evidence.as_ref().ok_or("the evidence")?;
    let candidate_evidence =
        map_at(stored_evidence, "candidate_evidence").ok_or("the candidate evidence")?;
    assert_eq!(
        door["candidate_evidence_hex"]
            .as_str()
            .ok_or("the door's evidence")?,
        hex_of(candidate_evidence)?
    );
    Ok(())
}

/// Accumulate lands every member and asks no step.
#[test]
fn accumulate_lands_every_member() -> TestResult<()> {
    let run = run_case_two(
        &[],
        &["owen chooses green tea", "owen chooses black coffee"],
        &[
            ("preference.food", json!("green tea")),
            ("preference.food", json!("black coffee")),
        ],
        accumulate_script(),
        &[],
        Vec::new(),
    )?;
    let SetOutcome::Decided(decision) = &run.outcome.sets[0] else {
        panic!("the accumulate decides");
    };
    assert_eq!(decision.resolution, Resolution::Accumulate);
    assert_eq!((run.counts.correction(), run.counts.resolution()), (0, 1));
    let planned = plan(Input {
        client: &run.step_client,
        reply: &run.reply,
        outcome: &run.outcome,
    })?;
    assert_eq!(run.step_backend.call_count(), 0);
    let SetPlan::Resolved { outcome, .. } = &planned.sets[0] else {
        panic!("an accumulate resolves");
    };
    assert_eq!(*outcome, ResolvedOutcome::Accumulate);
    let answer = commit_dreamer(
        &run.vault,
        Some(run.attempt_id),
        json!({"items": planned.items(), "sources": []}),
    )?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    let rows = item["rows"].as_array().ok_or("the rows")?;
    assert_eq!(rows.len(), 2, "{answer}");
    let first = EntityId::from_hex(rows[0].as_str().ok_or("the first row")?)?;
    let second = EntityId::from_hex(rows[1].as_str().ok_or("the second row")?)?;
    let first_body = run.vault.get_claim(&first)?.ok_or("the first claim")?;
    let second_body = run.vault.get_claim(&second)?.ok_or("the second claim")?;
    assert_eq!(first_body.value, RmpValue::from("green tea"), "set order");
    assert_eq!(
        second_body.value,
        RmpValue::from("black coffee"),
        "set order"
    );
    Ok(())
}

/// Escalate opens native's marker and asks no step.
#[test]
fn escalate_opens_native_marker() -> TestResult<()> {
    let run = run_case_two(
        &[],
        &["owen chooses green tea", "owen chooses black coffee"],
        &[
            ("preference.food", json!("green tea")),
            ("preference.food", json!("black coffee")),
        ],
        escalate_script(),
        &[],
        Vec::new(),
    )?;
    let SetOutcome::Decided(decision) = &run.outcome.sets[0] else {
        panic!("the escalate decides");
    };
    assert_eq!(decision.resolution, Resolution::Escalate);
    let planned = plan(Input {
        client: &run.step_client,
        reply: &run.reply,
        outcome: &run.outcome,
    })?;
    assert_eq!(run.step_backend.call_count(), 0);
    let SetPlan::Opened { cause, item } = &planned.sets[0] else {
        panic!("an escalate opens");
    };
    assert_eq!(*cause, OpenCause::Escalated);
    assert_eq!(item["kind"], json!("conflict"));
    let answer = commit_dreamer(
        &run.vault,
        Some(run.attempt_id),
        json!({"items": planned.items(), "sources": []}),
    )?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    let built = built_for(
        &run.vault,
        &answer,
        &run.attempt,
        &run.outcome.set_operands[0].candidates,
    )?;
    assert_eq!(built["marker"], item["rows"][0]);
    let marker = EntityId::from_hex(item["rows"][0].as_str().ok_or("the row")?)?;
    let open = open_for(&run.vault, run.subject)?;
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].marker, marker);
    assert_eq!(
        built["predicate"].as_str().ok_or("p")?,
        open[0].body.predicate.as_str()
    );
    let ClaimSubject::Entity(stored) = open[0].body.subject else {
        return Err("the marker names an entity subject".into());
    };
    assert_eq!(built["subject"].as_str().ok_or("s")?, stored.to_hex());
    assert_eq!(
        built["value_hex"].as_str().ok_or("v")?,
        hex_of(&open[0].body.value)?
    );
    let stored_evidence = open[0].body.evidence.as_ref().ok_or("e")?;
    let candidate_evidence = map_at(stored_evidence, "candidate_evidence").ok_or("ce")?;
    assert_eq!(
        built["evidence_hex"].as_str().ok_or("ee")?,
        hex_of(candidate_evidence)?
    );
    let provenance = map_at(stored_evidence, "provenance").ok_or("p")?;
    let at = |key: &str| map_at(provenance, key).and_then(RmpValue::as_str);
    assert_eq!(at("surface"), Some("vault.derive"));
    assert_eq!(at("batch"), answer["batch"].as_str());
    assert_eq!(at("item"), Some("conflict-set-0"));
    assert_eq!(at("run"), Some("run"));
    assert_ne!(at("run"), Some(run.attempt.as_str()));
    assert!(map_at(provenance, "decisions").is_none());
    Ok(())
}

/// A null merged value opens a marker with no claim.
#[test]
fn null_value_opens_marker_without_claim() -> TestResult<()> {
    let run = run_case_two(
        &[],
        &["owen chooses green tea", "owen chooses black coffee"],
        &[
            ("preference.food", json!("green tea")),
            ("preference.food", json!("black coffee")),
        ],
        merge_script(),
        &[],
        vec!["{}".to_owned()],
    )?;
    let planned = plan(Input {
        client: &run.step_client,
        reply: &run.reply,
        outcome: &run.outcome,
    })?;
    assert_eq!(run.step_backend.call_count(), 1);
    let SetPlan::Opened { cause, item } = &planned.sets[0] else {
        panic!("a null value opens");
    };
    assert_eq!(*cause, OpenCause::NoMergedValue);
    assert_eq!(item["kind"], json!("conflict"));
    let answer = commit_dreamer(
        &run.vault,
        Some(run.attempt_id),
        json!({"items": planned.items(), "sources": []}),
    )?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    assert_eq!(item["rows"].as_array().ok_or("the rows")?.len(), 1);
    let built = built_for(
        &run.vault,
        &answer,
        &run.attempt,
        &run.outcome.set_operands[0].candidates,
    )?;
    assert_eq!(built["marker"], item["rows"][0]);
    Ok(())
}

/// Two components land two items in one batch.
#[test]
fn two_components_land_in_one_batch() -> TestResult<()> {
    let run = run_case_two(
        &[],
        &[
            "owen chooses green tea",
            "owen chooses black coffee",
            "owen drinks water",
            "owen drinks juice",
        ],
        &[
            ("preference.food", json!("green tea")),
            ("preference.food", json!("black coffee")),
            ("preference.drink", json!("water")),
            ("preference.drink", json!("juice")),
        ],
        merge_script(),
        &[],
        vec![
            json!({"value": "food blend"}).to_string(),
            json!({"value": "drink blend"}).to_string(),
        ],
    )?;
    assert_eq!(run.outcome.sets.len(), 2);
    assert_eq!((run.counts.correction(), run.counts.resolution()), (0, 2));
    let planned = plan(Input {
        client: &run.step_client,
        reply: &run.reply,
        outcome: &run.outcome,
    })?;
    assert_eq!(planned.sets.len(), 2);
    assert_eq!(run.step_backend.call_count(), 2);
    let items = planned.items();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["spec"]["local"], json!("conflict-set-0"));
    assert_eq!(items[1]["spec"]["local"], json!("conflict-set-1"));
    let answer = commit_dreamer(
        &run.vault,
        Some(run.attempt_id),
        json!({"items": items, "sources": []}),
    )?;
    assert_eq!(answer["items"][0]["landed"], true, "{answer}");
    assert_eq!(answer["items"][1]["landed"], true, "{answer}");
    Ok(())
}
