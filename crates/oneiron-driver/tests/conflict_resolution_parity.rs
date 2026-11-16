//! Parity of the crate policy against native builds over lent fixtures.
//!
//! The tests reuse `extraction_decisions.rs` fixtures, varying verdicts, step
//! answers and member facts. They run `run`, plan with a second client lending
//! the merged-value step, and commit as the attempt's Dreamer.

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
use oneiron::claim::lexical_query_hint_claim_id;
use oneiron::dreamer_consolidation::OpenConflict;
use oneiron::test_doors::derive::claim_lifecycle;
use oneiron::test_doors::derive_conflict;
use oneiron::test_doors::derive_conflict_resolution::build_native_merge;
use oneiron::test_doors::derive_conflict_resolution::build_native_skip;
use oneiron::test_doors::open_conflict_marker::build_native_open_conflict;
use oneiron::test_doors::steward::dreamer;
use oneiron_dreamer::conflict_decisions::Resolution;
use oneiron_dreamer::conflict_resolution::Error as PlanError;
use oneiron_dreamer::conflict_resolution::Input;
use oneiron_dreamer::conflict_resolution::OpenCause;
use oneiron_dreamer::conflict_resolution::ResolvedOutcome;
use oneiron_dreamer::conflict_resolution::SetPlan;
use oneiron_dreamer::conflict_resolution::plan;
use oneiron_dreamer::conflict_resolution::step_request;
use oneiron_dreamer::extraction_decisions::SetOutcome;
use oneiron_dreamer::extraction_decisions::SkipRule;
use parity::ReplyOptions;
use parity::TestResult;
use parity::ValueBackend;
use parity::accumulate_script;
use parity::escalate_script;
use parity::merge_script;
use parity::merge_second_script;
use parity::none_script;
use parity::run_case_two;
use parity::run_case_with;
use parity::supersede_script;
use parity::unnamed_merge_script;
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

/// Checks that the one rendered step names the item's kept member and resolution.
fn assert_kept_step(run: &parity::DualRun, item: &Value, resolution: &str) -> TestResult<()> {
    assert_eq!(run.step_backend.call_count(), 1);
    let requests = run.step_backend.requests()?;
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    let expected_resolution = format!("resolution {resolution}");
    assert_eq!(
        request.lines().next(),
        Some(expected_resolution.as_str()),
        "{request}"
    );
    let kept_ref = request
        .lines()
        .find_map(|line| line.strip_prefix("keeps candidate_ref "))
        .ok_or("the step names its kept candidate")?;
    let kept = usize::try_from(item["spec"]["kept"].as_u64().ok_or("the kept position")?)?;
    let candidate = &item["spec"]["members"][kept]["candidate"];
    let predicate = candidate["predicate"]
        .as_str()
        .ok_or("the kept predicate")?;
    let expected_member = format!(
        "- candidate_ref: {kept_ref} predicate: {predicate} value: {}",
        candidate["value"]
    );
    assert!(
        request.lines().any(|line| line == expected_member),
        "{request}"
    );
    Ok(())
}

/// Compares a merged row's stable fields and candidate evidence with native's build.
fn assert_native_merged_row(
    run: &parity::DualRun,
    door: &Value,
    answer: &Value,
) -> TestResult<EntityId> {
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    assert_eq!(
        item["rows"].as_array().ok_or("the merged rows")?.len(),
        1,
        "{answer}"
    );
    assert_eq!(door["claim"], item["rows"][0], "{answer}");
    let claim = EntityId::from_hex(item["rows"][0].as_str().ok_or("the merged row")?)?;
    let stored = run
        .vault
        .get_claim(&claim)?
        .ok_or("the stored merged claim")?;
    assert_eq!(
        door["predicate"].as_str().ok_or("the native predicate")?,
        stored.predicate,
        "{answer}"
    );
    let ClaimSubject::Entity(subject) = stored.subject else {
        return Err("the merged claim names an entity subject".into());
    };
    assert_eq!(door["subject"], json!(subject.to_hex()), "{answer}");
    assert_eq!(door["value_hex"], json!(hex_of(&stored.value)?), "{answer}");
    assert_eq!(door["confidence"], json!(stored.confidence), "{answer}");
    assert_eq!(
        door["source"].as_str().ok_or("the native source")?,
        stored.source.ok_or("the merged source")?.as_str(),
        "{answer}"
    );
    assert_eq!(
        door["scope_hex"],
        json!(hex_of(stored.scope.as_ref().ok_or("the merged scope")?)?),
        "{answer}"
    );
    assert_eq!(
        door["facet"],
        json!(stored.scope_facet.to_hex()),
        "{answer}"
    );
    assert_eq!(
        door["project"],
        json!(stored.scope_project.to_hex()),
        "{answer}"
    );
    assert_eq!(
        door["world"],
        json!(stored.world.map(|world| world.to_hex())),
        "{answer}"
    );
    let relationships: Option<Vec<String>> = stored
        .rel
        .as_ref()
        .map(|rel| rel.iter().map(EntityId::to_hex).collect());
    assert_eq!(door["relationship"], json!(relationships), "{answer}");
    let evidence = stored.evidence.as_ref().ok_or("the merged evidence")?;
    let candidate_evidence =
        map_at(evidence, "candidate_evidence").ok_or("the candidate evidence")?;
    assert_eq!(
        door["candidate_evidence_hex"],
        json!(hex_of(candidate_evidence)?),
        "{answer}"
    );
    Ok(claim)
}

/// Checks a failed step's status, set, one call and absence of derive commits.
fn assert_step_failure(
    step_backend: ValueBackend,
    expected_status: &str,
    expected_message: &str,
) -> TestResult<()> {
    let run = run_case_with(
        &[],
        &["owen chooses green tea", "owen chooses black coffee"],
        &[
            ("preference.food", json!("green tea")),
            ("preference.food", json!("black coffee")),
        ],
        merge_script(),
        &[],
        step_backend,
        ReplyOptions::default(),
    )?;
    assert_eq!(run.outcome.sets.len(), 1);
    let actor = dreamer(&run.vault)?;
    let before = run.vault.derive_batches_of(actor)?;
    assert!(before.is_empty());
    let answer = plan(Input {
        client: &run.step_client,
        reply: &run.reply,
        outcome: &run.outcome,
    });
    let Err(PlanError::Step {
        set,
        status,
        message,
    }) = &answer
    else {
        return Err(format!("the failed merged-value step must name its set: {answer:?}").into());
    };
    assert_eq!(*set, 0, "{answer:?}");
    assert_eq!(status, expected_status, "{answer:?}");
    assert!(message.contains(expected_message), "{answer:?}");
    assert_eq!(run.step_backend.call_count(), 1, "{answer:?}");
    assert_eq!(run.step_backend.requests()?.len(), 1, "{answer:?}");
    assert_eq!(run.vault.derive_batches_of(actor)?, before, "{answer:?}");
    assert!(open_for(&run.vault, run.subject)?.is_empty(), "{answer:?}");
    Ok(())
}

/// Compares the one landed marker with native's build at the batch's clock.
fn assert_native_marker(run: &parity::DualRun, answer: &Value) -> TestResult<()> {
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    assert_eq!(
        item["rows"].as_array().ok_or("the marker rows")?.len(),
        1,
        "{answer}"
    );
    let built = built_for(
        &run.vault,
        answer,
        &run.attempt,
        &run.outcome.set_operands[0].candidates,
    )?;
    assert_eq!(built["marker"], item["rows"][0], "{answer}");
    let marker = EntityId::from_hex(item["rows"][0].as_str().ok_or("the marker row")?)?;
    let open = open_for(&run.vault, run.subject)?;
    assert_eq!(open.len(), 1, "{answer}");
    assert_eq!(open[0].marker, marker, "{answer}");
    assert_eq!(
        built["predicate"]
            .as_str()
            .ok_or("the native marker predicate")?,
        open[0].body.predicate,
        "{answer}"
    );
    let ClaimSubject::Entity(subject) = open[0].body.subject else {
        return Err("the marker names an entity subject".into());
    };
    assert_eq!(built["subject"], json!(subject.to_hex()), "{answer}");
    assert_eq!(
        built["value_hex"],
        json!(hex_of(&open[0].body.value)?),
        "{answer}"
    );
    let evidence = open[0]
        .body
        .evidence
        .as_ref()
        .ok_or("the marker evidence")?;
    let candidate_evidence =
        map_at(evidence, "candidate_evidence").ok_or("the marker's candidate evidence")?;
    assert_eq!(
        built["evidence_hex"],
        json!(hex_of(candidate_evidence)?),
        "{answer}"
    );
    Ok(())
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
    // The set's order is the selection's ready order (score, then claim
    // id), not the reply's. The two siblings tie on score, so either may
    // come first in a fresh vault; the rows stand in the item's set order.
    let items = planned.items();
    let spec = &items[0]["spec"];
    let positions = spec["set_members"].as_array().ok_or("the set members")?;
    let mut expected = Vec::new();
    for position in positions {
        let position = usize::try_from(position.as_u64().ok_or("a position")?)?;
        let value = spec["members"][position]["candidate"]["value"]
            .as_str()
            .ok_or("a member's value")?;
        expected.push(value.to_owned());
    }
    let mut both = expected.clone();
    both.sort_unstable();
    assert_eq!(both, ["black coffee", "green tea"]);
    let answer = commit_dreamer(
        &run.vault,
        Some(run.attempt_id),
        json!({"items": items, "sources": []}),
    )?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    let rows = item["rows"].as_array().ok_or("the rows")?;
    assert_eq!(rows.len(), expected.len(), "{answer}");
    for (row, value) in rows.iter().zip(&expected) {
        let claim = EntityId::from_hex(row.as_str().ok_or("a row")?)?;
        let stored = run.vault.get_claim(&claim)?.ok_or("the stored claim")?;
        assert_eq!(stored.value, RmpValue::from(value.as_str()), "set order");
    }
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
    let run = run_case_with(
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
        ValueBackend::by_predicate(&[
            ("preference.food", json!("food blend")),
            ("preference.drink", json!("drink blend")),
        ]),
        ReplyOptions::default(),
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
    let mut expected = Vec::new();
    for (set, item) in items.iter().enumerate() {
        let operands = &run.outcome.set_operands[set];
        let position = *operands.set_members.first().ok_or("a set member")?;
        let predicate = operands.candidates[position]["predicate"]
            .as_str()
            .ok_or("the set's predicate")?;
        let value = match predicate {
            "preference.food" => "food blend",
            "preference.drink" => "drink blend",
            _ => return Err("an unexpected component predicate".into()),
        };
        assert_eq!(item["spec"]["value"], json!(value));
        expected.push((predicate.to_owned(), value));
    }
    let requests = run.step_backend.requests()?;
    assert_eq!(requests.len(), expected.len());
    for (request, (predicate, _)) in requests.iter().zip(&expected) {
        let rendered_predicate = format!("predicate {predicate}");
        assert!(
            request.lines().any(|line| line == rendered_predicate),
            "{request}"
        );
    }
    let answer = commit_dreamer(
        &run.vault,
        Some(run.attempt_id),
        json!({"items": items, "sources": []}),
    )?;
    assert_eq!(answer["items"][0]["landed"], true, "{answer}");
    assert_eq!(answer["items"][1]["landed"], true, "{answer}");
    for (item, (predicate, value)) in answer["items"]
        .as_array()
        .ok_or("the landed items")?
        .iter()
        .zip(&expected)
    {
        assert_eq!(
            item["rows"].as_array().ok_or("the component rows")?.len(),
            1,
            "{answer}"
        );
        let claim = EntityId::from_hex(item["rows"][0].as_str().ok_or("the component row")?)?;
        let stored = run
            .vault
            .get_claim(&claim)?
            .ok_or("the stored component claim")?;
        assert_eq!(&stored.predicate, predicate, "{answer}");
        assert_eq!(stored.value, RmpValue::from(*value), "{answer}");
    }
    Ok(())
}

/// The component's second member is kept by both the bound step and native build.
#[test]
fn merge_keeps_second_member_as_native_builds_it() -> TestResult<()> {
    let merged = json!("oolong tea");
    let run = run_case_two(
        &[],
        &["owen chooses green tea", "owen chooses black coffee"],
        &[
            ("preference.food", json!("green tea")),
            ("preference.food", json!("black coffee")),
        ],
        merge_second_script(),
        &[],
        vec![json!({"value": merged.clone()}).to_string()],
    )?;
    assert_eq!(run.outcome.sets.len(), 1);
    let operands = &run.outcome.set_operands[0];
    assert_eq!(operands.set_members, [0, 1]);
    let SetOutcome::Decided(decision) = &run.outcome.sets[0] else {
        return Err("the second-member merge decides".into());
    };
    assert_eq!(decision.resolution, Resolution::Merge);
    assert_eq!(decision.identity, Some(operands.representatives[1]));
    let request = step_request(operands, &run.outcome.sets[0], 0)?.ok_or("a kept merge asks")?;
    assert_eq!(request["kept"], json!(1));
    assert_eq!(request["candidates"][1], operands.candidates[1]);
    let planned = plan(Input {
        client: &run.step_client,
        reply: &run.reply,
        outcome: &run.outcome,
    })?;
    assert_eq!(planned.sets.len(), 1);
    let SetPlan::Resolved { outcome, item } = &planned.sets[0] else {
        return Err("the second-member merge resolves".into());
    };
    assert_eq!(*outcome, ResolvedOutcome::Merge);
    assert_eq!(item["spec"]["kept"], json!(1));
    assert_eq!(item["spec"]["value"], merged);
    assert_eq!(
        item["spec"]["members"][1]["candidate"],
        operands.candidates[1]
    );
    assert_kept_step(&run, item, "merge")?;
    let kept = usize::try_from(item["spec"]["kept"].as_u64().ok_or("the kept position")?)?;
    let door = build_native_merge(
        &run.vault,
        &run.attempt,
        run.now_ms,
        &operands.candidates,
        kept,
        &merged,
    )?;
    let answer = commit_dreamer(
        &run.vault,
        Some(run.attempt_id),
        json!({"items": planned.items(), "sources": []}),
    )?;
    let claim = assert_native_merged_row(&run, &door, &answer)?;
    let stored = run.vault.get_claim(&claim)?.ok_or("the stored merge")?;
    assert_eq!(
        door["approval"],
        json!(stored.approval.as_str()),
        "{answer}"
    );
    assert_eq!(stored.approval, ClaimApprovalStatus::Auto, "{answer}");
    assert_eq!(door["supersedes"], json!(null), "{answer}");
    assert!(
        !run.vault
            .edges_out(&claim)?
            .iter()
            .any(|edge| edge.kind == oneiron::EdgeKind::Supersedes),
        "{answer}"
    );
    Ok(())
}

/// Supersede asks with its native label, then lands a merge replacing the prior head.
#[test]
fn supersede_lands_as_native_merge_builds_it() -> TestResult<()> {
    let merged = json!("black coffee");
    let run = run_case_two(
        &[("preference.food", "white tea")],
        &["owen chooses green tea", "owen chooses black coffee"],
        &[
            ("preference.food", json!("green tea")),
            ("preference.food", json!("black coffee")),
        ],
        supersede_script(),
        &[],
        vec![json!({"value": merged.clone()}).to_string()],
    )?;
    assert_eq!(run.outcome.sets.len(), 1);
    let SetOutcome::Decided(decision) = &run.outcome.sets[0] else {
        return Err("the supersede decides rather than skipping".into());
    };
    assert_eq!(decision.resolution, Resolution::Supersede);
    let operands = &run.outcome.set_operands[0];
    let request = step_request(operands, &run.outcome.sets[0], 0)?.ok_or("a supersede asks")?;
    assert_eq!(request["resolution"], json!("supersede"));
    let kept = usize::try_from(
        request["kept"]
            .as_u64()
            .ok_or("the supersede's kept position")?,
    )?;
    let head = run.outcome.route.judge_sets[0]
        .prior_head
        .as_ref()
        .ok_or("the superseded head")?;
    let planned = plan(Input {
        client: &run.step_client,
        reply: &run.reply,
        outcome: &run.outcome,
    })?;
    assert_eq!(planned.sets.len(), 1);
    let SetPlan::Resolved { outcome, item } = &planned.sets[0] else {
        return Err("a valued supersede resolves".into());
    };
    assert_eq!(*outcome, ResolvedOutcome::Merge);
    assert_eq!(item["spec"]["outcome"], json!("merge"));
    assert_eq!(item["spec"]["kept"], request["kept"]);
    assert_eq!(item["spec"]["value"], merged);
    assert_kept_step(&run, item, "supersede")?;
    // This build door has no resolution-label argument; its shared merge
    // assembly is also the supersede landing path. Build before replacing the head.
    let door = build_native_merge(
        &run.vault,
        &run.attempt,
        run.now_ms,
        &operands.candidates,
        kept,
        &merged,
    )?;
    assert_eq!(door["supersedes"], json!(head), "{door}");
    assert_eq!(door["approval"], json!("proposed"), "{door}");
    let answer = commit_dreamer(
        &run.vault,
        Some(run.attempt_id),
        json!({"items": planned.items(), "sources": []}),
    )?;
    let claim = assert_native_merged_row(&run, &door, &answer)?;
    let stored = run.vault.get_claim(&claim)?.ok_or("the stored supersede")?;
    // Native's build stops at Proposed; the stager's replacement grant is Auto.
    assert_eq!(answer["items"][0]["approval"], json!("auto"), "{answer}");
    assert_eq!(stored.approval, ClaimApprovalStatus::Auto, "{answer}");
    let superseded: Vec<_> = run
        .vault
        .edges_out(&claim)?
        .into_iter()
        .filter(|edge| edge.kind == oneiron::EdgeKind::Supersedes)
        .map(|edge| edge.target.to_hex())
        .collect();
    assert_eq!(superseded, [head.clone()], "{answer}");
    assert_eq!(
        claim_lifecycle(&run.vault, EntityId::from_hex(head)?)?,
        Some("superseded".to_owned()),
        "{answer}"
    );
    Ok(())
}

/// A terminal merged-value failure names its set without committing a batch.
#[test]
fn failed_merged_value_step_leaves_no_batch() -> TestResult<()> {
    assert_step_failure(ValueBackend::refusing(), "failed", "response erased")
}

/// A budget-denied step preserves the set and trap message without committing a batch.
#[test]
fn budget_denied_merged_value_step_leaves_no_batch() -> TestResult<()> {
    assert_step_failure(
        ValueBackend::budget_denied(),
        "budget_denied",
        "the merged-value step was denied its budget at trap ",
    )
}

/// Paged cross-predicate merge naming none opens native's marker without asking a step.
#[test]
fn unnamed_cross_predicate_merge_opens_native_marker_without_step() -> TestResult<()> {
    let run = run_case_with(
        &[],
        &["owen chooses green tea", "owen drinks black coffee"],
        &[
            ("preference.food", support::big_value("tea")),
            ("preference.drink", support::big_value("coffee")),
        ],
        unnamed_merge_script(),
        &[],
        ValueBackend::scripted(Vec::new()),
        ReplyOptions {
            shared_vectors: true,
            ..ReplyOptions::default()
        },
    )?;
    assert_eq!(run.outcome.sets.len(), 1);
    let operands = &run.outcome.set_operands[0];
    assert_eq!(operands.set_members.len(), 2);
    assert!(operands.spans_predicates);
    assert_ne!(
        operands.candidates[0]["predicate"],
        operands.candidates[1]["predicate"]
    );
    let SetOutcome::Decided(decision) = &run.outcome.sets[0] else {
        return Err("the paged cross-predicate merge decides".into());
    };
    assert_eq!(decision.resolution, Resolution::Merge);
    assert_eq!(decision.identity, None);
    assert_eq!((run.counts.correction(), run.counts.resolution()), (0, 2));
    assert_eq!(step_request(operands, &run.outcome.sets[0], 0)?, None);
    let planned = plan(Input {
        client: &run.step_client,
        reply: &run.reply,
        outcome: &run.outcome,
    })?;
    assert_eq!(planned.sets.len(), 1);
    assert_eq!(run.step_backend.call_count(), 0);
    let SetPlan::Opened { cause, item } = &planned.sets[0] else {
        return Err("a cross-predicate merge naming none opens a marker".into());
    };
    assert_eq!(*cause, OpenCause::CrossPredicateMergeUnnamed);
    assert_eq!(item["kind"], json!("conflict"));
    let answer = commit_dreamer(
        &run.vault,
        Some(run.attempt_id),
        json!({"items": planned.items(), "sources": []}),
    )?;
    assert_native_marker(&run, &answer)?;
    Ok(())
}

/// A set with two stored heads escalates to native's marker and replaces neither head.
#[test]
fn multi_head_escalation_opens_native_marker() -> TestResult<()> {
    let run = run_case_two(
        &[
            ("preference.food", "green tea"),
            ("preference.food", "black coffee"),
        ],
        &["owen chooses oolong tea"],
        &[("preference.food", json!("oolong tea"))],
        escalate_script(),
        &[],
        Vec::new(),
    )?;
    assert_eq!(run.outcome.sets.len(), 1);
    let routed = &run.outcome.route.judge_sets[0];
    assert_eq!(routed.prior_heads.len(), 2);
    assert_eq!(routed.prior_head, None);
    let operands = &run.outcome.set_operands[0];
    assert_eq!(operands.priors.len(), 2);
    let heads: Vec<_> = operands
        .priors
        .iter()
        .map(|prior| prior.claim.clone())
        .collect();
    assert_eq!(heads, routed.prior_heads);
    let SetOutcome::Decided(decision) = &run.outcome.sets[0] else {
        return Err("the multi-head set decides rather than skipping".into());
    };
    assert_eq!(decision.resolution, Resolution::Escalate);
    assert_eq!((run.counts.correction(), run.counts.resolution()), (1, 1));
    let planned = plan(Input {
        client: &run.step_client,
        reply: &run.reply,
        outcome: &run.outcome,
    })?;
    assert_eq!(planned.sets.len(), 1);
    assert_eq!(run.step_backend.call_count(), 0);
    let SetPlan::Opened { cause, item } = &planned.sets[0] else {
        return Err("the multi-head escalation opens a marker".into());
    };
    assert_eq!(*cause, OpenCause::Escalated);
    assert_eq!(item["kind"], json!("conflict"));
    assert_eq!(
        item["spec"]["heads"],
        serde_json::to_value(&operands.priors)?
    );
    let answer = commit_dreamer(
        &run.vault,
        Some(run.attempt_id),
        json!({"items": planned.items(), "sources": []}),
    )?;
    assert_native_marker(&run, &answer)?;
    for head in &heads {
        assert_eq!(
            claim_lifecycle(&run.vault, EntityId::from_hex(head)?)?,
            Some("active".to_owned()),
            "{answer}"
        );
    }
    Ok(())
}

/// Accumulate keeps each member's confidence and its own prospective-query hint.
#[test]
fn accumulate_preserves_member_confidences_and_hint() -> TestResult<()> {
    let hint = "which tea does owen prefer";
    let run = run_case_with(
        &[],
        &["owen chooses green tea", "owen chooses black coffee"],
        &[
            ("preference.food", json!("green tea")),
            ("preference.food", json!("black coffee")),
        ],
        accumulate_script(),
        &[],
        ValueBackend::scripted(Vec::new()),
        ReplyOptions {
            facts: vec![(0.6, vec![hint.to_owned()]), (0.8, Vec::new())],
            ..ReplyOptions::default()
        },
    )?;
    assert_eq!(run.outcome.sets.len(), 1);
    let SetOutcome::Decided(decision) = &run.outcome.sets[0] else {
        return Err("the distinct-confidence accumulate decides".into());
    };
    assert_eq!(decision.resolution, Resolution::Accumulate);
    let planned = plan(Input {
        client: &run.step_client,
        reply: &run.reply,
        outcome: &run.outcome,
    })?;
    assert_eq!(run.step_backend.call_count(), 0);
    assert_eq!(planned.sets.len(), 1);
    let SetPlan::Resolved { outcome, item } = &planned.sets[0] else {
        return Err("the distinct-confidence accumulate resolves".into());
    };
    assert_eq!(*outcome, ResolvedOutcome::Accumulate);
    let spec = &item["spec"];
    let positions = spec["set_members"].as_array().ok_or("the set members")?;
    assert_eq!(positions.len(), 2);
    let mut expected = Vec::new();
    let mut hinted_members = 0;
    for position in positions {
        let position = usize::try_from(position.as_u64().ok_or("a member position")?)?;
        let member = &spec["members"][position];
        let candidate = &member["candidate"];
        let original = run
            .reply
            .candidates
            .iter()
            .find(|original| {
                original.value == candidate["value"]
                    && candidate["predicate"].as_str() == Some(original.predicate.as_str())
            })
            .ok_or("the member's original reply candidate")?;
        assert_eq!(member["confidence"], json!(original.confidence));
        assert_eq!(
            member["prospective_queries"],
            json!(original.prospective_queries)
        );
        if !original.prospective_queries.is_empty() {
            hinted_members += 1;
            assert_eq!(original.prospective_queries, [hint]);
        }
        let confidence: f32 = serde_json::from_value(json!(original.confidence))?;
        expected.push((
            original
                .value
                .as_str()
                .ok_or("the original value")?
                .to_owned(),
            confidence,
        ));
    }
    assert_eq!(hinted_members, 1);
    let answer = commit_dreamer(
        &run.vault,
        Some(run.attempt_id),
        json!({"items": planned.items(), "sources": []}),
    )?;
    let landed = &answer["items"][0];
    assert_eq!(landed["landed"], true, "{answer}");
    let rows = landed["rows"].as_array().ok_or("the accumulated rows")?;
    assert_eq!(rows.len(), expected.len(), "{answer}");
    for (row, (value, confidence)) in rows.iter().zip(&expected) {
        let claim = EntityId::from_hex(row.as_str().ok_or("an accumulated row")?)?;
        let stored = run
            .vault
            .get_claim(&claim)?
            .ok_or("the accumulated claim")?;
        assert_eq!(stored.value, RmpValue::from(value.as_str()), "{answer}");
        assert_eq!(stored.confidence, *confidence, "{answer}");
        // Signed Dreamer writes intentionally materialize no hint side claims.
        let hint_id = lexical_query_hint_claim_id(&claim, hint)?;
        assert!(run.vault.get_claim(&hint_id)?.is_none(), "{answer}");
    }
    Ok(())
}
