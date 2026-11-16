//! Runs the crate's extraction job over one client bound with the production lender.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-driver --all-features --test dreamer_extraction_job`
#![cfg(oneiron_test_support)]

#[allow(dead_code)]
#[path = "dreamer_extraction_job/support.rs"]
mod support;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use oneiron::EdgeActorClass;
use oneiron::EntityId;
use oneiron::claim::ClaimApprovalStatus;
use oneiron::claim::ClaimSubject;
use oneiron::test_doors::extraction_steps::native_extraction_slice_transcripts;
use oneiron::test_doors::steward::dreamer;
use oneiron_dreamer::conflict_resolution;
use oneiron_dreamer::conflict_resolution::ResolvedOutcome;
use oneiron_dreamer::conflict_resolution::SetPlan;
use oneiron_dreamer::extraction;
use rmpv::Value as RmpValue;
use support::TestResult;
use support::declared_step_reply;
use support::find_person_label;
use support::job_fixture;
use support::job_merge_fixture;
use support::listed_step_reply;
use support::rebind_same_attempt;

/// One candidate about a seeded person with no head lands one claim in one
/// batch, written by the Dreamer, with no person batch.
#[test]
fn a_listed_candidate_with_no_head_lands_one_claim() -> TestResult<()> {
    let handler: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(|transcript: &str| {
        let label = find_person_label(transcript, "owen").expect("owen lists");
        listed_step_reply(&label, "profile.hobby", "tea", "T1", "owen likes tea")
    });
    let fixture = job_fixture(
        &["owen likes tea"],
        &["owen"],
        &[],
        None,
        handler,
        true,
        true,
    )?;
    let outcome = extraction::run(extraction::Input {
        client: &fixture.client,
        attempt: &fixture.attempt_hex,
        now_ms: fixture.now_ms,
    })?;
    assert_eq!(outcome.served_turns, 1);
    assert_eq!(outcome.finished_steps, 1);
    assert!(outcome.people.is_empty());
    assert!(outcome.skipped.is_empty());
    assert_eq!(outcome.components.len(), 1);
    let component = &outcome.components[0];
    assert_eq!(component.representative_index, 0);
    assert_eq!(component.set, None);
    assert!(component.planned.is_none());
    assert_eq!(component.view.kind, "candidate");
    assert!(component.view.landed);
    assert_eq!(component.view.rows.len(), 1);
    assert_eq!(component.view.approval.as_deref(), Some("auto"));
    assert!(component.view.reasons.is_empty());
    assert!(!component.view.batch.is_empty());
    assert_eq!(outcome.already_represented, 0);
    assert_eq!(outcome.held_groups, 0);
    assert_eq!(outcome.retry_at_ms, None);
    assert_eq!(outcome.pending_bindings, 0);
    assert_eq!(outcome.batches, 1);
    assert_eq!(fixture.step_backend.calls(), 1);
    assert_eq!(fixture.counts.correction(), 0);
    assert_eq!(fixture.counts.resolution(), 0);
    let owen = fixture.seeded[0];
    let claim = EntityId::from_hex(&component.view.rows[0])?;
    let stored = fixture
        .vault
        .get_claim(&claim)?
        .ok_or("the landed candidate reads back")?;
    assert_eq!(stored.subject, ClaimSubject::Entity(owen));
    assert_eq!(stored.approval, ClaimApprovalStatus::Auto);
    let batch = EntityId::from_hex(&component.view.batch)?;
    let record = fixture
        .vault
        .derive_batch(batch)?
        .ok_or("the component batch records its writer")?;
    assert_eq!(record.actor, dreamer(&fixture.vault)?);
    Ok(())
}

/// A window whose TURNs fall in two native slices is refused with the typed
/// layout and resubmitted once for each slice: two steps, two generations.
///
/// Each TURN names a different known PERSON, so each forms its own slice
/// group (its part line with its co-mentioned known entities). The native
/// slice count is asserted before the job runs.
#[test]
fn two_slices_are_resubmitted_as_two_steps() -> TestResult<()> {
    let handler: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(|transcript: &str| {
        if transcript.contains("yuki likes tea") {
            let label = find_person_label(transcript, "yuki").expect("yuki lists");
            listed_step_reply(&label, "profile.hobby", "tea", "T1", "yuki likes tea")
        } else {
            let label = find_person_label(transcript, "owen").expect("owen lists");
            listed_step_reply(&label, "profile.hobby", "tea", "T1", "owen likes tea")
        }
    });
    let fixture = job_fixture(
        &["owen likes tea", "yuki likes tea"],
        &["owen", "yuki"],
        &[],
        None,
        handler,
        true,
        true,
    )?;
    assert!(
        fixture
            .vault
            .consolidation_selection()?
            .extraction_turns_per_child
            >= 2
    );
    let material: Vec<String> = Vec::new();
    let native = native_extraction_slice_transcripts(
        &fixture.vault,
        fixture.attempt,
        &fixture.turn_ids,
        &material,
    )?;
    assert_eq!(native.len(), 2);
    let outcome = extraction::run(extraction::Input {
        client: &fixture.client,
        attempt: &fixture.attempt_hex,
        now_ms: fixture.now_ms,
    })?;
    assert_eq!(outcome.served_turns, 2);
    assert_eq!(outcome.finished_steps, 2);
    assert!(outcome.people.is_empty());
    assert!(outcome.skipped.is_empty());
    assert_eq!(outcome.components.len(), 2);
    for component in &outcome.components {
        assert_eq!(component.set, None);
        assert!(component.planned.is_none());
        assert_eq!(component.view.kind, "candidate");
        assert!(component.view.landed);
        assert_eq!(component.view.rows.len(), 1);
        assert_eq!(component.view.approval.as_deref(), Some("auto"));
        assert!(component.view.reasons.is_empty());
        assert!(!component.view.batch.is_empty());
    }
    let mut reps: Vec<usize> = outcome
        .components
        .iter()
        .map(|component| component.representative_index)
        .collect();
    reps.sort_unstable();
    assert_eq!(reps, vec![0, 1]);
    assert_eq!(outcome.already_represented, 0);
    assert_eq!(outcome.held_groups, 0);
    assert_eq!(outcome.retry_at_ms, None);
    assert_eq!(outcome.pending_bindings, 0);
    assert_eq!(outcome.batches, 2);
    assert_eq!(fixture.step_backend.calls(), 2);
    assert_eq!(fixture.counts.correction(), 0);
    assert_eq!(fixture.counts.resolution(), 0);
    Ok(())
}

/// A declared person is minted in a first batch, and its candidate lands
/// about the returned id in a later batch.
#[test]
fn a_declared_person_is_minted_before_its_candidate_lands() -> TestResult<()> {
    let handler: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(|_transcript: &str| {
        declared_step_reply("owen", "profile.hobby", "tea", "T1", "owen likes tea")
    });
    let fixture = job_fixture(&["owen likes tea"], &[], &[], None, handler, true, true)?;
    let outcome = extraction::run(extraction::Input {
        client: &fixture.client,
        attempt: &fixture.attempt_hex,
        now_ms: fixture.now_ms,
    })?;
    assert_eq!(outcome.served_turns, 1);
    assert_eq!(outcome.finished_steps, 1);
    assert_eq!(outcome.people.len(), 1);
    let person = &outcome.people[0];
    assert_eq!(person.key, 0);
    let person_id = person.id.clone().ok_or("the declared owen mints an id")?;
    assert!(person.view.landed);
    assert_eq!(person.view.kind, "person");
    assert_eq!(person.view.rows, vec![person_id.clone()]);
    assert_eq!(person.view.approval, None);
    assert!(person.view.reasons.is_empty());
    assert!(!person.view.batch.is_empty());
    assert!(outcome.skipped.is_empty());
    assert_eq!(outcome.components.len(), 1);
    let component = &outcome.components[0];
    assert_eq!(component.representative_index, 0);
    assert_eq!(component.set, None);
    assert!(component.planned.is_none());
    assert_eq!(component.view.kind, "candidate");
    assert!(component.view.landed);
    assert_eq!(component.view.rows.len(), 1);
    assert_eq!(component.view.approval.as_deref(), Some("auto"));
    assert!(component.view.reasons.is_empty());
    assert!(!component.view.batch.is_empty());
    assert_ne!(person.view.batch, component.view.batch);
    assert_eq!(outcome.already_represented, 0);
    assert_eq!(outcome.held_groups, 0);
    assert_eq!(outcome.retry_at_ms, None);
    assert_eq!(outcome.pending_bindings, 0);
    assert_eq!(outcome.batches, 2);
    assert_eq!(fixture.step_backend.calls(), 1);
    assert_eq!(fixture.counts.correction(), 0);
    assert_eq!(fixture.counts.resolution(), 0);
    let minted = EntityId::from_hex(&person_id)?;
    let claim = EntityId::from_hex(&component.view.rows[0])?;
    let stored = fixture
        .vault
        .get_claim(&claim)?
        .ok_or("the landed candidate reads back")?;
    assert_eq!(stored.subject, ClaimSubject::Entity(minted));
    let person_batch = EntityId::from_hex(&person.view.batch)?;
    let candidate_batch = EntityId::from_hex(&component.view.batch)?;
    let author = dreamer(&fixture.vault)?;
    let batches = fixture.vault.derive_batches_of(author)?;
    let person_at = batches
        .iter()
        .position(|batch| *batch == person_batch)
        .ok_or("the person batch commits")?;
    let candidate_at = batches
        .iter()
        .position(|batch| *batch == candidate_batch)
        .ok_or("the candidate batch commits")?;
    assert!(
        person_at < candidate_at,
        "the person batch commits before the candidate batch"
    );
    Ok(())
}

/// A first run mints the declared person and then ends on a refused verdict;
/// a second run of the same attempt is refused the person item as
/// `person_id_taken`, skips that person's candidate with the token, and lands
/// the other candidate's set.
///
/// This pins the engine's rule as it stands: a refused person view names no
/// row, so the job cannot bind the candidate to the PERSON the first run
/// minted. The second binding of the attempt borrows the same production
/// lender.
///
/// The candidate about the seeded owen first asks a correction against the
/// listed head. The verdict backend refuses the first run's call. On the
/// second run the correction answers none, the unequal head then forms a
/// one-member judge set, and its resolution answers accumulate. No
/// merged-value step is asked.
///
/// The test does not assert that the second run's steps are answered from
/// the saved ones: nothing here pins the attempt's listing, and the PERSON
/// the first run minted may change the second run's step request.
#[test]
fn a_retry_after_a_minted_person_skips_that_person_s_candidate() -> TestResult<()> {
    let handler: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(|transcript: &str| {
        if transcript.contains("yuki likes tea") {
            declared_step_reply("yuki", "profile.hobby", "tea", "T1", "yuki likes tea")
        } else {
            let label = find_person_label(transcript, "owen").expect("owen lists");
            listed_step_reply(&label, "profile.hobby", "tea", "T1", "owen likes tea")
        }
    });
    let fixture = job_fixture(
        &["yuki likes tea", "owen likes tea"],
        &["owen"],
        &[(0, "profile.hobby", "coffee")],
        None,
        handler,
        true,
        true,
    )?;
    fixture.reasoner.refusing.store(true, Ordering::SeqCst);
    let first = extraction::run(extraction::Input {
        client: &fixture.client,
        attempt: &fixture.attempt_hex,
        now_ms: fixture.now_ms,
    });
    let refused = first.expect_err("the verdict backend refusal leaves PERSON without CLAIM");
    assert_eq!(refused.code(), Some("MODEL_UNAVAILABLE"));
    assert_eq!(fixture.step_backend.calls(), 2);
    assert_eq!(fixture.counts.correction(), 0);
    assert_eq!(fixture.counts.resolution(), 0);
    assert!(fixture.reasoner.refused_calls.load(Ordering::SeqCst) > 0);
    let author = dreamer(&fixture.vault)?;
    let batches = fixture.vault.derive_batches_of(author)?;
    assert_eq!(
        batches.len(),
        1,
        "only the person batch commits before land fails"
    );
    let record = fixture
        .vault
        .derive_batch(batches[0])?
        .ok_or("the person batch records")?;
    assert_eq!(record.items.len(), 1);
    assert_eq!(record.items[0].kind, "person");
    assert!(record.items[0].landed);
    assert_eq!(record.items[0].rows.len(), 1);
    assert_eq!(
        fixture.vault.get_entity_type(&record.items[0].rows[0])?,
        Some(oneiron::registry::ENTITY_TYPE_PERSON),
    );
    fixture.reasoner.refusing.store(false, Ordering::SeqCst);
    let rebound = rebind_same_attempt(&fixture)?;
    let outcome = extraction::run(extraction::Input {
        client: &rebound,
        attempt: &fixture.attempt_hex,
        now_ms: fixture.now_ms,
    })?;
    assert_eq!(outcome.served_turns, 2);
    assert_eq!(outcome.finished_steps, 2);
    assert_eq!(outcome.people.len(), 1);
    let person = &outcome.people[0];
    assert_eq!(person.key, 0);
    assert_eq!(person.id, None);
    assert!(!person.view.landed);
    assert_eq!(person.view.kind, "person");
    assert!(person.view.rows.is_empty());
    assert_eq!(person.view.approval, None);
    assert_eq!(
        person.view.reasons,
        vec!["gate.deny.derive.person_id_taken".to_owned()]
    );
    assert!(!person.view.batch.is_empty());
    assert_eq!(outcome.skipped.len(), 1);
    assert_eq!(
        outcome.skipped[0].reasons,
        vec!["gate.deny.derive.person_id_taken".to_owned()]
    );
    assert_eq!(outcome.components.len(), 1);
    let component = &outcome.components[0];
    assert_eq!(component.representative_index, 0);
    assert_eq!(component.set, Some(0));
    assert!(matches!(
        &component.planned,
        Some(SetPlan::Resolved {
            outcome: ResolvedOutcome::Accumulate,
            ..
        })
    ));
    assert_eq!(component.view.kind, "conflict_resolution");
    assert!(component.view.landed);
    assert!(!component.view.rows.is_empty());
    assert!(component.view.reasons.is_empty());
    assert!(!component.view.batch.is_empty());
    assert_eq!(outcome.already_represented, 0);
    assert_eq!(outcome.held_groups, 0);
    assert_eq!(outcome.retry_at_ms, None);
    assert_eq!(outcome.pending_bindings, 0);
    assert_eq!(outcome.batches, 2);
    assert_eq!(fixture.counts.correction(), 1);
    assert_eq!(fixture.counts.resolution(), 1);
    Ok(())
}

/// A two-member merge lands as one `conflict_resolution` component in one batch.
///
/// The words, predicate and scripts are those of the parity test
/// `merge_lands_as_native_builds_it`: green tea and black coffee under
/// `preference.food` merge to oolong tea through one merged-value generation
/// on the verdict role.
#[test]
fn a_merge_lands_one_conflict_resolution_component() -> TestResult<()> {
    let handler: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(support::merge_step_reply);
    let fixture = job_merge_fixture(
        &["owen chooses green tea", "owen chooses black coffee"],
        &["owen"],
        None,
        handler,
        vec!["{\"value\":\"oolong tea\"}".to_owned()],
        true,
        true,
    )?;
    let native = native_extraction_slice_transcripts(
        &fixture.vault,
        fixture.attempt,
        &fixture.turn_ids,
        &[],
    )?;
    let outcome = extraction::run(extraction::Input {
        client: &fixture.client,
        attempt: &fixture.attempt_hex,
        now_ms: fixture.now_ms,
    })?;
    assert_eq!(outcome.served_turns, 2);
    assert_eq!(outcome.finished_steps, native.len());
    assert!(outcome.people.is_empty());
    assert!(outcome.skipped.is_empty());
    assert_eq!(outcome.components.len(), 1);
    let component = &outcome.components[0];
    assert!(component.representative_index < 2);
    assert_eq!(component.set, Some(0));
    assert!(matches!(
        &component.planned,
        Some(SetPlan::Resolved {
            outcome: ResolvedOutcome::Merge,
            ..
        })
    ));
    assert_eq!(component.view.kind, "conflict_resolution");
    assert!(component.view.landed);
    assert_eq!(component.view.rows.len(), 1);
    assert_eq!(component.view.approval.as_deref(), Some("auto"));
    assert!(component.view.reasons.is_empty());
    assert!(!component.view.batch.is_empty());
    assert_eq!(outcome.already_represented, 0);
    assert_eq!(outcome.held_groups, 0);
    assert_eq!(outcome.retry_at_ms, None);
    assert_eq!(outcome.pending_bindings, 0);
    assert_eq!(outcome.batches, 1);
    assert_eq!(fixture.step_backend.calls(), native.len());
    assert_eq!(fixture.counts.correction(), 0);
    assert_eq!(fixture.counts.resolution(), 1);
    let values = fixture
        .value_backend
        .as_ref()
        .ok_or("the merge attempt multiplexes merged values")?;
    assert_eq!(values.value_calls(), 1);
    let claim = EntityId::from_hex(&component.view.rows[0])?;
    let stored = fixture
        .vault
        .get_claim(&claim)?
        .ok_or("the merged claim reads back")?;
    assert_eq!(stored.value, RmpValue::from("oolong tea"));
    assert_eq!(stored.predicate, "preference.food");
    Ok(())
}

/// A group held for too few citations is not committed; the outcome reports
/// the hold and its retry time.
#[test]
fn a_held_group_commits_nothing_and_reports_its_retry() -> TestResult<()> {
    let handler: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(|transcript: &str| {
        let label = find_person_label(transcript, "owen").expect("owen lists");
        listed_step_reply(&label, "profile.hobby", "tea", "T1", "owen likes tea")
    });
    let fixture = job_fixture(
        &["owen likes tea"],
        &["owen"],
        &[],
        Some((0, 2)),
        handler,
        true,
        true,
    )?;
    let outcome = extraction::run(extraction::Input {
        client: &fixture.client,
        attempt: &fixture.attempt_hex,
        now_ms: fixture.now_ms,
    })?;
    assert_eq!(outcome.served_turns, 1);
    assert_eq!(outcome.finished_steps, 1);
    assert!(outcome.people.is_empty());
    assert!(outcome.skipped.is_empty());
    assert!(outcome.components.is_empty());
    assert_eq!(outcome.already_represented, 0);
    assert_eq!(outcome.held_groups, 1);
    assert_eq!(outcome.retry_at_ms, Some(fixture.now_ms + 60_000));
    assert_eq!(outcome.pending_bindings, 0);
    assert_eq!(outcome.batches, 0);
    assert_eq!(fixture.step_backend.calls(), 1);
    assert_eq!(fixture.counts.correction(), 0);
    assert_eq!(fixture.counts.resolution(), 0);
    Ok(())
}

/// A second run of the same attempt lands nothing new: its candidate item is
/// refused as `candidate_duplicate`.
#[test]
fn a_second_run_refuses_the_candidate_as_a_duplicate() -> TestResult<()> {
    let handler: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(|transcript: &str| {
        let label = find_person_label(transcript, "owen").expect("owen lists");
        listed_step_reply(&label, "profile.hobby", "tea", "T1", "owen likes tea")
    });
    let fixture = job_fixture(
        &["owen likes tea"],
        &["owen"],
        &[],
        None,
        handler,
        true,
        true,
    )?;
    let first = extraction::run(extraction::Input {
        client: &fixture.client,
        attempt: &fixture.attempt_hex,
        now_ms: fixture.now_ms,
    })?;
    assert_eq!(first.served_turns, 1);
    assert_eq!(first.finished_steps, 1);
    assert!(first.people.is_empty());
    assert!(first.skipped.is_empty());
    assert_eq!(first.components.len(), 1);
    assert!(first.components[0].view.landed);
    assert_eq!(first.components[0].view.kind, "candidate");
    assert_eq!(first.batches, 1);
    assert_eq!(fixture.step_backend.calls(), 1);
    let rebound = rebind_same_attempt(&fixture)?;
    let second = extraction::run(extraction::Input {
        client: &rebound,
        attempt: &fixture.attempt_hex,
        now_ms: fixture.now_ms,
    })?;
    assert_eq!(second.served_turns, 1);
    assert_eq!(second.finished_steps, 1);
    assert!(second.people.is_empty());
    assert!(second.skipped.is_empty());
    assert_eq!(second.components.len(), 1);
    let component = &second.components[0];
    assert_eq!(component.representative_index, 0);
    assert_eq!(component.set, None);
    assert!(component.planned.is_none());
    assert_eq!(component.view.kind, "candidate");
    assert!(!component.view.landed);
    assert!(component.view.rows.is_empty());
    assert_eq!(component.view.approval, None);
    assert_eq!(
        component.view.reasons,
        vec!["gate.deny.derive.candidate_duplicate".to_owned()]
    );
    assert!(!component.view.batch.is_empty());
    assert_ne!(first.components[0].view.batch, component.view.batch);
    assert_eq!(second.already_represented, 0);
    assert_eq!(second.held_groups, 0);
    assert_eq!(second.retry_at_ms, None);
    assert_eq!(second.pending_bindings, 0);
    assert_eq!(second.batches, 1);
    Ok(())
}

/// A merged-value call the host refuses to lend opens no marker and commits nothing.
///
/// The gate admits the extraction steps and the Merge resolution, then
/// refuses the next step loan, which is the merged-value step's. The plan
/// answers the client refusal; a refused call does not show an ending native
/// parks a marker for, so no batch is committed and no conflict opens.
#[test]
fn a_refused_merged_value_call_opens_no_marker() -> TestResult<()> {
    let handler: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(support::merge_step_reply);
    let fixture = job_merge_fixture(
        &["owen chooses green tea", "owen chooses black coffee"],
        &["owen"],
        None,
        handler,
        Vec::new(),
        true,
        true,
    )?;
    let native = native_extraction_slice_transcripts(
        &fixture.vault,
        fixture.attempt,
        &fixture.turn_ids,
        &[],
    )?;
    fixture
        .gate
        .step_budget
        .store(native.len(), Ordering::SeqCst);
    let failed = extraction::run(extraction::Input {
        client: &fixture.client,
        attempt: &fixture.attempt_hex,
        now_ms: fixture.now_ms,
    });
    let refused = failed.expect_err("a denied merged-value step fails the plan");
    assert!(matches!(refused, extraction::Error::Plan(_)));
    assert_eq!(refused.code(), Some("MODEL_UNAVAILABLE"));
    assert_eq!(fixture.step_backend.calls(), native.len());
    assert_eq!(fixture.counts.correction(), 0);
    assert_eq!(fixture.counts.resolution(), 1);
    let values = fixture
        .value_backend
        .as_ref()
        .ok_or("the merge attempt multiplexes merged values")?;
    assert_eq!(values.value_calls(), 0);
    let author = dreamer(&fixture.vault)?;
    assert!(fixture.vault.derive_batches_of(author)?.is_empty());
    let memory = fixture.vault.memory(author, EdgeActorClass::System);
    assert!(
        memory
            .open_conflicts(None, Some(fixture.seeded[0]), usize::MAX)?
            .is_empty()
    );
    Ok(())
}

/// A merged-value step that fails opens its set's marker and lands nothing else.
///
/// The verdict backend answers the Merge resolution and then fails the
/// merged-value generation with a fatal model error. The step answers a
/// `failed` result of a class native's pass parks the set's open marker for,
/// so the job commits that one `conflict` item and answers the step's error.
#[test]
fn a_failed_merged_value_step_opens_the_set_s_marker() -> TestResult<()> {
    let handler: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(support::merge_step_reply);
    let fixture = job_merge_fixture(
        &["owen chooses green tea", "owen chooses black coffee"],
        &["owen"],
        None,
        handler,
        Vec::new(),
        true,
        true,
    )?;
    let values = fixture
        .value_backend
        .as_ref()
        .ok_or("the merge attempt multiplexes merged values")?;
    values.value_refusing.store(true, Ordering::SeqCst);
    let failed = extraction::run(extraction::Input {
        client: &fixture.client,
        attempt: &fixture.attempt_hex,
        now_ms: fixture.now_ms,
    });
    let refused = failed.expect_err("a failed merged-value step fails the plan");
    let extraction::Error::SetFailed { error, marker } = &refused else {
        panic!("the failed step names its set's marker: {refused:?}");
    };
    let conflict_resolution::Error::Step { set, status, .. } = error else {
        panic!("the plan answers the failed step: {error:?}");
    };
    assert_eq!((*set, status.as_str()), (0, "failed"));
    assert_eq!(error.failed_set_marker(), Some(0));
    assert_eq!(marker.kind, "conflict");
    assert!(marker.landed, "the marker lands: {:?}", marker.reasons);
    assert_eq!(fixture.counts.resolution(), 1);
    assert!(values.value_refused_calls.load(Ordering::SeqCst) > 0);
    assert_eq!(values.value_calls(), 0);
    let author = dreamer(&fixture.vault)?;
    let batches = fixture.vault.derive_batches_of(author)?;
    assert_eq!(batches.len(), 1, "only the marker's batch commits");
    assert_eq!(batches[0], EntityId::from_hex(&marker.batch)?);
    let record = fixture
        .vault
        .derive_batch(batches[0])?
        .ok_or("the marker batch records")?;
    assert_eq!(record.items.len(), 1);
    assert_eq!(record.items[0].kind, "conflict");
    assert!(record.items[0].landed);
    let memory = fixture.vault.memory(author, EdgeActorClass::System);
    let open = memory.open_conflicts(None, Some(fixture.seeded[0]), usize::MAX)?;
    assert_eq!(open.len(), 1, "the set's conflict waits open");
    Ok(())
}
