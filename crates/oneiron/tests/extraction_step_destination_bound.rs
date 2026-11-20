//! A lent extraction step lists for the destination bound of the pass that lends it (FIX row
//! BOUND-STEP-LISTING-DESTINATION). A driven pass reads its wake's listings for the bound its
//! executors stated (FIX 12735). The lent step rebuilt the same listing for a destination nobody
//! proved, whatever the pass stated, so it could list other rows than the pass's native
//! extraction lists.
//!
//! The fixture is a named PERSON with one relationship membership whose backing claim sits in a
//! world the owner keeps on this machine. A listing read for this device shows the membership
//! as a `relationship R1` line; a listing read for a destination nobody proved does not. Before
//! the fix the first test fails: the lent request renders the listing that native renders with
//! no bound stated.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test extraction_step_destination_bound`.
#![cfg(oneiron_test_support)]

#[path = "extraction_steps/support.rs"]
mod step_support;

use std::sync::Arc;

use oneiron::claim::relationship_predicates::PREDICATE_RELATIONSHIP_PERSON_REF;
use oneiron::dreamer_runner::{DreamerAdmittedAttempt, DreamerAttemptBinding};
use oneiron::registry::{ENTITY_TYPE_RELATIONSHIP, ENTITY_TYPE_WORLD};
use oneiron::settings::ReadDestination;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::extraction_inputs::{
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::extraction_steps::{
    ExtractionStepFixture, attach_extraction_step_lender, native_extraction_slice_transcripts,
    native_extraction_slice_transcripts_for_bound,
};
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{
    AttemptId, ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, Vault,
};
use serde_json::{Value, json};
use step_support::{
    CapturingStepBackend, ExtractionStepTestResult, QUEUE_NOW, bind_extraction,
    extraction_attempt_hex, extraction_step_evidence, extraction_step_request, invoke_bound_step,
    invoke_bound_step_receipt, open_extraction_step_vault, page_turns_with_versions,
    read_bound_extraction_page, step_plain_reply,
};

/// The line a listing page leads with for the one relationship the fixture's PERSON is a member
/// of.
const MEMBERSHIP_LINE: &str = "relationship R1\n";

/// One admitted attempt over one witnessed turn that names owen, whose one relationship
/// membership is backed by a claim in a world kept on this machine.
struct KeptWorldFixture {
    /// Owns the temporary directory for the lifetime of the bound attempt.
    _directory: tempfile::TempDir,
    /// Holds the vault the native door reads beside the bound binding.
    vault: Arc<Vault>,
    /// Holds the admitted attempt id the native door prepares.
    attempt: AttemptId,
    /// Holds the admission each binding binds from.
    admitted: DreamerAdmittedAttempt,
    /// Holds the queued turns in witness order.
    turn_ids: Vec<EntityId>,
    /// Holds the served turn refs with their pinned versions in page order.
    turns: Vec<(String, Value)>,
}

/// Seeds owen, a relationship he is a member of by a claim in a world of its own, keeps that
/// world on this machine as its owner does, witnesses one turn that names owen, and admits one
/// Meso attempt over it.
fn kept_world_fixture() -> ExtractionStepTestResult<KeptWorldFixture> {
    let directory = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_step_vault(&directory)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let at = TimeRange { start: 1, end: 1 };
    let owen = EntityId::now();
    seed_named_person(&vault, &owen, "owen", vault.now_recorded_at())?;
    let (world, relationship) = (EntityId::now(), EntityId::now());
    vault.put_entity(&world, ENTITY_TYPE_WORLD, at, 1, b"world")?;
    vault.put_entity(
        &relationship,
        ENTITY_TYPE_RELATIONSHIP,
        at,
        1,
        b"relationship",
    )?;
    let mut membership = ClaimBody::new(
        PREDICATE_RELATIONSHIP_PERSON_REF,
        ClaimSubject::Entity(relationship),
        rmpv::Value::from(owen.to_hex()),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    // A RELATIONSHIP subject has no FACET of its own: the claim takes the vault default facet,
    // as the engine's own relationship writer stamps it.
    membership.scope_facet = vault.default_facet()?;
    membership.world = Some(world);
    vault.put_claim(&EntityId::now(), &membership, at, 1)?;
    vault.keep_world_on_this_machine_for_test(world, true)?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea"])?;
    let (attempt, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 1);
    Ok(KeptWorldFixture {
        _directory: directory,
        vault,
        attempt,
        admitted,
        turn_ids: witnessed.turns,
        turns,
    })
}

/// Binds the admitted attempt and lends the step fixture's resources to the binding.
fn lent_binding(
    fixture: &KeptWorldFixture,
    step: &Arc<ExtractionStepFixture>,
) -> ExtractionStepTestResult<DreamerAttemptBinding> {
    Ok(attach_extraction_step_lender(
        bind_extraction(&fixture.vault, &fixture.admitted)?,
        step,
    ))
}

/// Builds the step request over the fixture's one served turn.
fn one_turn_request(fixture: &KeptWorldFixture) -> Value {
    let (turn, version) = &fixture.turns[0];
    extraction_step_request(json!([extraction_step_evidence(
        turn,
        version.clone(),
        None
    ),]))
}

/// A lent step whose lender states the pass's bound lists what the pass's native extraction
/// lists for that bound. The pass here runs on this device, so its listing shows the membership
/// a kept world backs; the lent transcript equals that native transcript byte for byte. The
/// native transcript for no stated bound is the control: it differs, and it leaves the
/// membership out.
#[test]
fn a_lent_step_lists_for_the_destination_bound_its_lender_states() -> ExtractionStepTestResult<()> {
    let fixture = kept_world_fixture()?;
    let on_device = ReadDestination::on_device();
    let material: Vec<String> = Vec::new();
    let native_bound = native_extraction_slice_transcripts_for_bound(
        &fixture.vault,
        fixture.attempt,
        &fixture.turn_ids,
        &material,
        Some(&on_device),
    )?;
    let native_plain = native_extraction_slice_transcripts(
        &fixture.vault,
        fixture.attempt,
        &fixture.turn_ids,
        &material,
    )?;
    assert_eq!(native_bound.len(), 1);
    assert_eq!(native_plain.len(), 1);
    assert!(
        native_bound[0].transcript.contains("entity P2 \"owen\"\n"),
        "the native slice lists owen: {}",
        native_bound[0].transcript
    );
    assert!(
        native_bound[0].transcript.contains(MEMBERSHIP_LINE),
        "a wake that lists for this device shows the membership a kept world backs: {}",
        native_bound[0].transcript
    );
    assert!(
        !native_plain[0].transcript.contains(MEMBERSHIP_LINE),
        "a wake that lists for a destination nobody proved leaves that membership out: {}",
        native_plain[0].transcript
    );
    let backend = Arc::new(CapturingStepBackend::new(step_plain_reply(), 100, 50));
    let step = ExtractionStepFixture::new(backend.clone())?;
    step.set_destination_bound(Some(on_device));
    let binding = lent_binding(&fixture, &step)?;
    let submit =
        invoke_bound_step(&binding, one_turn_request(&fixture)).expect("the lent step finishes");
    assert_eq!(submit["result"]["status"], json!("finished"));
    assert_eq!(backend.call_count(), 1);
    let transcripts = backend.request_transcripts();
    assert_eq!(transcripts.len(), 1);
    assert_eq!(
        transcripts[0], native_bound[0].transcript,
        "the lent transcript equals the native transcript for the bound the pass stated"
    );
    Ok(())
}

/// A lender that states no bound changes nothing: the lent step lists for a destination nobody
/// proved, as a direct native execution does, the membership a kept world backs stays out of
/// its request, and its receipt answers.
#[test]
fn a_lent_step_with_no_stated_bound_lists_for_a_destination_nobody_proved()
-> ExtractionStepTestResult<()> {
    let fixture = kept_world_fixture()?;
    let material: Vec<String> = Vec::new();
    let native_plain = native_extraction_slice_transcripts(
        &fixture.vault,
        fixture.attempt,
        &fixture.turn_ids,
        &material,
    )?;
    assert_eq!(native_plain.len(), 1);
    let backend = Arc::new(CapturingStepBackend::new(step_plain_reply(), 100, 50));
    let step = ExtractionStepFixture::new(backend.clone())?;
    let binding = lent_binding(&fixture, &step)?;
    let submit =
        invoke_bound_step(&binding, one_turn_request(&fixture)).expect("the lent step finishes");
    assert_eq!(submit["result"]["status"], json!("finished"));
    assert_eq!(backend.request_texts().len(), 1);
    let transcripts = backend.request_transcripts();
    assert_eq!(transcripts.len(), 1);
    assert!(
        !transcripts[0].contains(MEMBERSHIP_LINE),
        "no stated bound keeps the kept world's membership out of the request: {}",
        transcripts[0]
    );
    assert_eq!(
        transcripts[0], native_plain[0].transcript,
        "the lent transcript equals the native transcript for no stated bound"
    );
    let step_ref = submit["step_ref"]
        .as_str()
        .expect("the submit answers its step ref");
    let served =
        invoke_bound_step_receipt(&binding, step_ref).expect("the receipt answers while it reads");
    assert_eq!(served["result"]["status"], json!("finished"));
    Ok(())
}
