//! The bound extraction step shows the listing its native slice shows, names its layout, and
//! skips an unbound quote by native's correctable rule.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test extraction_step_listing`.
#![cfg(oneiron_test_support)]

#[path = "extraction_steps/support.rs"]
mod step_support;

use std::sync::Arc;

use oneiron::dreamer_runner::{DreamerAdmittedAttempt, DreamerAttemptBinding};
use oneiron::memory::{ExtractionLayout, ExtractionStepSlice, MEMORY_CODE_BAD_REQUEST};
use oneiron::test_doors::extraction_inputs::{
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::extraction_steps::{
    ExtractionStepFixture, NativeExtractionSlice, attach_extraction_step_lender,
    extraction_step_state_present, native_extraction_slice_transcripts,
};
use oneiron::test_doors::extraction_verdict::land_extraction_verdict_listing_claim;
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{AttemptId, EntityId, Vault};
use serde_json::{Value, json};
use step_support::{
    CapturingStepBackend, ExtractionStepTestResult, QUEUE_NOW, bind_extraction,
    extraction_attempt_hex, extraction_step_evidence, extraction_step_request, invoke_bound_step,
    open_extraction_step_vault, page_turns_with_versions, read_bound_extraction_page,
    step_plain_reply,
};

/// One bound step attempt over witnessed turns with its served page already read.
struct ListingFixture {
    /// Owns the temporary directory for the lifetime of the bound attempt.
    _directory: tempfile::TempDir,
    /// Holds the vault the native door reads beside the bound binding.
    vault: Arc<Vault>,
    /// Holds the admitted attempt id the native door prepares.
    attempt: AttemptId,
    /// Holds the admission both bindings bind from.
    admitted: DreamerAdmittedAttempt,
    /// Holds the queued turns in witness order.
    turn_ids: Vec<EntityId>,
    /// Holds the served turn refs with their pinned versions in page order.
    turns: Vec<(String, Value)>,
}

/// Opens a vault with its steward grant standing, like the step tests do.
fn open_listing_vault(directory: &tempfile::TempDir) -> ExtractionStepTestResult<Arc<Vault>> {
    let vault = Arc::new(open_extraction_step_vault(directory)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    Ok(vault)
}

/// Lands one `profile.name` claim about owen, witnesses `words`, and admits one Meso attempt
/// over the witnessed turns, reading the served page through a plain binding.
fn listing_fixture(
    words: &[&str],
) -> ExtractionStepTestResult<(ListingFixture, EntityId, EntityId)> {
    let directory = tempfile::tempdir()?;
    let vault = open_listing_vault(&directory)?;
    let (subject, claim) = land_extraction_verdict_listing_claim(&vault)?;
    let witnessed = witness_extraction_turns(&vault, words)?;
    let (attempt, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), words.len());
    Ok((
        ListingFixture {
            _directory: directory,
            vault,
            attempt,
            admitted,
            turn_ids: witnessed.turns,
            turns,
        },
        subject,
        claim,
    ))
}

/// Seeds `seeds` persons named owen, witnesses `words`, and admits one Meso attempt over the
/// witnessed turns, reading the served page through a plain binding.
fn paging_fixture(words: &[&str], seeds: usize) -> ExtractionStepTestResult<ListingFixture> {
    let directory = tempfile::tempdir()?;
    let vault = open_listing_vault(&directory)?;
    for _ in 0..seeds {
        let id = EntityId::now();
        seed_named_person(&vault, &id, "owen", vault.now_recorded_at())?;
    }
    let witnessed = witness_extraction_turns(&vault, words)?;
    let (attempt, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), words.len());
    Ok(ListingFixture {
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
    fixture: &ListingFixture,
    step: &Arc<ExtractionStepFixture>,
) -> ExtractionStepTestResult<DreamerAttemptBinding> {
    Ok(attach_extraction_step_lender(
        bind_extraction(&fixture.vault, &fixture.admitted)?,
        step,
    ))
}

/// Builds one extraction reply naming the listed `subject` label with one `quote`.
fn listed_reply(subject: &str, quote: &str) -> String {
    json!({
        "persons": [],
        "candidates": [{
            "subject": subject,
            "predicate": "likes",
            "value": "tea",
            "confidence": 0.9,
            "evidence_refs": [{"source": "T1", "quote": quote}],
        }],
    })
    .to_string()
}

/// Builds one step request over `evidence`, naming `page` when one is given.
fn paged_step_request(evidence: Value, page: Option<usize>) -> Value {
    let mut request = extraction_step_request(evidence);
    if let Some(page) = page {
        request["page"] = json!(page);
    }
    request
}

/// Maps each native slice to its turns' positions in `turns`, in native slice order.
fn slice_evidence_positions(
    native: &[NativeExtractionSlice],
    turns: &[(String, Value)],
) -> Vec<Vec<usize>> {
    native
        .iter()
        .map(|slice| {
            slice
                .turns
                .iter()
                .map(|turn| {
                    turns
                        .iter()
                        .position(|(named, _)| named == &turn.to_hex())
                        .unwrap_or_else(|| panic!("a native slice turn is a cited turn"))
                })
                .collect()
        })
        .collect()
}

/// One listed claim renders beside its entity, and a reply naming that entity's label decodes
/// to its listed id: the request carries the author's bare line, owen's named line and the
/// profile claim line, and the finished reply's subject is the landed subject.
#[test]
fn a_bound_step_lists_native_entities_and_decodes_a_listed_subject() -> ExtractionStepTestResult<()>
{
    let (fixture, subject, _claim) = listing_fixture(&["owen likes tea"])?;
    let backend = Arc::new(CapturingStepBackend::new(
        listed_reply("P2", "owen likes tea"),
        100,
        50,
    ));
    let step = ExtractionStepFixture::new(backend.clone())?;
    let binding = lent_binding(&fixture, &step)?;
    let (turn, version) = &fixture.turns[0];
    let request = extraction_step_request(json!([extraction_step_evidence(
        turn,
        version.clone(),
        None
    ),]));
    let submit = invoke_bound_step(&binding, request).expect("the listed step finishes");
    assert_eq!(submit["result"]["status"], json!("finished"));
    let decoded = &submit["result"]["json"];
    assert_eq!(decoded["skipped"], json!([]));
    assert_eq!(
        decoded["candidates"][0]["subject"],
        json!({"listed": subject.to_hex()})
    );
    assert_eq!(
        decoded["candidates"][0]["evidence"],
        json!([{"turn": turn, "version": version, "span": {"start": 0, "end": 14}}])
    );
    let texts = backend.request_texts();
    assert_eq!(texts.len(), 1);
    assert!(
        texts[0].contains("conversation V1\n"),
        "the cited conversation heads the request: {}",
        texts[0]
    );
    assert!(
        texts[0].contains("entity P1\n"),
        "the turn author lists first with no name: {}",
        texts[0]
    );
    assert!(
        texts[0].contains("entity P2 \"owen\"\n"),
        "owen lists second by name: {}",
        texts[0]
    );
    assert!(
        texts[0].contains("  claim C1 profile.name = \"owen\"\n"),
        "the profile claim lists under owen: {}",
        texts[0]
    );
    assert!(
        texts[0].contains("[T1 user"),
        "the cited turn keeps its speaker: {}",
        texts[0]
    );
    assert!(
        texts[0].contains("owen likes tea"),
        "the cited words render: {}",
        texts[0]
    );
    Ok(())
}

/// The bound transcript over one cited turn is byte-identical to its native slice transcript:
/// the same conversation header, listing lines and turn line, with no host material on either.
#[test]
fn a_bound_step_transcript_equals_its_native_slice() -> ExtractionStepTestResult<()> {
    let (fixture, _subject, _claim) = listing_fixture(&["owen likes tea"])?;
    let material: Vec<String> = Vec::new();
    let native = native_extraction_slice_transcripts(
        &fixture.vault,
        fixture.attempt,
        &fixture.turn_ids,
        &material,
    )?;
    assert_eq!(native.len(), 1);
    assert!(
        native[0].transcript.contains("entity P2 \"owen\"\n"),
        "the native slice lists owen: {}",
        native[0].transcript
    );
    let backend = Arc::new(CapturingStepBackend::new(step_plain_reply(), 100, 50));
    let step = ExtractionStepFixture::new(backend.clone())?;
    let binding = lent_binding(&fixture, &step)?;
    let (turn, version) = &fixture.turns[0];
    let request = extraction_step_request(json!([extraction_step_evidence(
        turn,
        version.clone(),
        None
    ),]));
    let submit = invoke_bound_step(&binding, request).expect("the listed step finishes");
    assert_eq!(submit["result"]["status"], json!("finished"));
    let transcripts = backend.request_transcripts();
    assert_eq!(transcripts.len(), 1);
    assert_eq!(
        transcripts[0], native[0].transcript,
        "the bound user transcript equals its native slice transcript"
    );
    Ok(())
}

/// Two host materials prefix both transcripts with the same lines, and the material moves the
/// request hash: the material submit generates again under a new step ref, then replays its memo.
#[test]
fn host_material_prefixes_both_transcripts_and_moves_the_request_hash()
-> ExtractionStepTestResult<()> {
    let (fixture, _subject, _claim) = listing_fixture(&["owen likes tea"])?;
    let backend = Arc::new(CapturingStepBackend::scripted(
        vec![step_plain_reply(), step_plain_reply()],
        100,
        50,
    ));
    let step = ExtractionStepFixture::new(backend.clone())?;
    let binding = lent_binding(&fixture, &step)?;
    let (turn, version) = &fixture.turns[0];
    let request = extraction_step_request(json!([extraction_step_evidence(
        turn,
        version.clone(),
        None
    ),]));
    let plain = invoke_bound_step(&binding, request.clone()).expect("the plain step finishes");
    let plain_ref = plain["step_ref"]
        .as_str()
        .expect("the plain submit answers its step ref")
        .to_owned();
    let no_material: Vec<String> = Vec::new();
    let native_plain = native_extraction_slice_transcripts(
        &fixture.vault,
        fixture.attempt,
        &fixture.turn_ids,
        &no_material,
    )?;
    assert_eq!(native_plain.len(), 1);
    let transcripts = backend.request_transcripts();
    assert_eq!(transcripts.len(), 1);
    assert_eq!(
        transcripts[0], native_plain[0].transcript,
        "the plain bound user transcript equals its native transcript"
    );
    assert!(
        !transcripts[0].contains("[host material]"),
        "no held material renders no material line: {}",
        transcripts[0]
    );
    let material = vec![
        "first host material".to_owned(),
        "second host material".to_owned(),
    ];
    step.set_hook_material(material.clone());
    let native_held = native_extraction_slice_transcripts(
        &fixture.vault,
        fixture.attempt,
        &fixture.turn_ids,
        &material,
    )?;
    assert_eq!(native_held.len(), 1);
    let held = invoke_bound_step(&binding, request.clone()).expect("the held step finishes");
    let held_ref = held["step_ref"]
        .as_str()
        .expect("the held submit answers its step ref")
        .to_owned();
    assert_ne!(held_ref, plain_ref);
    assert_eq!(backend.call_count(), 2);
    let transcripts = backend.request_transcripts();
    assert_eq!(transcripts.len(), 2);
    assert_eq!(
        transcripts[1], native_held[0].transcript,
        "the held bound user transcript equals its native transcript"
    );
    assert!(
        transcripts[1].contains(
            "[host material] first host material\n[host material] second host material\n"
        ),
        "both held materials prefix the bound transcript in order: {}",
        transcripts[1]
    );
    assert!(
        native_held[0].transcript.starts_with(
            "[host material] first host material\n[host material] second host material\n"
        ),
        "both held materials prefix the native transcript in order: {}",
        native_held[0].transcript
    );
    let again = invoke_bound_step(&binding, request).expect("the held step replays its memo");
    assert_eq!(again["result"]["memoized"], json!(true));
    assert_eq!(again["result"]["json"], held["result"]["json"]);
    assert_eq!(backend.call_count(), 2);
    Ok(())
}

/// An unbound quote about a correctable listed subject skips that candidate instead of refusing:
/// the submit finishes with no candidates, one skip naming the quote fault and the correctable
/// rule, and no fabricated evidence, and its memo agrees.
#[test]
fn an_unbound_quote_about_a_correctable_listed_subject_is_skipped() -> ExtractionStepTestResult<()>
{
    let (fixture, _subject, _claim) = listing_fixture(&["owen likes tea"])?;
    let backend = Arc::new(CapturingStepBackend::new(
        listed_reply("P2", "owen likes coffee"),
        100,
        50,
    ));
    let step = ExtractionStepFixture::new(backend.clone())?;
    let binding = lent_binding(&fixture, &step)?;
    let (turn, version) = &fixture.turns[0];
    let request = extraction_step_request(json!([extraction_step_evidence(
        turn,
        version.clone(),
        None
    ),]));
    let submit = invoke_bound_step(&binding, request.clone()).expect("the skipped step finishes");
    assert_eq!(submit["result"]["status"], json!("finished"));
    assert_eq!(submit["result"]["memoized"], json!(false));
    let decoded = &submit["result"]["json"];
    assert_eq!(decoded["candidates"], json!([]));
    let skipped = decoded["skipped"]
        .as_array()
        .expect("the finished reply carries its skips");
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0]["index"], json!(0));
    let reason = skipped[0]["reason"]
        .as_str()
        .expect("the skip carries its reason");
    assert!(
        reason.contains("QuoteNotFound"),
        "the skip names its quote fault: {reason}"
    );
    assert!(
        reason.contains("correctable"),
        "the skip names its correctable rule: {reason}"
    );
    assert!(
        skipped[0].get("evidence").is_none(),
        "a skip fabricates no span: {reason}"
    );
    let again = invoke_bound_step(&binding, request).expect("the skipped step replays its memo");
    assert_eq!(again["result"]["memoized"], json!(true));
    assert_eq!(again["result"]["json"], *decoded);
    assert_eq!(backend.call_count(), 1);
    Ok(())
}

/// An unbound quote about a listed subject with no correctable claim still refuses: the turn
/// author's bare entity line lists it, but nothing corrects it, so the submit fails naming the
/// quote outside its source.
#[test]
fn an_unbound_quote_about_a_non_correctable_listed_subject_still_refuses()
-> ExtractionStepTestResult<()> {
    let (fixture, _subject, _claim) = listing_fixture(&["owen likes tea"])?;
    let backend = Arc::new(CapturingStepBackend::new(
        listed_reply("P1", "owen likes coffee"),
        100,
        50,
    ));
    let step = ExtractionStepFixture::new(backend.clone())?;
    let binding = lent_binding(&fixture, &step)?;
    let (turn, version) = &fixture.turns[0];
    let request = extraction_step_request(json!([extraction_step_evidence(
        turn,
        version.clone(),
        None
    ),]));
    let refused = invoke_bound_step(&binding, request)?;
    assert_eq!(refused["result"]["status"], json!("failed"));
    let message = refused["result"]["failure"]["message"]
        .as_str()
        .expect("the failed submit carries its failure message");
    assert!(
        message.contains("cites outside its source"),
        "a non-correctable listed subject still refuses: {message}"
    );
    Ok(())
}

/// A two-page listing cited without a page refuses before any generation with its typed layout:
/// one slice over the cited evidence with two pages, read from the typed field, never the message.
#[test]
fn a_two_page_listing_cited_without_a_page_refuses_with_its_layout() -> ExtractionStepTestResult<()>
{
    let fixture = paging_fixture(&["owen likes tea"], 90)?;
    let material: Vec<String> = Vec::new();
    let native = native_extraction_slice_transcripts(
        &fixture.vault,
        fixture.attempt,
        &fixture.turn_ids,
        &material,
    )?;
    assert_eq!(native.len(), 2);
    let backend = Arc::new(CapturingStepBackend::new(step_plain_reply(), 100, 50));
    let step = ExtractionStepFixture::new(backend.clone())?;
    let binding = lent_binding(&fixture, &step)?;
    let (turn, version) = &fixture.turns[0];
    let request = paged_step_request(
        json!([extraction_step_evidence(turn, version.clone(), None)]),
        None,
    );
    let Err(refused) = invoke_bound_step(&binding, request) else {
        panic!("a two-page cite without a page refuses");
    };
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(
        refused.extraction_layout,
        Some(Box::new(ExtractionLayout::StepSlices {
            slices: vec![ExtractionStepSlice {
                evidence: vec![0],
                pages: 2
            }],
        }))
    );
    assert_eq!(backend.call_count(), 0);
    assert!(!extraction_step_state_present(
        &fixture.vault,
        fixture.attempt
    )?);
    Ok(())
}

/// Each named page of a two-page listing finishes with exactly that page's lines: page zero
/// renders the author's bare line, page one does not, and each bound transcript equals its
/// native page transcript under its own step ref.
#[test]
fn each_named_page_of_a_two_page_listing_renders_its_page() -> ExtractionStepTestResult<()> {
    let fixture = paging_fixture(&["owen likes tea"], 90)?;
    let material: Vec<String> = Vec::new();
    let native = native_extraction_slice_transcripts(
        &fixture.vault,
        fixture.attempt,
        &fixture.turn_ids,
        &material,
    )?;
    assert_eq!(native.len(), 2);
    assert!(
        native[0].transcript.contains("entity P1\n"),
        "page zero opens with the bare author line: {}",
        native[0].transcript
    );
    assert!(
        !native[1].transcript.contains("entity P1\n"),
        "page one holds only named owens: {}",
        native[1].transcript
    );
    let backend = Arc::new(CapturingStepBackend::scripted(
        vec![step_plain_reply(), step_plain_reply()],
        100,
        50,
    ));
    let step = ExtractionStepFixture::new(backend.clone())?;
    let binding = lent_binding(&fixture, &step)?;
    let (turn, version) = &fixture.turns[0];
    let evidence = json!([extraction_step_evidence(turn, version.clone(), None)]);
    let first = invoke_bound_step(&binding, paged_step_request(evidence.clone(), Some(0)))
        .expect("page zero finishes");
    assert_eq!(first["result"]["status"], json!("finished"));
    let first_ref = first["step_ref"]
        .as_str()
        .expect("page zero answers its step ref")
        .to_owned();
    let second = invoke_bound_step(&binding, paged_step_request(evidence, Some(1)))
        .expect("page one finishes");
    assert_eq!(second["result"]["status"], json!("finished"));
    let second_ref = second["step_ref"]
        .as_str()
        .expect("page one answers its step ref")
        .to_owned();
    assert_ne!(first_ref, second_ref);
    assert_eq!(backend.call_count(), 2);
    let transcripts = backend.request_transcripts();
    assert_eq!(transcripts.len(), 2);
    assert_eq!(
        transcripts[0], native[0].transcript,
        "the page zero user transcript equals its native page transcript"
    );
    assert_eq!(
        transcripts[1], native[1].transcript,
        "the page one user transcript equals its native page transcript"
    );
    Ok(())
}

/// A cite across two native slices refuses with both slices in native order, each naming its
/// cited evidence positions: the expected order comes from the native door, never regrouped here.
#[test]
fn a_cite_across_two_slices_refuses_naming_both_in_native_order() -> ExtractionStepTestResult<()> {
    let (fixture, _subject, _claim) = listing_fixture(&["owen likes tea", "yuki likes tea"])?;
    assert_eq!(fixture.turns.len(), 2);
    let material: Vec<String> = Vec::new();
    let native = native_extraction_slice_transcripts(
        &fixture.vault,
        fixture.attempt,
        &fixture.turn_ids,
        &material,
    )?;
    assert_eq!(native.len(), 2);
    let backend = Arc::new(CapturingStepBackend::new(step_plain_reply(), 100, 50));
    let step = ExtractionStepFixture::new(backend.clone())?;
    let binding = lent_binding(&fixture, &step)?;
    let (first_turn, first_version) = &fixture.turns[0];
    let (second_turn, second_version) = &fixture.turns[1];
    let request = extraction_step_request(json!([
        extraction_step_evidence(first_turn, first_version.clone(), None),
        extraction_step_evidence(second_turn, second_version.clone(), None),
    ]));
    let Err(refused) = invoke_bound_step(&binding, request) else {
        panic!("a two-slice cite refuses");
    };
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST);
    let positions = slice_evidence_positions(&native, &fixture.turns);
    assert_eq!(positions.len(), 2);
    let expected = positions
        .into_iter()
        .map(|evidence| ExtractionStepSlice { evidence, pages: 1 })
        .collect::<Vec<_>>();
    assert_eq!(
        refused.extraction_layout,
        Some(Box::new(ExtractionLayout::StepSlices { slices: expected }))
    );
    assert_eq!(backend.call_count(), 0);
    Ok(())
}
