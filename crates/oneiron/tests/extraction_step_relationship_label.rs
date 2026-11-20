//! A lent extraction step reads the relationship a candidate names back to its id, as the
//! native reply reader does (FIX row LENT-REPLY-RELATIONSHIP-LABEL-NOT-READ-BACK). The request
//! lists each relationship a claim may hold within as a `relationship R<n>` line, and the prompt
//! asks for that label in `rel`. The step kept `rel` as the model wrote it, so the job could
//! not pass it on.
//!
//! The fixture is the one of `tests/extraction_step_destination_bound.rs`: a named PERSON with
//! one relationship membership whose backing claim sits in a world the owner keeps on this
//! machine, listed for this device, so the request leads with `relationship R1`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test extraction_step_relationship_label`.
#![cfg(oneiron_test_support)]

#[path = "extraction_steps/support.rs"]
mod step_support;

use std::sync::Arc;

use oneiron::claim::relationship_predicates::PREDICATE_RELATIONSHIP_PERSON_REF;
use oneiron::dreamer_runner::DreamerAttemptBinding;
use oneiron::memory::MemoryResult;
use oneiron::registry::{ENTITY_TYPE_RELATIONSHIP, ENTITY_TYPE_WORLD};
use oneiron::settings::ReadDestination;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::extraction_inputs::{
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::extraction_steps::{ExtractionStepFixture, attach_extraction_step_lender};
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, Vault,
};
use serde_json::{Value, json};
use step_support::{
    CapturingStepBackend, ExtractionStepTestResult, QUEUE_NOW, bind_extraction,
    extraction_attempt_hex, extraction_step_evidence, extraction_step_request, invoke_bound_step,
    open_extraction_step_vault, page_turns_with_versions, read_bound_extraction_page,
};

/// The predicate every candidate here proposes.
const FOOD: &str = "preference.food";

/// The words of the one witnessed turn, which name owen.
const WORDS: &str = "owen likes tea";

/// A quote the witnessed turn does not hold.
const WORDS_NOT_SERVED: &str = "owen likes coffee";

/// A relationship label the request does not list: it lists one relationship.
const UNLISTED_LABEL: &str = "R9";

/// One lent step attempt over one witnessed turn that names owen, who is a member of one
/// relationship the request lists, with one scripted reply.
struct RelationshipFixture {
    /// Owns the temporary directory for the lifetime of the bound attempt.
    _directory: tempfile::TempDir,
    /// Keeps the vault open beside the binding.
    _vault: Arc<Vault>,
    /// Holds the live extraction binding with its loan attached.
    binding: DreamerAttemptBinding,
    /// Names the one served turn.
    turn: String,
    /// Holds the served turn's pinned version.
    turn_version: Value,
    /// Names the one relationship owen is a member of.
    relationship: EntityId,
    /// Captures the requests that reached the scripted backend.
    backend: Arc<CapturingStepBackend>,
    /// Keeps the lent step resources alive beside the binding.
    _step: Arc<ExtractionStepFixture>,
}

/// Seeds owen, a relationship he is a member of by a claim in a world kept on this machine,
/// witnesses the turn, and lends one step that lists for this device and whose model answers
/// what `reply` builds from the relationship's id.
fn relationship_fixture(
    reply: impl FnOnce(EntityId) -> String,
) -> ExtractionStepTestResult<RelationshipFixture> {
    let directory = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_step_vault(&directory)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
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
    // The membership recipe of `tests/extraction_step_destination_bound.rs`: an Auto claim on
    // the vault default facet, in a world of its own that the owner keeps on this machine.
    let mut membership = ClaimBody::new(
        PREDICATE_RELATIONSHIP_PERSON_REF,
        ClaimSubject::Entity(relationship),
        rmpv::Value::from(owen.to_hex()),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    membership.scope_facet = vault.default_facet()?;
    membership.world = Some(world);
    vault.put_claim(&EntityId::now(), &membership, at, 1)?;
    vault.keep_world_on_this_machine_for_test(world, true)?;
    let witnessed = witness_extraction_turns(&vault, &[WORDS])?;
    let (attempt, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt))?;
    let mut turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 1, "the inputs page serves the one turn");
    let (turn, turn_version) = turns.remove(0);
    let backend = Arc::new(CapturingStepBackend::new(reply(relationship), 100, 50));
    let step = ExtractionStepFixture::new(backend.clone())?;
    step.set_destination_bound(Some(ReadDestination::on_device()));
    let binding = attach_extraction_step_lender(binding, &step);
    Ok(RelationshipFixture {
        _directory: directory,
        _vault: vault,
        binding,
        turn,
        turn_version,
        relationship,
        backend,
        _step: step,
    })
}

impl RelationshipFixture {
    /// Submits the one step over the whole served turn.
    fn submit(&self) -> MemoryResult<Value> {
        invoke_bound_step(
            &self.binding,
            extraction_step_request(json!([extraction_step_evidence(
                &self.turn,
                self.turn_version.clone(),
                None
            )])),
        )
    }

    /// Checks that the one request lists the relationship as `R1` and owen as `P2`. Every
    /// reply here names those labels.
    fn assert_listed(&self) {
        let texts = self.backend.request_texts();
        assert_eq!(texts.len(), 1, "the step asks its model once");
        assert!(
            texts[0].contains("relationship R1\n"),
            "the request lists the relationship as R1: {}",
            texts[0]
        );
        assert!(
            texts[0].contains("entity P2 \"owen\"\n"),
            "the request lists owen as P2: {}",
            texts[0]
        );
    }
}

/// Builds one extraction reply with one candidate about owen (`P2`) that names `rel` and
/// quotes `quote` from the turn.
fn reply_naming(rel: &str, quote: &str) -> String {
    json!({
        "persons": [],
        "candidates": [{
            "subject": "P2",
            "predicate": FOOD,
            "value": "tea",
            "confidence": 0.9,
            "rel": rel,
            "evidence_refs": [{"source": "T1", "quote": quote}],
        }],
    })
    .to_string()
}

/// A candidate that names the listed relationship by its label is kept, and carries the
/// relationship's id as a one-item list, the form the verdict operand takes.
#[test]
fn a_listed_relationship_label_decodes_to_the_relationship_id() -> ExtractionStepTestResult<()> {
    let fixture = relationship_fixture(|_| reply_naming("R1", WORDS))?;
    let submit = fixture.submit()?;
    fixture.assert_listed();
    assert_eq!(submit["result"]["status"], json!("finished"));
    let decoded = &submit["result"]["json"];
    assert_eq!(
        decoded["skipped"],
        json!([]),
        "a candidate that names a listed relationship is not skipped"
    );
    assert_eq!(
        decoded["candidates"][0]["rel"],
        json!([fixture.relationship.to_hex()]),
        "the label reads back to the relationship's id"
    );
    Ok(())
}

/// A candidate that names a relationship by its full id, in either letter case, carries that
/// id in lowercase, as the native reader takes a `rel` that is no listed label.
#[test]
fn a_relationship_named_by_its_id_is_carried_as_that_id() -> ExtractionStepTestResult<()> {
    let fixture = relationship_fixture(|relationship| {
        reply_naming(&relationship.to_hex().to_uppercase(), WORDS)
    })?;
    let submit = fixture.submit()?;
    fixture.assert_listed();
    assert_eq!(submit["result"]["status"], json!("finished"));
    let decoded = &submit["result"]["json"];
    assert_eq!(
        decoded["skipped"],
        json!([]),
        "a candidate that names a relationship by its id is not skipped"
    );
    assert_eq!(
        decoded["candidates"][0]["rel"],
        json!([fixture.relationship.to_hex()]),
        "the id is carried in lowercase"
    );
    Ok(())
}

/// A candidate whose `rel` is neither a label the request lists nor an id is skipped by name,
/// and the reply stands.
#[test]
fn a_relationship_label_the_request_does_not_list_skips_the_candidate()
-> ExtractionStepTestResult<()> {
    let fixture = relationship_fixture(|_| reply_naming(UNLISTED_LABEL, WORDS))?;
    let submit = fixture.submit()?;
    fixture.assert_listed();
    assert_eq!(submit["result"]["status"], json!("finished"));
    let decoded = &submit["result"]["json"];
    assert_eq!(
        decoded["candidates"],
        json!([]),
        "a candidate with an unreadable relationship is not kept"
    );
    assert_eq!(decoded["skipped"][0]["index"], json!(0));
    assert_eq!(
        decoded["skipped"][0]["reason"],
        json!("invalid relationship ref")
    );
    Ok(())
}

/// A candidate with an unreadable relationship would not build, so native's citation check
/// refuses no reply over it. Owen holds no claim a correction could be asked about, and the
/// quote is of words the turn does not hold: the candidate is skipped for its relationship
/// and the reply stands, where the step refused the whole reply for the quote.
#[test]
fn an_unreadable_relationship_beside_an_unbound_quote_refuses_no_reply()
-> ExtractionStepTestResult<()> {
    let fixture = relationship_fixture(|_| reply_naming(UNLISTED_LABEL, WORDS_NOT_SERVED))?;
    let submit = fixture.submit()?;
    fixture.assert_listed();
    assert_eq!(
        submit["result"]["status"],
        json!("finished"),
        "a candidate that would not build refuses no reply: {submit}"
    );
    let decoded = &submit["result"]["json"];
    assert_eq!(decoded["candidates"], json!([]));
    assert_eq!(decoded["skipped"][0]["index"], json!(0));
    assert_eq!(
        decoded["skipped"][0]["reason"],
        json!("invalid relationship ref")
    );
    Ok(())
}
