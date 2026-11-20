//! Words that carry a relationship label bind the lent candidates drawn from them.
//!
//! On a branch whose scope holds no relationship set, an operand over labelled words is
//! assembled under the relationships every labelled word shares: a candidate that names no
//! relationship takes its words' label, and one that names a relationship outside it is
//! refused. A stored head that holds wider than that label is offered to no correction of
//! such a candidate. An operand that names its recorded step candidate is bound over that
//! step's turns, while one that names no step is bound over every queued turn.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test extraction_operand_relationship_bound`
#![cfg(oneiron_test_support)]

#[path = "extraction_steps/support.rs"]
mod step_support;
#[path = "extraction_verdict/support.rs"]
mod verdict_support;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::dreamer_runner::{DreamerAdmittedAttempt, DreamerAttemptBinding};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MemoryResult, WitnessAssertions, WitnessAuthor, WitnessMessage,
    WitnessTurn,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::extraction_inputs::{
    ExtractionConversation, enqueue_admitted_extraction_attempt,
};
use oneiron::test_doors::extraction_steps::{ExtractionStepFixture, attach_extraction_step_lender};
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{EdgeActorClass, EntityId, Vault};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::slice::from_ref;
use std::sync::Arc;
use verdict_support::{
    ExtractionVerdictTestResult, QUEUE_NOW, bind_extraction, extraction_attempt_hex,
    extraction_candidate, open_extraction_verdict_vault, page_turns_with_versions,
    read_bound_extraction_page,
};

/// The verb that serves the bound candidate and correction-listing facts.
const OBSERVATIONS_PAGE_VERB: &str = "vault.consolidation.extraction.observations.page";

/// The host clock the observations page takes, in Unix milliseconds.
const OBSERVATION_NOW_MS: u64 = 21_000;

/// The predicate shared by the proposed values.
const FOOD: &str = "preference.food";

/// Witnesses each `(words, metadata)` pair as one visible user MESSAGE carrying that metadata
/// into its own TURN of one fresh conversation, each spoken by a fresh person.
fn witness_labelled_turns(
    vault: &Vault,
    labelled: &[(&str, Value)],
) -> ExtractionVerdictTestResult<ExtractionConversation> {
    let conversation = EntityId::now();
    let mut turns = Vec::with_capacity(labelled.len());
    let mut messages = Vec::with_capacity(labelled.len());
    for (index, (words, metadata)) in labelled.iter().enumerate() {
        let speaker = EntityId::now();
        vault.put_entity(
            &speaker,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"witness",
        )?;
        let turn = EntityId::now();
        let message = EntityId::now();
        vault
            .memory(speaker, EdgeActorClass::Human)
            .witness(&WitnessTurn {
                conversation_ref: conversation.to_hex(),
                turn_ref: Some(turn.to_hex()),
                thread_audience: None,
                project: None,
                messages: vec![WitnessMessage {
                    id: Some(message.to_hex()),
                    author: WitnessAuthor::User,
                    message_type: "dialogue".to_owned(),
                    content: words.to_string(),
                    parts: None,
                    metadata: Some(metadata.clone()),
                    is_visible: true,
                    order: 0,
                    quote: None,
                }],
                occurred_at: 10 + index as u64,
                assertions: WitnessAssertions::default(),
            })?;
        turns.push(turn);
        messages.push(message);
    }
    Ok(ExtractionConversation {
        conversation,
        turns,
        messages,
    })
}

/// Stores one relationship entity.
fn store_relationship(vault: &Vault) -> ExtractionVerdictTestResult<EntityId> {
    let relationship = EntityId::now();
    vault.put_entity(
        &relationship,
        ENTITY_TYPE_RELATIONSHIP,
        TimeRange { start: 1, end: 1 },
        1,
        b"relationship",
    )?;
    Ok(relationship)
}

/// Grants the Dreamer a live `MessagesRead` grant on `relationship`, so its TURN reader
/// serves the MESSAGEs that carry that label.
fn grant_relationship(vault: &Vault, relationship: EntityId) -> ExtractionVerdictTestResult<()> {
    let actor = dreamer(vault)?;
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    vault.create_access_grant(
        &EntityId::now(),
        &AccessGrant {
            authority_scope,
            principal_ref: actor,
            scope: AccessGrantScope::Messages {
                space_ref: relationship,
            },
            capability: AccessGrantCapability::MessagesRead,
            status: AccessGrantStatus::Active,
            created_at: vault.now_recorded_at(),
            revoked_at: None,
            expires_at: None,
            companion_bounds: None,
        },
    )?;
    Ok(())
}

/// Lands one active, stated food preference about `subject` that names no relationship, so
/// it holds within all relationships: a plain public put on the default facet with Auto
/// approval, as the claim evidence test lands its stated heads.
fn land_unlabelled_food_head(
    vault: &Vault,
    subject: EntityId,
    value: &str,
) -> ExtractionVerdictTestResult<EntityId> {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        FOOD,
        ClaimSubject::Entity(subject),
        RmpValue::from(value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    body.scope = Some(RmpValue::Map(vec![(
        RmpValue::from("sensitivity"),
        RmpValue::from(0u64),
    )]));
    body.scope_facet = vault.default_facet()?;
    let now = vault.now_recorded_at();
    vault.put_claim(
        &id,
        &body,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    Ok(id)
}

/// One bound attempt over labelled turns that name owen.
struct LabelFixture {
    /// Owns the temporary directory for the lifetime of the bound attempt.
    _directory: tempfile::TempDir,
    /// Holds the vault the step leg rebinds from.
    vault: Arc<Vault>,
    /// Holds the admission every binding of the attempt binds from.
    admitted: DreamerAdmittedAttempt,
    /// Holds the live extraction binding without a loan.
    binding: DreamerAttemptBinding,
    /// Holds the attempt as the pages name it.
    attempt: String,
    /// Holds the served turn refs with their pinned versions in page order.
    turns: Vec<(String, Value)>,
    /// Names owen, the listed subject.
    subject: EntityId,
    /// Names the stored head about owen, when the fixture landed one.
    head: Option<EntityId>,
}

/// Seeds owen, lands a stated food head about owen proposing `head` when one is given,
/// stores one relationship per `words`, witnesses each turn's MESSAGE carrying its
/// relationship, grants the Dreamer every one of them, and admits one attempt over the
/// turns. Returns the fixture with its relationships in turn order.
fn label_fixture(
    words: &[&str],
    head: Option<&str>,
) -> ExtractionVerdictTestResult<(LabelFixture, Vec<EntityId>)> {
    let directory = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&directory)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let head = head
        .map(|value| land_unlabelled_food_head(&vault, subject, value))
        .transpose()?;
    let mut relationships = Vec::with_capacity(words.len());
    let mut labelled = Vec::with_capacity(words.len());
    for text in words {
        let relationship = store_relationship(&vault)?;
        labelled.push((*text, json!({"rel": relationship.to_hex()})));
        relationships.push(relationship);
    }
    let witnessed = witness_labelled_turns(&vault, &labelled)?;
    for relationship in &relationships {
        grant_relationship(&vault, *relationship)?;
    }
    let (attempt, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let attempt = extraction_attempt_hex(attempt);
    let page = read_bound_extraction_page(&binding, &attempt)?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(
        turns.len(),
        words.len(),
        "The inputs page serves every labelled turn."
    );
    Ok((
        LabelFixture {
            _directory: directory,
            vault,
            admitted,
            binding,
            attempt,
            turns,
            subject,
            head,
        },
        relationships,
    ))
}

impl LabelFixture {
    /// Reads one observations page for `candidates`.
    fn observe(&self, candidates: &[Value]) -> MemoryResult<Value> {
        self.binding
            .invoke(
                OBSERVATIONS_PAGE_VERB,
                json!({
                    "attempt": self.attempt,
                    "now_ms": OBSERVATION_NOW_MS,
                    "candidates": candidates,
                }),
                None,
            )
            .map(|answer| answer["value"].clone())
    }
}

/// Returns the candidate row at operand `index`.
fn page_candidate(page: &Value, index: u64) -> &Value {
    page["candidates"]
        .as_array()
        .expect("The page has a candidate rows array.")
        .iter()
        .find(|row| row["index"] == json!(index))
        .expect("The page serves the requested candidate row.")
}

/// Checks that `result` is refused as a bad request whose message holds every `part`.
fn assert_bad_request(result: MemoryResult<Value>, parts: &[&str]) {
    let error = result.expect_err("The request is refused.");
    assert_eq!(
        error.code, MEMORY_CODE_BAD_REQUEST,
        "The request is invalid: {error:?}."
    );
    for part in parts {
        assert!(
            error.message.contains(part),
            "The refusal holds {part:?}; it was {:?}.",
            error.message,
        );
    }
}

/// A candidate over labelled words is assembled under their label: the operand that names no
/// relationship and the one that names the words' label derive the same claim and token.
#[test]
fn a_candidate_over_labelled_words_is_assembled_under_their_label()
-> ExtractionVerdictTestResult<()> {
    let (fixture, relationships) = label_fixture(&["owen likes tea"], None)?;
    assert_eq!(relationships.len(), 1);
    let relationship = relationships[0];
    let (turn, version) = &fixture.turns[0];
    let plain = extraction_candidate(
        &fixture.subject.to_hex(),
        FOOD,
        json!("green tea"),
        turn,
        version.clone(),
    );
    let mut named = plain.clone();
    named["rel"] = json!([relationship.to_hex()]);
    let page = fixture
        .observe(&[plain, named])
        .expect("The page assembles both operands.");
    let first = page_candidate(&page, 0);
    let second = page_candidate(&page, 1);
    assert_eq!(
        first["claim"], second["claim"],
        "Both operands derive the same claim."
    );
    assert_eq!(
        first["identity_token"], second["identity_token"],
        "Both operands share their identity token."
    );
    Ok(())
}

/// A relationship outside the words' label is refused: the operand that names it never
/// assembles.
#[test]
fn a_relationship_outside_the_words_label_is_refused() -> ExtractionVerdictTestResult<()> {
    let (fixture, relationships) = label_fixture(&["owen likes tea"], None)?;
    assert_eq!(relationships.len(), 1);
    let other = store_relationship(&fixture.vault)?;
    let (turn, version) = &fixture.turns[0];
    let mut operand = extraction_candidate(
        &fixture.subject.to_hex(),
        FOOD,
        json!("green tea"),
        turn,
        version.clone(),
    );
    operand["rel"] = json!([other.to_hex()]);
    assert_bad_request(
        fixture.observe(from_ref(&operand)),
        &["extraction relationship crossed branch scope"],
    );
    Ok(())
}

/// A stored head that holds within all relationships is offered to no correction of a
/// candidate over labelled words: a candidate that corrected it would take its wider set,
/// so the page lists no such head and asks the candidate about none.
#[test]
fn a_head_wider_than_the_words_label_is_offered_to_no_correction() -> ExtractionVerdictTestResult<()>
{
    let (fixture, relationships) = label_fixture(&["owen likes tea"], Some("black coffee"))?;
    assert_eq!(relationships.len(), 1);
    let head = fixture
        .head
        .expect("The fixture landed its stored head.")
        .to_hex();
    let (turn, version) = &fixture.turns[0];
    let operand = extraction_candidate(
        &fixture.subject.to_hex(),
        FOOD,
        json!("green tea"),
        turn,
        version.clone(),
    );
    let page = fixture
        .observe(from_ref(&operand))
        .expect("The page assembles the operand.");
    let listed = page["listed"]
        .as_array()
        .expect("The page has a listed rows array.");
    assert!(
        listed.iter().all(|row| row["claim"] != json!(head)),
        "The head that holds within all relationships is not listed: {page}."
    );
    assert_eq!(
        page_candidate(&page, 0)["correctable"],
        json!([]),
        "The candidate is asked about no head."
    );
    Ok(())
}

/// An operand that names its step is bound over that step's turns: it asks under its turn's
/// label, while the inline form over both turns assembles under the empty set, and naming
/// one turn's label on the inline form is refused.
#[test]
fn an_operand_that_names_its_step_is_bound_over_that_steps_turns() -> ExtractionVerdictTestResult<()>
{
    let (fixture, relationships) =
        label_fixture(&["owen savors green tea", "owen cooks daily"], None)?;
    assert_eq!(relationships.len(), 2);
    let first_label = relationships[0];
    let backend = Arc::new(step_support::CapturingStepBackend::new(
        json!({"persons": [], "candidates": [{
            "subject": "P2",
            "predicate": FOOD,
            "value": "green tea",
            "confidence": 0.9,
            "evidence_refs": [{"source": "T1", "quote": "green tea"}],
        }]})
        .to_string(),
        100,
        50,
    ));
    let lent = ExtractionStepFixture::new(backend)?;
    let stepped =
        attach_extraction_step_lender(bind_extraction(&fixture.vault, &fixture.admitted)?, &lent);
    let (turn, version) = &fixture.turns[0];
    let submit = step_support::invoke_bound_step(
        &stepped,
        step_support::extraction_step_request(json!([step_support::extraction_step_evidence(
            turn,
            version.clone(),
            None
        )])),
    )?;
    assert_eq!(
        submit["result"]["status"],
        json!("finished"),
        "The step over the first turn finishes."
    );
    let step = submit["step_ref"]
        .as_str()
        .expect("The submit answers its step ref.")
        .to_owned();
    let candidate = &submit["result"]["json"]["candidates"][0];
    assert_eq!(
        candidate["subject"],
        json!({"listed": fixture.subject.to_hex()}),
        "The kept candidate is about owen."
    );
    let inline = json!({
        "subject": candidate["subject"]["listed"],
        "predicate": candidate["predicate"],
        "value": candidate["value"],
        "evidence": candidate["evidence"],
    });
    let mut stepped_operand = inline.clone();
    stepped_operand["from_steps"] = json!([{"step": step, "index": 0}]);
    let stepped_page = fixture
        .observe(from_ref(&stepped_operand))
        .expect("The operand that names its step asks.");
    let inline_page = fixture
        .observe(from_ref(&inline))
        .expect("The inline operand asks.");
    assert_ne!(
        page_candidate(&stepped_page, 0)["claim"],
        page_candidate(&inline_page, 0)["claim"],
        "The stepped operand assembles under its turn's label, the inline one under the empty set."
    );
    let mut crossed = inline.clone();
    crossed["rel"] = json!([first_label.to_hex()]);
    assert_bad_request(
        fixture.observe(from_ref(&crossed)),
        &["extraction relationship crossed branch scope"],
    );
    Ok(())
}
