//! The person item of a derivation batch (untangle 6.9h, S69-C-KINDS = A):
//! an agent names a PERSON it found in a TURN it reads, through
//! `vault.derive.commit` on its live run, and the engine mints it as the
//! Dreamer's extraction does, under the agent's derive verdict. The engine
//! keeps the name rule (a bounded span of the TURN's words), the speaker
//! rule, the id (derived, never the caller's) and the mint door's refusal of
//! a taken id. A batch revert archives the PERSON while no other row's
//! claim names it, after taking back the batch's own claims about it.
//!
//! Under an extraction binding's commit a taken id that holds the live
//! PERSON is answered, not refused: a retry of the attempt learns the id and
//! lands its claim, two items of one batch that spell one name share one
//! PERSON, the Dreamer's stamp commit and an archived id are refused as
//! before, and a revert of the answering batch leaves the row to the batch
//! that minted it. A batch record stored before the answer decodes unchanged.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derive_person`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "extraction_verdict/support.rs"]
#[allow(dead_code)]
mod support;

use oneiron::attempt_queue::{AttemptQueue, RetryAttempt, RetryOutcome};
use oneiron::dreamer_consolidation::selection::SelectionConfig;
use oneiron::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptBinding, DreamerConsolidationScope, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt,
};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{
    batches_of, claim_lifecycle, claim_subject, derive_item_receipts, row_live, source_version,
};
use oneiron::test_doors::derive_conflict;
use oneiron::test_doors::derive_person::{cleanup_lists, person_body};
use oneiron::test_doors::derive_verbs::{LiveRun, define_agent, grant_derive_rows, lease_run};
use oneiron::test_doors::extraction_inputs::{
    EXTRACTION_LEASE_OWNER, ExtractionConversation, admit_extraction_attempt,
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::extraction_outputs::recorded_outputs;
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{AttemptId, EdgeActorClass, EntityId, Vault};
use serde_json::{Value, json};
use std::sync::Arc;
use support::{
    QUEUE_NOW, bind_extraction, extraction_attempt_hex, extraction_attempt_with_turns,
    extraction_candidate, open_extraction_verdict_vault, page_turns_with_versions,
    read_bound_extraction_page,
};

const READER: &str = "reader";

const NAME_UNREAD: &str = "gate.deny.derive.person_name_unread";
const SOURCE_INADMISSIBLE: &str = "gate.deny.derive.person_source_inadmissible";
const ID_TAKEN: &str = "gate.deny.derive.person_id_taken";
const MINTED_BEFORE: &str = "gate.allow.derive.person_minted_before";
const NOT_ATTEMPT_DREAMER: &str = "gate.deny.derive.person_not_attempt_dreamer";

fn put(vault: &Vault, entity_type: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_entity(&id, entity_type, TimeRange { start: at, end: at }, at, body)
        .expect("a row");
    id
}

/// A TURN holding its own `words`, spoken by `speaker`.
fn turn(vault: &Vault, speaker: &str, words: &str) -> EntityId {
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([
        ("speaker", speaker),
        ("text", words),
    ]))
    .expect("a TURN body");
    put(vault, ENTITY_TYPE_TURN, &body)
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    agent: EntityId,
    run: LiveRun,
}

/// A vault with one agent the owner's policy lets derive, on a leased run.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let agent = define_agent(&vault, "oneiron.agent.derive-person").expect("an agent");
    grant_derive_rows(&vault, &[agent]).expect("the agent's policy rows");
    let run = lease_run(&vault, agent).expect("the agent's live run");
    Fixture {
        _dir: dir,
        vault,
        agent,
        run,
    }
}

/// The wire item naming `name` in `turns`, as `local`.
fn person(local: &str, name: &str, turns: &[EntityId]) -> Value {
    let evidence: Vec<Value> = turns.iter().map(|turn| json!({ "stored": turn })).collect();
    json!({
        "kind": "person",
        "spec": { "local": local, "name": name, "evidence": evidence },
    })
}

/// The wire item of a claim about `subject` citing `turn`, as `local`.
fn claim(local: &str, subject: Value, turn: EntityId) -> Value {
    json!({
        "kind": "claim",
        "spec": {
            "local": local,
            "predicate": "profile.drink",
            "subject": subject,
            "value": "an oat milk flat white",
            "confidence": 0.9,
            "evidence": [{ "stored": turn }],
        },
    })
}

/// Commits `items` on `run`, citing each of `sources` at the version
/// `agent`'s own read serves; the wire answer.
fn commit_on(
    vault: &Vault,
    agent: EntityId,
    run: &LiveRun,
    items: Vec<Value>,
    sources: &[EntityId],
) -> Value {
    let versions: Vec<Value> = sources
        .iter()
        .map(|source| {
            let version = source_version(vault, agent, EdgeActorClass::Agent, *source)
                .expect("read")
                .expect("the agent reads the source");
            serde_json::to_value(version).expect("a version")
        })
        .collect();
    run.commit(vault, json!({ "items": items, "sources": versions }))
        .expect("the batch commits")
}

fn commit(fixture: &Fixture, items: Vec<Value>, sources: &[EntityId]) -> Value {
    commit_on(&fixture.vault, fixture.agent, &fixture.run, items, sources)
}

/// Commits `request` as the Dreamer in `attempt`, through the Conflict
/// door's stamp door (as `derive_candidate`'s `commit_dreamer` does).
fn commit_dreamer(vault: &Vault, attempt: Option<AttemptId>, request: Value) -> Value {
    let actor = dreamer(vault).expect("the Dreamer");
    derive_conflict::commit(
        vault,
        actor,
        EdgeActorClass::System,
        "run",
        attempt,
        request,
    )
    .expect("the batch commits")
}

/// Commits `items` as the Dreamer in `attempt`, citing each of `sources` at
/// the version the Dreamer's own read serves.
fn commit_dreamer_citing(
    vault: &Vault,
    attempt: AttemptId,
    items: Vec<Value>,
    sources: &[EntityId],
) -> Value {
    let actor = dreamer(vault).expect("the Dreamer");
    let versions: Vec<Value> = sources
        .iter()
        .map(|source| {
            let version = source_version(vault, actor, EdgeActorClass::System, *source)
                .expect("read")
                .expect("the Dreamer reads the source");
            serde_json::to_value(version).expect("a version")
        })
        .collect();
    commit_dreamer(
        vault,
        Some(attempt),
        json!({ "items": items, "sources": versions }),
    )
}

/// Witnesses one MESSAGE with explicit metadata through the public witness
/// path (copied from `extraction_read_gate`'s `witness_metadata_turn`).
fn witness_metadata_turn(vault: &Vault, metadata: Value) -> ExtractionConversation {
    let conversation = EntityId::now();
    let turn = EntityId::now();
    let message = EntityId::now();
    let speaker = EntityId::now();
    seed_named_person(vault, &speaker, "owen", 1).expect("a speaker");
    vault
        .memory(speaker, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: "owen likes tea".to_owned(),
                parts: None,
                metadata: Some(metadata),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: 10,
            assertions: WitnessAssertions::default(),
        })
        .expect("witness");
    ExtractionConversation {
        conversation,
        turns: vec![turn],
        messages: vec![message],
    }
}

fn id(value: &Value) -> EntityId {
    EntityId::from_hex(value.as_str().expect("an id")).expect("a 32-character hex id")
}

/// The one item of `answer`: whether it landed, its first row, its reasons.
fn only_item(answer: &Value) -> (bool, Option<EntityId>, Vec<String>) {
    let items = answer["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "{answer}");
    let item = &items[0];
    let reasons = item["reasons"]
        .as_array()
        .expect("reasons")
        .iter()
        .map(|reason| reason.as_str().expect("a token").to_owned())
        .collect();
    (
        item["landed"].as_bool().expect("landed"),
        item["rows"]
            .as_array()
            .and_then(|rows| rows.first())
            .map(id),
        reasons,
    )
}

const DERIVE_COMMIT_VERB: &str = "vault.derive.commit";

struct ExtractionPersonFixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    admitted: DreamerAdmittedAttempt,
    binding: DreamerAttemptBinding,
    turns: Vec<(String, Value)>,
}

/// One witnessed TURN that names Owen, queued and admitted as an extraction
/// attempt and bound: the fixture of `extraction_commit`'s person test, with
/// the selection its candidate test sets, so that a claim lands at once.
fn extraction_person_fixture() -> ExtractionPersonFixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(open_extraction_verdict_vault(&dir).expect("vault"));
    stand_steward_grant(
        &vault,
        dreamer(&vault).expect("the Dreamer"),
        &STEWARD_VERBS,
    )
    .expect("the Dreamer's grant");
    vault
        .set_consolidation_selection(&SelectionConfig {
            soak_ms: 0,
            evidence_minimum: 1,
            ..vault.consolidation_selection().expect("selection")
        })
        .expect("selection");
    let witnessed =
        witness_extraction_turns(&vault, &["Owen chooses green tea"]).expect("one witnessed TURN");
    let (attempt, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)
            .expect("an admitted attempt");
    let binding = bind_extraction(&vault, &admitted).expect("a binding");
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt))
        .expect("the inputs page");
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 1);
    ExtractionPersonFixture {
        _dir: dir,
        vault,
        admitted,
        binding,
        turns,
    }
}

fn commit_bound_people(
    binding: &DreamerAttemptBinding,
    turns: &[(String, Value)],
    items: Vec<Value>,
) -> Value {
    let versions: Vec<Value> = turns.iter().map(|(_, version)| version.clone()).collect();
    binding
        .invoke(
            DERIVE_COMMIT_VERB,
            json!({"items": items, "sources": versions}),
            None,
        )
        .expect("the binding commits the person batch")
}

/// Retries the fixture's leased attempt and admits its successor: the
/// queue's own retry (the successor names the first try as `retry_of`), then
/// the Dreamer's enqueue under the same dedupe key, which answers the pending
/// successor and stamps it, then the admission.
fn retry_extraction(fixture: &ExtractionPersonFixture) -> DreamerAdmittedAttempt {
    let source = &fixture.admitted.status;
    assert!(
        source.attempt.dedupe_key.is_some(),
        "the planner supplies dedupe"
    );
    let RetryOutcome::Retried(successor) = AttemptQueue::new(&fixture.vault)
        .retry(RetryAttempt {
            id: source.attempt.id,
            lease_owner: EXTRACTION_LEASE_OWNER.to_owned(),
            attempt_count: source.attempt.attempt_count,
            backoff_until: 0,
            last_error: Some("extraction interrupted before claims".to_owned()),
            now: fixture.vault.now_recorded_at(),
        })
        .expect("retry the leased attempt")
    else {
        panic!("the queue creates a retry");
    };
    assert_ne!(successor.id, source.attempt.id);
    assert_eq!(successor.retry_of, Some(source.attempt.id));
    let enqueued = DreamerRunnerStore::new(&fixture.vault)
        .enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Meso,
            input: source.payload.input.clone(),
            parent_attempt: source.payload.parent_attempt,
            dedupe_key: source.attempt.dedupe_key.clone(),
            run_id: source.attempt.run_id.clone(),
            now: fixture.vault.now_recorded_at(),
        })
        .expect("stamp the existing successor through the Dreamer enqueue");
    let EnqueueDreamerAttemptOutcome::Existing(existing) = enqueued else {
        panic!("enqueue must reuse the pending retry, not make another attempt");
    };
    assert_eq!(existing.attempt.id, successor.id);
    let admitted = admit_extraction_attempt(&fixture.vault, fixture.vault.now_recorded_at())
        .expect("admit the retry");
    assert_eq!(admitted.status.attempt.id, successor.id);
    assert_eq!(admitted.status.attempt.retry_of, Some(source.attempt.id));
    admitted
}

/// Asserts that the wire `item`'s own receipt is an allowance naming exactly
/// `token` and the item's first row, found by its id in the ledger.
fn assert_item_allowance(vault: &Vault, item: &Value, token: &str) {
    let decisions = vault.gate_decisions(usize::MAX).expect("gate decisions");
    let receipt = item["receipt"].as_str().expect("the item's receipt");
    let decision = decisions
        .iter()
        .find(|decision| decision.decision_id.to_hex() == receipt)
        .expect("the item's own gate decision");
    assert_eq!(decision.outcome, "approved");
    assert_eq!(decision.reason_codes, vec![token.to_owned()]);
    assert_eq!(decision.claim_id, Some(*id(&item["rows"][0]).as_bytes()));
}

/// Asserts that the derivation receipts about `person` are allowances with
/// exactly the `expected` tokens, in any order.
fn assert_person_allowances(vault: &Vault, person: EntityId, expected: &[&str]) {
    let receipts = derive_item_receipts(vault, &person).expect("person receipts");
    let mut actual: Vec<Vec<String>> = receipts
        .into_iter()
        .map(|receipt| {
            assert_eq!(receipt.outcome, "approved");
            assert!(receipt.grant_ref.is_some());
            receipt.reasons
        })
        .collect();
    actual.sort();
    let mut expected: Vec<Vec<String>> = expected
        .iter()
        .map(|token| vec![(*token).to_owned()])
        .collect();
    expected.sort();
    assert_eq!(actual, expected);
}

fn assert_taken_without_row(answer: &Value) {
    let (landed, row, reasons) = only_item(answer);
    assert!(!landed, "{answer}");
    assert!(row.is_none(), "{answer}");
    assert_eq!(answer["items"][0]["rows"], json!([]), "{answer}");
    assert_eq!(reasons, vec![ID_TAKEN.to_owned()], "{answer}");
}

#[test]
fn a_person_named_in_a_turn_lands_with_its_receipt() {
    let fixture = fixture();
    let said = turn(&fixture.vault, "user", "I had lunch with Ann today.");
    let answer = commit(&fixture, vec![person("ann", "Ann", &[said])], &[said]);
    let (landed, row, reasons) = only_item(&answer);
    assert!(landed, "the person lands: {answer}");
    assert!(reasons.is_empty(), "{answer}");
    assert_eq!(answer["items"][0]["kind"], "person", "{answer}");
    let person = row.expect("the PERSON it minted");
    assert!(row_live(&fixture.vault, person).expect("read"));
    assert_eq!(
        person_body(&fixture.vault, person)
            .expect("read")
            .and_then(|body| body.name),
        Some("Ann".to_owned()),
        "the PERSON holds the name as the TURN spells it"
    );
    assert!(
        cleanup_lists(&fixture.vault, person).expect("read"),
        "it is the extraction mint's row: empty, the cleanup lists it"
    );
    let receipts = derive_item_receipts(&fixture.vault, &person).expect("read");
    let [receipt] = receipts.as_slice() else {
        panic!("one receipt for the person: {receipts:?}");
    };
    assert_eq!(receipt.outcome, "approved");
    assert_eq!(receipt.reasons, vec!["gate.allow.derive.person".to_owned()]);
    assert!(
        receipt.grant_ref.is_some(),
        "the receipt names what judged it"
    );
    assert_eq!(
        batches_of(&fixture.vault, fixture.agent).expect("read"),
        vec![id(&answer["batch"])],
        "the batch is recorded under the run's actor"
    );
}

#[test]
fn a_later_claim_names_the_person_by_its_local_name() {
    let fixture = fixture();
    let said = turn(
        &fixture.vault,
        "user",
        "Coffee with Ann: an oat milk flat white, as every Tuesday.",
    );
    let answer = commit(
        &fixture,
        vec![
            person("ann", "Ann", &[said]),
            claim("lunch", json!({ "local": "ann" }), said),
        ],
        &[said],
    );
    let items = answer["items"].as_array().expect("items");
    assert_eq!(items[0]["landed"], true, "{answer}");
    assert_eq!(items[1]["landed"], true, "{answer}");
    let person = id(&items[0]["rows"][0]);
    let claim = id(&items[1]["rows"][0]);
    assert_eq!(
        claim_subject(&fixture.vault, claim).expect("read"),
        Some(person),
        "the claim is about the PERSON the batch minted"
    );
}

#[test]
fn the_revert_takes_back_the_claim_then_archives_the_person() {
    let fixture = fixture();
    let said = turn(
        &fixture.vault,
        "user",
        "Coffee with Ann: an oat milk flat white, as every Tuesday.",
    );
    let answer = commit(
        &fixture,
        vec![
            person("ann", "Ann", &[said]),
            claim("lunch", json!({ "local": "ann" }), said),
        ],
        &[said],
    );
    let person = id(&answer["items"][0]["rows"][0]);
    let claim = id(&answer["items"][1]["rows"][0]);
    let reverted = fixture
        .run
        .revert(&fixture.vault, id(&answer["batch"]))
        .expect("the agent reverts its own batch");
    assert_eq!(reverted["reverted"], json!(["lunch", "ann"]), "{reverted}");
    assert_eq!(reverted["left"], json!([]), "{reverted}");
    assert_ne!(
        claim_lifecycle(&fixture.vault, claim).expect("read"),
        Some("active".to_owned())
    );
    assert!(
        !row_live(&fixture.vault, person).expect("read"),
        "the PERSON no longer reads"
    );
    assert!(
        fixture
            .vault
            .archived_entity(&person)
            .expect("read")
            .is_some(),
        "it is archived, for the owner's restore, never unborn"
    );
}

#[test]
fn a_person_another_batch_claims_about_stays_born() {
    let fixture = fixture();
    let said = turn(
        &fixture.vault,
        "user",
        "Coffee with Ann: an oat milk flat white, as every Tuesday.",
    );
    let minted = commit(&fixture, vec![person("ann", "Ann", &[said])], &[said]);
    let person = id(&minted["items"][0]["rows"][0]);
    let claimed = commit(
        &fixture,
        vec![claim("lunch", json!({ "stored": person }), said)],
        &[said],
    );
    assert_eq!(claimed["items"][0]["landed"], true, "{claimed}");
    let reverted = fixture
        .run
        .revert(&fixture.vault, id(&minted["batch"]))
        .expect("the agent reverts its own batch");
    assert_eq!(reverted["reverted"], json!([]), "{reverted}");
    assert_eq!(
        reverted["left"],
        json!([{ "local": "ann", "reason": "derive.revert.inverse_refused" }]),
        "{reverted}"
    );
    assert!(row_live(&fixture.vault, person).expect("read"));
}

#[test]
fn a_name_the_words_do_not_bound_is_refused() {
    let fixture = fixture();
    let said = turn(&fixture.vault, "user", "I met Ann-Marie at the station.");
    for name in ["Ann", "Bob", "   ", "42"] {
        let answer = commit(&fixture, vec![person("p", name, &[said])], &[said]);
        let (landed, _, reasons) = only_item(&answer);
        assert!(!landed, "{name:?}: {answer}");
        assert_eq!(reasons, vec![NAME_UNREAD.to_owned()], "{name:?}: {answer}");
    }
    let answer = commit(
        &fixture,
        vec![person("p", "  ann-marie ", &[said])],
        &[said],
    );
    assert!(
        only_item(&answer).0,
        "the whole name, in any case: {answer}"
    );
}

#[test]
fn a_source_that_is_no_user_or_assistant_turn_is_refused() {
    let fixture = fixture();
    let system = turn(&fixture.vault, "system", "Ann joined the workspace.");
    let row = put(&fixture.vault, ENTITY_TYPE_PERSON, b"Ann");
    for source in [system, row] {
        let answer = commit(&fixture, vec![person("p", "Ann", &[source])], &[source]);
        let (landed, _, reasons) = only_item(&answer);
        assert!(!landed, "{answer}");
        assert_eq!(reasons, vec![SOURCE_INADMISSIBLE.to_owned()], "{answer}");
    }
}

#[test]
fn a_person_minted_again_in_the_same_lineage_is_refused_as_taken() {
    let fixture = fixture();
    let said = turn(&fixture.vault, "user", "I had lunch with Ann today.");
    let first = commit(&fixture, vec![person("ann", "Ann", &[said])], &[said]);
    assert!(only_item(&first).0, "{first}");
    let again = commit(&fixture, vec![person("ann", "ann", &[said])], &[said]);
    let (landed, _, reasons) = only_item(&again);
    assert!(!landed, "one id for one person in one lineage: {again}");
    assert_eq!(reasons, vec![ID_TAKEN.to_owned()], "{again}");
}

#[test]
fn the_wire_names_no_person_id_or_target() {
    let fixture = fixture();
    let said = turn(&fixture.vault, "user", "I had lunch with Ann today.");
    let hidden = put(&fixture.vault, ENTITY_TYPE_PERSON, b"Ann");
    for (field, value) in [
        ("id", json!(hidden)),
        ("dedupe_target", json!({ "stored": hidden })),
        ("source_audience", json!({ "private": false })),
    ] {
        let mut item = person("ann", "Ann", &[said]);
        item["spec"][field] = value;
        let refusal = fixture
            .run
            .commit(&fixture.vault, json!({ "items": [item], "sources": [] }))
            .expect_err(field);
        assert_eq!(
            refusal.code, MEMORY_CODE_BAD_REQUEST,
            "{field}: {refusal:?}"
        );
    }
    assert!(
        batches_of(&fixture.vault, fixture.agent)
            .expect("read")
            .is_empty(),
        "nothing is committed"
    );
}

#[test]
fn a_name_in_a_turn_the_attempt_queues_lands_for_the_dreamer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, attempt, served, _) =
        extraction_attempt_with_turns(&dir, "owen", &["Owen chooses green tea"])
            .expect("an attempt");
    assert_eq!(served.len(), 1);
    let queued = EntityId::from_hex(&served[0].0).expect("a turn");
    let answer = commit_dreamer_citing(
        &vault,
        attempt,
        vec![person("owen", "Owen", &[queued])],
        &[queued],
    );
    let (landed, row, reasons) = only_item(&answer);
    assert!(landed, "the person lands: {answer}");
    assert!(reasons.is_empty(), "{answer}");
    assert_eq!(answer["items"][0]["kind"], "person", "{answer}");
    let person = row.expect("the PERSON it minted");
    assert!(row_live(&vault, person).expect("read"));
    let body = person_body(&vault, person).expect("read").expect("a body");
    assert_eq!(
        body.name,
        Some("Owen".to_owned()),
        "the PERSON holds the name as the TURN spells it"
    );
    assert!(
        !body.source_audience,
        "an open TURN names no source audience"
    );
    assert!(
        cleanup_lists(&vault, person).expect("read"),
        "it is the extraction mint's row: empty, the cleanup lists it"
    );
    let receipts = derive_item_receipts(&vault, &person).expect("read");
    let [receipt] = receipts.as_slice() else {
        panic!("one receipt for the person: {receipts:?}");
    };
    assert_eq!(receipt.outcome, "approved");
    assert_eq!(receipt.reasons, vec!["gate.allow.derive.person".to_owned()]);
    assert!(
        receipt.grant_ref.is_some(),
        "the receipt names what judged it"
    );
    assert_eq!(
        batches_of(&vault, dreamer(&vault).expect("the Dreamer")).expect("read"),
        vec![id(&answer["batch"])],
        "the batch is recorded under the Dreamer"
    );
}

#[test]
fn a_name_only_in_a_turn_the_attempt_does_not_queue_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_extraction_verdict_vault(&dir).expect("vault");
    stand_steward_grant(
        &vault,
        dreamer(&vault).expect("the Dreamer"),
        &STEWARD_VERBS,
    )
    .expect("the Dreamer's grant");
    let witnessed =
        witness_extraction_turns(&vault, &["Yuki likes coffee", "Owen chooses green tea"])
            .expect("turns");
    let (attempt, _) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns[..1], QUEUE_NOW)
            .expect("an attempt");
    let outside = witnessed.turns[1];
    let answer = commit_dreamer_citing(
        &vault,
        attempt,
        vec![person("owen", "Owen", &[outside])],
        &[outside],
    );
    let (landed, row, reasons) = only_item(&answer);
    assert!(!landed, "{answer}");
    assert_eq!(reasons, vec![SOURCE_INADMISSIBLE.to_owned()], "{answer}");
    assert!(row.is_none(), "no row: {answer}");
}

#[test]
fn a_name_only_in_a_turn_the_gate_withholds_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_extraction_verdict_vault(&dir).expect("vault");
    stand_steward_grant(
        &vault,
        dreamer(&vault).expect("the Dreamer"),
        &STEWARD_VERBS,
    )
    .expect("the Dreamer's grant");
    let witnessed = witness_metadata_turn(&vault, json!({"scope": {"private": true}}));
    let (attempt, _) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)
        .expect("an attempt");
    let gated = witnessed.turns[0];
    let answer = commit_dreamer_citing(
        &vault,
        attempt,
        vec![person("owen", "owen", &[gated])],
        &[gated],
    );
    let (landed, row, reasons) = only_item(&answer);
    assert!(!landed, "{answer}");
    assert_eq!(reasons, vec![SOURCE_INADMISSIBLE.to_owned()], "{answer}");
    assert!(row.is_none(), "no row: {answer}");
}

#[test]
fn an_agent_naming_the_extraction_attempt_is_not_its_dreamer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_extraction_verdict_vault(&dir).expect("vault");
    stand_steward_grant(
        &vault,
        dreamer(&vault).expect("the Dreamer"),
        &STEWARD_VERBS,
    )
    .expect("the Dreamer's grant");
    let witnessed = witness_extraction_turns(&vault, &["Owen chooses green tea"]).expect("turns");
    let (attempt, _) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)
        .expect("an attempt");
    let agent = define_agent(&vault, "oneiron.agent.derive-person-extraction").expect("an agent");
    grant_derive_rows(&vault, &[agent]).expect("the agent's policy rows");
    let said = turn(&vault, "user", "I had lunch with Ann today.");
    let version = source_version(&vault, agent, EdgeActorClass::Agent, said)
        .expect("read")
        .expect("the agent reads the source");
    let answer = derive_conflict::commit(
        &vault,
        agent,
        EdgeActorClass::Agent,
        "run-agent-names-extraction",
        Some(attempt),
        json!({
            "items": [person("ann", "Ann", &[said])],
            "sources": [serde_json::to_value(version).expect("a version")],
        }),
    )
    .expect("the batch commits");
    let (landed, row, reasons) = only_item(&answer);
    assert!(!landed, "{answer}");
    assert_eq!(reasons, vec![NOT_ATTEMPT_DREAMER.to_owned()], "{answer}");
    assert!(row.is_none(), "no row: {answer}");
}

#[test]
fn an_agent_with_no_derive_rows_is_refused() {
    let fixture = fixture();
    let other =
        define_agent(&fixture.vault, "oneiron.agent.derive-person-other").expect("another agent");
    let other_run = lease_run(&fixture.vault, other).expect("its live run");
    let said = turn(&fixture.vault, "user", "I had lunch with Ann today.");
    let answer = commit_on(
        &fixture.vault,
        other,
        &other_run,
        vec![person("ann", "Ann", &[said])],
        &[said],
    );
    let (landed, _, reasons) = only_item(&answer);
    assert!(!landed, "{answer}");
    assert_eq!(
        reasons,
        vec!["gate.deny.derive.no_landing_rows".to_owned()],
        "{answer}"
    );
}

/// A retry of the attempt must learn the PERSON its lineage minted and land
/// its claim about it; a refusal here would lose every claim about a person
/// after an interrupted attempt minted the PERSON.
#[test]
fn an_extraction_retry_answers_the_person_then_lands_its_claim() {
    let fixture = extraction_person_fixture();
    let turn = EntityId::from_hex(&fixture.turns[0].0).expect("a TURN");
    let minted = commit_bound_people(
        &fixture.binding,
        &fixture.turns,
        vec![person("owen", "Owen", &[turn])],
    );
    assert!(only_item(&minted).0, "{minted}");
    let person_id = only_item(&minted).1.expect("the minted PERSON");
    let body_before = fixture.vault.get(&person_id).expect("read").expect("body");
    assert_person_allowances(&fixture.vault, person_id, &["gate.allow.derive.person"]);
    let actor = dreamer(&fixture.vault).expect("the Dreamer");
    let batches_before = batches_of(&fixture.vault, actor).expect("batches");
    let retried = retry_extraction(&fixture);
    let binding = bind_extraction(&fixture.vault, &retried).expect("the retry binds");
    let page =
        read_bound_extraction_page(&binding, &extraction_attempt_hex(retried.status.attempt.id))
            .expect("the retry inputs page");
    let turns = page_turns_with_versions(&page);
    let answered = commit_bound_people(&binding, &turns, vec![person("owen", "Owen", &[turn])]);
    assert!(only_item(&answered).0, "{answered}");
    assert_eq!(answered["items"][0]["rows"], json!([person_id]));
    assert_item_allowance(&fixture.vault, &answered["items"][0], MINTED_BEFORE);
    assert_eq!(
        fixture.vault.get(&person_id).expect("read"),
        Some(body_before)
    );
    let mut expected_batches = batches_before;
    expected_batches.push(id(&answered["batch"]));
    let mut actual_batches = batches_of(&fixture.vault, actor).expect("batches");
    expected_batches.sort();
    actual_batches.sort();
    assert_eq!(actual_batches, expected_batches);
    assert_person_allowances(
        &fixture.vault,
        person_id,
        &["gate.allow.derive.person", MINTED_BEFORE],
    );
    let operand = extraction_candidate(
        &person_id.to_hex(),
        "preference.food",
        json!("green tea"),
        &turns[0].0,
        turns[0].1.clone(),
    );
    let claimed = binding
        .invoke(
            DERIVE_COMMIT_VERB,
            json!({
                "items": [{"kind": "candidate", "spec": {
                    "local": "green-tea",
                    "member": {"candidate": operand, "confidence": 0.0, "prospective_queries": []},
                }}],
                "sources": [],
            }),
            None,
        )
        .expect("the retry commits its claim");
    assert!(only_item(&claimed).0, "{claimed}");
    let claim_id = only_item(&claimed).1.expect("the claim");
    assert_eq!(
        claim_subject(&fixture.vault, claim_id).expect("read"),
        Some(person_id)
    );
    assert_eq!(
        claim_lifecycle(&fixture.vault, claim_id).expect("read"),
        Some("active".to_owned())
    );
    assert_eq!(
        recorded_outputs(&fixture.vault, retried.status.attempt.id).expect("outputs"),
        vec![claim_id],
    );
}

/// Both items must land one id, with separate receipts and the first
/// spelling; minting twice or refusing the second item breaks this.
#[test]
fn two_person_pages_in_one_binding_batch_share_the_first_mint() {
    let fixture = extraction_person_fixture();
    let turn = EntityId::from_hex(&fixture.turns[0].0).expect("a TURN");
    let people_before = fixture
        .vault
        .entities_by_type(ENTITY_TYPE_PERSON)
        .expect("people");
    let answer = commit_bound_people(
        &fixture.binding,
        &fixture.turns,
        vec![
            person("owen-first", "Owen", &[turn]),
            person("owen-second", "owen", &[turn]),
        ],
    );
    let items = answer["items"].as_array().expect("items");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["landed"], true, "{answer}");
    assert_eq!(items[1]["landed"], true, "{answer}");
    assert_eq!(items[0]["rows"], items[1]["rows"]);
    assert_ne!(items[0]["receipt"], items[1]["receipt"]);
    assert_item_allowance(&fixture.vault, &items[0], "gate.allow.derive.person");
    assert_item_allowance(&fixture.vault, &items[1], MINTED_BEFORE);
    let person_id = id(&items[0]["rows"][0]);
    let added: Vec<EntityId> = fixture
        .vault
        .entities_by_type(ENTITY_TYPE_PERSON)
        .expect("people")
        .into_iter()
        .filter(|row| !people_before.contains(row))
        .collect();
    assert_eq!(added, vec![person_id]);
    assert_eq!(
        person_body(&fixture.vault, person_id)
            .expect("read")
            .expect("body")
            .name
            .as_deref(),
        Some("Owen")
    );
    assert_person_allowances(
        &fixture.vault,
        person_id,
        &["gate.allow.derive.person", MINTED_BEFORE],
    );
    assert!(
        recorded_outputs(&fixture.vault, fixture.admitted.status.attempt.id)
            .expect("outputs")
            .is_empty()
    );
}

/// The Dreamer's stamp door must still refuse a taken id and name no row;
/// an answer here would reach a commit that no binding proved.
#[test]
fn the_dreamers_stamp_commit_still_refuses_a_person_minted_before() {
    let fixture = extraction_person_fixture();
    let turn = EntityId::from_hex(&fixture.turns[0].0).expect("a TURN");
    let attempt = fixture.admitted.status.attempt.id;
    let first = commit_dreamer_citing(
        &fixture.vault,
        attempt,
        vec![person("owen", "Owen", &[turn])],
        &[turn],
    );
    assert!(only_item(&first).0, "{first}");
    let again = commit_dreamer_citing(
        &fixture.vault,
        attempt,
        vec![person("owen", "Owen", &[turn])],
        &[turn],
    );
    assert_taken_without_row(&again);
}

/// An archived PERSON stays taken under a binding too; an answer here would
/// name a row the archive took away.
#[test]
fn an_extraction_binding_still_refuses_an_archived_person() {
    let fixture = extraction_person_fixture();
    let turn = EntityId::from_hex(&fixture.turns[0].0).expect("a TURN");
    let minted = commit_bound_people(
        &fixture.binding,
        &fixture.turns,
        vec![person("owen", "Owen", &[turn])],
    );
    assert!(only_item(&minted).0, "{minted}");
    let person_id = only_item(&minted).1.expect("PERSON");
    let reverted = fixture
        .vault
        .derive_revert(fixture.binding.actor(), None, id(&minted["batch"]))
        .expect("the Dreamer reverts its mint");
    assert_eq!(reverted.reverted, vec!["owen".to_owned()]);
    assert!(reverted.left.is_empty());
    assert!(
        fixture
            .vault
            .archived_entity(&person_id)
            .expect("read")
            .is_some()
    );
    let again = commit_bound_people(
        &fixture.binding,
        &fixture.turns,
        vec![person("owen", "Owen", &[turn])],
    );
    assert_taken_without_row(&again);
    assert!(
        fixture
            .vault
            .archived_entity(&person_id)
            .expect("read")
            .is_some()
    );
}

/// An answering batch owns no row, even after the minting batch changes
/// the row's revision by archiving it. Either revert order must report
/// no_inverse, not archive another batch's row or report changed_since.
#[test]
fn either_revert_order_leaves_the_answered_person_to_its_minting_batch() {
    for mint_first in [false, true] {
        let fixture = extraction_person_fixture();
        let turn = EntityId::from_hex(&fixture.turns[0].0).expect("a TURN");
        let minted = commit_bound_people(
            &fixture.binding,
            &fixture.turns,
            vec![person("owen", "Owen", &[turn])],
        );
        assert!(only_item(&minted).0, "{minted}");
        let person_id = only_item(&minted).1.expect("PERSON");
        let body_before = fixture.vault.get(&person_id).expect("read").expect("body");
        let retried = retry_extraction(&fixture);
        let binding = bind_extraction(&fixture.vault, &retried).expect("the retry binds");
        let page = read_bound_extraction_page(
            &binding,
            &extraction_attempt_hex(retried.status.attempt.id),
        )
        .expect("the inputs page");
        let turns = page_turns_with_versions(&page);
        let answered = commit_bound_people(&binding, &turns, vec![person("owen", "Owen", &[turn])]);
        assert!(only_item(&answered).0, "{answered}");
        assert_eq!(answered["items"][0]["rows"], json!([person_id]));
        let revert_mint = || {
            let reverted = fixture
                .vault
                .derive_revert(binding.actor(), None, id(&minted["batch"]))
                .expect("revert mint");
            assert_eq!(reverted.reverted, vec!["owen".to_owned()]);
            assert!(reverted.left.is_empty());
            assert!(
                fixture
                    .vault
                    .archived_entity(&person_id)
                    .expect("read")
                    .is_some()
            );
        };
        if mint_first {
            revert_mint();
        }
        let reverted = fixture
            .vault
            .derive_revert(binding.actor(), None, id(&answered["batch"]))
            .expect("revert answer");
        assert!(reverted.reverted.is_empty());
        assert_eq!(
            reverted.left,
            vec![("owen".to_owned(), "derive.revert.no_inverse".to_owned())]
        );
        if mint_first {
            assert!(
                fixture
                    .vault
                    .archived_entity(&person_id)
                    .expect("read")
                    .is_some()
            );
        } else {
            assert!(
                fixture
                    .vault
                    .archived_entity(&person_id)
                    .expect("read")
                    .is_none()
            );
            assert!(row_live(&fixture.vault, person_id).expect("read"));
            assert_eq!(
                fixture.vault.get(&person_id).expect("read"),
                Some(body_before)
            );
            revert_mint();
        }
    }
}

/// A named record stored without the additive field must decode exactly as
/// the minting record; a missing serde default breaks this read.
#[test]
fn a_named_person_batch_without_row_ownership_decodes_unchanged() {
    let fixture = extraction_person_fixture();
    let turn = EntityId::from_hex(&fixture.turns[0].0).expect("a TURN");
    let minted = commit_bound_people(
        &fixture.binding,
        &fixture.turns,
        vec![person("owen", "Owen", &[turn])],
    );
    assert!(only_item(&minted).0, "{minted}");
    let record = fixture
        .vault
        .derive_batch(id(&minted["batch"]))
        .expect("read")
        .expect("batch");
    let bytes = rmp_serde::to_vec_named(&record).expect("a named record");
    let mut stored = rmpv::decode::read_value(&mut bytes.as_slice()).expect("a map");
    let rmpv::Value::Map(fields) = &mut stored else {
        panic!("a named map");
    };
    let Some((_, rmpv::Value::Array(items))) = fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("items"))
    else {
        panic!("items");
    };
    for item in items {
        let rmpv::Value::Map(fields) = item else {
            panic!("a named item");
        };
        assert!(
            fields
                .iter()
                .any(|(key, _)| key.as_str() == Some("row_stood_before"))
        );
        fields.retain(|(key, _)| key.as_str() != Some("row_stood_before"));
    }
    let mut old_bytes = Vec::new();
    rmpv::encode::write_value(&mut old_bytes, &stored).expect("the old named bytes");
    let decoded: oneiron::derive::DerivationBatchRecord =
        rmp_serde::from_slice(&old_bytes).expect("old record decodes");
    assert_eq!(decoded, record);
}
