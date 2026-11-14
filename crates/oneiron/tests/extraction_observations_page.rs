//! One bound extraction observations page, read as opaque facts without words.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test extraction_observations_page`.
#![cfg(oneiron_test_support)]

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::dreamer_runner::{DreamerAdmittedAttempt, DreamerAttemptBinding};
use oneiron::memory::{
    MEMORY_CODE_FORBIDDEN, MemoryResult, WitnessAssertions, WitnessAuthor, WitnessMessage,
    WitnessTurn,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::session_lifecycle::{
    SessionClosePredicate, SessionEndWake, SessionKey, SessionMintOutcome,
};
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::dreamer_attempt_binding::enqueue_strength_attempt;
use oneiron::test_doors::extraction_inputs::{
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{AttemptId, EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};
use std::sync::Arc;

/// Returns a fixture or assertion error without hiding its source.
type ObservationsTestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// The observations page an extraction attempt reads its operand facts through.
const OBSERVATIONS_PAGE_VERB: &str = "vault.consolidation.extraction.observations.page";

/// The inputs page an extraction attempt reads its turns and pins through.
const INPUTS_PAGE_VERB: &str = "vault.consolidation.extraction.inputs.page";

/// The queue clock every enqueue and admission here runs at, in seconds.
const QUEUE_NOW: u64 = 1_000;

/// The host clock the observations requests here carry, in Unix milliseconds.
const OBSERVATION_NOW_MS: u64 = 21_000;

/// Opens a vault the way the extraction verdict test does.
fn open_observations_vault(dir: &tempfile::TempDir) -> ObservationsTestResult<Vault> {
    drop(open_dreamer_vault(dir.path(), "owen")?);
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    Ok(vault)
}

/// Returns the attempt id as the page names it.
fn observation_attempt_hex(id: AttemptId) -> String {
    id.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Reads the extraction inputs page for `attempt` through `binding`.
fn read_bound_inputs_page(binding: &DreamerAttemptBinding, attempt: &str) -> MemoryResult<Value> {
    binding
        .invoke(INPUTS_PAGE_VERB, json!({"attempt": attempt}), None)
        .map(|answer| answer["value"].clone())
}

/// Reads the turn refs with their served versions from a bound inputs page.
fn page_turns_with_versions(page: &Value) -> Vec<(String, Value)> {
    page["turns"]
        .as_array()
        .unwrap_or_else(|| panic!("turns is an array"))
        .iter()
        .map(|served| {
            let turn = served["turn"]
                .as_str()
                .unwrap_or_else(|| panic!("the turn is a string"))
                .to_owned();
            (turn, served["version"].clone())
        })
        .collect()
}

/// Binds `admitted` in `vault` and returns the live extraction binding.
fn bind_observations(
    vault: &Arc<Vault>,
    admitted: &DreamerAdmittedAttempt,
) -> ObservationsTestResult<DreamerAttemptBinding> {
    Ok(vault.bind_dreamer_attempt(admitted)?)
}

/// Asks one bound observations page through `binding` with `request` as plain JSON.
fn invoke_observations(binding: &DreamerAttemptBinding, request: Value) -> MemoryResult<Value> {
    binding.invoke(OBSERVATIONS_PAGE_VERB, request, None)
}

/// Builds one candidate operand over `subject` and `predicate` with `value`, citing one turn.
fn observations_candidate(
    subject: &str,
    predicate: &str,
    value: Value,
    turn: &str,
    version: Value,
) -> Value {
    json!({
        "subject": subject,
        "predicate": predicate,
        "value": value,
        "evidence": [{"turn": turn, "version": version}],
    })
}

/// Builds one candidate operand citing every turn of `evidence` in order.
fn observations_candidate_with_evidence(
    subject: &str,
    predicate: &str,
    value: Value,
    evidence: &[(String, Value)],
) -> Value {
    let cited: Vec<Value> = evidence
        .iter()
        .map(|(turn, version)| json!({"turn": turn, "version": version.clone()}))
        .collect();
    json!({
        "subject": subject,
        "predicate": predicate,
        "value": value,
        "evidence": cited,
    })
}

/// Lands one Active Auto UserStated `preference.food` claim about `subject` with `value`.
fn land_user_stated_food_prior(
    vault: &Vault,
    subject: EntityId,
    value: &str,
) -> ObservationsTestResult<EntityId> {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        "preference.food",
        ClaimSubject::Entity(subject),
        RmpValue::from(value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
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

/// Witnesses three user turns saying `words` into `conversation`, across two sessions when asked.
fn witness_three_turns_in_sessions(
    vault: &Vault,
    conversation: EntityId,
    speaker: EntityId,
    session_key: SessionKey,
    words: [&str; 3],
    split_sessions: bool,
) -> ObservationsTestResult<Vec<EntityId>> {
    let first = match vault.mint_session(session_key, vault.now_recorded_at())? {
        SessionMintOutcome::Minted(session) => session,
        SessionMintOutcome::AlreadyOpen(_) => panic!("no session is open before the first mint"),
    };
    let mut turns = Vec::new();
    for word in words.iter().take(2) {
        turns.push(witness_session_turn(
            vault,
            conversation,
            speaker,
            session_key,
            word,
        )?);
    }
    if split_sessions {
        let ended = vault.end_session_with_wake(
            &first,
            SessionClosePredicate::Explicit,
            vault.now_recorded_at(),
            &SessionEndWake::none(first, 0),
        )?;
        if ended.is_none() {
            panic!("the first session closes");
        }
        match vault.mint_session(session_key, vault.now_recorded_at())? {
            SessionMintOutcome::Minted(second) => {
                if second == first {
                    panic!("the second session is a new sitting");
                }
            }
            SessionMintOutcome::AlreadyOpen(_) => panic!("the first session was closed"),
        }
    }
    turns.push(witness_session_turn(
        vault,
        conversation,
        speaker,
        session_key,
        words[2],
    )?);
    Ok(turns)
}

/// Witnesses one user turn saying `word` into `conversation` under `session_key`.
fn witness_session_turn(
    vault: &Vault,
    conversation: EntityId,
    speaker: EntityId,
    session_key: SessionKey,
    word: &str,
) -> ObservationsTestResult<EntityId> {
    let receipt = vault
        .memory(speaker, EdgeActorClass::Human)
        .with_session(session_key)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(EntityId::now().to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: word.to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: WitnessAssertions::default(),
        })?;
    Ok(receipt.turn_id)
}

/// Returns the candidate row of `index` from an observations page.
fn page_candidate(page: &Value, index: u64) -> Value {
    page["candidates"]
        .as_array()
        .unwrap_or_else(|| panic!("candidates is an array"))
        .iter()
        .find(|row| row["index"] == json!(index))
        .unwrap_or_else(|| panic!("the candidate row is served"))
        .clone()
}

/// Returns the prior row of `claim` from an observations page.
fn page_prior(page: &Value, claim: &str) -> Value {
    page["priors"]
        .as_array()
        .unwrap_or_else(|| panic!("priors is an array"))
        .iter()
        .find(|row| row["claim"] == json!(claim))
        .unwrap_or_else(|| panic!("the prior row is served"))
        .clone()
}

/// Reads a required string field from a page row.
fn row_text(row: &Value, field: &str) -> String {
    row[field]
        .as_str()
        .unwrap_or_else(|| panic!("the row names its field"))
        .to_owned()
}

/// A bound Extraction read serves the page with normalized tokens and a writable UserStated prior.
#[test]
fn bound_extraction_serves_normalized_tokens_and_writable_prior() -> ObservationsTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_observations_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let prior = land_user_stated_food_prior(&vault, subject, "green tea")?;
    let witnessed =
        witness_extraction_turns(&vault, &["owen savors green tea", "owen cooks daily"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_observations(&vault, &admitted)?;
    let inputs = read_bound_inputs_page(&binding, &observation_attempt_hex(id))?;
    let turns = page_turns_with_versions(&inputs);
    assert_eq!(turns.len(), 2, "both witnessed turns are served");
    let request = json!({
        "attempt": observation_attempt_hex(id),
        "now_ms": OBSERVATION_NOW_MS,
        "candidates": [
            observations_candidate(
                &subject.to_hex(),
                "preference.food",
                json!("  GREEN   Tea  "),
                &turns[0].0,
                turns[0].1.clone(),
            ),
            observations_candidate(
                &subject.to_hex(),
                "preference.food",
                json!("green tea"),
                &turns[1].0,
                turns[1].1.clone(),
            ),
        ],
    });
    let answer = invoke_observations(&binding, request);
    assert!(answer.is_ok(), "the extraction observations page answers");
    let page = answer.unwrap_or_else(|_| panic!("the page answered"))["value"].clone();
    assert_eq!(page["attempt"], json!(observation_attempt_hex(id)));
    assert_eq!(page["now_ms"], json!(OBSERVATION_NOW_MS));
    assert!(!row_text(&page, "policy_pin").is_empty());
    assert!(!row_text(&page, "facts_pin").is_empty());
    let first = page_candidate(&page, 0);
    let second = page_candidate(&page, 1);
    let head = page_prior(&page, &prior.to_hex());
    assert_eq!(
        row_text(&first, "value_token"),
        row_text(&second, "value_token")
    );
    assert_eq!(
        row_text(&first, "value_token"),
        row_text(&head, "value_token")
    );
    assert_eq!(
        row_text(&second, "value_token"),
        row_text(&head, "value_token")
    );
    assert_eq!(
        row_text(&first, "identity_token"),
        row_text(&head, "identity_token")
    );
    assert_eq!(
        row_text(&first, "topic_token"),
        row_text(&head, "topic_token")
    );
    assert_ne!(row_text(&first, "claim"), row_text(&second, "claim"));
    assert_eq!(row_text(&head, "source"), "user_stated".to_owned());
    assert_eq!(row_text(&head, "standing"), "prior".to_owned());
    assert_eq!(head["writable"], json!(true));
    assert_eq!(row_text(&first, "predicate"), "preference.food".to_owned());
    Ok(())
}

/// Three user turns across two live sessions observe, while one session does not.
#[test]
fn three_user_turns_observe_across_two_live_sessions_only() -> ObservationsTestResult<()> {
    for split_sessions in [true, false] {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(open_observations_vault(&dir)?);
        let actor = dreamer(&vault)?;
        stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
        let subject = EntityId::now();
        vault.put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"owen",
        )?;
        let conversation = EntityId::now();
        let session_key = vault.local_session_key(subject)?;
        let turns = witness_three_turns_in_sessions(
            &vault,
            conversation,
            subject,
            session_key,
            [
                "I choose green tea.",
                "Green tea again.",
                "Green tea this time too.",
            ],
            split_sessions,
        )?;
        let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &turns, QUEUE_NOW)?;
        let binding = bind_observations(&vault, &admitted)?;
        let inputs = read_bound_inputs_page(&binding, &observation_attempt_hex(id))?;
        let served = page_turns_with_versions(&inputs);
        assert_eq!(served.len(), 3, "all three session turns are served");
        let request = json!({
            "attempt": observation_attempt_hex(id),
            "now_ms": OBSERVATION_NOW_MS,
            "candidates": [
                observations_candidate_with_evidence(
                    &subject.to_hex(),
                    "preference.food",
                    json!("green tea"),
                    &served,
                ),
            ],
        });
        let answer = invoke_observations(&binding, request);
        assert!(answer.is_ok(), "the extraction observations page answers");
        let page = answer.unwrap_or_else(|_| panic!("the page answered"))["value"].clone();
        let only = page_candidate(&page, 0);
        assert_eq!(only["observed"], json!(split_sessions));
        assert_eq!(
            only["evidence_count"]
                .as_u64()
                .unwrap_or_else(|| panic!("evidence_count is a count")),
            3
        );
    }
    Ok(())
}

/// The serialized page carries tokens and counts, never operand or prior words.
#[test]
fn serialized_page_carries_no_operand_prior_or_speaker_words() -> ObservationsTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_observations_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    land_user_stated_food_prior(&vault, subject, "papaya custard")?;
    let witnessed =
        witness_extraction_turns(&vault, &["owen writes ginger broth to owen@example.com"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_observations(&vault, &admitted)?;
    let inputs = read_bound_inputs_page(&binding, &observation_attempt_hex(id))?;
    let turns = page_turns_with_versions(&inputs);
    assert_eq!(turns.len(), 1, "the witnessed turn is served");
    let request = json!({
        "attempt": observation_attempt_hex(id),
        "now_ms": OBSERVATION_NOW_MS,
        "candidates": [
            observations_candidate(
                &subject.to_hex(),
                "preference.food",
                json!("ginger broth"),
                &turns[0].0,
                turns[0].1.clone(),
            ),
        ],
    });
    let answer = invoke_observations(&binding, request);
    assert!(answer.is_ok(), "the extraction observations page answers");
    let page = answer.unwrap_or_else(|_| panic!("the page answered"))["value"].clone();
    let serialized = serde_json::to_string(&page)?;
    for word in [
        "papaya",
        "custard",
        "ginger",
        "broth",
        "owen@example.com",
        "owen",
        "yuki",
    ] {
        assert!(
            !serialized.contains(word),
            "the serialized page carries no source word"
        );
    }
    Ok(())
}

/// A cursor read after a graph change refuses as stale.
#[test]
fn cursor_read_after_graph_change_refuses_as_stale() -> ObservationsTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_observations_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed =
        witness_extraction_turns(&vault, &["owen savors green tea", "owen cooks daily"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_observations(&vault, &admitted)?;
    let inputs = read_bound_inputs_page(&binding, &observation_attempt_hex(id))?;
    let turns = page_turns_with_versions(&inputs);
    assert_eq!(turns.len(), 2, "both witnessed turns are served");
    let candidates = json!([
        observations_candidate(
            &subject.to_hex(),
            "preference.food",
            json!("green tea"),
            &turns[0].0,
            turns[0].1.clone(),
        ),
        observations_candidate(
            &subject.to_hex(),
            "preference.food",
            json!("black coffee"),
            &turns[1].0,
            turns[1].1.clone(),
        ),
    ]);
    let first = json!({
        "attempt": observation_attempt_hex(id),
        "now_ms": OBSERVATION_NOW_MS,
        "candidates": candidates.clone(),
        "limit": 1,
    });
    let answer = invoke_observations(&binding, first);
    assert!(answer.is_ok(), "the first observations page answers");
    let page = answer.unwrap_or_else(|_| panic!("the page answered"))["value"].clone();
    let cursor = page["next"]
        .as_str()
        .unwrap_or_else(|| panic!("the first page names its cursor"))
        .to_owned();
    vault
        .batch()
        .edge_with_created_at(
            &witnessed.turns[0],
            EdgeKind::Mentions,
            &subject,
            1.0,
            5_000,
        )
        .commit()?;
    let planted = vault.edges_in(&subject)?;
    assert_eq!(planted.len(), 1, "one incoming edge is planted");
    let second = json!({
        "attempt": observation_attempt_hex(id),
        "now_ms": OBSERVATION_NOW_MS,
        "candidates": candidates,
        "cursor": cursor,
        "limit": 1,
    });
    let stale = invoke_observations(&binding, second);
    assert!(stale.is_err(), "a cursor after a graph change is stale");
    Ok(())
}

/// A Strength-bound binding is refused for the observations verb.
#[test]
fn strength_binding_is_refused_for_observations() -> ObservationsTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_observations_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let witnessed = witness_extraction_turns(&vault, &["owen savors green tea"])?;
    let (id, _) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let strength = enqueue_strength_attempt(&vault, id, QUEUE_NOW)?;
    let binding = vault.bind_dreamer_attempt(&strength)?;
    let refused = invoke_observations(
        &binding,
        json!({
            "attempt": observation_attempt_hex(id),
            "now_ms": OBSERVATION_NOW_MS,
            "candidates": [],
        }),
    );
    let Err(error) = refused else {
        panic!("a strength binding is refused");
    };
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN);
    Ok(())
}

/// The request clock decides the freshness of one incoming edge.
#[test]
fn request_clock_decides_freshness_of_one_incoming_edge() -> ObservationsTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_observations_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "yuki", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, &["yuki walks daily"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_observations(&vault, &admitted)?;
    let inputs = read_bound_inputs_page(&binding, &observation_attempt_hex(id))?;
    let turns = page_turns_with_versions(&inputs);
    assert_eq!(turns.len(), 1, "the witnessed turn is served");
    let created_at = 5_000;
    vault
        .batch()
        .edge_with_created_at(
            &witnessed.turns[0],
            EdgeKind::Mentions,
            &subject,
            1.0,
            created_at,
        )
        .commit()?;
    let planted = vault.edges_in(&subject)?;
    assert_eq!(planted.len(), 1, "one incoming edge is planted");
    assert_eq!(planted[0].created_at, created_at);
    for (now_ms, new_refs) in [
        ((created_at - 5) * 1_000, 1_u64),
        ((created_at + 5) * 1_000, 0_u64),
    ] {
        let request = json!({
            "attempt": observation_attempt_hex(id),
            "now_ms": now_ms,
            "candidates": [
                observations_candidate(
                    &subject.to_hex(),
                    "profile.name",
                    json!("yuki"),
                    &turns[0].0,
                    turns[0].1.clone(),
                ),
            ],
        });
        let answer = invoke_observations(&binding, request);
        assert!(answer.is_ok(), "the extraction observations page answers");
        let page = answer.unwrap_or_else(|_| panic!("the page answered"))["value"].clone();
        let only = page_candidate(&page, 0);
        assert_eq!(
            only["fan_in"]
                .as_u64()
                .unwrap_or_else(|| panic!("fan_in is a count")),
            1
        );
        assert_eq!(
            only["new_refs"]
                .as_u64()
                .unwrap_or_else(|| panic!("new_refs is a count")),
            new_refs
        );
        assert_eq!(only["has_vector"], json!(false));
    }
    Ok(())
}
