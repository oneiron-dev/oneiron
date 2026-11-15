//! Restriction wave 8 (owner 16 Nov 00:44, "optional freedom with good defaults everywhere"):
//! fixed bounds become owner keys on the Setting primitive, each defaulting to today's value, so
//! nothing changes until the owner moves one.
//! - `receipt.action.max_input_entities` (default 64): an action naming more entities states no
//!   input digest; the owner may raise the cap.
//! - `derive.batch.max_items` (default 256, never below it): a larger derivation batch is
//!   malformed; the owner may raise the cap.
//! - `note.birth.agent_min_chars` (default 16): an agent's NOTE born shorter is refused; the
//!   owner may lower the floor.
//! - `actor_claims.note.max_bytes` (default 1024, within 4..=16384): a longer actor note this
//!   vault writes is refused; the owner may raise the cap (Engine RULING RESTRICTION-WAVE-8-ROWS,
//!   C95 = A).
//! - `claim.observed_preference.min_observations` / `.min_sessions` (defaults 3 and 2, at least
//!   1): the bar an Observed preference meets; the owner may lower it for preferences about the
//!   owner, and every other person keeps three across two (same RULING, C96 = C).
//!
//! For each key, a moved value lets the formerly refused act stand, and the default refuses it
//! exactly as before.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test restriction_wave_8`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use oneiron::actor_claims::{ActorClaimEvidence, ActorClaimRow, write_actor_claim};
use oneiron::claim::ClaimSource;
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use oneiron::session_lifecycle::{
    SessionClosePredicate, SessionEndWake, SessionKey, SessionMintOutcome,
};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{
    Claim, Committed, Named, commit_claims, define_auto_agent, grant_derive_rows,
};
use oneiron::test_doors::steward::dreamer;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

const INPUT_ENTITIES_KEY: &str = "receipt.action.max_input_entities";
const BATCH_ITEMS_KEY: &str = "derive.batch.max_items";
const AGENT_NOTE_KEY: &str = "note.birth.agent_min_chars";
const NOTE_CAP_KEY: &str = "actor_claims.note.max_bytes";
const OBSERVATIONS_KEY: &str = "claim.observed_preference.min_observations";
const SESSIONS_KEY: &str = "claim.observed_preference.min_sessions";

/// The owner's change of `key` at the vault scope, as the Setting door answers it.
fn owner_sets(vault: &Vault, key: &str, value: Value) -> oneiron::Result<SetSettingOutcome> {
    let actor = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the embedded owner");
    let owner = vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: the owner's proof");
    vault.set_setting(
        SettingCaller::Owner(&owner),
        SetSetting::vault_value(key, value),
    )
}

/// The owner moves `key` to `value`, and the change applies.
fn owner_moves(vault: &Vault, key: &str, value: Value) {
    let outcome = owner_sets(vault, key, value).expect("the owner's change");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "FIXTURE: the owner's change did not apply: {outcome:?}"
    );
}

fn plain_vault(dir: &tempfile::TempDir) -> Vault {
    Vault::open(dir.path(), VaultConfig::default()).expect("open vault")
}

fn put(vault: &Vault, entity_type: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_entity(&id, entity_type, TimeRange { start: at, end: at }, at, body)
        .expect("a row");
    id
}

fn named_entities(count: usize) -> BTreeSet<EntityId> {
    let mut named = BTreeSet::new();
    while named.len() < count {
        named.insert(EntityId::now());
    }
    named
}

// receipt.action.max_input_entities

#[test]
fn an_owner_raised_input_entity_cap_versions_a_wider_action() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = plain_vault(&dir);
    owner_moves(&vault, INPUT_ENTITIES_KEY, json!(65));
    let named = named_entities(65);
    let inputs = vault
        .action_inputs(&named)
        .expect("the capture reads")
        .expect("65 named entities fit the owner's cap of 65");
    let text = format!("{inputs:?}");
    for id in &named {
        assert!(
            text.contains(&format!("entity:{}", id.to_hex())),
            "every named entity is versioned: {text}"
        );
    }
}

#[test]
fn an_action_naming_more_than_64_entities_states_no_input_digest_by_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = plain_vault(&dir);
    assert!(
        vault
            .action_inputs(&named_entities(65))
            .expect("the capture reads")
            .is_none(),
        "65 named entities pass the default cap of 64: no input digest"
    );
    assert!(
        vault
            .action_inputs(&named_entities(64))
            .expect("the capture reads")
            .is_some(),
        "64 named entities are versioned under the default"
    );
}

// derive.batch.max_items

/// `count` claims about one person, each citing nothing: each is judged alone (and refused by
/// the evidence floor); the batch itself commits when its size is admitted.
fn claims_about(person: EntityId, count: usize) -> Vec<Claim> {
    (0..count)
        .map(|index| Claim {
            local: Box::leak(format!("claim-{index}").into_boxed_str()),
            predicate: "preference.coffee",
            subject: Named::Stored(person),
            value: json!(format!("cup {index}")),
            evidence: Vec::new(),
        })
        .collect()
}

fn commit_batch_of(vault: &Vault, count: usize) -> oneiron::Result<Committed> {
    let person = put(vault, ENTITY_TYPE_PERSON, b"someone");
    let actor = dreamer(vault).expect("the Dreamer");
    commit_claims(
        vault,
        actor,
        EdgeActorClass::System,
        "run-batch-cap",
        &claims_about(person, count),
    )
}

#[test]
fn an_owner_raised_batch_cap_commits_a_larger_derivation_batch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), "reader").expect("vault");
    owner_moves(&vault, BATCH_ITEMS_KEY, json!(257));
    let committed = commit_batch_of(&vault, 257).expect("257 items fit the owner's cap of 257");
    assert_eq!(committed.items.len(), 257, "every item has its outcome");
}

#[test]
fn a_derivation_batch_over_256_items_is_malformed_by_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), "reader").expect("vault");
    let refused = commit_batch_of(&vault, 257).expect_err("257 items pass the default cap");
    assert!(
        format!("{refused:?}").contains("derive.batch.max_items"),
        "the batch is malformed by its size: {refused:?}"
    );
    let committed = commit_batch_of(&vault, 256).expect("256 items fit the default cap");
    assert_eq!(committed.items.len(), 256);
}

#[test]
fn a_batch_cap_below_256_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), "reader").expect("vault");
    let refused = owner_sets(&vault, BATCH_ITEMS_KEY, json!(255))
        .expect_err("the engine's own jobs fill 256-item batches");
    assert!(
        format!("{refused:?}").contains("at least 256"),
        "the cap's own check refuses it: {refused:?}"
    );
    owner_moves(&vault, BATCH_ITEMS_KEY, json!(256));
}

// note.birth.agent_min_chars

fn agent(vault: &Vault) -> EntityId {
    put(vault, ENTITY_TYPE_PERSON, b"agent")
}

const SHORT_NOTE: &str = "Low tide.";
const SIXTEEN_CHARS: &str = "Low tide at six.";

#[test]
fn an_owner_lowered_agent_note_floor_lets_a_short_agent_note_land() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = plain_vault(&dir);
    let agent = agent(&vault);
    owner_moves(&vault, AGENT_NOTE_KEY, json!(8));
    vault
        .memory(agent, EdgeActorClass::Agent)
        .create_note("research", SHORT_NOTE)
        .expect("a 9-character agent NOTE meets the owner's floor of 8");
}

#[test]
fn an_agent_note_under_16_chars_is_refused_by_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = plain_vault(&dir);
    let agent = agent(&vault);
    let memory = vault.memory(agent, EdgeActorClass::Agent);
    let refused = memory
        .create_note("research", SHORT_NOTE)
        .expect_err("a 9-character agent NOTE is under the default floor of 16");
    assert!(
        format!("{refused:?}").contains("under the minimum length"),
        "the birth floor refuses it: {refused:?}"
    );
    assert_eq!(SIXTEEN_CHARS.chars().count(), 16);
    memory
        .create_note("research", SIXTEEN_CHARS)
        .expect("a 16-character agent NOTE meets the default floor");
}

// actor_claims.note.max_bytes

/// A PERSON actor and chat evidence for one note about it: a SESSION and a user TURN.
fn actor_note_fixture(vault: &Vault) -> (EntityId, ActorClaimEvidence) {
    let actor = put(vault, ENTITY_TYPE_PERSON, b"learner");
    let session = put(vault, ENTITY_TYPE_SESSION, b"session");
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")]))
        .expect("a TURN body");
    let turn = put(vault, ENTITY_TYPE_TURN, &body);
    let evidence = ActorClaimEvidence::chat(session, vec![turn], 20).expect("chat evidence");
    (actor, evidence)
}

/// A lesson of `bytes` bytes and no whitespace, so normalizing keeps every byte.
fn lesson_of(actor: EntityId, bytes: usize, letter: char) -> ActorClaimRow {
    ActorClaimRow::Lesson {
        actor,
        text: letter.to_string().repeat(bytes),
    }
}

#[test]
fn an_owner_raised_note_cap_lets_a_longer_actor_note_land() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = plain_vault(&dir);
    let (actor, evidence) = actor_note_fixture(&vault);
    owner_moves(&vault, NOTE_CAP_KEY, json!(2048));
    assert_eq!(vault.actor_note_max_bytes().expect("the cap reads"), 2048);
    write_actor_claim(&vault, lesson_of(actor, 1500, 'a'), &evidence)
        .expect("a 1500-byte note fits the owner's cap of 2048");
}

#[test]
fn an_actor_note_over_1024_bytes_is_refused_by_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = plain_vault(&dir);
    let (actor, evidence) = actor_note_fixture(&vault);
    let refused = write_actor_claim(&vault, lesson_of(actor, 1025, 'a'), &evidence)
        .expect_err("a 1025-byte note passes the default cap of 1024");
    assert!(
        format!("{refused:?}").contains("exceeds the note length bound"),
        "the note bound refuses it: {refused:?}"
    );
    write_actor_claim(&vault, lesson_of(actor, 1024, 'b'), &evidence)
        .expect("a 1024-byte note fits the default cap");
}

#[test]
fn a_note_cap_outside_4_to_16384_bytes_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = plain_vault(&dir);
    for cap in [3, 16_385] {
        let refused = owner_sets(&vault, NOTE_CAP_KEY, json!(cap))
            .expect_err("the cap stays within one character and the structural ceiling");
        assert!(
            format!("{refused:?}").contains("between 4 and 16384"),
            "the cap's own check refuses {cap}: {refused:?}"
        );
    }
    owner_moves(&vault, NOTE_CAP_KEY, json!(16_384));
}

// claim.observed_preference.min_observations / min_sessions

struct PreferenceFixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    agent: EntityId,
    subject: EntityId,
    session_key: SessionKey,
}

/// A Dreamer vault with an Auto agent that derives, and a preference subject: the vault's owner,
/// or another person.
fn preference_fixture(subject_is_owner: bool) -> PreferenceFixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), "reader").expect("vault");
    let agent = define_auto_agent(&vault).expect("an Auto agent");
    grant_derive_rows(&vault, &[agent]).expect("the agent's policy rows");
    let subject = if subject_is_owner {
        vault.ensure_embedded_owner_actor().expect("embedded owner")
    } else {
        put(&vault, ENTITY_TYPE_PERSON, b"owen")
    };
    let session_key = vault.local_session_key(subject).expect("a session key");
    PreferenceFixture {
        _dir: dir,
        vault,
        agent,
        subject,
        session_key,
    }
}

fn witness_user_turn(fixture: &PreferenceFixture, words: &str) -> EntityId {
    let turn = EntityId::now();
    let receipt = fixture
        .vault
        .memory(fixture.subject, EdgeActorClass::Human)
        .with_session(fixture.session_key)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: words.to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: fixture.vault.now_recorded_at(),
            assertions: WitnessAssertions::default(),
        })
        .expect("a witnessed TURN");
    assert_eq!(receipt.turn_id, turn);
    turn
}

/// User TURNs in consecutive sessions, `per_session[i]` of them in the i-th; each session closes
/// before the next opens.
fn user_turns_in_sessions(fixture: &PreferenceFixture, per_session: &[usize]) -> Vec<EntityId> {
    let mut turns = Vec::new();
    for (index, count) in per_session.iter().enumerate() {
        let SessionMintOutcome::Minted(session) = fixture
            .vault
            .mint_session(fixture.session_key, fixture.vault.now_recorded_at())
            .expect("a session opens")
        else {
            panic!("a session of the fixture was still open");
        };
        for turn in 0..*count {
            turns.push(witness_user_turn(
                fixture,
                &format!("Green tea in sitting {index}, turn {turn}."),
            ));
        }
        fixture
            .vault
            .end_session_with_wake(
                &session,
                SessionClosePredicate::Explicit,
                fixture.vault.now_recorded_at(),
                &SessionEndWake::none(session, 0),
            )
            .expect("the session closes")
            .expect("the session was open");
    }
    turns
}

/// The source a derived preference claim citing `evidence` lands with. Each call names its own
/// predicate, so no two claims of one test meet as duplicates.
fn derived_preference_source(
    fixture: &PreferenceFixture,
    predicate: &'static str,
    evidence: &[EntityId],
) -> ClaimSource {
    let committed = commit_claims(
        &fixture.vault,
        fixture.agent,
        EdgeActorClass::Agent,
        "run-preference-bar",
        &[Claim {
            local: "preference",
            predicate,
            subject: Named::Stored(fixture.subject),
            value: json!("green tea"),
            evidence: evidence.iter().copied().map(Named::Stored).collect(),
        }],
    )
    .expect("the batch commits");
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(item.landed, "the claim lands: {:?}", item.reasons);
    let [claim] = item.rows.as_slice() else {
        panic!("one claim row: {:?}", item.rows);
    };
    fixture
        .vault
        .get_claim(claim)
        .expect("read")
        .expect("the claim")
        .source
        .expect("a stamped source")
}

#[test]
fn an_owner_lowered_session_bar_observes_an_owner_preference_in_one_session() {
    let fixture = preference_fixture(true);
    owner_moves(&fixture.vault, SESSIONS_KEY, json!(1));
    let evidence = user_turns_in_sessions(&fixture, &[3]);
    assert_eq!(
        derived_preference_source(&fixture, "preference.drink", &evidence),
        ClaimSource::Observed,
        "three of the owner's TURNs in one session meet the owner's bar of one session"
    );
}

#[test]
fn an_owner_lowered_observation_bar_observes_an_owner_preference_on_two_turns() {
    let fixture = preference_fixture(true);
    owner_moves(&fixture.vault, OBSERVATIONS_KEY, json!(2));
    let evidence = user_turns_in_sessions(&fixture, &[1, 1]);
    assert_eq!(
        derived_preference_source(&fixture, "preference.drink", &evidence),
        ClaimSource::Observed,
        "two of the owner's TURNs across two sessions meet the owner's bar of two"
    );
}

#[test]
fn an_owner_preference_below_three_across_two_stays_generated_by_default() {
    let fixture = preference_fixture(true);
    let one_session = user_turns_in_sessions(&fixture, &[3]);
    assert_eq!(
        derived_preference_source(&fixture, "preference.drink", &one_session),
        ClaimSource::Generated
    );
    let two_turns = user_turns_in_sessions(&fixture, &[1, 1]);
    assert_eq!(
        derived_preference_source(&fixture, "preference.tea", &two_turns),
        ClaimSource::Generated
    );
}

#[test]
fn another_persons_preference_keeps_three_across_two_whatever_the_owner_sets() {
    let fixture = preference_fixture(false);
    owner_moves(&fixture.vault, OBSERVATIONS_KEY, json!(1));
    owner_moves(&fixture.vault, SESSIONS_KEY, json!(1));
    let one_session = user_turns_in_sessions(&fixture, &[3]);
    assert_eq!(
        derived_preference_source(&fixture, "preference.drink", &one_session),
        ClaimSource::Generated,
        "the owner's bar never applies to another person's preference"
    );
    let canon = user_turns_in_sessions(&fixture, &[2, 1]);
    assert_eq!(
        derived_preference_source(&fixture, "preference.tea", &canon),
        ClaimSource::Observed,
        "three TURNs across two sessions still meet canon's bar"
    );
}

#[test]
fn an_observed_preference_count_of_zero_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = plain_vault(&dir);
    for key in [OBSERVATIONS_KEY, SESSIONS_KEY] {
        let refused = owner_sets(&vault, key, json!(0))
            .expect_err("an Observed stamp always rests on an observation");
        assert!(
            format!("{refused:?}").contains("at least 1"),
            "the count's own check refuses 0 for {key}: {refused:?}"
        );
    }
}
