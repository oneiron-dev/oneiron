//! The Dreamer's strength diversity counts each (sitting, speaker) pair once
//! (FIX 395, RULING FIX395-DIVERSITY-KEY = C): a fact the owner repeats in
//! three sittings counts once per sitting, not once for its one speaker, and
//! two speakers in one sitting count apart. A TURN witnessed in no sitting
//! keeps its bare speaker key.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test strength_diversity_sittings`.
#![cfg(oneiron_test_support)]

use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::session_lifecycle::{
    SessionClosePredicate, SessionEndWake, SessionKey, SessionMintOutcome,
};
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::consolidation::{consolidate_unbound_turn, open_dreamer_vault};
use oneiron::test_doors::steward::record_strength_observations;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

type DiversityTestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// A vault holding one Dreamer claim, `profile.name` = owen, landed from a
/// user TURN witnessed in no sitting, and a speaker whose sittings repeat it.
struct SittingFixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    claim: EntityId,
    landing_turn: EntityId,
    speaker: EntityId,
    key: SessionKey,
}

fn sitting_fixture() -> DiversityTestResult<SittingFixture> {
    let dir = tempfile::tempdir()?;
    drop(open_dreamer_vault(dir.path(), "owen")?);
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    let reply = json!({
        "persons": [{"id": "new:P1", "name": "owen", "evidence_turn_refs": ["T1"]}],
        "candidates": [{
            "subject": "new:P1",
            "predicate": "profile.name",
            "value": "owen",
            "confidence": 0.8,
            "evidence_refs": [{"source": "T1", "quote": "owen"}],
        }],
    })
    .to_string();
    let pass = consolidate_unbound_turn(&vault, "call me owen", None, None, &reply)?;
    assert_eq!(pass.landed.len(), 1);
    let speaker = EntityId::now();
    let now = vault.now_recorded_at();
    vault.put_entity(
        &speaker,
        ENTITY_TYPE_PERSON,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        b"owen",
    )?;
    let key = vault.local_session_key(speaker)?;
    Ok(SittingFixture {
        _dir: dir,
        vault,
        claim: pass.landed[0],
        landing_turn: pass.turn,
        speaker,
        key,
    })
}

/// Opens a fresh sitting for the fixture's speaker; its SESSION id.
fn open_sitting(fixture: &SittingFixture) -> DiversityTestResult<EntityId> {
    let SessionMintOutcome::Minted(session) = fixture
        .vault
        .mint_session(fixture.key, fixture.vault.now_recorded_at())?
    else {
        return Err("a sitting was already open".into());
    };
    Ok(session)
}

fn close_sitting(fixture: &SittingFixture, session: EntityId) -> DiversityTestResult<()> {
    let ended = fixture.vault.end_session_with_wake(
        &session,
        SessionClosePredicate::Explicit,
        fixture.vault.now_recorded_at(),
        &SessionEndWake::none(session, 0),
    )?;
    if ended.is_none() {
        return Err("the sitting was not open".into());
    }
    Ok(())
}

/// Witnesses `words` by `author` as one TURN of a fresh conversation, bound
/// to the open sitting when `in_sitting`; the TURN.
fn witness_words(
    fixture: &SittingFixture,
    author: WitnessAuthor,
    words: &str,
    in_sitting: bool,
) -> DiversityTestResult<EntityId> {
    let turn = EntityId::now();
    let memory = fixture.vault.memory(fixture.speaker, EdgeActorClass::Human);
    let memory = if in_sitting {
        memory.with_session(fixture.key)
    } else {
        memory
    };
    let receipt = memory.witness(&WitnessTurn {
        conversation_ref: EntityId::now().to_hex(),
        turn_ref: Some(turn.to_hex()),
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: Some(EntityId::now().to_hex()),
            author,
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
    })?;
    assert_eq!(receipt.turn_id, turn);
    Ok(turn)
}

/// Records `sources` as the claim's further evidence at the gated promotion
/// door, then reads the claim's signals from the owner's observation page.
fn observed_signals(fixture: &SittingFixture, sources: &[EntityId]) -> DiversityTestResult<Value> {
    let now_ms = fixture
        .vault
        .now_recorded_at()
        .saturating_add(1)
        .saturating_mul(1_000);
    record_strength_observations(&fixture.vault, fixture.claim, sources, now_ms)?;
    let owner = fixture.vault.ensure_embedded_owner_actor()?;
    let page = invoke(
        &fixture.vault.memory(owner, EdgeActorClass::Human),
        "vault.consolidation.strength.observations.page",
        json!({}),
    )?;
    let claims = page["value"]["claims"]
        .as_array()
        .unwrap_or_else(|| panic!("claims is an array: {page}"));
    assert_eq!(claims.len(), 1, "one observed claim: {page}");
    let observed = &claims[0];
    assert_eq!(observed["claim"], fixture.claim.to_hex());
    assert_eq!(
        observed["status"], "current",
        "every source still reads: {observed}"
    );
    Ok(observed["signals"].clone())
}

#[test]
fn a_fact_the_owner_repeats_in_three_sittings_counts_once_per_sitting() -> DiversityTestResult<()> {
    let fixture = sitting_fixture()?;
    // A repeat in no sitting keeps the bare speaker key the landing TURN has.
    let mut sources = vec![witness_words(
        &fixture,
        WitnessAuthor::User,
        "owen, as I said",
        false,
    )?];
    // The first sitting repeats the fact twice; it is one sitting.
    let first = open_sitting(&fixture)?;
    sources.push(witness_words(
        &fixture,
        WitnessAuthor::User,
        "call me owen",
        true,
    )?);
    sources.push(witness_words(
        &fixture,
        WitnessAuthor::User,
        "yes, owen",
        true,
    )?);
    close_sitting(&fixture, first)?;
    for words in ["it is owen", "owen, again"] {
        let sitting = open_sitting(&fixture)?;
        sources.push(witness_words(&fixture, WitnessAuthor::User, words, true)?);
        close_sitting(&fixture, sitting)?;
    }
    let signals = observed_signals(&fixture, &sources)?;
    assert_eq!(
        signals["source_count"],
        sources.len() + 1,
        "the landing TURN {} and every repeat are sources: {signals}",
        fixture.landing_turn
    );
    // On main every user TURN counts as the one speaker `user`: 1. Each of
    // the three sittings counts once beside the bare `user` key: 4.
    assert_eq!(
        signals["distinct_diversity"], 4,
        "the bare speaker key and one key per sitting: {signals}"
    );
    Ok(())
}

#[test]
fn two_speakers_in_one_sitting_count_apart_and_again_in_the_next() -> DiversityTestResult<()> {
    let fixture = sitting_fixture()?;
    let mut sources = Vec::new();
    for (user_words, counterparty_words) in [
        ("call me owen", "hi owen"),
        ("it is owen", "good to see you, owen"),
    ] {
        let sitting = open_sitting(&fixture)?;
        sources.push(witness_words(
            &fixture,
            WitnessAuthor::User,
            user_words,
            true,
        )?);
        sources.push(witness_words(
            &fixture,
            WitnessAuthor::Counterparty,
            counterparty_words,
            true,
        )?);
        close_sitting(&fixture, sitting)?;
    }
    let signals = observed_signals(&fixture, &sources)?;
    assert_eq!(signals["source_count"], sources.len() + 1);
    // On main the speakers `user` and `counterparty` count once each: 2.
    // Each sitting counts both of its speakers, beside the landing TURN's
    // bare `user` key: 1 + 2 + 2 = 5.
    assert_eq!(
        signals["distinct_diversity"], 5,
        "one key per (sitting, speaker) pair: {signals}"
    );
    Ok(())
}
