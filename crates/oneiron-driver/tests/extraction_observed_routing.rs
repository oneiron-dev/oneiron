//! Checks the observed-beside-stated route before any lender call or write.
#![cfg(oneiron_test_support)]

#[path = "extraction_observed_routing/support.rs"]
mod support;

use std::sync::Arc;

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::dreamer_consolidation::selection::SelectionConfig;
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::session_lifecycle::{
    SessionClosePredicate, SessionEndWake, SessionKey, SessionMintOutcome,
};
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::extraction_inputs::enqueue_admitted_extraction_attempt;
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_dreamer::extraction_observations::read_observations;
use oneiron_dreamer::extraction_selection::ExtractionSelectionConfig;
use oneiron_remote::OneironClient;
use rmpv::Value as RmpValue;
use serde_json::{Value, json};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Holds the live bound attempt and the facts used by either route adapter.
struct Fixture {
    _directory: tempfile::TempDir,
    vault: Arc<Vault>,
    client: OneironClient,
    attempt: String,
    now_ms: u64,
    operands: Vec<Value>,
    config: ExtractionSelectionConfig,
    policy_pin: String,
    stated: String,
    observed: bool,
}

impl Fixture {
    /// Calls the replaceable adapter without invoking a lender.
    fn routes(&self) -> TestResult<Value> {
        support::routes(
            &self.vault,
            &self.client,
            &self.attempt,
            self.now_ms,
            &self.operands,
            &self.config,
            &self.policy_pin,
        )
    }
}

/// Lands the Active Auto UserStated head that both adapters must see.
fn land_stated_head(vault: &Vault, subject: EntityId) -> TestResult<EntityId> {
    let head = EntityId::now();
    let mut body = ClaimBody::new(
        "preference.food",
        ClaimSubject::Entity(subject),
        RmpValue::from("green tea"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    body.scope_facet = vault.default_facet()?;
    let now = vault.now_recorded_at();
    vault.put_claim(
        &head,
        &body,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    Ok(head)
}

/// Witnesses one user TURN with live session membership through the memory door.
fn witness_turn(
    vault: &Vault,
    conversation: EntityId,
    speaker: EntityId,
    session_key: SessionKey,
    words: &str,
) -> TestResult<EntityId> {
    Ok(vault
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
                content: words.to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: WitnessAssertions::default(),
        })?
        .turn_id)
}

/// Witnesses three user TURNs under one or two live sessions.
fn witness_sessions(
    vault: &Vault,
    subject: EntityId,
    value: &str,
    split_sessions: bool,
) -> TestResult<Vec<EntityId>> {
    let conversation = EntityId::now();
    let key = vault.local_session_key(subject)?;
    let SessionMintOutcome::Minted(first) = vault.mint_session(key, vault.now_recorded_at())?
    else {
        return Err("the first session must be fresh".into());
    };
    let words = format!("owen chooses {value}.");
    let mut turns = vec![
        witness_turn(vault, conversation, subject, key, &words)?,
        witness_turn(vault, conversation, subject, key, &words)?,
    ];
    if split_sessions {
        if vault
            .end_session_with_wake(
                &first,
                SessionClosePredicate::Explicit,
                vault.now_recorded_at(),
                &SessionEndWake::none(first, 0),
            )?
            .is_none()
        {
            return Err("the first session must close".into());
        }
        let SessionMintOutcome::Minted(second) =
            vault.mint_session(key, vault.now_recorded_at())?
        else {
            return Err("the second session must be fresh".into());
        };
        if second == first {
            return Err("the second session must differ".into());
        }
    }
    turns.push(witness_turn(vault, conversation, subject, key, &words)?);
    Ok(turns)
}

/// Builds three user TURNs across one or two sessions and binds one extraction attempt.
fn fixture(value: &str, split_sessions: bool) -> TestResult<Fixture> {
    let directory = tempfile::tempdir()?;
    drop(open_dreamer_vault(directory.path(), "owen")?);
    let vault = Vault::open_owned(directory.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    let vault = Arc::new(vault);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    vault.set_consolidation_selection(&SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 1,
        ..vault.consolidation_selection()?
    })?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let stated = land_stated_head(&vault, subject)?.to_hex();
    let turns = witness_sessions(&vault, subject, value, split_sessions)?;
    let (attempt, admitted) = enqueue_admitted_extraction_attempt(&vault, &turns, 1_000)?;
    let attempt: String = attempt
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let client = OneironClient::for_dreamer_attempt(vault.bind_dreamer_attempt(&admitted)?);
    let now_ms = vault
        .now_recorded_at()
        .saturating_add(1)
        .saturating_mul(1_000);
    let inputs = client.agent_verb(
        "vault.consolidation.extraction.inputs.page",
        json!({"attempt": attempt}),
    )?;
    let page = &inputs["value"];
    let policy_pin = page["policy_pin"]
        .as_str()
        .ok_or("missing policy pin")?
        .to_owned();
    let config = ExtractionSelectionConfig::from_selection(
        page["policy"]["selection"].clone(),
        &policy_pin,
    )?;
    let evidence: Vec<Value> = page["turns"]
        .as_array()
        .ok_or("missing turns")?
        .iter()
        .map(|turn| json!({"turn": turn["turn"], "version": turn["version"]}))
        .collect();
    if evidence.len() != 3 {
        return Err("the bound attempt must serve all three TURNs".into());
    }
    let operands = vec![json!({
        "subject": subject.to_hex(), "predicate": "preference.food", "value": value, "evidence": evidence,
    })];
    let observations = read_observations(&client, &attempt, now_ms, &operands)?;
    if !observations
        .priors
        .iter()
        .any(|prior| prior.claim == stated)
    {
        return Err("the stated head must be admitted before testing its route".into());
    }
    let observed = observations
        .candidates
        .first()
        .ok_or("missing candidate")?
        .observed;
    Ok(Fixture {
        _directory: directory,
        vault,
        client,
        attempt,
        now_ms,
        operands,
        config,
        policy_pin,
        stated,
        observed,
    })
}

#[test]
fn agreeing_observed_preference_keeps_its_own_claim() -> TestResult<()> {
    let fixture = fixture("green tea", true)?;
    let routes = fixture.routes()?;
    assert_eq!(
        routes["attachment_heads"],
        json!([]),
        "an observed preference never attaches to the stated head"
    );
    assert_eq!(routes["own_claims"], json!([0]));
    assert!(
        fixture.observed,
        "the engine serves the observed qualification"
    );
    Ok(())
}

#[test]
fn disagreeing_observed_preference_never_judges_the_stated_head() -> TestResult<()> {
    let fixture = fixture("black coffee", true)?;
    let routes = fixture.routes()?;
    assert!(
        routes["judge_sets"]
            .as_array()
            .ok_or("missing judge sets")?
            .iter()
            .all(|set| {
                set["prior_heads"]
                    .as_array()
                    .is_some_and(|heads| !heads.contains(&json!(fixture.stated)))
            }),
        "no judge set may hold the stated head for this observed candidate"
    );
    assert_eq!(routes["own_claims"], json!([0]));
    assert_eq!(routes["attachment_heads"], json!([]));
    assert!(
        fixture.observed,
        "the engine serves the observed qualification"
    );
    Ok(())
}

#[test]
fn one_session_keeps_the_native_attachment() -> TestResult<()> {
    let fixture = fixture("green tea", false)?;
    let routes = fixture.routes()?;
    assert_eq!(routes["attachment_heads"], json!([fixture.stated]));
    assert_eq!(routes["own_claims"], json!([]));
    assert!(!fixture.observed, "one session cannot qualify as observed");
    Ok(())
}
