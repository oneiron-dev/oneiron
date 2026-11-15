//! Provides the minimal real-vault fixture for observed verdict checks.

use std::sync::Arc;

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::dreamer_consolidation::selection::SelectionConfig;
use oneiron::memory::{
    MemoryResult, WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn,
};
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

/// Returns fixture values or the underlying fixture error.
pub(crate) type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Holds the live bound attempt and the facts used by verdict checks.
pub(crate) struct Fixture {
    /// Holds the bound Dreamer attempt client.
    pub(crate) client: OneironClient,
    /// Names the bound attempt as lowercase hex.
    pub(crate) attempt: String,
    /// Holds the attempt clock in Unix milliseconds.
    pub(crate) now_ms: u64,
    /// Holds the two candidate operands with coffee first and juice second.
    pub(crate) operands: Vec<Value>,
    /// Holds the effective selection configuration.
    pub(crate) config: ExtractionSelectionConfig,
    /// Holds the effective policy pin.
    pub(crate) policy_pin: String,
    /// Names the stated head claim.
    pub(crate) stated: String,
    /// Names the generated head claim when present.
    pub(crate) generated: Option<String>,
    /// Retains the vault directory for the fixture lifetime.
    _directory: tempfile::TempDir,
    /// Retains the vault for the fixture lifetime.
    _vault: Arc<Vault>,
}

impl Fixture {
    /// Calls the bound verdict with the resolution choice contract.
    pub(crate) fn verdict(&self, pack: Value) -> MemoryResult<Value> {
        self.client.agent_verb(
            "ai.verdict",
            json!({
                "question": "resolution",
                "contract": {"kind": "choice", "options": ["merge", "supersede", "accumulate", "escalate"]},
                "evidence": [],
                "state": pack,
                "ceiling": "big",
                "reversibility": "reversible_read",
                "routine": false,
                "misses": 0,
            }),
        )
    }

    /// Returns the pinned claims for the given heads in head order.
    pub(crate) fn prior_pins(&self, heads: &[String]) -> TestResult<Vec<Value>> {
        let observations =
            read_observations(&self.client, &self.attempt, self.now_ms, &self.operands)?;
        let mut pins = Vec::with_capacity(heads.len());
        for head in heads {
            let prior = observations
                .priors
                .iter()
                .find(|prior| &prior.claim == head)
                .ok_or("the prior head must be admitted before pinning its version")?;
            let version = serde_json::to_value(&prior.version)?;
            pins.push(json!({"claim": head, "version": version}));
        }
        Ok(pins)
    }
}

/// Builds the fixture with coffee over one or two sessions and juice over one session.
///
/// Coffee cites three turns over two sessions when observed holds and over one session otherwise.
/// Juice cites one turn over one session.
/// The stated tea head always lands and the generated cocoa head lands when requested.
/// The bound attempt serves all four turns with soak zero and evidence minimum one.
pub(crate) fn fixture(observed: bool, with_generated: bool) -> TestResult<Fixture> {
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
    let stated = land_head(&vault, subject, "tea", ClaimSource::UserStated)?.to_hex();
    let generated = if with_generated {
        Some(land_head(&vault, subject, "cocoa", ClaimSource::Generated)?.to_hex())
    } else {
        None
    };
    let conversation = EntityId::now();
    let key = vault.local_session_key(subject)?;
    let SessionMintOutcome::Minted(first_coffee) =
        vault.mint_session(key, vault.now_recorded_at())?
    else {
        return Err("the first coffee session must be fresh".into());
    };
    let coffee_words = "owen chooses coffee.";
    let mut coffee_turns = vec![
        witness_turn(&vault, conversation, subject, key, coffee_words)?,
        witness_turn(&vault, conversation, subject, key, coffee_words)?,
    ];
    let mut open_coffee = first_coffee;
    if observed {
        if vault
            .end_session_with_wake(
                &first_coffee,
                SessionClosePredicate::Explicit,
                vault.now_recorded_at(),
                &SessionEndWake::none(first_coffee, 0),
            )?
            .is_none()
        {
            return Err("the first coffee session must close".into());
        }
        let SessionMintOutcome::Minted(second_coffee) =
            vault.mint_session(key, vault.now_recorded_at())?
        else {
            return Err("the second coffee session must be fresh".into());
        };
        if second_coffee == first_coffee {
            return Err("the second coffee session must differ".into());
        }
        open_coffee = second_coffee;
    }
    coffee_turns.push(witness_turn(
        &vault,
        conversation,
        subject,
        key,
        coffee_words,
    )?);
    if vault
        .end_session_with_wake(
            &open_coffee,
            SessionClosePredicate::Explicit,
            vault.now_recorded_at(),
            &SessionEndWake::none(open_coffee, 0),
        )?
        .is_none()
    {
        return Err("the final coffee session must close".into());
    }
    let SessionMintOutcome::Minted(juice_session) =
        vault.mint_session(key, vault.now_recorded_at())?
    else {
        return Err("the juice session must be fresh".into());
    };
    if juice_session == open_coffee {
        return Err("the juice session must differ".into());
    }
    let juice_turn = witness_turn(&vault, conversation, subject, key, "owen chooses juice.")?;
    let mut turns = Vec::with_capacity(4);
    turns.extend(coffee_turns.iter().copied());
    turns.push(juice_turn);
    let (attempt_id, admitted) = enqueue_admitted_extraction_attempt(&vault, &turns, 1_000)?;
    let attempt: String = attempt_id
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
    let served = page["turns"].as_array().ok_or("missing turns")?;
    if served.len() != 4 {
        return Err("the bound attempt must serve all four TURNs".into());
    }
    let mut coffee_evidence = Vec::with_capacity(3);
    for turn in &coffee_turns {
        let version = pin_for(served, *turn)?;
        coffee_evidence.push(json!({"turn": turn.to_hex(), "version": version}));
    }
    let juice_version = pin_for(served, juice_turn)?;
    let operands = vec![
        json!({
            "subject": subject.to_hex(), "predicate": "preference.food",
            "value": "coffee", "evidence": coffee_evidence,
        }),
        json!({
            "subject": subject.to_hex(), "predicate": "preference.food",
            "value": "juice", "evidence": [{"turn": juice_turn.to_hex(), "version": juice_version}],
        }),
    ];
    let observations = read_observations(&client, &attempt, now_ms, &operands)?;
    let stated_prior = observations
        .priors
        .iter()
        .find(|prior| prior.claim == stated)
        .ok_or("the stated head must be admitted before testing its verdict")?;
    if stated_prior.source != "user_stated" || !stated_prior.writable {
        return Err("the stated head must be user_stated and writable".into());
    }
    if let Some(generated_hex) = &generated {
        let generated_prior = observations
            .priors
            .iter()
            .find(|prior| &prior.claim == generated_hex)
            .ok_or("the generated head must be admitted before testing its verdict")?;
        if generated_prior.source != "generated" || !generated_prior.writable {
            return Err("the generated head must be generated and writable".into());
        }
    }
    Ok(Fixture {
        client,
        attempt,
        now_ms,
        operands,
        config,
        policy_pin,
        stated,
        generated,
        _directory: directory,
        _vault: vault,
    })
}

/// Lands one active auto head with the given value and source.
fn land_head(
    vault: &Vault,
    subject: EntityId,
    value: &str,
    source: ClaimSource,
) -> TestResult<EntityId> {
    let head = EntityId::now();
    let mut body = ClaimBody::new(
        "preference.food",
        ClaimSubject::Entity(subject),
        RmpValue::from(value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(source);
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

/// Witnesses one user turn with live session membership through the memory door.
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

/// Finds the served pin for one recorded turn by its identifier.
fn pin_for(served: &[Value], turn: EntityId) -> TestResult<Value> {
    let hex = turn.to_hex();
    for row in served {
        if row["turn"].as_str() == Some(hex.as_str()) {
            return Ok(row["version"].clone());
        }
    }
    Err("the bound attempt must serve every recorded TURN".into())
}
