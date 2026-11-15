#![cfg(oneiron_test_support)]
//! [VOICE-PHONE-AGENT-REACH] PR R3: compaction works under every preset.
//! A kept phone turn now enters the line agent's breakpoint for its caller's
//! thread, reading the thread through the line agent's ordinary lane under
//! its per-caller witness-read grant, never through the call's key, so the
//! line's reach Setting (`voice.phone.reach`) cannot stop it (owner 16 Nov
//! 00:44). Under the default, caller B's call must not retrieve caller A's
//! words; under the whole vault it can. The epoch reads only where its
//! caller's words read.
//!
//! The call's brain is the one a phone call's boot builds
//! (`oneiron_server::test_doors::voice_call::PhoneCall`), its line agent the
//! seeded default agent, on a served vault whose chat seat and compaction
//! seat are one scripted model. The line agent carries no memory profile, so
//! it compacts as itself on the host's window (FIX 7744), set small here.
//! Run with:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test voice_phone_epoch`.

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use engine_stack::on_engine_stack;
use fake_llm::{FakeLlm, Reply};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip};
use oneiron::channel_identity::{
    ChannelActorRegistration, ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment,
    ChannelIdentityStep, SelfHeldShape,
};
use oneiron::claim::{CallerLocality, ScopedReadActorKey, base_world_id};
use oneiron::compaction::{ChatLog, ChatLogLine, read_chat_log};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::phone_line::{PhoneLineArrival, PhoneLineConfig};
use oneiron::registry::{
    ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SESSION, ENTITY_TYPE_SUMMARY,
    ENTITY_TYPE_TURN,
};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope};
use oneiron::test_doors::connector_thread_session::thread_session;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::voice_call::PhoneReach;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::voice_call::PhoneCall;
use serde_json::{Value, json};

type TestError = Box<dyn std::error::Error>;
type TestResult<T = ()> = Result<T, TestError>;

/// The host's compaction window, in tokens: the line agent's threshold.
const WINDOW_TOKENS: u64 = 2_000;
/// What the caller says each turn, about the length of a spoken paragraph.
const TRANSCRIPT: &str = "I am walking back from the allotment now. Remember that the new \
    garden gate code is four four one seven, that the tomato beds by the shed need water \
    on Thursday, that Mira borrowed the long ladder and will bring it back after the \
    weekend, and that the compost order from the cooperative arrives on the twelfth. \
    Can you keep all of that for me and remind me of the ladder on Sunday evening?";
/// What the line agent answers each turn.
const ANSWER: &str = "Got it. The gate code is four four one seven, the tomato beds by the \
    shed need water on Thursday, Mira has the long ladder until after the weekend, and \
    the compost arrives on the twelfth. I will remind you about the ladder on Sunday \
    evening.";
/// A fact every compaction summary carries, so the test finds its words.
const SUMMARY_FACT: &str = "the gate code is four four one seven";
/// How long the call's compaction flight may take to land.
const FLIGHT_PATIENCE: Duration = Duration::from_secs(60);
/// The line's number, as its provider gives it.
const LINE_NUMBER: &str = "+15550100";
/// Caller A's number.
const CALLER_A: &str = "+15550000001";
/// Caller B's number.
const CALLER_B: &str = "+15550000002";
/// When the test line is requested and its arrivals land.
const OCCURRED_AT: u64 = 1_769_947_200;
/// A control row outside any call, which a band grant reads.
const CONTROL_WORDS: &str = "a control row outside any call";
/// The bridge's challenge, as the R1/R2 tests use it.
const BRIDGE_CHALLENGE: &[u8] = b"oneiron-request:phone-line-bridge";
/// An agent's challenge, as the R1/R2 tests use it.
const AGENT_CHALLENGE: &[u8] = b"oneiron-request:phone-line-agent";

/// A chat message's text, whether a string or an array of text parts.
fn content(message: &Value) -> String {
    match &message["content"] {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|part| part["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// The scripted model: a compaction pass gets a summary of its span, with
/// every pin copied word for word; any other call is the line agent's answer.
fn reply(body: &Value) -> String {
    let messages = body["messages"].as_array().cloned().unwrap_or_default();
    let texts: Vec<String> = messages.iter().map(content).collect();
    if texts.iter().any(|text| text.contains("You compact")) {
        let input = texts
            .iter()
            .rev()
            .find_map(|text| {
                serde_json::from_str::<Value>(text)
                    .ok()
                    .filter(|input| input.get("from").is_some())
            })
            .unwrap_or_default();
        let mut summary = format!(
            "On the call the caller listed their garden errands and I kept them: {SUMMARY_FACT}."
        );
        for pin in input["pins"].as_array().cloned().unwrap_or_default() {
            summary.push('\n');
            summary.push_str(pin.as_str().unwrap_or_default());
        }
        return json!({"from": input["from"], "through": input["through"], "summary": summary})
            .to_string();
    }
    ANSWER.to_owned()
}

/// The `[models]` table: one scripted local model serves every role, and
/// compaction runs on the host's small window.
fn models_text(base_url: &str) -> String {
    let prompts = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../oneiron/tests/fixtures/prompts")
        .canonicalize()
        .expect("the fixture prompt package");
    format!(
        "default = \"local:test-model\"\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [code_mode]\nprompt_package = {prompts:?}\n\
         [code_mode.compaction]\nwindow_tokens = {WINDOW_TOKENS}\nhot_steps = 1\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n\
         context_tokens = 500000\n",
        prompts = prompts.display().to_string(),
    )
}

/// A served vault with its owner, and the host that runs its flights.
struct Fixture {
    server: Arc<SyncServer>,
    vault: Arc<Vault>,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    issuer: HostSlipIssuer,
    _host: AiHost,
    _model: FakeLlm,
    _dir: tempfile::TempDir,
}

impl Fixture {
    async fn new() -> TestResult<Self> {
        let model = FakeLlm::start(Vec::new(), Some(Reply::Computed(Arc::new(reply)))).await;
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (owner, owner_proof) = embedded_owner(&vault)?;
        let server = SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("voice-phone-epoch".into()),
                ..Default::default()
            },
        )?;
        let models = ModelsConfig::from_toml(&models_text(&model.base_url), None)?;
        let (server, host) = AiHost::attach(server, Some(&models)).await;
        Ok(Self {
            server: Arc::new(server),
            vault,
            owner,
            owner_proof,
            issuer,
            _host: host,
            _model: model,
            _dir: dir,
        })
    }

    /// The thread's log, as its owner reads it.
    fn log(&self, thread: EntityId) -> TestResult<ChatLog> {
        let reader = self.vault.memory(self.owner, EdgeActorClass::Human);
        Ok(read_chat_log(&reader, thread, 1, usize::MAX)?)
    }
}

/// The summaries standing in `log`: (summary, epoch, words).
fn summaries(log: &ChatLog) -> Vec<(EntityId, u64, String)> {
    log.lines
        .iter()
        .filter_map(|line| match line {
            ChatLogLine::Summary {
                summary,
                epoch,
                text,
            } => Some((*summary, *epoch, text.clone())),
            ChatLogLine::Message { .. } => None,
        })
        .collect()
}

/// The seeded default agent that `PhoneCall::answer` answers as.
fn seeded_default_agent(fixture: &Fixture) -> TestResult<EntityId> {
    let (agent, _) = fixture
        .vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .ok_or("the seeded default agent stands")?;
    Ok(agent)
}

/// The line for `agent` on this vault: its identity and its bridge's read
/// key, enabled. The reach is set separately, per test.
fn provision_line(
    fixture: &Fixture,
    agent: EntityId,
    label: &str,
) -> TestResult<(EntityId, ScopedReadActorKey)> {
    let mut line = ChannelIdentity::requested(
        "voice",
        LINE_NUMBER,
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(agent),
        OCCURRED_AT,
    );
    for step in [
        ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
        ChannelIdentityStep::Fulfill,
    ] {
        line = line.step(step, OCCURRED_AT)?;
    }
    let bridge_signing = SigningKey::from_bytes(&[0x51; 32]);
    let registered = fixture.vault.register_channel_actor(
        &fixture.issuer,
        ChannelActorRegistration {
            identity: line,
            provider_key: "test.voice.bridge".to_owned(),
            scope: Scope::top(),
            binding_key: bridge_signing.verifying_key().to_bytes(),
            lifetime_secs: 3_600,
            confidence_prior: 0.75,
            prior_evidence: "owner configured telephony bridge".to_owned(),
        },
    )?;
    let signature = bridge_signing
        .sign(&registered.slip.binding_transcript(BRIDGE_CHALLENGE)?)
        .to_bytes();
    let bridge_proof = fixture.vault.verify_capability_slip(
        &fixture.issuer.public_key(),
        &registered.slip,
        BRIDGE_CHALLENGE,
        &signature,
    )?;
    let bridge_key = fixture
        .vault
        .credential_read_key(&bridge_proof)?
        .ok_or("the bridge credential grants read")?;
    let state = fixture.vault.configure_phone_line(
        &fixture.owner_proof,
        registered.identity_ref,
        PhoneLineConfig { enabled: true },
    )?;
    assert!(
        state.enabled && state.agent_ref == agent && state.bridge_actor == registered.actor_ref,
        "{label}: the line is enabled for its agent and bridge; seen {state:?}",
    );
    Ok((registered.identity_ref, bridge_key))
}

/// The owner sets the line's reach, then reads it back.
fn set_reach_as_owner(
    fixture: &Fixture,
    identity: EntityId,
    reach: PhoneReach,
    label: &str,
) -> TestResult {
    let outcome = fixture.vault.set_setting(
        SettingCaller::Owner(&fixture.owner_proof),
        SetSetting {
            key: "voice.phone.reach".to_owned(),
            item: Some(identity.to_hex()),
            scope: SettingScope::Vault,
            mode: SettingMode::Value,
            value: Some(serde_json::to_value(&reach)?),
            expected_revision: None,
            why: None,
            check_in_ref: None,
        },
    )?;
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "{label}: the owner's reach change applies; seen {outcome:?}",
    );
    assert_eq!(
        fixture
            .vault
            .phone_line_reach(identity, seeded_default_agent(fixture)?)?,
        reach,
        "{label}: the line's reach reads the value the owner set",
    );
    Ok(())
}

/// The agent's own paired credential, as the voice host presents it.
fn paired_slip_for(fixture: &Fixture, agent: EntityId, key_byte: u8) -> TestResult<VerifiedSlip> {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "core:read".to_owned(),
        "core:write".to_owned(),
    ]));
    let holder = agent.to_hex();
    let link = fixture.vault.issue_owner_pairing_link(
        &fixture.issuer,
        &fixture.owner_proof,
        scope,
        3_600,
        PairingPrincipal {
            holder_ref: Some(holder.clone()),
            actor_class: Some("agent".to_owned()),
            ..PairingPrincipal::default()
        },
    )?;
    let signing_key = SigningKey::from_bytes(&[key_byte; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &link.code,
        &binding_key,
        &holder,
        link.pin.as_ref(),
    )?;
    let slip = fixture.vault.redeem_pairing_link(
        &fixture.issuer,
        &link.code,
        &holder,
        binding_key,
        &signing_key.sign(&transcript).to_bytes(),
    )?;
    let signature = signing_key
        .sign(&slip.binding_transcript(AGENT_CHALLENGE)?)
        .to_bytes();
    Ok(fixture.vault.verify_capability_slip(
        &fixture.issuer.public_key(),
        &slip,
        AGENT_CHALLENGE,
        &signature,
    )?)
}

/// The ordinary key of `proof`: its credential's read, off this device.
fn ordinary_key(fixture: &Fixture, proof: &VerifiedSlip) -> TestResult<ScopedReadActorKey> {
    Ok(fixture
        .vault
        .credential_read_key(proof)?
        .ok_or("the agent credential grants read")?
        .at(CallerLocality::OffDevice))
}

/// An enabled, active agent definition the owner creates as `agent_id`.
fn create_enabled_agent(fixture: &Fixture, agent_id: &str) -> TestResult<EntityId> {
    let agent = EntityId::now();
    create_agent_definition_as(
        &fixture.vault,
        &fixture.owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "Reads where its bands read",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))?,
        },
    )?;
    Ok(agent)
}

/// The owner mints `agent` a band read grant over the base world whose bands
/// hold the transcript rows and the summary, so a refusal is the phone
/// gate's, not a missing band.
fn mint_banded_read_grant(fixture: &Fixture, agent: EntityId, label: &str) -> TestResult {
    let mut authority_scope = Scope::top();
    authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    authority_scope.bands = ScopeAxis::Some(BTreeSet::from([
        ENTITY_TYPE_TURN,
        ENTITY_TYPE_SESSION,
        ENTITY_TYPE_MESSAGE,
        ENTITY_TYPE_CONVERSATION,
        ENTITY_TYPE_SUMMARY,
    ]));
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )?;
    assert!(
        minted.grant.confers,
        "{label}: the band grant confers its read",
    );
    Ok(())
}

/// One plain conversation with one MESSAGE, written by the owner outside any
/// call: the control row a band read reaches.
fn witness_control_message(fixture: &Fixture) -> TestResult<EntityId> {
    let turn = WitnessTurn {
        conversation_ref: EntityId::now().to_hex(),
        turn_ref: None,
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: None,
            author: WitnessAuthor::User,
            message_type: "text".to_owned(),
            content: CONTROL_WORDS.to_owned(),
            parts: None,
            metadata: None,
            is_visible: true,
            order: 0,
            quote: None,
        }],
        occurred_at: OCCURRED_AT,
        assertions: Default::default(),
    };
    let receipt = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .witness(&turn)?;
    Ok(EntityId::from_hex(&receipt.messages[0].id)?)
}

/// One arrival on the line: `call_id` from `caller`.
fn stranger_call_with(call_id: &str, caller: Option<&str>) -> PhoneLineArrival {
    PhoneLineArrival {
        call_id: call_id.to_owned(),
        caller: caller.map(|caller| caller.to_owned()),
    }
}

/// The bridge submits `arrival`; the opaque payload ref its call key needs.
fn submit_arrival(
    fixture: &Fixture,
    bridge_key: &ScopedReadActorKey,
    identity: EntityId,
    arrival: PhoneLineArrival,
) -> TestResult<String> {
    let read = fixture.vault.scoped_read(bridge_key.clone());
    let receipt =
        fixture
            .vault
            .enqueue_phone_line_arrival_as(&read, identity, arrival, OCCURRED_AT)?;
    Ok(receipt.record.payload_ref)
}

/// Enough long turns that the raw ones outgrow the window, the last one
/// still hot. Answers the turn count.
async fn say_enough_turns(call: &mut PhoneCall) -> TestResult<u64> {
    let per_turn = (oneiron::count_context_pack_tokens(TRANSCRIPT)
        + oneiron::count_context_pack_tokens(ANSWER)) as u64;
    let turns = WINDOW_TOKENS / per_turn.max(1) + 2;
    for generation in 1..=turns {
        call.say(generation, TRANSCRIPT).await?;
    }
    Ok(turns)
}

/// The thread's log once its epoch stands, or the raw log after the flight's
/// patience. The flight runs off the call's path.
async fn poll_epoch(fixture: &Fixture, thread: EntityId) -> TestResult<ChatLog> {
    let deadline = Instant::now() + FLIGHT_PATIENCE;
    loop {
        let log = fixture.log(thread)?;
        if !summaries(&log).is_empty() || Instant::now() > deadline {
            return Ok(log);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[test]
fn a_phone_threads_earlier_turns_compact_into_its_own_epoch() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let mut call = PhoneCall::answer(&fixture.server, Some(CALLER_A))?;
        let thread = call.conversation();
        let turns = say_enough_turns(&mut call).await?;
        let log = poll_epoch(&fixture, thread).await?;
        let standing = summaries(&log);
        assert_eq!(
            standing.len(),
            1,
            "row 1 Default: exactly one Summary stands after {turns} turns",
        );
        let (summary, epoch, words) = &standing[0];
        assert_eq!(*epoch, 1, "row 1 Default: the thread's first epoch");
        assert!(
            words.contains(SUMMARY_FACT),
            "row 1 Default: the summary carries the call's fact: {words}",
        );
        let spans = fixture
            .vault
            .summary_folded_spans(summary)?
            .ok_or("row 1 Default: the summary's receipt names the turns it covers")?;
        assert!(
            spans.len() >= 2,
            "row 1 Default: the epoch covers the call's earlier turns: {}",
            spans.len(),
        );
        assert!(
            spans
                .iter()
                .any(|span| span.role == WitnessAuthor::Counterparty.as_str()),
            "row 1 Default: the epoch's spans hold the caller's first words",
        );
        assert!(
            matches!(
                log.lines.last(),
                Some(ChatLogLine::Message { author: WitnessAuthor::Companion, text }) if text == ANSWER
            ),
            "row 1 Default: the call's last answer stays raw",
        );
        assert_eq!(
            log.session,
            Some(thread_session(thread)?),
            "row 1 Default: the thread's turns are held in the thread's own SESSION",
        );
        call.hang_up();
        Ok(())
    })
}

#[test]
fn a_phone_thread_compacts_under_the_whole_vault_reach() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let agent = seeded_default_agent(&fixture)?;
        let (identity, _) = provision_line(&fixture, agent, "row 2 WholeVault")?;
        set_reach_as_owner(
            &fixture,
            identity,
            PhoneReach::WholeVault,
            "row 2 WholeVault",
        )?;
        let mut call = PhoneCall::answer(&fixture.server, Some(CALLER_A))?;
        assert_eq!(
            call.agent(),
            agent,
            "row 2 WholeVault: the call answers as the line's agent",
        );
        let thread = call.conversation();
        let turns = say_enough_turns(&mut call).await?;
        let log = poll_epoch(&fixture, thread).await?;
        let standing = summaries(&log);
        assert_eq!(
            standing.len(),
            1,
            "row 2 WholeVault: exactly one Summary stands after {turns} turns",
        );
        let (summary, epoch, words) = &standing[0];
        assert_eq!(*epoch, 1, "row 2 WholeVault: the thread's first epoch");
        assert!(
            words.contains(SUMMARY_FACT),
            "row 2 WholeVault: the summary carries the call's fact: {words}",
        );
        let spans = fixture
            .vault
            .summary_folded_spans(summary)?
            .ok_or("row 2 WholeVault: the summary's receipt names the turns it covers")?;
        assert!(
            spans.len() >= 2,
            "row 2 WholeVault: the epoch covers the call's earlier turns: {}",
            spans.len(),
        );
        assert!(
            spans
                .iter()
                .any(|span| span.role == WitnessAuthor::Counterparty.as_str()),
            "row 2 WholeVault: the epoch's spans hold the caller's first words",
        );
        assert!(
            matches!(
                log.lines.last(),
                Some(ChatLogLine::Message { author: WitnessAuthor::Companion, text }) if text == ANSWER
            ),
            "row 2 WholeVault: the call's last answer stays raw",
        );
        assert_eq!(
            log.session,
            Some(thread_session(thread)?),
            "row 2 WholeVault: the thread's turns are held in the thread's own SESSION",
        );
        call.hang_up();
        Ok(())
    })
}

#[test]
fn a_phone_thread_compacts_under_a_custom_reach_that_excludes_its_words() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let agent = seeded_default_agent(&fixture)?;
        let (identity, _) = provision_line(&fixture, agent, "row 3 Custom")?;
        let mut scope = Scope::top();
        let mut bands = BTreeSet::new();
        for band in 0u8..=u8::MAX {
            if band != ENTITY_TYPE_MESSAGE && band != ENTITY_TYPE_TURN {
                bands.insert(band);
            }
        }
        scope.bands = ScopeAxis::Some(bands);
        let reach = PhoneReach::Custom {
            scope,
            include_other_callers: false,
        };
        set_reach_as_owner(&fixture, identity, reach, "row 3 Custom")?;
        let mut call = PhoneCall::answer(&fixture.server, Some(CALLER_A))?;
        assert_eq!(
            call.agent(),
            agent,
            "row 3 Custom: the call answers as the line's agent",
        );
        let thread = call.conversation();
        let turns = say_enough_turns(&mut call).await?;
        let log = poll_epoch(&fixture, thread).await?;
        let standing = summaries(&log);
        assert_eq!(
            standing.len(),
            1,
            "row 3 Custom: exactly one Summary stands after {turns} turns",
        );
        let (summary, epoch, words) = &standing[0];
        assert_eq!(*epoch, 1, "row 3 Custom: the thread's first epoch");
        assert!(
            words.contains(SUMMARY_FACT),
            "row 3 Custom: the summary carries the call's fact: {words}",
        );
        let spans = fixture
            .vault
            .summary_folded_spans(summary)?
            .ok_or("row 3 Custom: the summary's receipt names the turns it covers")?;
        assert!(
            spans.len() >= 2,
            "row 3 Custom: the epoch covers the call's earlier turns: {}",
            spans.len(),
        );
        assert!(
            spans
                .iter()
                .any(|span| span.role == WitnessAuthor::Counterparty.as_str()),
            "row 3 Custom: the epoch's spans hold the caller's first words",
        );
        assert!(
            matches!(
                log.lines.last(),
                Some(ChatLogLine::Message { author: WitnessAuthor::Companion, text }) if text == ANSWER
            ),
            "row 3 Custom: the call's last answer stays raw",
        );
        assert_eq!(
            log.session,
            Some(thread_session(thread)?),
            "row 3 Custom: the thread's turns are held in the thread's own SESSION",
        );
        call.hang_up();
        Ok(())
    })
}

#[test]
fn a_phone_epoch_reads_only_where_its_callers_words_read() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let agent = seeded_default_agent(&fixture)?;
        let (identity, bridge_key) = provision_line(&fixture, agent, "row 4 Default")?;
        set_reach_as_owner(
            &fixture,
            identity,
            PhoneReach::Default {
                documents: Vec::new(),
            },
            "row 4 Default",
        )?;
        let line_proof = paired_slip_for(&fixture, agent, 0x52)?;
        let mut call = PhoneCall::answer(&fixture.server, Some(CALLER_A))?;
        assert_eq!(
            call.agent(),
            agent,
            "row 4 Default: the call answers as the line's agent",
        );
        let thread = call.conversation();
        let turns = say_enough_turns(&mut call).await?;
        let log = poll_epoch(&fixture, thread).await?;
        let standing = summaries(&log);
        assert_eq!(
            standing.len(),
            1,
            "row 4 Default: the epoch precondition stands after {turns} turns",
        );
        let summary = standing[0].0;
        call.hang_up();

        let control = witness_control_message(&fixture)?;
        let generic = create_enabled_agent(&fixture, "generic_reader")?;
        mint_banded_read_grant(&fixture, generic, "row 4c Default")?;
        let generic_proof = paired_slip_for(&fixture, generic, 0x53)?;
        let owner_key = fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .read_key()?;
        let line_key = ordinary_key(&fixture, &line_proof)?;
        let generic_key = ordinary_key(&fixture, &generic_proof)?;

        let owner_reads = fixture
            .vault
            .scoped_read(owner_key)
            .is_entity_readable(&summary)?;
        assert!(
            owner_reads,
            "row 4a Default: the owner reads the caller's Summary",
        );
        let line_reads = fixture
            .vault
            .scoped_read(line_key)
            .is_entity_readable(&summary)?;
        assert!(
            line_reads,
            "row 4b Default: the line agent's ordinary key reads the Summary",
        );
        let generic_reads_summary = fixture
            .vault
            .scoped_read(generic_key.clone())
            .is_entity_readable(&summary)?;
        assert!(
            !generic_reads_summary,
            "row 4c Default: a band grant does not read the caller's Summary",
        );
        let generic_reads_control = fixture
            .vault
            .scoped_read(generic_key)
            .is_entity_readable(&control)?;
        assert!(
            generic_reads_control,
            "row 4c Default: the band grant reads the control row, so the refusal is the phone gate's",
        );

        let payload_b = submit_arrival(
            &fixture,
            &bridge_key,
            identity,
            stranger_call_with("call-B", Some(CALLER_B)),
        )?;
        let call_b_key =
            fixture
                .vault
                .phone_line_answer_read_key(&line_proof, identity, &payload_b)?;
        let caller_b_reads = fixture
            .vault
            .scoped_read(call_b_key)
            .is_entity_readable(&summary)?;
        assert!(
            !caller_b_reads,
            "row 4d Default: caller B's call does not read caller A's Summary",
        );

        set_reach_as_owner(
            &fixture,
            identity,
            PhoneReach::WholeVault,
            "row 4e WholeVault",
        )?;
        let payload_b2 = submit_arrival(
            &fixture,
            &bridge_key,
            identity,
            stranger_call_with("call-B2", Some(CALLER_B)),
        )?;
        let call_b2_key =
            fixture
                .vault
                .phone_line_answer_read_key(&line_proof, identity, &payload_b2)?;
        let caller_b2_reads = fixture
            .vault
            .scoped_read(call_b2_key)
            .is_entity_readable(&summary)?;
        assert!(
            caller_b2_reads,
            "row 4e WholeVault: the next call from caller B reads caller A's Summary",
        );
        Ok(())
    })
}

#[test]
fn a_phone_epochs_intent_note_reads_only_where_its_callers_words_read() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let agent = seeded_default_agent(&fixture)?;
        let (identity, _bridge_key) = provision_line(&fixture, agent, "row 5 Default")?;
        set_reach_as_owner(
            &fixture,
            identity,
            PhoneReach::Default {
                documents: Vec::new(),
            },
            "row 5 Default",
        )?;
        let line_proof = paired_slip_for(&fixture, agent, 0x54)?;
        let mut call = PhoneCall::answer(&fixture.server, Some(CALLER_A))?;
        let thread = call.conversation();
        let turns = say_enough_turns(&mut call).await?;
        let log = poll_epoch(&fixture, thread).await?;
        let standing = summaries(&log);
        assert_eq!(
            standing.len(),
            1,
            "row 5 Default: the epoch precondition stands after {turns} turns",
        );
        let summary = standing[0].0;
        call.hang_up();
        // The pass's intent NOTE sits About its epoch and was written from
        // the epoch's sources, the caller's turns (Engine RULING
        // REACH-INTENT-NOTE-SOURCES = A, 16 Nov 07:19).
        let intents = fixture.vault.sources(
            &summary,
            oneiron::EdgeKind::About,
            Some(oneiron::registry::ENTITY_TYPE_NOTE),
        )?;
        assert_eq!(
            intents.len(),
            1,
            "row 5 Default: precondition: one intent NOTE sits About the epoch",
        );
        let intent = intents[0];
        assert!(
            !fixture
                .vault
                .targets(&intent, oneiron::EdgeKind::DerivedFrom, None)?
                .is_empty(),
            "row 5 Default: precondition: the intent NOTE is DerivedFrom the epoch's sources",
        );

        let control = witness_control_message(&fixture)?;
        let generic = create_enabled_agent(&fixture, "generic_reader")?;
        mint_banded_read_grant(&fixture, generic, "row 5c Default")?;
        let generic_proof = paired_slip_for(&fixture, generic, 0x55)?;
        let owner_key = fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .read_key()?;
        let line_key = ordinary_key(&fixture, &line_proof)?;
        let generic_key = ordinary_key(&fixture, &generic_proof)?;

        assert!(
            fixture
                .vault
                .scoped_read(owner_key)
                .is_entity_readable(&intent)?,
            "row 5a Default: the owner reads the epoch's intent NOTE",
        );
        assert!(
            fixture
                .vault
                .scoped_read(line_key)
                .is_entity_readable(&intent)?,
            "row 5b Default: the line agent's ordinary key reads the epoch's intent NOTE",
        );
        assert!(
            fixture
                .vault
                .scoped_read(generic_key.clone())
                .is_entity_readable(&control)?,
            "row 5c Default: the band grant reads the control row, so a refusal is the source rule's",
        );
        assert!(
            !fixture
                .vault
                .scoped_read(generic_key)
                .is_entity_readable(&intent)?,
            "LEAK row 5c Default: a band grant reads the intent NOTE of the caller's epoch without reading the caller's words",
        );
        Ok(())
    })
}
