//! VOICE-PHONE-AGENT-REACH PR R1: the phone-thread mark, the per-caller grant,
//! the current-caller rule. The line agent's reach is one owner choice per
//! line; the DEFAULT is "this caller's own history + documents the owner
//! picks". Under the default, caller B's call cannot retrieve caller A's
//! words. A generic read (an agent Grant whose bands cover MESSAGE +
//! CONVERSATION) no longer reaches phone call rows.
//!
//! This file uses only items that exist on the base e4d7100d4b1 too, so the
//! red run compiles and fails at assertions. Run with:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --test phone_thread_reach`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip};
use oneiron::channel_identity::{
    ChannelActorRegistration, ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment,
    ChannelIdentityStep, SelfHeldShape,
};
use oneiron::claim::{CallerLocality, ScopedReadActorKey, base_world_id};
use oneiron::consent::{AuthenticatedOwner, ConsentRegistryQuery};
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::phone_line::{PhoneLineArrival, PhoneLineArrivalReceipt, PhoneLineConfig};
use oneiron::registry::ENTITY_TYPE_CONVERSATION;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, ConnectorWitnessReadGrantRevokeRequest,
    create_agent_definition_as, mint_agent_grant_as, revoke_connector_witness_read_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

const OCCURRED_AT: u64 = 1_769_947_200;
const LINE_NUMBER: &str = "+15550100";
const CALLER_A: &str = "+15550000001";
const CALLER_B: &str = "+15550000002";
const CALLER_C: &str = "+15550000003";
const CALL_A: &str = "call-A";
const CALL_B: &str = "call-B";
const A_SECRET: &str = "A's secret is 1234";
const A_ANSWER: &str = "Acknowledged, A.";
const B_WORDS: &str = "B says hello.";
const B_ANSWER: &str = "Acknowledged, B.";
const CONTROL_WORDS: &str = "a control row outside any call";
const BRIDGE_CHALLENGE: &[u8] = b"oneiron-request:phone-line-bridge";
const AGENT_CHALLENGE: &[u8] = b"oneiron-request:phone-line-agent";

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    agent: EntityId,
    identity: EntityId,
    bridge: EntityId,
    bridge_proof: VerifiedSlip,
    bridge_key: ScopedReadActorKey,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    // The owner's agent Grant act is carried by this install's live machine
    // profile, as a serving start or `init` enrols it (FIX 4648).
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let agent = create_enabled_agent(&vault, &owner_proof, "phone_line_agent");

    // The line's identity answers for the agent; its channel actor (the
    // telephony bridge, a MACHINE) carries the credential that submits calls.
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
        line = line
            .step(step, OCCURRED_AT)
            .expect("self-held line walks to Active");
    }
    let bridge_signing = SigningKey::from_bytes(&[0x51; 32]);
    let registered = vault
        .register_channel_actor(
            &issuer,
            ChannelActorRegistration {
                identity: line,
                provider_key: "test.voice.bridge".to_owned(),
                scope: Scope::top(),
                binding_key: bridge_signing.verifying_key().to_bytes(),
                lifetime_secs: 3_600,
                confidence_prior: 0.75,
                prior_evidence: "owner configured telephony bridge".to_owned(),
            },
        )
        .expect("host registers the voice line and its bridge");
    let signature = bridge_signing
        .sign(
            &registered
                .slip
                .binding_transcript(BRIDGE_CHALLENGE)
                .expect("bridge request transcript"),
        )
        .to_bytes();
    let bridge_proof = vault
        .verify_capability_slip(
            &issuer.public_key(),
            &registered.slip,
            BRIDGE_CHALLENGE,
            &signature,
        )
        .expect("bridge proves possession of its credential");
    let bridge_key = vault
        .credential_read_key(&bridge_proof)
        .expect("bridge credential read key")
        .expect("bridge credential grants read");
    Fixture {
        vault,
        _dir: dir,
        issuer,
        owner,
        owner_proof,
        agent,
        identity: registered.identity_ref,
        bridge: registered.actor_ref,
        bridge_proof,
        bridge_key,
    }
}

/// An enabled, active agent definition the owner creates as `agent_id`.
fn create_enabled_agent(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    agent_id: &str,
) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        vault,
        owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "Answers the agent phone line",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates an enabled, active agent definition");
    agent
}

/// The agent's own paired credential, as the voice host presents it.
fn paired_agent_slip(fixture: &Fixture) -> VerifiedSlip {
    paired_slip_for(fixture, fixture.agent, 0x52)
}

/// A second agent's paired credential, on its own key.
fn paired_generic_slip(fixture: &Fixture, generic: EntityId) -> VerifiedSlip {
    paired_slip_for(fixture, generic, 0x53)
}

fn paired_slip_for(fixture: &Fixture, agent: EntityId, key_byte: u8) -> VerifiedSlip {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "core:read".to_owned(),
        "core:write".to_owned(),
    ]));
    let holder = agent.to_hex();
    let link = fixture
        .vault
        .issue_owner_pairing_link(
            &fixture.issuer,
            &fixture.owner_proof,
            scope,
            3_600,
            PairingPrincipal {
                holder_ref: Some(holder.clone()),
                actor_class: Some("agent".to_owned()),
                ..PairingPrincipal::default()
            },
        )
        .expect("owner issues the agent's pairing link");
    let signing_key = SigningKey::from_bytes(&[key_byte; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &link.code,
        &binding_key,
        &holder,
        link.pin.as_ref(),
    )
    .expect("agent pairing transcript");
    let slip = fixture
        .vault
        .redeem_pairing_link(
            &fixture.issuer,
            &link.code,
            &holder,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )
        .expect("agent redeems its pairing link");
    let signature = signing_key
        .sign(
            &slip
                .binding_transcript(AGENT_CHALLENGE)
                .expect("agent request transcript"),
        )
        .to_bytes();
    fixture
        .vault
        .verify_capability_slip(
            &fixture.issuer.public_key(),
            &slip,
            AGENT_CHALLENGE,
            &signature,
        )
        .expect("agent proves possession of its credential")
}

fn worlds_scope(worlds: &[EntityId]) -> Scope {
    let mut scope = Scope::top();
    scope.worlds = ScopeAxis::Some(worlds.iter().copied().map(ScopeId).collect());
    scope
}

fn configure(fixture: &Fixture, enabled: bool, share_scope: Scope) {
    let state = fixture
        .vault
        .configure_phone_line(
            &fixture.owner_proof,
            fixture.identity,
            PhoneLineConfig {
                enabled,
                share_scope: share_scope.clone(),
            },
        )
        .expect("owner stores the phone line setting");
    assert!(
        state.enabled == enabled
            && state.share_scope == share_scope
            && state.agent_ref == fixture.agent
            && state.bridge_actor == fixture.bridge,
        "line {:?}; expected enabled={enabled}, agent={:?}, bridge={:?}; seen {state:?}",
        fixture.identity,
        fixture.agent,
        fixture.bridge,
    );
}

fn stranger_call_with(call_id: &str, caller: Option<&str>) -> PhoneLineArrival {
    PhoneLineArrival {
        call_id: call_id.to_owned(),
        caller: caller.map(|caller| caller.to_owned()),
    }
}

fn submit(
    fixture: &Fixture,
    arrival: PhoneLineArrival,
) -> oneiron::Result<PhoneLineArrivalReceipt> {
    let read = fixture.vault.scoped_read(fixture.bridge_key.clone());
    fixture
        .vault
        .enqueue_phone_line_arrival_as(&read, fixture.identity, arrival, OCCURRED_AT)
}

/// The owner mints `agent` a read Grant over the base world, so a band read
/// would reach the rows.
fn mint_read_grant(fixture: &Fixture, agent: EntityId) {
    let mut authority_scope = worlds_scope(&[base_world_id()]);
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
    )
    .expect("owner mints the agent a read Grant");
    assert!(minted.grant.confers, "the agent's Grant confers its read");
}

/// The line agent's thread with `number`: the same bytes as
/// `voice_phone_conversation_id` (moved to `oneiron::voice_call` in R1),
/// derived here so this file compiles on the base too.
fn phone_thread_id(agent: EntityId, number: &str) -> EntityId {
    EntityId::derive(
        b"oneiron.conversation.voice_phone.v1",
        &[agent.as_bytes(), number.as_bytes()],
    )
    .expect("phone thread id derives")
}

/// One phone message as a turn of `conversation`: the caller's words as one
/// Counterparty message or the answer as one Companion message, as
/// `KeptTurn::keep_phone` builds them.
fn phone_turn(
    conversation: EntityId,
    author: WitnessAuthor,
    content: &str,
    call_id: &str,
    caller_speaker: bool,
    at: u64,
) -> WitnessTurn {
    let mut turn = WitnessTurn {
        conversation_ref: conversation.to_hex(),
        turn_ref: None,
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: None,
            author,
            message_type: "text".to_owned(),
            content: content.to_owned(),
            parts: None,
            metadata: None,
            is_visible: true,
            order: 0,
            quote: None,
        }],
        occurred_at: at,
        assertions: Default::default(),
    };
    let metadata = if caller_speaker {
        json!({ "voice": { "call": call_id, "speaker": "caller", "speaker_label": "another speaker" } })
    } else {
        json!({ "voice": { "call": call_id } })
    };
    turn.messages[0].metadata = Some(metadata);
    turn
}

/// Keeps one phone message, each its own witness call, as
/// `KeptTurn::keep_phone` keeps them.
#[allow(clippy::too_many_arguments)]
fn keep_phone_message(
    vault: &Vault,
    agent: EntityId,
    conversation: EntityId,
    author: WitnessAuthor,
    content: &str,
    call_id: &str,
    caller_speaker: bool,
    at: u64,
) -> (EntityId, EntityId) {
    let turn = phone_turn(conversation, author, content, call_id, caller_speaker, at);
    let receipt = vault
        .witness_call_turn(agent, &turn)
        .expect("the phone message is kept");
    let message = EntityId::from_hex(&receipt.messages[0].id).expect("kept message id");
    (receipt.turn_id, message)
}

/// One plain conversation with one MESSAGE, written by the owner outside any
/// call: the control row a band read reaches.
fn witness_control_message(fixture: &Fixture) -> EntityId {
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
        .witness(&turn)
        .expect("the control message is witnessed");
    EntityId::from_hex(&receipt.messages[0].id).expect("control message id")
}

fn ordinary_key(fixture: &Fixture, proof: &VerifiedSlip) -> ScopedReadActorKey {
    fixture
        .vault
        .credential_read_key(proof)
        .expect("agent credential read key")
        .expect("agent credential grants read")
        .at(CallerLocality::OffDevice)
}

struct Reach {
    fixture: Fixture,
    conv_a: EntityId,
    conv_b: EntityId,
    turn_a1: EntityId,
    turn_a2: EntityId,
    turn_b1: EntityId,
    turn_b2: EntityId,
    msg_a_caller: EntityId,
    msg_a_answer: EntityId,
    msg_b_caller: EntityId,
    msg_b_answer: EntityId,
    control_msg: EntityId,
    l_key: ScopedReadActorKey,
    g_key: ScopedReadActorKey,
    b_call_key: ScopedReadActorKey,
    owner_key: ScopedReadActorKey,
}

fn reach_fixture() -> Reach {
    let fixture = fixture();
    let generic = create_enabled_agent(&fixture.vault, &fixture.owner_proof, "generic_reader");
    mint_read_grant(&fixture, fixture.agent);
    mint_read_grant(&fixture, generic);
    configure(&fixture, true, worlds_scope(&[base_world_id()]));
    submit(&fixture, stranger_call_with(CALL_A, Some(CALLER_A))).expect("A's arrival lands");
    let receipt_b =
        submit(&fixture, stranger_call_with(CALL_B, Some(CALLER_B))).expect("B's arrival lands");
    let conv_a = phone_thread_id(fixture.agent, CALLER_A);
    let conv_b = phone_thread_id(fixture.agent, CALLER_B);
    let (turn_a1, msg_a_caller) = keep_phone_message(
        &fixture.vault,
        fixture.agent,
        conv_a,
        WitnessAuthor::Counterparty,
        A_SECRET,
        CALL_A,
        true,
        OCCURRED_AT,
    );
    let (turn_a2, msg_a_answer) = keep_phone_message(
        &fixture.vault,
        fixture.agent,
        conv_a,
        WitnessAuthor::Companion,
        A_ANSWER,
        CALL_A,
        false,
        OCCURRED_AT + 1,
    );
    let (turn_b1, msg_b_caller) = keep_phone_message(
        &fixture.vault,
        fixture.agent,
        conv_b,
        WitnessAuthor::Counterparty,
        B_WORDS,
        CALL_B,
        true,
        OCCURRED_AT + 2,
    );
    let (turn_b2, msg_b_answer) = keep_phone_message(
        &fixture.vault,
        fixture.agent,
        conv_b,
        WitnessAuthor::Companion,
        B_ANSWER,
        CALL_B,
        false,
        OCCURRED_AT + 3,
    );
    let control_msg = witness_control_message(&fixture);
    let l_proof = paired_agent_slip(&fixture);
    let g_proof = paired_generic_slip(&fixture, generic);
    let l_key = ordinary_key(&fixture, &l_proof);
    let g_key = ordinary_key(&fixture, &g_proof);
    let b_call_key = fixture
        .vault
        .phone_line_answer_read_key(&l_proof, fixture.identity, &receipt_b.record.payload_ref)
        .expect("B's call key");
    let owner_key = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .read_key()
        .expect("owner read key");
    Reach {
        fixture,
        conv_a,
        conv_b,
        turn_a1,
        turn_a2,
        turn_b1,
        turn_b2,
        msg_a_caller,
        msg_a_answer,
        msg_b_caller,
        msg_b_answer,
        control_msg,
        l_key,
        g_key,
        b_call_key,
        owner_key,
    }
}

#[test]
fn a_generic_read_grant_does_not_read_a_kept_call() {
    let reach = reach_fixture();
    let reader = reach.fixture.vault.scoped_read(reach.g_key.clone());
    assert!(
        reader
            .is_entity_readable(&reach.control_msg)
            .expect("G reads the control MESSAGE"),
        "precondition: G's band Grant reads the control MESSAGE",
    );
    for id in [
        &reach.conv_a,
        &reach.turn_a1,
        &reach.turn_a2,
        &reach.msg_a_caller,
        &reach.msg_a_answer,
    ] {
        assert!(
            !reader.is_entity_readable(id).expect("G reads A's thread"),
            "G must not read A's thread row {id:?}",
        );
    }
}

#[test]
fn the_line_agent_reads_its_callers_threads_outside_a_call() {
    let reach = reach_fixture();
    let reader = reach.fixture.vault.scoped_read(reach.l_key.clone());
    for id in [
        &reach.msg_a_caller,
        &reach.msg_a_answer,
        &reach.msg_b_caller,
        &reach.msg_b_answer,
    ] {
        assert!(
            reader.is_entity_readable(id).expect("L reads its callers"),
            "L must read its callers' MESSAGEs outside a call: {id:?}",
        );
    }
}

#[test]
fn under_the_default_caller_b_cannot_retrieve_caller_a_words() {
    let reach = reach_fixture();
    let call = reach.fixture.vault.scoped_read(reach.b_call_key.clone());
    for id in [&reach.msg_b_caller, &reach.msg_b_answer] {
        assert!(
            call.is_entity_readable(id).expect("B's call reads B"),
            "B's call must read B's MESSAGEs: {id:?}",
        );
    }
    for id in [&reach.msg_a_caller, &reach.msg_a_answer] {
        assert!(
            !call.is_entity_readable(id).expect("B's call reads A"),
            "B's call must not read A's MESSAGEs: {id:?}",
        );
    }
    let ordinary = reach.fixture.vault.scoped_read(reach.l_key.clone());
    for id in [&reach.msg_a_caller, &reach.msg_a_answer] {
        assert!(
            ordinary
                .is_entity_readable(id)
                .expect("L's ordinary key reads A"),
            "L's ordinary key must read A's MESSAGEs (the refusal is the call's, not a missing grant): {id:?}",
        );
    }
}

#[test]
fn revoking_the_callers_grant_stops_the_line_agent_reading() {
    let reach = reach_fixture();
    let registry = reach
        .fixture
        .vault
        .consent_registry(ConsentRegistryQuery {
            limit: 100,
            include_revoked: false,
        })
        .expect("the consent registry reads");
    let agent_hex = reach.fixture.agent.to_hex();
    let want = format!("conversation:{}", reach.conv_a.to_hex());
    let row = registry
        .rows
        .iter()
        .find(|row| {
            row.class.as_str() == "connector_witness_read"
                && row.subject == agent_hex
                && row
                    .selectors
                    .iter()
                    .any(|selector| selector.as_str() == want.as_str())
        })
        .expect("L's witness-read grant over A's thread");
    let grant_ref = EntityId::from_hex(&row.grant_ref).expect("grant id");
    let revoked = revoke_connector_witness_read_grant_as(
        &reach.fixture.vault,
        &reach.fixture.owner_proof,
        ActSurface::ThisInstall,
        ConnectorWitnessReadGrantRevokeRequest { grant_ref },
    )
    .expect("the owner revokes the grant");
    assert!(revoked.changed, "the revoke changed the grant");
    let reader = reach.fixture.vault.scoped_read(reach.l_key.clone());
    for id in [&reach.msg_a_caller, &reach.msg_a_answer] {
        assert!(
            !reader
                .is_entity_readable(id)
                .expect("L reads A after the revoke"),
            "revoked: L must not read A's MESSAGEs: {id:?}",
        );
    }
    for id in [&reach.msg_b_caller, &reach.msg_b_answer] {
        assert!(
            reader.is_entity_readable(id).expect("L reads B"),
            "L must still read B's MESSAGEs: {id:?}",
        );
    }
}

#[test]
fn the_owner_reads_every_kept_call() {
    let reach = reach_fixture();
    let reader = reach.fixture.vault.scoped_read(reach.owner_key.clone());
    for id in [
        &reach.conv_a,
        &reach.turn_a1,
        &reach.turn_a2,
        &reach.msg_a_caller,
        &reach.msg_a_answer,
        &reach.conv_b,
        &reach.turn_b1,
        &reach.turn_b2,
        &reach.msg_b_caller,
        &reach.msg_b_answer,
    ] {
        assert!(
            reader.is_entity_readable(id).expect("the owner reads"),
            "the owner must read every kept row: {id:?}",
        );
    }
}

#[test]
fn a_kept_call_thread_is_marked_and_keeps_its_mark() {
    let reach = reach_fixture();
    let body = reach
        .fixture
        .vault
        .conversation_body(reach.conv_a)
        .expect("A's thread body reads");
    let agent_hex = reach.fixture.agent.to_hex();
    assert_eq!(
        body.extra
            .get("phone_line_agent")
            .and_then(|value| value.as_str()),
        Some(agent_hex.as_str()),
        "A's thread names L as its phone line agent",
    );
    let mut stripped = body.clone();
    stripped.extra.remove("phone_line_agent");
    let bytes = stripped.to_bytes().expect("the stripped body encodes");
    let at = TimeRange {
        start: OCCURRED_AT,
        end: OCCURRED_AT,
    };
    let put = reach.fixture.vault.put_entity(
        &reach.conv_a,
        ENTITY_TYPE_CONVERSATION,
        at,
        OCCURRED_AT,
        &bytes,
    );
    assert!(put.is_err(), "dropping the mark must be refused");
    let err = format!("{:?}", put.unwrap_err());
    assert!(
        err.contains("birth fact"),
        "the refusal names the birth fact; seen {err}",
    );
}

#[test]
fn a_call_does_not_keep_into_a_thread_that_does_not_name_its_line_agent() {
    let reach = reach_fixture();
    let squatted = phone_thread_id(reach.fixture.agent, CALLER_C);
    let at = TimeRange {
        start: OCCURRED_AT,
        end: OCCURRED_AT,
    };
    // An unmarked CONVERSATION (an empty MessagePack map, as a plain mint)
    // stands at the id the line agent's calls from C land in.
    reach
        .fixture
        .vault
        .put_entity(
            &squatted,
            ENTITY_TYPE_CONVERSATION,
            at,
            OCCURRED_AT,
            &[0x80],
        )
        .expect("an unmarked conversation stands at C's thread id");
    let turn = phone_turn(
        squatted,
        WitnessAuthor::Counterparty,
        "C's words",
        "call-C",
        true,
        OCCURRED_AT + 4,
    );
    let kept = reach
        .fixture
        .vault
        .witness_call_turn(reach.fixture.agent, &turn);
    assert!(
        kept.is_err(),
        "a call must not keep into a thread that does not name its line agent",
    );
}
