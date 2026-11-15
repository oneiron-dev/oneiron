//! VOICE-PHONE-AGENT-REACH PR R2: the per-line reach Setting
//! (`voice.phone.reach`). R1's mark, per-caller grant and current-caller rule
//! stand; the line agent's reach is one owner choice per line: the DEFAULT
//! (this caller's own history + documents the owner picks), the WHOLE VAULT,
//! or a CUSTOM scope. Under the default, caller B's call cannot retrieve
//! caller A's words; under the whole vault it can. A generic read (an agent
//! Grant whose bands cover MESSAGE + CONVERSATION) no longer reaches phone
//! call rows. An agent's narrowing of the reach lands; a widening waits for
//! the owner.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --test phone_thread_reach`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip};
use oneiron::channel_identity::{
    ChannelActorRegistration, ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment,
    ChannelIdentityStep, SelfHeldShape,
};
use oneiron::claim::{CallerLocality, ScopedReadActorKey, base_world_id, default_project_id};
use oneiron::consent::{AuthenticatedOwner, ConsentRegistryQuery};
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{
    AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput, WitnessAuthor,
    WitnessMessage, WitnessTurn,
};
use oneiron::phone_line::{
    PhoneLineArrival, PhoneLineArrivalReceipt, PhoneLineConfig, PhoneLineState,
};
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, ConnectorWitnessReadGrantRevokeRequest,
    create_agent_definition_as, mint_agent_grant_as, revoke_connector_witness_read_grant_as,
};
use oneiron::voice_call::PhoneReach;
use oneiron::{EdgeActorClass, EdgeKind, EntityId, Vault, VaultConfig};
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
            PhoneLineConfig { enabled },
        )
        .expect("owner stores the phone line setting");
    assert!(
        state.enabled == enabled
            && state.agent_ref == fixture.agent
            && state.bridge_actor == fixture.bridge,
        "line {:?}; expected enabled={enabled}, agent={:?}, bridge={:?}; seen {state:?}",
        fixture.identity,
        fixture.agent,
        fixture.bridge,
    );
    if enabled {
        set_reach_as_owner(
            fixture,
            PhoneReach::Custom {
                scope: share_scope,
                include_other_callers: false,
            },
        );
    }
}

/// The owner sets the line's reach, then reads it back.
fn set_reach_as_owner(fixture: &Fixture, reach: PhoneReach) {
    let outcome = fixture
        .vault
        .set_setting(
            SettingCaller::Owner(&fixture.owner_proof),
            SetSetting {
                key: "voice.phone.reach".to_owned(),
                item: Some(fixture.identity.to_hex()),
                scope: SettingScope::Vault,
                mode: SettingMode::Value,
                value: Some(serde_json::to_value(&reach).expect("the reach encodes")),
                expected_revision: None,
                why: None,
                check_in_ref: None,
            },
        )
        .expect("owner sets the line's reach");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the owner's reach change applies; seen {outcome:?}",
    );
    assert_eq!(
        fixture
            .vault
            .phone_line_reach(fixture.identity, fixture.agent)
            .expect("the line's reach reads"),
        reach,
        "the line's reach reads the value the owner set",
    );
}

/// The Custom preset the R1 tests keep: the base world, the old share_scope
/// plus the current-caller rule.
fn custom_base() -> PhoneReach {
    PhoneReach::Custom {
        scope: worlds_scope(&[base_world_id()]),
        include_other_callers: false,
    }
}

/// One plain CLAIM row in `world`: the tests' picked and unpicked documents,
/// readable by the line agent's base-world Grant outside a call.
fn write_owner_claim(fixture: &Fixture, world: EntityId, value: &str) -> EntityId {
    let id = EntityId::now();
    fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_owner_authorship(&fixture.owner_proof)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(id.to_hex()),
            predicate: "profile.preference".to_owned(),
            subject_ref: fixture.owner.to_hex(),
            value: json!(value),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: world.to_hex(),
                scope_facet_id: fixture
                    .vault
                    .default_facet()
                    .expect("owner default facet")
                    .to_hex(),
                scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                scope_project_id: default_project_id().to_hex(),
            },
            sensitivity: None,
            evidence_turn_refs: Vec::new(),
            valid_from: None,
            valid_to: None,
            occurred_at: Some(OCCURRED_AT),
            learned_at: Some(OCCURRED_AT),
            salience: None,
        })
        .expect("owner writes a claim in the requested world");
    id
}

/// The owner mints `agent` a Grant listing `vault.settings.set`, so an
/// agent's widening opens a check-in instead of being refused.
fn mint_settings_grant(fixture: &Fixture, agent: EntityId) {
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "read".to_owned(),
        "vault.settings.set".to_owned(),
    ]));
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
    .expect("owner mints the agent a settings Grant");
    assert!(
        minted.grant.confers,
        "the agent's settings Grant confers its read"
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
    doc: EntityId,
    doc_part: EntityId,
    other_doc: EntityId,
    l_key: ScopedReadActorKey,
    g_key: ScopedReadActorKey,
    b_call_key: ScopedReadActorKey,
    owner_key: ScopedReadActorKey,
    l_proof: VerifiedSlip,
    receipt_b: PhoneLineArrivalReceipt,
}

fn reach_fixture(reach: PhoneReach) -> Reach {
    let fixture = fixture();
    let generic = create_enabled_agent(&fixture.vault, &fixture.owner_proof, "generic_reader");
    mint_read_grant(&fixture, fixture.agent);
    mint_read_grant(&fixture, generic);
    configure(&fixture, true, worlds_scope(&[base_world_id()]));
    if reach != custom_base() {
        set_reach_as_owner(&fixture, reach);
    }
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
    let doc = write_owner_claim(&fixture, base_world_id(), "the picked document");
    let doc_part = write_owner_claim(
        &fixture,
        base_world_id(),
        "a row derived from the picked document",
    );
    fixture
        .vault
        .put_edge(&doc_part, EdgeKind::DerivedFrom, &doc, 1.0)
        .expect("the derived row names its document");
    let other_doc = write_owner_claim(&fixture, base_world_id(), "an unpicked document");
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
        doc,
        doc_part,
        other_doc,
        l_key,
        g_key,
        b_call_key,
        owner_key,
        l_proof,
        receipt_b,
    }
}

#[test]
fn a_generic_read_grant_does_not_read_a_kept_call() {
    let reach = reach_fixture(custom_base());
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
    let reach = reach_fixture(custom_base());
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
    for reach in [
        PhoneReach::Default {
            documents: Vec::new(),
        },
        custom_base(),
    ] {
        let preset = if matches!(reach, PhoneReach::Default { .. }) {
            "Default"
        } else {
            "Custom"
        };
        let got = reach_fixture(reach);
        let call = got.fixture.vault.scoped_read(got.b_call_key.clone());
        for (row, id) in [
            ("msg_b_caller", &got.msg_b_caller),
            ("msg_b_answer", &got.msg_b_answer),
        ] {
            assert!(
                call.is_entity_readable(id).expect("B's call reads B"),
                "preset {preset}: B's call must read B's {row}",
            );
        }
        for (row, id) in [
            ("msg_a_caller", &got.msg_a_caller),
            ("msg_a_answer", &got.msg_a_answer),
        ] {
            assert!(
                !call.is_entity_readable(id).expect("B's call reads A"),
                "preset {preset}: B's call must not read A's {row}",
            );
        }
        let ordinary = got.fixture.vault.scoped_read(got.l_key.clone());
        for (row, id) in [
            ("msg_a_caller", &got.msg_a_caller),
            ("msg_a_answer", &got.msg_a_answer),
        ] {
            assert!(
                ordinary
                    .is_entity_readable(id)
                    .expect("L's ordinary key reads A"),
                "preset {preset}: L's ordinary key must read A's {row} (the refusal is the call's, not a missing grant)",
            );
        }
    }
}

#[test]
fn revoking_the_callers_grant_stops_the_line_agent_reading() {
    let reach = reach_fixture(custom_base());
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
    let reach = reach_fixture(custom_base());
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
    let reach = reach_fixture(custom_base());
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
    let reach = reach_fixture(custom_base());
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

#[test]
fn under_the_whole_vault_caller_b_reads_caller_a_words() {
    let got = reach_fixture(PhoneReach::WholeVault);
    let call = got.fixture.vault.scoped_read(got.b_call_key.clone());
    for (row, id) in [
        ("msg_a_caller", &got.msg_a_caller),
        ("msg_a_answer", &got.msg_a_answer),
        ("msg_b_caller", &got.msg_b_caller),
        ("msg_b_answer", &got.msg_b_answer),
        ("control_msg", &got.control_msg),
    ] {
        assert!(
            call.is_entity_readable(id)
                .expect("preset WholeVault: B's call reads"),
            "preset WholeVault: B's call must read {row}",
        );
    }
}

/// REACH-CUSTOM-CALLER-RULE = A (Engine 16 Nov 04:16): a custom scope that
/// includes other callers is decided by its Scope alone, so B's call reads
/// A's words in the base world, as under the whole vault; the same scope
/// without the flag keeps the current-caller rule
/// (`under_the_default_caller_b_cannot_retrieve_caller_a_words`).
#[test]
fn a_custom_reach_that_includes_other_callers_reads_them() {
    let got = reach_fixture(PhoneReach::Custom {
        scope: worlds_scope(&[base_world_id()]),
        include_other_callers: true,
    });
    let call = got.fixture.vault.scoped_read(got.b_call_key.clone());
    for (row, id) in [
        ("msg_a_caller", &got.msg_a_caller),
        ("msg_a_answer", &got.msg_a_answer),
        ("msg_b_caller", &got.msg_b_caller),
        ("msg_b_answer", &got.msg_b_answer),
    ] {
        assert!(
            call.is_entity_readable(id)
                .expect("preset Custom with other callers: B's call reads"),
            "preset Custom with other callers: B's call must read {row}",
        );
    }
}

#[test]
fn under_the_default_a_call_reads_only_its_callers_thread_and_the_picked_documents() {
    // `doc` only exists once the fixture stands, so the fixture answers
    // under an empty Default first; the owner then picks `doc`, and B's call
    // answers again, freezing the picked set. The effective reach is
    // Default{documents: [doc]}.
    let got = reach_fixture(PhoneReach::Default {
        documents: Vec::new(),
    });
    set_reach_as_owner(
        &got.fixture,
        PhoneReach::Default {
            documents: vec![got.doc.to_hex()],
        },
    );
    let key = got
        .fixture
        .vault
        .phone_line_answer_read_key(
            &got.l_proof,
            got.fixture.identity,
            &got.receipt_b.record.payload_ref,
        )
        .expect("preset Default{doc}: B's new call key");
    let call = got.fixture.vault.scoped_read(key);
    for (row, id) in [
        ("msg_b_caller", &got.msg_b_caller),
        ("msg_b_answer", &got.msg_b_answer),
        ("doc", &got.doc),
        ("doc_part", &got.doc_part),
    ] {
        assert!(
            call.is_entity_readable(id)
                .expect("preset Default{doc}: B's call reads"),
            "preset Default{{doc}}: B's call must read {row}",
        );
    }
    for (row, id) in [
        ("msg_a_caller", &got.msg_a_caller),
        ("msg_a_answer", &got.msg_a_answer),
        ("control_msg", &got.control_msg),
        ("other_doc", &got.other_doc),
    ] {
        assert!(
            !call
                .is_entity_readable(id)
                .expect("preset Default{doc}: B's call reads"),
            "preset Default{{doc}}: B's call must not read {row}",
        );
    }
    let ordinary = got.fixture.vault.scoped_read(got.l_key.clone());
    for (row, id) in [
        ("msg_b_caller", &got.msg_b_caller),
        ("msg_b_answer", &got.msg_b_answer),
        ("doc", &got.doc),
        ("doc_part", &got.doc_part),
        ("msg_a_caller", &got.msg_a_caller),
        ("msg_a_answer", &got.msg_a_answer),
        ("control_msg", &got.control_msg),
        ("other_doc", &got.other_doc),
    ] {
        assert!(
            ordinary
                .is_entity_readable(id)
                .expect("preset Default{doc}: L's ordinary key reads"),
            "preset Default{{doc}}: L's ordinary key must read {row} (the refusal is the call's)",
        );
    }
}

#[test]
fn the_line_agents_narrowing_lands_at_the_next_read() {
    let got = reach_fixture(PhoneReach::WholeVault);
    let call = got.fixture.vault.scoped_read(got.b_call_key.clone());
    assert!(
        call.is_entity_readable(&got.msg_a_caller)
            .expect("preset WholeVault: B's call reads A's caller row"),
        "preset WholeVault: B's call must read msg_a_caller",
    );
    let outcome = got
        .fixture
        .vault
        .set_setting(
            SettingCaller::Agent(got.fixture.agent),
            SetSetting {
                key: "voice.phone.reach".to_owned(),
                item: Some(got.fixture.identity.to_hex()),
                scope: SettingScope::Agent(got.fixture.agent),
                mode: SettingMode::Value,
                value: Some(
                    serde_json::to_value(&PhoneReach::Default {
                        documents: Vec::new(),
                    })
                    .expect("the narrowing encodes"),
                ),
                expected_revision: None,
                why: None,
                check_in_ref: None,
            },
        )
        .expect("the line agent's narrowing sets");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the line agent's narrowing lands; seen {outcome:?}",
    );
    let narrowed = got.fixture.vault.scoped_read(got.b_call_key.clone());
    for (row, id) in [
        ("msg_a_caller", &got.msg_a_caller),
        ("control_msg", &got.control_msg),
    ] {
        assert!(
            !narrowed
                .is_entity_readable(id)
                .expect("narrowed to Default: B's call reads"),
            "narrowed to Default: the same call must no longer read {row}",
        );
    }
    assert!(
        narrowed
            .is_entity_readable(&got.msg_b_caller)
            .expect("narrowed to Default: B's call reads B"),
        "narrowed to Default: the same call must still read msg_b_caller",
    );
}

#[test]
fn an_agents_widening_of_a_lines_reach_waits_for_the_owner() {
    let got = reach_fixture(PhoneReach::Default {
        documents: Vec::new(),
    });
    mint_settings_grant(&got.fixture, got.fixture.agent);
    let outcome = got
        .fixture
        .vault
        .set_setting(
            SettingCaller::Agent(got.fixture.agent),
            SetSetting {
                key: "voice.phone.reach".to_owned(),
                item: Some(got.fixture.identity.to_hex()),
                scope: SettingScope::Vault,
                mode: SettingMode::Value,
                value: Some(
                    serde_json::to_value(&PhoneReach::WholeVault).expect("the widening encodes"),
                ),
                expected_revision: None,
                why: None,
                check_in_ref: None,
            },
        )
        .expect("the line agent's widening asks");
    assert!(
        matches!(outcome, SetSettingOutcome::Pending { .. }),
        "an agent's widening waits for the owner; seen {outcome:?}",
    );
    assert_eq!(
        got.fixture
            .vault
            .phone_line_reach(got.fixture.identity, got.fixture.agent)
            .expect("the line's reach reads"),
        PhoneReach::Default {
            documents: Vec::new(),
        },
        "while the widening waits, the line's reach still reads Default",
    );
    let call = got.fixture.vault.scoped_read(got.b_call_key.clone());
    assert!(
        !call
            .is_entity_readable(&got.msg_a_caller)
            .expect("pending widening: B's call reads"),
        "pending widening: B's call must still not read msg_a_caller",
    );
}

#[test]
fn the_owners_widening_waits_for_the_next_call() {
    let got = reach_fixture(PhoneReach::Default {
        documents: Vec::new(),
    });
    set_reach_as_owner(&got.fixture, PhoneReach::WholeVault);
    let call = got.fixture.vault.scoped_read(got.b_call_key.clone());
    assert!(
        !call
            .is_entity_readable(&got.msg_a_caller)
            .expect("frozen Default: the old call reads"),
        "frozen Default: the same call must still not read msg_a_caller after the owner's widening",
    );
    let fresh = got
        .fixture
        .vault
        .phone_line_answer_read_key(
            &got.l_proof,
            got.fixture.identity,
            &got.receipt_b.record.payload_ref,
        )
        .expect("live WholeVault: a new call key");
    let answered = got.fixture.vault.scoped_read(fresh);
    assert!(
        answered
            .is_entity_readable(&got.msg_a_caller)
            .expect("live WholeVault: the new call reads"),
        "live WholeVault: the next call must read msg_a_caller",
    );
}

#[test]
fn the_line_config_no_longer_takes_share_scope() {
    assert!(
        serde_json::from_str::<PhoneLineConfig>(r#"{"enabled":true, "share_scope":{}}"#).is_err(),
        "a body still naming share_scope is refused",
    );
    assert!(
        serde_json::from_str::<PhoneLineConfig>(r#"{"enabled":true}"#).is_ok(),
        "an {enabled}-only body decodes",
    );
    let fixture = fixture();
    configure(&fixture, true, worlds_scope(&[base_world_id()]));
    let state = fixture
        .vault
        .phone_line_state_as(&fixture.owner_proof, fixture.identity)
        .expect("owner reads the line state")
        .expect("the line state stands");
    let json = serde_json::to_value(&state).expect("the state encodes");
    assert!(
        json.get("share_scope").is_some(),
        "the stored state still names share_scope",
    );
    assert!(
        serde_json::from_value::<PhoneLineState>(json).is_ok(),
        "a state naming share_scope still decodes",
    );
}

/// The `phone_thread` value a TURN/MESSAGE/SESSION body carries, if any.
/// Decoded here because `voice_call::phone_thread_stamp` is crate-private.
fn phone_thread_of(body: &[u8]) -> Option<String> {
    let mut cursor = body;
    let Ok(rmpv::Value::Map(fields)) = rmpv::decode::read_value(&mut cursor) else {
        return None;
    };
    if !cursor.is_empty() {
        return None;
    }
    let mut found = None;
    for (key, value) in &fields {
        if key.as_str() != Some("phone_thread") {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = value.as_str().map(|text| text.to_owned());
    }
    found
}

#[test]
fn a_kept_turn_and_message_carry_their_threads_stamp() {
    let reach = reach_fixture(custom_base());
    let want = reach.conv_a.to_hex();
    for (id, label) in [
        (&reach.turn_a1, "turn_a1"),
        (&reach.turn_a2, "turn_a2"),
        (&reach.msg_a_caller, "msg_a_caller"),
        (&reach.msg_a_answer, "msg_a_answer"),
    ] {
        let body = reach
            .fixture
            .vault
            .get(id)
            .unwrap_or_else(|_| panic!("A's {label} raw row reads as the owner"))
            .unwrap_or_else(|| panic!("A's {label} raw row is present"));
        let got = phone_thread_of(&body);
        assert_eq!(
            got.as_deref(),
            Some(want.as_str()),
            "A's {label} must carry phone_thread=conv_a; seen {got:?}",
        );
    }
}

#[test]
fn an_empty_put_of_a_phone_thread_is_refused() {
    let reach = reach_fixture(custom_base());
    let at = TimeRange {
        start: OCCURRED_AT,
        end: OCCURRED_AT,
    };
    let conv_put = reach.fixture.vault.put_entity(
        &reach.conv_a,
        ENTITY_TYPE_CONVERSATION,
        at,
        OCCURRED_AT,
        b"",
    );
    assert!(
        conv_put.is_err(),
        "an empty put of A's CONVERSATION conv_a must be refused",
    );
    // A MESSAGE raw put never stages (the witness door owns MESSAGE rows),
    // so this is refused at the builder door before the phone guard; still
    // refused.
    let msg_put = reach.fixture.vault.put_entity(
        &reach.msg_a_caller,
        ENTITY_TYPE_MESSAGE,
        at,
        OCCURRED_AT,
        b"",
    );
    assert!(
        msg_put.is_err(),
        "an empty put of A's MESSAGE msg_a_caller must be refused",
    );
}

#[test]
fn deleting_a_phone_thread_alone_leaves_its_words_gated() {
    use oneiron::memory::SafeDeleteReason;
    let reach = reach_fixture(custom_base());
    reach
        .fixture
        .vault
        .memory(reach.fixture.owner, EdgeActorClass::Human)
        .safe_delete(&reach.conv_a.to_hex(), SafeDeleteReason::UserDelete)
        .expect("the owner deletes A's CONVERSATION conv_a alone");
    let generic = reach.fixture.vault.scoped_read(reach.g_key.clone());
    for id in [&reach.msg_a_caller, &reach.msg_a_answer] {
        assert!(
            !generic
                .is_entity_readable(id)
                .unwrap_or_else(|_| panic!("G reads A's MESSAGE {id:?} after the delete")),
            "after deleting A's CONVERSATION conv_a alone, G must still not read A's MESSAGE {id:?}",
        );
    }
    let b_call = reach.fixture.vault.scoped_read(reach.b_call_key.clone());
    for id in [&reach.msg_a_caller, &reach.msg_a_answer] {
        assert!(
            !b_call
                .is_entity_readable(id)
                .unwrap_or_else(|_| panic!("B's call reads A's MESSAGE {id:?} after the delete")),
            "after deleting A's CONVERSATION conv_a alone, B's call must still not read A's MESSAGE {id:?}",
        );
    }
}

#[test]
fn a_generic_read_does_not_read_a_phone_threads_session() {
    let reach = reach_fixture(custom_base());
    let session_a = oneiron::test_doors::connector_thread_session::thread_session(reach.conv_a)
        .expect("A's thread SESSION session_a id derives");
    let owner = reach.fixture.vault.scoped_read(reach.owner_key.clone());
    assert!(
        owner
            .is_entity_readable(&session_a)
            .expect("the owner reads A's thread SESSION session_a"),
        "the owner must read A's thread SESSION session_a",
    );
    let generic = reach.fixture.vault.scoped_read(reach.g_key.clone());
    assert!(
        !generic
            .is_entity_readable(&session_a)
            .expect("G reads A's thread SESSION session_a"),
        "G must not read A's thread SESSION session_a",
    );
    let b_call = reach.fixture.vault.scoped_read(reach.b_call_key.clone());
    assert!(
        !b_call
            .is_entity_readable(&session_a)
            .expect("B's call reads A's thread SESSION session_a"),
        "B's call must not read A's thread SESSION session_a",
    );
}

#[cfg(all(feature = "sync", feature = "test-hooks"))]
#[test]
fn a_restricted_selector_does_not_carry_a_kept_call() {
    use oneiron::federation::{
        FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
    };
    use oneiron::sync::schema::create_window_doc;
    use oneiron::sync::window::reverse_rematerialize;
    use oneiron::sync::{
        SyncSelector, SyncSelectorWorld, WindowKey, authorize_sync_selector, filtered_window_doc,
        put_selector_test_federation_grant,
    };
    use oneiron_authority::federation::scope_codec::read_preset;

    const SHARED_VAULT_ID: u64 = 7;

    let reach = reach_fixture(custom_base());
    let member = EntityId::now();
    let now = reach.fixture.vault.now_recorded_at();
    let at = TimeRange {
        start: now,
        end: now,
    };
    reach
        .fixture
        .vault
        .put_entity(
            &member,
            oneiron::registry::ENTITY_TYPE_PERSON,
            at,
            now,
            &rmp_serde::to_vec_named(&serde_json::json!({ "name": "member" }))
                .expect("member PERSON body"),
        )
        .expect("FIXTURE: a member PERSON");
    let scope = FederationGrantScope::vault(SHARED_VAULT_ID);
    let grant_id = EntityId::now();
    let mut grant = FederationGrant::new(
        scope,
        member,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    grant.authority_scope = read_preset();
    put_selector_test_federation_grant(&reach.fixture.vault, &grant_id, &grant, now)
        .expect("FIXTURE: the member's federation grant");
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    authorize_sync_selector(&reach.fixture.vault, scope, &selector)
        .expect("FIXTURE: the member's selector is authorized");
    // The kept rows were learned at OCCURRED_AT; pack that window.
    let key = WindowKey::from_timestamp(OCCURRED_AT);
    let source = create_window_doc("selector", &key);
    reverse_rematerialize(&reach.fixture.vault, &source, &key).expect("the window pack");
    for (id, label) in [
        (&reach.conv_a, "conv_a"),
        (&reach.turn_a1, "turn_a1"),
        (&reach.msg_a_caller, "msg_a_caller"),
        (&reach.control_msg, "control_msg"),
    ] {
        assert!(
            source.get_map("entities").get(&id.to_hex()).is_some(),
            "FIXTURE: the packed window holds A's {label}",
        );
    }
    let selected = filtered_window_doc(&reach.fixture.vault, &source, &key, scope, &selector)
        .expect("the member's restricted selector window");
    let mut carried = BTreeSet::new();
    selected.get_map("entities").for_each(|key, _| {
        if let Ok(id) = EntityId::from_hex(key) {
            carried.insert(id);
        }
    });
    assert!(
        carried.contains(&reach.control_msg),
        "precondition: the Member restricted window still carries the control MESSAGE control_msg",
    );
    for (id, label) in [
        (&reach.conv_a, "conv_a"),
        (&reach.turn_a1, "turn_a1"),
        (&reach.turn_a2, "turn_a2"),
        (&reach.msg_a_caller, "msg_a_caller"),
        (&reach.msg_a_answer, "msg_a_answer"),
    ] {
        assert!(
            !carried.contains(id),
            "LEAK: the Member restricted window carries A's {label}",
        );
    }
}

#[test]
fn an_off_record_session_cannot_strip_a_phone_stamp() {
    use oneiron::RawEntityPut;
    use oneiron::off_record::OffRecordBackendClass;
    let reach = reach_fixture(custom_base());
    let room = reach
        .fixture
        .vault
        .off_record_session_vault()
        .enter("phone-f2-room", OffRecordBackendClass::Local)
        .expect("FIXTURE: an off-record room");
    let body = reach
        .fixture
        .vault
        .conversation_body(reach.conv_a)
        .expect("A's thread CONVERSATION conv_a body reads");
    let mut stripped = body.clone();
    stripped.extra.remove("phone_line_agent");
    let bytes = stripped.to_bytes().expect("the stripped body encodes");
    let now = reach.fixture.vault.now_recorded_at();
    let at = TimeRange {
        start: now,
        end: now,
    };
    let put = reach
        .fixture
        .vault
        .memory(reach.fixture.owner, EdgeActorClass::Human)
        .in_off_record_session(room.session_ref())
        .raw_put_entity(RawEntityPut {
            id: reach.conv_a,
            entity_type: ENTITY_TYPE_CONVERSATION,
            occurred: at,
            learned_at: now,
            data: &bytes,
        });
    assert!(
        put.is_err(),
        "an off-record session restage of A's CONVERSATION conv_a without its mark must be refused",
    );
}

/// A MessagePack map of `entries`, as a raw put carries a body.
fn map_body(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(
            entries
                .iter()
                .map(|(key, value)| (rmpv::Value::from(*key), rmpv::Value::from(*value)))
                .collect(),
        ),
    )
    .expect("FIXTURE: the body encodes");
    body
}

/// Asserts `put` was refused for the phone mark its body names.
fn assert_phone_mark_refused<T, E: std::fmt::Debug>(put: Result<T, E>, what: &str) {
    match put {
        Ok(_) => panic!("LEAK: {what} landed with a phone mark no phone keep wrote"),
        Err(err) => {
            let text = format!("{err:?}");
            assert!(
                text.contains("phone keep"),
                "{what} must be refused for its phone mark; seen {text}",
            );
        }
    }
}

/// R2 review F1: under the default reach a row's own phone stamp admits it
/// to its caller's call, so no writer but the phone keep births a phone
/// mark. A plain put of a fresh TURN, of a stored unstamped TURN and of a
/// fresh CONVERSATION, each naming a phone mark, is refused; the same TURN
/// without the mark lands.
#[test]
fn no_write_but_the_phone_keep_births_a_phone_mark() {
    use oneiron::registry::ENTITY_TYPE_TURN;
    let reach = reach_fixture(custom_base());
    let vault = &reach.fixture.vault;
    let now = vault.now_recorded_at();
    let at = TimeRange {
        start: now,
        end: now,
    };
    let conv_b = reach.conv_b.to_hex();
    let plain = map_body(&[("role", "user"), ("text", CONTROL_WORDS)]);
    let forged = map_body(&[
        ("role", "user"),
        ("text", CONTROL_WORDS),
        ("phone_thread", conv_b.as_str()),
    ]);
    let stored = EntityId::now();
    vault
        .put_entity(&stored, ENTITY_TYPE_TURN, at, now, &plain)
        .expect("precondition: a plain TURN with no phone mark lands");
    assert_phone_mark_refused(
        vault.put_entity(&stored, ENTITY_TYPE_TURN, at, now, &forged),
        "a stored unstamped TURN restamped into B's thread",
    );
    assert_phone_mark_refused(
        vault.put_entity(&EntityId::now(), ENTITY_TYPE_TURN, at, now, &forged),
        "a fresh TURN stamped into B's thread",
    );
    let agent = reach.fixture.agent.to_hex();
    assert_phone_mark_refused(
        vault.put_entity(
            &EntityId::now(),
            ENTITY_TYPE_CONVERSATION,
            at,
            now,
            &map_body(&[("phone_line_agent", agent.as_str())]),
        ),
        "a fresh CONVERSATION marked as L's phone thread",
    );
    let body = vault
        .get(&stored)
        .expect("the stored TURN reads as the owner")
        .expect("the stored TURN is present");
    assert_eq!(
        phone_thread_of(&body),
        None,
        "the stored TURN keeps no phone mark after the refused restamp",
    );
}

#[cfg(all(feature = "sync", feature = "test-hooks"))]
fn reach_summary_canonical(conversation: EntityId) -> oneiron::conversation_dag::ScopeSelector {
    oneiron::conversation_dag::ScopeSelector {
        conversation,
        session: None,
        path: oneiron::conversation_dag::ScopePath::Canonical,
        include_forks: false,
    }
}

#[cfg(all(feature = "sync", feature = "test-hooks"))]
struct ReachSummaryNoInner;

#[cfg(all(feature = "sync", feature = "test-hooks"))]
impl oneiron::DreamerAttemptExecutor for ReachSummaryNoInner {
    async fn execute(
        &mut self,
        _attempt: &oneiron::dreamer_runner::DreamerAdmittedAttempt,
        _ctx: &mut oneiron::WakeAttemptContext<'_>,
    ) -> oneiron::Result<oneiron::DreamerAttemptExecution> {
        panic!("FIXTURE: only the requested scope-summary attempt runs")
    }
}

#[cfg(all(feature = "sync", feature = "test-hooks"))]
struct ReachSummaryBackend {
    source_text: String,
    response: std::sync::Mutex<Option<oneiron::LlmResponse>>,
}

#[cfg(all(feature = "sync", feature = "test-hooks"))]
impl oneiron::LlmBackend for ReachSummaryBackend {
    fn generate<'a>(
        &'a self,
        request: oneiron::LlmRequest,
        _lease: &'a oneiron::BudgetLease,
    ) -> oneiron::LlmGenerateFuture<'a> {
        assert!(
            request
                .messages
                .iter()
                .flat_map(|message| &message.content)
                .any(|part| {
                    matches!(part, oneiron::ContentPart::Text { text, .. }
                    if text.contains(self.source_text.as_str()))
                }),
            "FIXTURE: the Dreamer's actual input contains the source MESSAGE's words"
        );
        let response = self
            .response
            .lock()
            .expect("script")
            .take()
            .expect("one call");
        Box::pin(async move { Ok(response) })
    }

    fn stream<'a>(
        &'a self,
        _request: oneiron::LlmRequest,
        _lease: &'a oneiron::BudgetLease,
    ) -> oneiron::LlmStreamResult<'a> {
        Err(oneiron::LlmError::Fatal(
            oneiron::FatalLlmError::InvalidRequest,
        ))
    }
}

#[cfg(all(feature = "sync", feature = "test-hooks"))]
fn reach_summary_response(text: &str) -> oneiron::LlmResponse {
    use oneiron::llm::ReplyAssertions;
    use oneiron::{ContentPart, FinishReason, LlmMessage, LlmMessageRole, LlmUsage};

    oneiron::LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text {
                text: json!({ "text": text, "keep": "" }).to_string(),
                signature: None,
            }],
        },
        usage: LlmUsage::zero(),
        finish_reason: FinishReason::Stop,
        reply_assertions: ReplyAssertions::default(),
        token_scores: None,
    }
}

#[cfg(all(feature = "sync", feature = "test-hooks"))]
fn reach_block_on_ready<F: std::future::Future>(future: F) -> F::Output {
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(output) => output,
        std::task::Poll::Pending => panic!("FIXTURE: the scripted executor unexpectedly waited"),
    }
}

#[cfg(all(feature = "sync", feature = "test-hooks"))]
fn reach_allow_egress(_: &oneiron::LlmRequest) -> bool {
    true
}

#[cfg(all(feature = "sync", feature = "test-hooks"))]
fn reach_compose_summary(
    vault: &Vault,
    owner: EntityId,
    conversation: EntityId,
    text: &str,
    now: u64,
) -> EntityId {
    use oneiron::dreamer_consolidation::ScopeSummaryExecutor;
    use oneiron::dreamer_runner::{
        AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt, CompleteDreamerAttempt,
        DreamerAdmissionOutcome, DreamerClaimAuthoringAdmission, DreamerClaimAuthoringBatchTier,
        DreamerConsolidationAdmissionOutcome, DreamerConsolidationScope, DreamerRunnerStore,
    };
    use oneiron::llm::{HostInferenceBinding, HostInferenceContext};
    use oneiron::scope_summary::{ScopeSummaryRequest, ScopeSummaryTarget};
    use oneiron::{
        BudgetExhaustionPolicy, BudgetGuard, DreamerAttemptExecution, DreamerAttemptExecutor,
        ModelId, ModelLocality, WakeAttemptContext, WakePassDeadline, WriteActor,
    };

    let queued = vault
        .request_scope_summary(&ScopeSummaryRequest {
            target: ScopeSummaryTarget::Scope {
                scope: reach_summary_canonical(conversation),
                land_on: None,
                as_record: false,
            },
            requester: WriteActor::new(owner, EdgeActorClass::Human),
        })
        .expect("declare summary");
    assert!(!queued.coalesced, "FIXTURE: a fresh summary declaration");
    let store = DreamerRunnerStore::new(vault);
    let admitted = match store
        .admit_next_consolidation(AdmitDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            local_node_id: 1,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
            admission: AdmitDreamerAttempt {
                lease_owner: "fixture".to_owned(),
                now,
                budget_id: "wake".to_owned(),
                budget_total_units: 10_000,
                reserve_units: 100,
                started_milestone: None,
            },
        })
        .expect("admit summary")
    {
        DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
            admitted,
        )) => *admitted,
        other => panic!("FIXTURE: summary was not admitted: {other:?}"),
    };
    assert_eq!(
        admitted.status.attempt.id, queued.attempt,
        "FIXTURE: the admitted attempt is this summary's declaration"
    );
    let backend = ReachSummaryBackend {
        source_text: text.to_owned(),
        response: std::sync::Mutex::new(Some(reach_summary_response(text))),
    };
    let guard =
        BudgetGuard::with_reserve_units("wake", 10_000, 100, BudgetExhaustionPolicy::Suspend);
    let model = ModelId::new("test/model@r1").expect("model");
    let inference = HostInferenceContext {
        binding: HostInferenceBinding::Advertised {
            model: model.clone(),
            locality: ModelLocality::OwnServer,
            keyless: false,
        },
        extraction_egress: Some(&reach_allow_egress),
    };
    let deadline = WakePassDeadline::with_clock(180_000, Arc::new(|| 0u64));
    let mut executor = ScopeSummaryExecutor::new(
        ReachSummaryNoInner,
        &backend,
        &guard,
        vault.dreamer_authority().expect("Dreamer authority"),
        model,
        inference,
        Some("Summarize the supplied records."),
    );
    let mut context = WakeAttemptContext {
        vault,
        deadline: &deadline,
        cancel: None,
        device_cancel: None,
        budget_id: "wake",
        now_ms: now.saturating_mul(1000),
        prepared_wake: None,
        prepared_attempt: None,
        spend_meter: None,
    };
    let outcome =
        reach_block_on_ready(executor.execute(&admitted, &mut context)).expect("compose summary");
    assert!(
        matches!(outcome, DreamerAttemptExecution::Completed { .. }),
        "FIXTURE: the summary completed, not parked: {outcome:?}"
    );
    store
        .complete(CompleteDreamerAttempt {
            id: admitted.status.attempt.id,
            lease_owner: "fixture".to_owned(),
            attempt_count: admitted.status.attempt.attempt_count,
            now,
        })
        .expect("complete summary attempt");
    let result = vault
        .scope_summary_status(queued.attempt)
        .expect("summary status")
        .result
        .expect("the summary landed");
    EntityId::from_hex(&result.summary).expect("summary id")
}

#[cfg(all(feature = "sync", feature = "test-hooks"))]
fn reach_land_reply(
    vault: &Vault,
    owner: EntityId,
    summary: EntityId,
    turn: EntityId,
    text: &str,
) -> EntityId {
    use oneiron::WriteActor;

    let reply = vault
        .land_header(
            &summary,
            &turn,
            WriteActor::new(owner, EdgeActorClass::Human),
            true,
        )
        .expect("land the summary reply")
        .record
        .expect("as_record lands a TURN");
    let body: serde_json::Value = rmp_serde::from_slice(
        &vault
            .get(&reply)
            .expect("reply read")
            .expect("reply exists"),
    )
    .expect("reply body");
    assert_eq!(
        body["txt"], text,
        "FIXTURE: the reply copies the summary's words"
    );
    assert_eq!(
        body["summary"],
        summary.to_hex(),
        "FIXTURE: the reply names this summary"
    );
    reply
}

#[cfg(all(feature = "sync", feature = "test-hooks"))]
#[test]
fn a_restricted_selector_does_not_carry_a_summary_of_a_kept_call() {
    use oneiron::federation::{
        FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
    };
    use oneiron::scope_summary::decode_scope_summary_body;
    use oneiron::sync::schema::create_window_doc;
    use oneiron::sync::window::reverse_rematerialize;
    use oneiron::sync::{
        SyncSelector, SyncSelectorWorld, WindowKey, authorize_sync_selector, filtered_window_doc,
        put_selector_test_federation_grant,
    };
    use oneiron::{CallPurpose, ModelLocality};
    use oneiron_authority::federation::scope_codec::read_preset;

    const SHARED_VAULT_ID: u64 = 7;

    let reach = reach_fixture(custom_base());
    let vault = &reach.fixture.vault;
    let owner = reach.fixture.owner;

    // Scripted inference policy, as the precedent test sets it: the Dreamer
    // executor's model call is admitted at OwnServer locality.
    let mut defaults = vault.purpose_default_table().expect("inference defaults");
    defaults.extraction_max_locality = ModelLocality::OwnServer;
    defaults
        .purposes
        .get_mut(&CallPurpose::Extraction)
        .expect("extraction defaults")
        .locality = ModelLocality::OwnServer;
    vault
        .set_purpose_default_table(&defaults)
        .expect("scripted inference policy");

    // CONTROL conversation: one ordinary turn as witness_control_message
    // witnesses it, into a fresh conversation id.
    let control_conv = EntityId::now();
    let control_turn = WitnessTurn {
        conversation_ref: control_conv.to_hex(),
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
    let control_receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&control_turn)
        .expect("the control turn is witnessed");
    let control_turn_id = control_receipt.turn_id;
    let control_msg_id =
        EntityId::from_hex(&control_receipt.messages[0].id).expect("control message id");
    assert_eq!(
        vault
            .resolve_dag_scope(&reach_summary_canonical(control_conv))
            .expect("scope")
            .records,
        vec![control_turn_id],
        "FIXTURE: the control conversation resolves to its TURN, not its MESSAGE"
    );

    let now = vault.now_recorded_at();
    let s_control = reach_compose_summary(vault, owner, control_conv, CONTROL_WORDS, now);
    let control_body = decode_scope_summary_body(
        &vault
            .get(&s_control)
            .expect("summary read")
            .expect("summary exists"),
    )
    .expect("a scope-summary body, not an epoch");
    assert_eq!(control_body.v, 2, "FIXTURE: a composed v2 summary");
    assert_eq!(
        control_body.scope,
        Some(reach_summary_canonical(control_conv)),
        "FIXTURE: the source scope"
    );
    assert_eq!(
        control_body.covers,
        vec![control_turn_id],
        "FIXTURE: the exact TURN cover"
    );
    assert_eq!(
        control_body
            .messages
            .iter()
            .map(|source| source.id)
            .collect::<Vec<_>>(),
        vec![control_msg_id],
        "FIXTURE: the MESSAGE is a word source, not merely a child of a covered TURN"
    );
    assert_eq!(
        control_body.text, CONTROL_WORDS,
        "FIXTURE: the composed source words"
    );

    // S_phone over A's phone thread: the v1 test door, not the Dreamer path
    // (the Dreamer reads no phone row: its TURN read carries no principal
    // for the thread's ConversationMessages grant). Its covers are the kept
    // TURNs themselves, which carry phone_thread, so it is a scope SUMMARY
    // of the kept call all the same.
    let s_phone = oneiron::test_doors::scope_summary::mint_scope_summary(
        vault,
        &reach_summary_canonical(reach.conv_a),
        A_SECRET,
    )
    .expect("the phone summary mints");
    let phone_body = decode_scope_summary_body(
        &vault
            .get(&s_phone)
            .expect("summary read")
            .expect("summary exists"),
    )
    .expect("a scope-summary body, not an epoch");
    assert_eq!(
        phone_body.v, 1,
        "FIXTURE: the v1 test door mints a v1 summary"
    );
    assert_eq!(
        phone_body.scope,
        Some(reach_summary_canonical(reach.conv_a)),
        "FIXTURE: the source scope"
    );
    assert_eq!(
        phone_body.covers.len(),
        2,
        "FIXTURE: the phone summary covers both kept TURNs"
    );
    assert!(
        phone_body.covers.contains(&reach.turn_a1) && phone_body.covers.contains(&reach.turn_a2),
        "FIXTURE: the phone summary covers turn_a1 and turn_a2",
    );
    assert!(
        phone_body.messages.is_empty(),
        "FIXTURE: the v1 test door leaves messages empty",
    );
    assert_eq!(
        phone_body.text, A_SECRET,
        "FIXTURE: the minted source words"
    );

    let r_phone = reach_land_reply(vault, owner, s_phone, reach.turn_a2, A_SECRET);

    let member = EntityId::now();
    let member_now = vault.now_recorded_at();
    let at = TimeRange {
        start: member_now,
        end: member_now,
    };
    vault
        .put_entity(
            &member,
            oneiron::registry::ENTITY_TYPE_PERSON,
            at,
            member_now,
            &rmp_serde::to_vec_named(&serde_json::json!({ "name": "member" }))
                .expect("member PERSON body"),
        )
        .expect("FIXTURE: a member PERSON");
    let scope = FederationGrantScope::vault(SHARED_VAULT_ID);
    let grant_id = EntityId::now();
    let mut grant = FederationGrant::new(
        scope,
        member,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    grant.authority_scope = read_preset();
    put_selector_test_federation_grant(vault, &grant_id, &grant, member_now)
        .expect("FIXTURE: the member's federation grant");
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    authorize_sync_selector(vault, scope, &selector)
        .expect("FIXTURE: the member's selector is authorized");

    // The kept rows were learned at OCCURRED_AT; the summaries and the reply
    // were learned at the vault clock. Pack every window that holds
    // S_control, S_phone and R_phone.
    let keys = [
        WindowKey::from_timestamp(OCCURRED_AT),
        WindowKey::from_timestamp(now),
        WindowKey::from_timestamp(member_now),
        WindowKey::from_timestamp(vault.now_recorded_at()),
    ];
    let mut carried = BTreeSet::new();
    let mut packed = BTreeSet::new();
    for key in &keys {
        let source = create_window_doc("selector", key);
        reverse_rematerialize(vault, &source, key).expect("the window pack");
        for id in [&s_control, &s_phone, &r_phone] {
            if source.get_map("entities").get(&id.to_hex()).is_some() {
                packed.insert(*id);
            }
        }
        let selected = filtered_window_doc(vault, &source, key, scope, &selector)
            .expect("the member's restricted selector window");
        selected.get_map("entities").for_each(|key, _| {
            if let Ok(id) = EntityId::from_hex(key) {
                carried.insert(id);
            }
        });
    }
    for (id, label) in [
        (&s_control, "S_control"),
        (&s_phone, "S_phone"),
        (&r_phone, "R_phone"),
    ] {
        assert!(
            packed.contains(id),
            "FIXTURE: a packed window holds {label}"
        );
    }
    assert!(
        carried.contains(&s_control),
        "precondition: the Member restricted window still carries the control SUMMARY S_control",
    );
    assert!(
        !carried.contains(&s_phone),
        "LEAK: the Member restricted window carries the phone SUMMARY S_phone",
    );
    assert!(
        !carried.contains(&r_phone),
        "LEAK: the Member restricted window carries the phone reply TURN R_phone",
    );
}
