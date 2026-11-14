//! The agent phone line (OF-605, ARCH-0061 #agent-phone-line): off by
//! default, a stranger's call lands in the inbox the way stranger mail does,
//! the owner reads or erases its private metadata by an opaque ref, and the
//! agent answering the call reads only what the line may share.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::agent_inbox_lens::{AgentInboxLensItem, AgentInboxLensQuery};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip};
use oneiron::channel_identity::{
    ChannelActorRegistration, ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment,
    ChannelIdentityStep, SelfHeldShape,
};
use oneiron::claim::{CallerLocality, ScopedReadActorKey, base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::phone_line::{PhoneLineArrival, PhoneLineArrivalReceipt, PhoneLineConfig};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

const OCCURRED_AT: u64 = 1_769_947_200;
const LINE_NUMBER: &str = "+15550100";
const CALLER_NUMBER: &str = "+15550199";
const REFUSAL: &str = "phone line is absent, disabled, mismatched or unauthorized";
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
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "core:read".to_owned(),
        "core:write".to_owned(),
    ]));
    let holder = fixture.agent.to_hex();
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
    let signing_key = SigningKey::from_bytes(&[0x52; 32]);
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

fn stranger_call(call_id: &str) -> PhoneLineArrival {
    PhoneLineArrival {
        call_id: call_id.to_owned(),
        caller: Some(CALLER_NUMBER.to_owned()),
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

fn assert_refused<T>(outcome: oneiron::Result<T>, case: &str) {
    match outcome {
        Err(oneiron::Error::InvalidConfig(message)) if message == REFUSAL => {}
        other => panic!(
            "{case}: expected the phone line refusal {REFUSAL:?}; seen {:?}",
            other.map(|_| "an answer")
        ),
    }
}

/// The inbox rows the line's surface events draw; the identity's thread
/// memberships are not calls.
fn call_rows(fixture: &Fixture) -> Vec<AgentInboxLensItem> {
    fixture
        .vault
        .agent_inbox_lens(AgentInboxLensQuery {
            identity_ref: Some(fixture.identity),
            limit: 50,
            before: None,
        })
        .expect("owner inbox lens")
        .into_iter()
        .filter(|row| row.item_id.starts_with("surface:"))
        .collect()
}

#[test]
fn a_line_is_off_until_the_owner_turns_it_on() {
    let fixture = fixture();
    assert_eq!(
        fixture
            .vault
            .phone_line_state_as(&fixture.owner_proof, fixture.identity)
            .expect("owner reads the line setting"),
        None,
        "a line the owner never configured has no setting",
    );
    assert_refused(
        submit(&fixture, stranger_call("call-unconfigured")),
        "unconfigured line",
    );
    assert!(
        call_rows(&fixture).is_empty(),
        "an unconfigured line queues nothing; seen {:?}",
        call_rows(&fixture),
    );

    configure(&fixture, false, worlds_scope(&[base_world_id()]));
    assert_refused(
        submit(&fixture, stranger_call("call-disabled")),
        "disabled line",
    );
    assert!(
        call_rows(&fixture).is_empty(),
        "a disabled line queues nothing; seen {:?}",
        call_rows(&fixture),
    );

    configure(&fixture, true, worlds_scope(&[base_world_id()]));
    let receipt = submit(&fixture, stranger_call("call-enabled"))
        .expect("an enabled line admits the bridge's arrival");
    assert!(!receipt.replayed, "a first arrival is no replay");
    assert_eq!(call_rows(&fixture).len(), 1, "one call, one inbox row");
}

#[test]
fn a_stranger_call_is_one_inbox_row_with_no_sender_and_no_caller_text() {
    let fixture = fixture();
    configure(&fixture, true, worlds_scope(&[base_world_id()]));
    let first = submit(&fixture, stranger_call("call-1")).expect("the call lands");
    let digest = first
        .record
        .payload_ref
        .strip_prefix("phone-line:arrival:")
        .expect("an opaque arrival ref");
    assert_eq!(
        first.record.correlation_id,
        format!("phone-arrival:{digest}")
    );
    assert_eq!(
        (first.record.agent_ref, first.record.bridge_actor),
        (fixture.agent, fixture.bridge),
    );

    let rows = call_rows(&fixture);
    let [row] = rows.as_slice() else {
        panic!("expected one inbox row for the call; seen {rows:?}");
    };
    assert_eq!(
        row.item_id,
        format!(
            "surface:{}:{}",
            fixture.identity.to_hex(),
            first.record.correlation_id
        ),
    );
    assert_eq!(row.identity_ref, Some(fixture.identity));
    assert_eq!(row.actor_ref, fixture.agent, "the row is the agent's");
    assert_eq!(
        row.sender, None,
        "a stranger caller is no known counterparty, as stranger mail is not",
    );
    assert_eq!(
        row.payload_ref.as_deref(),
        Some(first.record.payload_ref.as_str())
    );
    let drawn = format!("{row:?}");
    assert!(
        !drawn.contains(CALLER_NUMBER) && !drawn.contains("call-1"),
        "the inbox row carries no caller or provider call text; seen {drawn}",
    );

    // The bridge's exact retry is the same call: the same refs, still one row.
    let retry = submit(&fixture, stranger_call("call-1")).expect("an exact retry replays");
    assert!(retry.replayed, "an exact retry answers as a replay");
    assert_eq!(
        (
            &retry.record.payload_ref,
            &retry.record.correlation_id,
            &retry.record.attempt_ref
        ),
        (
            &first.record.payload_ref,
            &first.record.correlation_id,
            &first.record.attempt_ref
        ),
    );
    assert_eq!(call_rows(&fixture).len(), 1, "a retry adds no row");

    // The same call id with other metadata is no retry.
    assert_refused(
        submit(
            &fixture,
            PhoneLineArrival {
                call_id: "call-1".to_owned(),
                caller: Some("+15550188".to_owned()),
            },
        ),
        "changed retry",
    );
    assert_eq!(call_rows(&fixture).len(), 1, "a refused retry adds no row");
}

#[test]
fn the_owner_reads_and_erases_a_call_by_its_ref() {
    let fixture = fixture();
    configure(&fixture, true, worlds_scope(&[base_world_id()]));
    let receipt = submit(&fixture, stranger_call("call-erase")).expect("the call lands");
    let payload_ref = receipt.record.payload_ref.clone();

    let read = fixture
        .vault
        .phone_line_arrival_by_ref_as(&fixture.owner_proof, fixture.identity, &payload_ref)
        .expect("owner reads the arrival");
    assert_eq!(read.as_ref(), Some(&receipt.record));
    assert_eq!(
        read.and_then(|record| record.arrival.caller).as_deref(),
        Some(CALLER_NUMBER),
        "the owner reads the caller the inbox row withholds",
    );

    assert!(
        fixture
            .vault
            .erase_phone_line_arrival_by_ref_as(
                &fixture.owner_proof,
                fixture.identity,
                &payload_ref
            )
            .expect("owner erases the arrival"),
        "the first erase removes the metadata",
    );
    assert_eq!(
        fixture
            .vault
            .phone_line_arrival_by_ref_as(&fixture.owner_proof, fixture.identity, &payload_ref)
            .expect("owner reads after the erase"),
        None,
        "an erased arrival reads as absent",
    );
    assert!(
        !fixture
            .vault
            .erase_phone_line_arrival_by_ref_as(
                &fixture.owner_proof,
                fixture.identity,
                &payload_ref
            )
            .expect("owner erases again"),
        "a second erase finds nothing",
    );
    assert_refused(
        submit(&fixture, stranger_call("call-erase")),
        "retry of an erased call",
    );
    assert_eq!(
        fixture
            .vault
            .phone_line_arrival_by_ref_as(&fixture.owner_proof, fixture.identity, &payload_ref)
            .expect("owner reads after the refused retry"),
        None,
        "a refused retry restores no erased text",
    );
}

#[test]
fn the_answering_agent_reads_only_what_the_line_shares() {
    let fixture = fixture();
    let other_world = fixture
        .vault
        .create_world(&fixture.owner_proof, "World the line keeps", OCCURRED_AT)
        .expect("owner creates a second world");
    let shared_claim = write_owner_claim(&fixture, base_world_id(), "shared on the line");
    let kept_claim = write_owner_claim(&fixture, other_world, "kept off the line");

    // The agent's own Grant reaches both worlds; the line shares one.
    let mut authority_scope = worlds_scope(&[base_world_id(), other_world]);
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent: fixture.agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .expect("owner mints the agent a read Grant");
    assert!(minted.grant.confers, "the agent's Grant confers its read");
    let agent_proof = paired_agent_slip(&fixture);
    let agent_key = fixture
        .vault
        .credential_read_key(&agent_proof)
        .expect("agent credential read key")
        .expect("agent credential grants read")
        .at(CallerLocality::OffDevice);
    let own = fixture.vault.scoped_read(agent_key);
    assert!(
        own.is_entity_readable(&shared_claim).expect("agent reads")
            && own.is_entity_readable(&kept_claim).expect("agent reads"),
        "control: outside a call the agent's Grant reads both worlds",
    );

    let share_scope = worlds_scope(&[base_world_id()]);
    configure(&fixture, true, share_scope.clone());
    let receipt = submit(&fixture, stranger_call("call-answer")).expect("the call lands");
    let payload_ref = receipt.record.payload_ref.clone();

    // The bridge carries calls; it never answers one.
    assert_refused(
        fixture.vault.phone_line_answer_read_key(
            &fixture.bridge_proof,
            fixture.identity,
            &payload_ref,
        ),
        "the bridge's credential builds no answer read",
    );

    let answer_key = fixture
        .vault
        .phone_line_answer_read_key(&agent_proof, fixture.identity, &payload_ref)
        .expect("the line's agent answers the call");
    let answer = fixture.vault.scoped_read(answer_key.clone());
    assert_eq!(
        answer.phone_line_scope().expect("the call's live ceiling"),
        Some(share_scope),
        "the call reads under the line's share_scope",
    );
    assert!(
        answer
            .is_entity_readable(&shared_claim)
            .expect("answer read of the shared world"),
        "the answering agent reads what the line shares",
    );
    assert!(
        !answer
            .is_entity_readable(&kept_claim)
            .expect("answer read of the kept world"),
        "the answering agent never reads past the line's share_scope",
    );

    // Consent changed mid-call narrows the call and never widens it: a line
    // now shared on the other world alone closes both worlds to this call.
    configure(&fixture, true, worlds_scope(&[other_world]));
    let rescoped = fixture.vault.scoped_read(answer_key.clone());
    assert!(
        !rescoped
            .is_entity_readable(&shared_claim)
            .expect("answer read after the rescope")
            && !rescoped
                .is_entity_readable(&kept_claim)
                .expect("answer read after the rescope"),
        "a rescoped line never widens a call already under way",
    );

    // A line turned off ends the call's reads.
    configure(&fixture, false, worlds_scope(&[other_world]));
    assert!(
        fixture
            .vault
            .scoped_read(answer_key)
            .phone_line_scope()
            .is_err(),
        "a call on a line turned off has no ceiling left to read under",
    );
}
