//! `self.memory.diary.pinned` through the generated verb dispatch
//! (`oneiron::task_verb::sdk::invoke`), as a client calls it: JSON in, JSON out, on the
//! caller's own `Memory`. An agent with no grant is refused; the holder of a live grant reads
//! the entries of its lane with their live revisions, never an entry outside it; a revoked
//! grant refuses again.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test verb_self_memory_diary_pinned`.

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::authority::{
    ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip,
    pairing_binding_transcript_pinned,
};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeId};
use oneiron::note::{NoteKind, NoteScope, NoteWriteEnvelope};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{
    AgentGrantMintRequest, AgentGrantRevokeRequest, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EdgeActorClass, EntityId, Memory,
    MemoryError, TimeRange, Vault, VaultConfig,
};
use serde_json::{Value, json};

const NOW: u64 = 1_700_000_000;
const VERB: &str = "self.memory.diary.pinned";
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:verb-self-memory-diary-pinned";

// Fixture ids are `[seed; 16]`, off the pinned bytes a fresh vault holds
// (`0x00 0x11 0x42 0x47 0xA1..=0xA6 0xD7 0xE1 0xFF`).
const AGENT: u8 = 0x60;
const GRANTLESS: u8 = 0x61;
const BINDING_SEED: u8 = 0x6A;

const BASE_MARKDOWN: &str = "a base reality diary entry owen keeps";
const OTHER_MARKDOWN: &str = "a diary entry from the excluded world";

/// An enabled, active agent definition the owner creates as `name`.
fn definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "home-reads pinned diary fixture",
        "1",
        Some("Count carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("definedVia"),
            rmpv::Value::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
}

/// A personal vault whose owner created two agents, granted one of them its base lane and the
/// verb, and whose diary holds one entry in base reality and one in an excluded world.
struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner_proof: AuthenticatedOwner,
    agent: EntityId,
    grantless: EntityId,
    base_entry: EntityId,
    other_entry: EntityId,
    grant_ref: EntityId,
    slip: VerifiedSlip,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("personal vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner_person = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let staging_proof = vault
        .authenticate_owner(
            owner_person,
            &owner_person.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let agent = EntityId::from_bytes([AGENT; 16]).expect("agent id");
    vault
        .create_agent_definition_as(
            &staging_proof,
            &agent,
            &definition("owen"),
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
        )
        .expect("owner creates the diary agent");
    let grantless = EntityId::from_bytes([GRANTLESS; 16]).expect("grantless id");
    vault
        .create_agent_definition_as(
            &staging_proof,
            &grantless,
            &definition("yuki"),
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
        )
        .expect("owner creates the grantless agent");
    // The owner's grant act is signed by this install's machine key, so the vault is rooted and
    // the install enrolled first, as a serving start does.
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("install carries the owner's grant act");
    let owner_proof = vault
        .authenticate_owner(
            owner_person,
            &owner_person.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof after rooting");
    let other_world = vault
        .create_world(&owner_proof, "Grant-excluded world", NOW)
        .expect("owner creates the excluded world");
    // Both entries are seeded before the agent holds any grant, so the author path meets no
    // read-only, base-only write scope while placing one entry outside base reality.
    let base_entry = author_diary(
        &vault.memory(agent, EdgeActorClass::Agent),
        BASE_MARKDOWN,
        [0x63; 16],
        None,
    );
    let other_entry = author_diary(
        &vault.memory(agent, EdgeActorClass::Agent),
        OTHER_MARKDOWN,
        [0x64; 16],
        Some(other_world),
    );
    // The agent's lane: base reality alone, with `read` so the grant confers, and the verb.
    let mut authority_scope = Scope::top();
    authority_scope.worlds = [ScopeId(base_world_id())].into_iter().collect();
    authority_scope.verbs = ["read".to_owned(), VERB.to_owned()].into_iter().collect();
    let minted = mint_agent_grant_as(
        &vault,
        &owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .expect("owner grants the agent its base lane and the verb");
    assert!(minted.grant.confers, "the grant confers");
    let slip = paired_agent_slip(&vault, &issuer, &owner_proof, agent);
    Fixture {
        vault,
        _dir: dir,
        owner_proof,
        agent,
        grantless,
        base_entry,
        other_entry,
        grant_ref: minted.grant.grant_ref,
        slip,
    }
}

/// One diary entry the bound agent authors: base reality, or `world` when placed.
fn author_diary(
    memory: &Memory<'_>,
    markdown: &str,
    source_revision_ref: [u8; 16],
    world: Option<EntityId>,
) -> EntityId {
    let receipt = memory
        .author_note_in_world(
            &NoteWriteEnvelope {
                kind: NoteKind::Diary,
                scope: NoteScope::ActorPrivate {
                    owner_ref: memory.actor(),
                },
                markdown: markdown.to_owned(),
                source_revision_ref,
                mask: None,
            },
            world,
        )
        .expect("the agent authors a diary entry");
    EntityId::from_hex(&receipt.id_hex).expect("entry id")
}

/// The agent's paired credential: only the verbs axis narrows the pairing scope. The grant, not
/// the pairing request, imposes the agent's world ceiling.
fn paired_agent_slip(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner: &AuthenticatedOwner,
    agent: EntityId,
) -> VerifiedSlip {
    let mut scope = Scope::top();
    scope.verbs = ["core:read".to_owned(), "core:write".to_owned()]
        .into_iter()
        .collect();
    let holder = agent.to_hex();
    let link = vault
        .issue_owner_pairing_link(
            issuer,
            owner,
            scope,
            3_600,
            PairingPrincipal {
                holder_ref: Some(holder.clone()),
                actor_class: Some("agent".to_owned()),
                ..PairingPrincipal::default()
            },
        )
        .expect("owner issues the agent's pairing link");
    let signing_key = SigningKey::from_bytes(&[BINDING_SEED; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript =
        pairing_binding_transcript_pinned(&link.code, &binding_key, &holder, link.pin.as_ref())
            .expect("agent pairing transcript");
    let slip = vault
        .redeem_pairing_link(
            issuer,
            &link.code,
            &holder,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )
        .expect("agent redeems its pairing link");
    let signature = signing_key
        .sign(
            &slip
                .binding_transcript(REQUEST_CHALLENGE)
                .expect("agent request transcript"),
        )
        .to_bytes();
    vault
        .verify_capability_slip(&issuer.public_key(), &slip, REQUEST_CHALLENGE, &signature)
        .expect("paired agent proves possession of its credential")
}

/// The verb by name, as a client calls it: JSON in, JSON out.
fn call(memory: &Memory<'_>, agent: EntityId) -> Result<Value, MemoryError> {
    invoke(
        memory,
        VERB,
        json!({"agent": agent.to_hex(), "reason": "home read"}),
    )
}

/// No live grant listing the verb: refused `FORBIDDEN`, never served. On main the name is
/// unknown and the refusal is `BAD_REQUEST`, so the code assertion fails there.
#[test]
fn agent_with_no_grant_is_refused_forbidden() {
    let fixture = fixture();
    let memory = fixture
        .vault
        .memory(fixture.grantless, EdgeActorClass::Agent);
    let error = call(&memory, fixture.agent).expect_err("a grantless agent is refused");
    assert_eq!(error.code, "FORBIDDEN", "unexpected refusal: {error:?}");
    assert!(
        error.message.contains(VERB),
        "the refusal names the verb: {error:?}"
    );
}

/// The holder reads its lane's entry with its live revision, and never the entry outside its
/// lane. On main the name is unknown and the call errors, so the unwrap fails there.
#[test]
fn holder_reads_lane_entry_with_live_revision_and_not_outside_entry() {
    let fixture = fixture();
    let memory = fixture
        .vault
        .memory(fixture.agent, EdgeActorClass::Agent)
        .with_read_proof(&fixture.slip);
    let out = call(&memory, fixture.agent).expect("the holder reads its lane");
    assert_eq!(out["outcome"]["state"], "granted", "{out}");
    assert!(
        out["outcome"]["read"].is_null(),
        "a self read logs no row: {out}"
    );
    let entries = out["outcome"]["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 1, "{out}");
    assert_eq!(
        entries[0]["id"],
        json!(fixture.base_entry.to_hex()),
        "{out}"
    );
    assert_eq!(entries[0]["markdown"], BASE_MARKDOWN, "{out}");
    let pins = out["pins"].as_array().expect("pins array");
    assert_eq!(pins.len(), 1, "{out}");
    assert_eq!(pins[0]["id"], json!(fixture.base_entry.to_hex()), "{out}");
    let revision = pins[0]["revision"].as_array().expect("live revision bytes");
    assert_eq!(revision.len(), 16, "{out}");
    let seen: Vec<String> = entries
        .iter()
        .filter_map(|entry| entry["id"].as_str().map(str::to_owned))
        .collect();
    assert!(
        !seen.contains(&fixture.other_entry.to_hex()),
        "the outside entry stays out: {out}"
    );
}

/// The same call, which reads before the revoke, after the owner revokes the grant: refused
/// again on the same handle, live. On main the name is unknown and the first call errors, so
/// the unwrap fails there.
#[test]
fn revoked_grant_refuses_again() {
    let fixture = fixture();
    let memory = fixture
        .vault
        .memory(fixture.agent, EdgeActorClass::Agent)
        .with_read_proof(&fixture.slip);
    let before = call(&memory, fixture.agent).expect("the holder reads before the revoke");
    assert_eq!(before["outcome"]["state"], "granted", "{before}");
    let revoked = revoke_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref: fixture.grant_ref,
            seen: None,
        },
    )
    .expect("the owner revokes the grant");
    assert!(
        revoked.changed,
        "the revoke of {} changed nothing",
        fixture.grant_ref.to_hex()
    );
    let error = call(&memory, fixture.agent).expect_err("a revoked grant is refused");
    assert_eq!(error.code, "FORBIDDEN", "unexpected refusal: {error:?}");
}
