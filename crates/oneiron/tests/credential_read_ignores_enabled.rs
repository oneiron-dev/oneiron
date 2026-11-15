//! A switched-off agent's credential reads nothing under its owner's
//! Grants (FIX-LIST 25935 [CREDENTIAL-READ-IGNORES-ENABLED]): a
//! credential-backed read judged the holder's Grants and slip but never
//! whether its AGENT_DEF is enabled, as the ordinary owner-grant path does
//! (`live_agent_principal_in`). The owner and a still-enabled agent are
//! the controls that tell a withheld row from missing setup.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test credential_read_ignores_enabled`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip};
use oneiron::claim::{ScopedReadActorKey, base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::graph_fs::GraphFsOptions;
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentDefinitionRequest, AgentDefinitionUpdateRequest,
    AgentGrantMintRequest, create_agent_definition_as, mint_agent_grant_as,
    read_agent_definition_as, update_agent_definition_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

const OCCURRED_AT: u64 = 1_769_947_200;
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:credential-read-ignores-enabled";

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    issuer: HostSlipIssuer,
    owner_proof: AuthenticatedOwner,
    base_path: String,
    other_path: String,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    // The owner's agent Grant act is carried by this install's live machine
    // profile, as a serving start or `init` enrols it.
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let other_world = vault
        .create_world(&owner_proof, "Second world", OCCURRED_AT)
        .expect("owner creates the second world");
    let base_claim = write_owner_claim(
        &vault,
        owner,
        &owner_proof,
        base_world_id(),
        "base-world claim",
    );
    let other_claim = write_owner_claim(
        &vault,
        owner,
        &owner_proof,
        other_world,
        "second-world claim",
    );
    Fixture {
        vault,
        _dir: dir,
        owner,
        issuer,
        owner_proof,
        base_path: format!("/worlds/base/claims/{}", base_claim.to_hex()),
        other_path: format!(
            "/worlds/{}/claims/{}",
            other_world.to_hex(),
            other_claim.to_hex()
        ),
    }
}

fn write_owner_claim(
    vault: &Vault,
    owner: EntityId,
    owner_proof: &AuthenticatedOwner,
    world: EntityId,
    value: &str,
) -> EntityId {
    let id = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(owner_proof)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(id.to_hex()),
            predicate: "profile.preference".to_owned(),
            subject_ref: owner.to_hex(),
            value: json!(value),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: world.to_hex(),
                scope_facet_id: vault.default_facet().expect("owner default facet").to_hex(),
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

/// The pairing Scope `oneiron token read` gives: every world, `core:read`.
fn read_slip_scope() -> Scope {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["core:read".to_owned()]));
    scope
}

/// `holder` pairs as class `agent` on a link the owner issues, and proves
/// possession of the slip it redeems.
fn paired_agent_slip(fixture: &Fixture, holder: EntityId, binding_seed: u8) -> VerifiedSlip {
    let vault = &fixture.vault;
    let issuer = &fixture.issuer;
    let holder_ref = holder.to_hex();
    let link = vault
        .issue_owner_pairing_link(
            issuer,
            &fixture.owner_proof,
            read_slip_scope(),
            3_600,
            PairingPrincipal {
                holder_ref: Some(holder_ref.clone()),
                actor_class: Some("agent".to_owned()),
                ..PairingPrincipal::default()
            },
        )
        .expect("owner issues the agent's pairing link");
    let signing_key = SigningKey::from_bytes(&[binding_seed; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &link.code,
        &binding_key,
        &holder_ref,
        link.pin.as_ref(),
    )
    .expect("agent pairing transcript");
    let slip = vault
        .redeem_pairing_link(
            issuer,
            &link.code,
            &holder_ref,
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

/// An enabled, active agent definition the owner creates as `agent_id`.
fn create_enabled_agent(fixture: &Fixture, agent_id: &str) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        &fixture.vault,
        &fixture.owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "Credential read enabled fixture",
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

/// The owner's `vault.agents.update` switch-off of `agent`: its stored
/// definition with `enabled` false and the version moved on, through the
/// typed door that verb calls (`update_agent_definition_as`).
fn switch_off(fixture: &Fixture, agent: EntityId) {
    let stored = read_agent_definition_as(
        &fixture.vault,
        &fixture.owner_proof,
        AgentDefinitionRequest {
            agent_def_ref: agent,
        },
    )
    .expect("owner reads the agent's definition");
    let mut definition = stored.definition;
    let expected_version = definition.version.clone();
    definition.enabled = false;
    definition.version = "1.0.1".to_owned();
    update_agent_definition_as(
        &fixture.vault,
        &fixture.owner_proof,
        AgentDefinitionUpdateRequest {
            agent_def_ref: agent,
            expected_version,
            definition,
        },
    )
    .expect("owner switches the agent off");
}

/// The owner mints `agent` a Grant that reads `world` alone.
fn mint_world_read_grant(fixture: &Fixture, agent: EntityId, world: EntityId) {
    let mut authority_scope = Scope::top();
    authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(world)]));
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
    .expect("owner mints the agent a one-world read Grant");
    assert!(
        minted.grant.confers,
        "actor=agent {agent:?}; expected a live read Grant; seen {minted:?}"
    );
}

/// The paths of `paths` that `key` reads back a row at. A withheld row is
/// an `Ok` read with no file on this surface, as a revoked Grant's rows
/// are withheld in `agent_pair_default_grant`.
fn readable(vault: &Vault, key: ScopedReadActorKey, paths: &[&str]) -> Vec<String> {
    let lane = vault
        .scoped_read(key)
        .recorded_lane()
        .expect("graph filesystem record lane");
    let tree = lane.graph_fs(GraphFsOptions::default());
    paths
        .iter()
        .filter(|path| {
            tree.read_file(path)
                .expect("graph filesystem read")
                .value
                .is_some()
        })
        .map(|path| (*path).to_owned())
        .collect()
}

/// The paths of `paths` a fresh read key for `slip` reads; none when the
/// slip grants no read key at all.
fn slip_reads(fixture: &Fixture, slip: &VerifiedSlip, paths: &[&str]) -> Vec<String> {
    fixture
        .vault
        .credential_read_key(slip)
        .expect("agent credential read key")
        .map_or_else(Vec::new, |key| readable(&fixture.vault, key, paths))
}

fn owner_reads(fixture: &Fixture, paths: &[&str]) -> Vec<String> {
    let key = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .read_key()
        .expect("owner read key");
    readable(&fixture.vault, key, paths)
}

#[test]
fn a_switched_off_agents_credential_reads_nothing_under_its_grants() {
    let fixture = fixture();
    let base = fixture.base_path.as_str();
    let other = fixture.other_path.as_str();

    let agent = create_enabled_agent(&fixture, "credential_read_switched_off_agent");
    mint_world_read_grant(&fixture, agent, base_world_id());
    let slip = paired_agent_slip(&fixture, agent, 0x61);
    let key = fixture
        .vault
        .credential_read_key(&slip)
        .expect("agent credential read key")
        .expect("agent credential grants read");

    let enabled = create_enabled_agent(&fixture, "credential_read_still_enabled_agent");
    mint_world_read_grant(&fixture, enabled, base_world_id());
    let enabled_slip = paired_agent_slip(&fixture, enabled, 0x62);

    let owner = owner_reads(&fixture, &[base, other]);
    assert_eq!(
        owner,
        vec![base.to_owned(), other.to_owned()],
        "actor=owner {:?}; expected readable names=[{base}, {other}]; seen names={owner:?}",
        fixture.owner,
    );
    let before = readable(&fixture.vault, key.clone(), &[base, other]);
    assert_eq!(
        before,
        vec![base.to_owned()],
        "actor=agent {agent:?}; expected its credential to read [{base}] under its Grant before the switch-off; seen names={before:?}"
    );

    switch_off(&fixture, agent);

    // The key held from before the switch-off: its next read is withheld.
    let after_held = readable(&fixture.vault, key, &[base, other]);
    assert!(
        after_held.is_empty(),
        "actor=agent {agent:?}; expected its held credential read to read nothing once its AGENT_DEF is switched off; seen names={after_held:?}"
    );
    // A fresh key for the same standing slip: withheld the same way.
    let after_fresh = slip_reads(&fixture, &slip, &[base, other]);
    assert!(
        after_fresh.is_empty(),
        "actor=agent {agent:?}; expected a fresh credential read to read nothing once its AGENT_DEF is switched off, though its slip and Grant still stand; seen names={after_fresh:?}"
    );

    // The still-enabled agent under its own Grant, and the owner, still read.
    let still = slip_reads(&fixture, &enabled_slip, &[base, other]);
    assert_eq!(
        still,
        vec![base.to_owned()],
        "actor=enabled agent {enabled:?}; expected its credential to still read [{base}]; seen names={still:?}"
    );
    let owner = owner_reads(&fixture, &[base, other]);
    assert_eq!(
        owner,
        vec![base.to_owned(), other.to_owned()],
        "actor=owner {:?}; expected the owner to still read [{base}, {other}]; seen names={owner:?}",
        fixture.owner,
    );
}
