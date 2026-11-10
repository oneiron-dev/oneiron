//! A paired agent's broad credential must not read beyond its owner's live
//! Grant. The owner controls distinguish withheld rows from missing setup.
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
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

const OCCURRED_AT: u64 = 1_769_947_200;
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:agent-grant-read-ceiling";

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    agent: EntityId,
    other_world: EntityId,
    third_world: EntityId,
    base_claim: EntityId,
    other_claim: EntityId,
    third_claim: EntityId,
    owner_key: ScopedReadActorKey,
    agent_key: ScopedReadActorKey,
}

fn paired_agent_slip(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner: &AuthenticatedOwner,
    agent: EntityId,
) -> VerifiedSlip {
    // Match token_pair: only the verbs axis narrows the pairing Scope. The
    // Grant, not the pairing request, must impose the agent's world ceiling.
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "core:read".to_owned(),
        "core:write".to_owned(),
    ]));
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
    let signing_key = SigningKey::from_bytes(&[0x47; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &link.code,
        &binding_key,
        &holder,
        link.pin.as_ref(),
    )
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

/// The worlds each of the agent's Grants names, given the second world's id:
/// one Grant per set, each minted alone.
type GrantWorlds = fn(EntityId) -> Vec<BTreeSet<ScopeId>>;

/// One Grant, naming the base world only.
fn base_grant(_other: EntityId) -> Vec<BTreeSet<ScopeId>> {
    vec![BTreeSet::from([ScopeId(base_world_id())])]
}

/// Two Grants: one names the base world, the other the second world.
fn base_and_second_grants(other: EntityId) -> Vec<BTreeSet<ScopeId>> {
    vec![
        BTreeSet::from([ScopeId(base_world_id())]),
        BTreeSet::from([ScopeId(other)]),
    ]
}

fn fixture(grants: GrantWorlds) -> Fixture {
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
    let other_world = vault
        .create_world(&owner_proof, "Grant-excluded world", OCCURRED_AT)
        .expect("owner creates the second world");
    let third_world = vault
        .create_world(&owner_proof, "World no Grant names", OCCURRED_AT)
        .expect("owner creates the third world");
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
        "grant-excluded-world claim",
    );
    let third_claim = write_owner_claim(
        &vault,
        owner,
        &owner_proof,
        third_world,
        "third-world claim",
    );

    let agent = EntityId::now();
    create_agent_definition_as(
        &vault,
        &owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": "grant_read_ceiling_agent",
                "desc": "Graph filesystem grant reader",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates an enabled, active agent definition");
    for worlds in grants(other_world) {
        let mut authority_scope = Scope::top();
        authority_scope.worlds = ScopeAxis::Some(worlds.clone());
        authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
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
            },
        )
        .expect("owner mints the agent a read Grant");
        assert!(
            minted.grant.confers,
            "actor=agent {agent:?}; expected live read Grant for worlds={worlds:?}; seen worlds={:?}, confers={}",
            minted.grant.authority_scope.worlds, minted.grant.confers,
        );
    }
    let slip = paired_agent_slip(&vault, &issuer, &owner_proof, agent);
    let agent_key = vault
        .credential_read_key(&slip)
        .expect("agent credential read key")
        .expect("agent credential grants read");
    let owner_key = vault
        .memory(owner, EdgeActorClass::Human)
        .read_key()
        .expect("owner read key");
    Fixture {
        vault,
        _dir: dir,
        owner,
        agent,
        other_world,
        third_world,
        base_claim,
        other_claim,
        third_claim,
        owner_key,
        agent_key,
    }
}

fn world_names(vault: &Vault, key: ScopedReadActorKey) -> BTreeSet<String> {
    let lane = vault
        .scoped_read(key)
        .recorded_lane()
        .expect("graph filesystem record lane");
    let tree = lane.graph_fs(GraphFsOptions::default());
    let mut names = BTreeSet::new();
    let mut cursor = None;
    loop {
        let page = tree
            .readdir("/worlds/", cursor.as_deref())
            .expect("graph filesystem world listing");
        names.extend(page.entries().iter().map(|entry| entry.name().to_owned()));
        cursor = page.next_cursor().map(str::to_owned);
        if cursor.is_none() {
            return names;
        }
    }
}

#[test]
fn paired_agent_lists_only_its_grant_worlds() {
    let fixture = fixture(base_grant);
    let other_name = fixture.other_world.to_hex();
    let owner_names = world_names(&fixture.vault, fixture.owner_key.clone());
    assert!(
        owner_names.contains("base") && owner_names.contains(&other_name),
        "actor=owner {:?}; expected names to include [base, {other_name}]; seen names={owner_names:?}",
        fixture.owner,
    );

    let agent_names = world_names(&fixture.vault, fixture.agent_key);
    assert!(
        agent_names.contains("base"),
        "actor=agent {:?}; expected names to include [base]; seen names={agent_names:?}",
        fixture.agent,
    );
    assert!(
        !agent_names.contains(&other_name),
        "actor=agent {:?}; expected names to exclude [{other_name}] and include [base]; seen names={agent_names:?}",
        fixture.agent,
    );
}

#[test]
fn paired_agent_reads_no_row_outside_its_grant_worlds() {
    let fixture = fixture(base_grant);
    let base_path = format!("/worlds/base/claims/{}", fixture.base_claim.to_hex());
    let other_name = fixture.other_world.to_hex();
    let other_path = format!(
        "/worlds/{other_name}/claims/{}",
        fixture.other_claim.to_hex()
    );
    let owner_lane = fixture
        .vault
        .scoped_read(fixture.owner_key)
        .recorded_lane()
        .expect("owner record lane");
    let owner_tree = owner_lane.graph_fs(GraphFsOptions::default());
    let owner_base = owner_tree.read_file(&base_path).expect("owner base read");
    let owner_other = owner_tree
        .read_file(&other_path)
        .expect("owner second-world read");
    let owner_names: Vec<_> = [&owner_base, &owner_other]
        .into_iter()
        .filter_map(|read| read.value.as_ref().map(|file| file.path()))
        .collect();
    assert!(
        owner_base.value.is_some() && owner_other.value.is_some(),
        "actor=owner {:?}; expected readable names=[{base_path}, {other_path}]; seen names={owner_names:?}",
        fixture.owner,
    );

    let agent_lane = fixture
        .vault
        .scoped_read(fixture.agent_key)
        .recorded_lane()
        .expect("agent record lane");
    let agent_tree = agent_lane.graph_fs(GraphFsOptions::default());
    let agent_base = agent_tree.read_file(&base_path).expect("agent base read");
    let agent_other = agent_tree
        .read_file(&other_path)
        .expect("agent second-world read");
    let agent_names: Vec<_> = [&agent_base, &agent_other]
        .into_iter()
        .filter_map(|read| read.value.as_ref().map(|file| file.path()))
        .collect();
    assert_eq!(
        agent_base.value, owner_base.value,
        "actor=agent {:?}; expected names=[{base_path}] to read back the owner's base row; seen names={agent_names:?}, base={agent_base:?}",
        fixture.agent,
    );
    assert!(
        agent_other.value.is_none(),
        "actor=agent {:?}; expected readable names=[{base_path}], not [{other_path}]; seen names={agent_names:?}",
        fixture.agent,
    );
}

/// Two Grants, each alone (Engine RULING GRANT-COMBINE Q1 = A): the agent
/// lists and reads the world each one names, and no world neither names.
#[test]
fn paired_agent_reads_each_grant_world_alone() {
    let fixture = fixture(base_and_second_grants);
    let other_name = fixture.other_world.to_hex();
    let third_name = fixture.third_world.to_hex();
    let owner_names = world_names(&fixture.vault, fixture.owner_key.clone());
    assert!(
        owner_names.contains("base")
            && owner_names.contains(&other_name)
            && owner_names.contains(&third_name),
        "actor=owner {:?}; expected names to include [base, {other_name}, {third_name}]; seen names={owner_names:?}",
        fixture.owner,
    );

    let agent_names = world_names(&fixture.vault, fixture.agent_key.clone());
    assert!(
        agent_names.contains("base") && agent_names.contains(&other_name),
        "actor=agent {:?}; expected names to include [base, {other_name}]; seen names={agent_names:?}",
        fixture.agent,
    );
    assert!(
        !agent_names.contains(&third_name),
        "actor=agent {:?}; expected names to exclude [{third_name}]; seen names={agent_names:?}",
        fixture.agent,
    );

    let paths = [
        format!("/worlds/base/claims/{}", fixture.base_claim.to_hex()),
        format!(
            "/worlds/{other_name}/claims/{}",
            fixture.other_claim.to_hex()
        ),
        format!(
            "/worlds/{third_name}/claims/{}",
            fixture.third_claim.to_hex()
        ),
    ];
    let owner_lane = fixture
        .vault
        .scoped_read(fixture.owner_key)
        .recorded_lane()
        .expect("owner record lane");
    let owner_tree = owner_lane.graph_fs(GraphFsOptions::default());
    let agent_lane = fixture
        .vault
        .scoped_read(fixture.agent_key)
        .recorded_lane()
        .expect("agent record lane");
    let agent_tree = agent_lane.graph_fs(GraphFsOptions::default());
    for (index, path) in paths.iter().enumerate() {
        let owner_read = owner_tree.read_file(path).expect("owner claim read");
        assert!(
            owner_read.value.is_some(),
            "actor=owner {:?}; expected readable name={path}; seen none",
            fixture.owner,
        );
        let agent_read = agent_tree.read_file(path).expect("agent claim read");
        if index < 2 {
            assert_eq!(
                agent_read.value, owner_read.value,
                "actor=agent {:?}; expected name={path} to read back the owner's row; seen {agent_read:?}",
                fixture.agent,
            );
        } else {
            assert!(
                agent_read.value.is_none(),
                "actor=agent {:?}; expected name={path} withheld; seen {agent_read:?}",
                fixture.agent,
            );
        }
    }
}
