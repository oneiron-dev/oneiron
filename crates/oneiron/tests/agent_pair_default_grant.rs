//! Pairing a named agent mints its default read Grant, and revoking an
//! agent's last Grant narrows its read (Engine RULINGs AGENT-PAIR-DEFAULT-GRANT
//! = A, 11 Nov 04:47, and PAIR-GRANT-DESIGN Q1-Q4, 06:51; closes FIX
//! AGENT-REVOKE-WIDENS). The owner and never-granted controls tell a withheld
//! row from missing setup.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip};
use oneiron::claim::{ScopedReadActorKey, base_world_id, default_project_id};
use oneiron::consent::{AuthenticatedOwner, ConsentRegistryQuery, ConsentRegistryRow};
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::graph_fs::GraphFsOptions;
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, AgentGrantRevokeRequest,
    create_agent_definition_as, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

const OCCURRED_AT: u64 = 1_769_947_200;
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:agent-pair-default-grant";

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
    // profile, as a serving start or `init` enrols it (FIX 4648).
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
                "desc": "Pairing default Grant reader",
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

/// The live owner-agent Grants of the registry that name `holder`.
fn grants_naming(vault: &Vault, holder: EntityId) -> Vec<ConsentRegistryRow> {
    vault
        .consent_registry(ConsentRegistryQuery::new(1_000, false))
        .expect("owner's consent registry")
        .rows
        .into_iter()
        .filter(|row| {
            row.agent_grant
                .as_ref()
                .is_some_and(|grant| grant.agent == holder)
        })
        .collect()
}

fn revoke(fixture: &Fixture, grant_ref: EntityId) {
    let revoked = revoke_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref,
            seen: None,
        },
    )
    .expect("owner revokes the agent's Grant");
    assert!(
        revoked.changed,
        "grant={grant_ref:?}; expected the revoke to sign an act; seen {revoked:?}"
    );
}

/// The paths of `paths` that `key` reads back a row at.
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

/// Q3/Q4: the owner's link for a named agent mints one Grant naming it:
/// verbs `read`, the slip's other axes, no expiry, wallet, repo bounds or
/// classes. A second pairing mints no second Grant, and an agent definition
/// gets none.
#[test]
fn pairing_a_named_agent_mints_its_default_read_grant() {
    let fixture = fixture();
    let agent = fixture
        .vault
        .ensure_agent_principal("pair_default_grant_agent")
        .expect("named agent principal");
    let _slip = paired_agent_slip(&fixture, agent, 0x51);
    let grants = grants_naming(&fixture.vault, agent);
    assert_eq!(
        grants.len(),
        1,
        "actor=named agent {agent:?}; expected the owner's pairing link to mint one Grant naming it; seen grants={grants:?}"
    );
    let mut expected_scope = Scope::top();
    expected_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let row = &grants[0];
    let grant = row.agent_grant.as_ref().expect("an owner-agent Grant row");
    assert_eq!(
        row.scope.as_ref(),
        Some(&expected_scope),
        "actor=named agent {agent:?}; expected the default Grant at the slip's axes with verbs [read]; seen row={row:?}"
    );
    assert!(
        grant.expires_at.is_none()
            && grant.wallet_ref.is_none()
            && grant.repo_bounds.is_none()
            && grant.verb_classes.is_empty()
            && grant.confers,
        "actor=named agent {agent:?}; expected a standing Grant with no expiry, wallet, repo bounds or classes; seen grant={grant:?}"
    );

    let _again = paired_agent_slip(&fixture, agent, 0x52);
    let after_second = grants_naming(&fixture.vault, agent);
    assert_eq!(
        after_second.iter().map(|row| &row.grant_ref).collect::<Vec<_>>(),
        vec![&row.grant_ref],
        "actor=named agent {agent:?}; expected a second pairing to keep its one Grant; seen grants={after_second:?}"
    );

    let definition = create_enabled_agent(&fixture, "pair_default_grant_definition");
    let _definition_slip = paired_agent_slip(&fixture, definition, 0x53);
    let definition_grants = grants_naming(&fixture.vault, definition);
    assert!(
        definition_grants.is_empty(),
        "actor=agent definition {definition:?}; expected no Grant from its pairing (Q3); seen grants={definition_grants:?}"
    );
}

/// The ruling's revoke-narrows proof: pair a named agent, revoke its default
/// Grant, and a fresh read key for its slip reads no base-world claim.
#[test]
fn revoking_the_default_grant_narrows_the_agents_read() {
    let fixture = fixture();
    let base = fixture.base_path.as_str();
    let agent = fixture
        .vault
        .ensure_agent_principal("pair_revoke_default_agent")
        .expect("named agent principal");
    let slip = paired_agent_slip(&fixture, agent, 0x61);
    let before = slip_reads(&fixture, &slip, &[base]);
    assert_eq!(
        before,
        vec![base.to_owned()],
        "actor=named agent {agent:?}; expected the paired agent to read [{base}] before the revoke; seen names={before:?}"
    );
    let grants = grants_naming(&fixture.vault, agent);
    assert_eq!(
        grants.len(),
        1,
        "actor=named agent {agent:?}; expected one default Grant to revoke; seen grants={grants:?}"
    );
    let grant_ref = EntityId::from_hex(&grants[0].grant_ref).expect("Grant id hex");
    revoke(&fixture, grant_ref);

    let after = slip_reads(&fixture, &slip, &[base]);
    assert!(
        after.is_empty(),
        "actor=named agent {agent:?}; expected no readable names after its last Grant's revoke; seen names={after:?}"
    );
    let owner = owner_reads(&fixture, &[base]);
    assert_eq!(
        owner,
        vec![base.to_owned()],
        "actor=owner {:?}; expected the owner to still read [{base}]; seen names={owner:?}",
        fixture.owner,
    );
}

/// Q2 = A: a holder a Grant has ever named reads only under its standing
/// Grants, so revoking an agent definition's last hand-minted Grant leaves it
/// reading nothing. A never-granted agent definition keeps its slip's reach.
#[test]
fn revoking_an_agents_last_hand_minted_grant_narrows_its_read() {
    let fixture = fixture();
    let base = fixture.base_path.as_str();
    let other = fixture.other_path.as_str();
    let agent = create_enabled_agent(&fixture, "pair_revoke_hand_minted_agent");
    let mut authority_scope = Scope::top();
    authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
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
        },
    )
    .expect("owner mints the agent a base-world read Grant");
    let slip = paired_agent_slip(&fixture, agent, 0x71);
    let before = slip_reads(&fixture, &slip, &[base, other]);
    assert_eq!(
        before,
        vec![base.to_owned()],
        "actor=agent {agent:?}; expected its Grant to admit [{base}] only before the revoke; seen names={before:?}"
    );
    revoke(&fixture, minted.grant.grant_ref);

    let after = slip_reads(&fixture, &slip, &[base, other]);
    assert!(
        after.is_empty(),
        "actor=agent {agent:?}; expected no readable names after its last Grant's revoke, not its slip's reach; seen names={after:?}"
    );

    let never_granted = create_enabled_agent(&fixture, "pair_never_granted_agent");
    let never_granted_slip = paired_agent_slip(&fixture, never_granted, 0x72);
    let control = slip_reads(&fixture, &never_granted_slip, &[base, other]);
    assert_eq!(
        control,
        vec![base.to_owned(), other.to_owned()],
        "actor=never-granted agent {never_granted:?}; expected its slip's reach [{base}, {other}]; seen names={control:?}"
    );
}

/// Nothing narrows at pairing: a named agent paired at every world reads the
/// base and second worlds' claims, as its slip alone did before.
#[test]
fn pairing_a_named_agent_keeps_its_reach() {
    let fixture = fixture();
    let base = fixture.base_path.as_str();
    let other = fixture.other_path.as_str();
    let agent = fixture
        .vault
        .ensure_agent_principal("pair_keeps_reach_agent")
        .expect("named agent principal");
    let slip = paired_agent_slip(&fixture, agent, 0x81);
    let reads = slip_reads(&fixture, &slip, &[base, other]);
    assert_eq!(
        reads,
        vec![base.to_owned(), other.to_owned()],
        "actor=named agent {agent:?}; expected readable names=[{base}, {other}]; seen names={reads:?}"
    );
}
