//! Removing a member withdraws the Grants naming its roster actor (FIX-LIST
//! 26610 [MEMBER-REMOVAL-KEEPS-ACTOR-GRANTS]): `drop_member_grants_in_txn`
//! dropped only Grants with `member_ref` the leaving PERSON or
//! `delegated_by` it, so a removed member's still-enabled roster actor kept
//! its owner-agent Grants and read under them. The removal now drops Grants
//! naming the member's roster actor too, with the existing signed-withdrawal
//! treatment; a role change that keeps the member drops nothing new.
//!
//! The shared vault holds two onboarded members with roster actors, each
//! actor holding one owner-agent Grant that reads the base world alone. The
//! red case removes A and reads through A's actor's credential; the controls
//! remove A and read through B's, and re-role A and read through A's.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test member_removal_drops_actor_grants`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip};
use oneiron::claim::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ScopedReadActorKey, base_world_id,
    default_project_id,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{
    FederationGrantPreset, FederationGrantRole as Role, Scope, ScopeAxis, ScopeId,
};
use oneiron::graph_fs::GraphFsOptions;
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::registry::{
    ENTITY_TYPE_FACET, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON,
};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{
    CompanionBirthIntent, CompanionChoice, EntityId, MemberGrantBundle, MemberOnboardingIntent,
    TimeRange, Vault, VaultConfig, WorkspaceRosterPreset, WriteActor,
};
use oneiron_keystore::MemoryKeystore;
use serde_json::json;

const WORKSPACE: &str = "member-removal-drops-actor-grants";
/// The workspace's shared vault. Not 7, the own-device residence scope's id,
/// whose Owner grants read as device access.
const SHARED: u64 = 41;
const OCCURRED_AT: u64 = 1_769_947_200;
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:member-removal-drops-actor-grants";

/// A plain row of `entity_type`, as a host's own import writes one.
fn seed_row(vault: &Vault, entity_type: u8) -> EntityId {
    let row = EntityId::now();
    vault
        .put_entity(
            &row,
            entity_type,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"member removal drops actor grants fixture",
        )
        .expect("a fixture row");
    row
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

fn definition(agent_id: &str) -> AgentDefinition {
    AgentDefinition::new(
        agent_id,
        "member removal drops actor grants fixture",
        "1",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::Imported,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("fixture"),
            rmpv::Value::from(agent_id),
        )]),
        None,
        true,
        None,
    )
}

/// Onboards one member with a work companion into `preset`: the member
/// PERSON and its roster actor. Returns both.
fn onboard_member(
    vault: &Vault,
    owner: EntityId,
    preset: &WorkspaceRosterPreset,
    onboarding_id: &str,
    agent_id: &str,
    companion_id: &str,
    display_name: &str,
) -> (EntityId, EntityId) {
    let member = seed_row(vault, ENTITY_TYPE_PERSON);
    let member_facet = seed_row(vault, ENTITY_TYPE_FACET);
    let companion_facet = seed_row(vault, ENTITY_TYPE_FACET);
    let profile_grant = EntityId::now();
    let actor = EntityId::now();
    let intent = MemberOnboardingIntent {
        onboarding_id: onboarding_id.to_owned(),
        workspace: preset.clone(),
        person_ref: member,
        actor_ref: actor,
        actor_definition: definition(agent_id),
        work_facet_ref: member_facet,
        grant_bundle: MemberGrantBundle {
            federation_grant_ref: EntityId::now(),
            role: Role::Member,
            preset: FederationGrantPreset::Member,
            companion_profile_grant_ref: Some(profile_grant),
        },
        companion: CompanionChoice::Work(CompanionBirthIntent {
            person_ref: EntityId::now(),
            actor_ref: EntityId::now(),
            work_facet_ref: companion_facet,
            profile_grant_ref: profile_grant,
            actor_definition: definition(companion_id),
            display_name: display_name.to_owned(),
        }),
        delegated_mailbox: None,
        occurred_at: vault.now_recorded_at(),
    };
    let outcome = vault
        .onboard_workspace_member(intent, &WriteActor::new(owner, EdgeActorClass::Human), None)
        .expect("the member onboards");
    assert_eq!(outcome.person_ref, member, "the outcome names the member");
    assert_eq!(
        outcome.actor_ref, actor,
        "the outcome names its roster actor"
    );
    (member, actor)
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
fn paired_agent_slip(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner_proof: &AuthenticatedOwner,
    holder: EntityId,
    binding_seed: u8,
) -> VerifiedSlip {
    let holder_ref = holder.to_hex();
    let link = vault
        .issue_owner_pairing_link(
            issuer,
            owner_proof,
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

/// The owner mints `agent` a Grant that reads `world` alone.
fn mint_world_read_grant(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    agent: EntityId,
    world: EntityId,
) {
    let mut authority_scope = Scope::top();
    authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(world)]));
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let minted = mint_agent_grant_as(
        vault,
        owner_proof,
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

/// The live FEDERATION_GRANT rows naming `member` now.
fn grants_naming(vault: &Vault, member: EntityId) -> Vec<EntityId> {
    vault
        .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
        .expect("grant rows")
        .into_iter()
        .filter_map(|id| {
            let body = vault.get(&id).expect("grant row")?;
            let grant = oneiron::federation::decode_federation_grant_body(&body).ok()?;
            (grant.member_ref == member).then_some(id)
        })
        .collect()
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

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner_proof: AuthenticatedOwner,
    member_a: EntityId,
    actor_a: EntityId,
    member_b: EntityId,
    actor_b: EntityId,
    slip_a: VerifiedSlip,
    slip_b: VerifiedSlip,
    base_path: String,
    other_path: String,
}

impl Fixture {
    /// A rooted vault whose shared vault holds two onboarded members with
    /// roster actors, each actor holding one owner-agent Grant that reads
    /// the base world alone, and each actor paired.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
        vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        oneiron::test_support::bind_host_owner(&vault, &issuer, owner)
            .expect("the owner's binding");
        let owner_proof = proof(&vault, owner);
        vault
            .initialize_shared_vault(&owner_proof, SHARED, None, &[], vault.now_recorded_at())
            .expect("a shared vault with the owner its Owner");
        let org = seed_row(&vault, ENTITY_TYPE_ORG);
        let (house, _) = vault
            .get_seeded_agent_definition_by_logical_id("sys.default")
            .expect("read the seeded agents")
            .expect("sys.default is seeded on open");
        let preset = WorkspaceRosterPreset {
            workspace_ref: WORKSPACE.to_owned(),
            workspace_vault_id: SHARED,
            org_ref: org,
            venture_name: "Garden Works".to_owned(),
            house_display_name: None,
            house_actor_ref: house,
            house_identity_ref: None,
        };
        let (member_a, actor_a) = onboard_member(
            &vault,
            owner,
            &preset,
            "member-removal-actor-a",
            "removal.actor.a",
            "removal.companion.a",
            "companion-a",
        );
        let (member_b, actor_b) = onboard_member(
            &vault,
            owner,
            &preset,
            "member-removal-actor-b",
            "removal.actor.b",
            "removal.companion.b",
            "companion-b",
        );
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
        mint_world_read_grant(&vault, &owner_proof, actor_a, base_world_id());
        mint_world_read_grant(&vault, &owner_proof, actor_b, base_world_id());
        let slip_a = paired_agent_slip(&vault, &issuer, &owner_proof, actor_a, 0x61);
        let slip_b = paired_agent_slip(&vault, &issuer, &owner_proof, actor_b, 0x62);
        Fixture {
            vault,
            _dir: dir,
            owner_proof,
            member_a,
            actor_a,
            member_b,
            actor_b,
            slip_a,
            slip_b,
            base_path: format!("/worlds/base/claims/{}", base_claim.to_hex()),
            other_path: format!(
                "/worlds/{}/claims/{}",
                other_world.to_hex(),
                other_claim.to_hex()
            ),
        }
    }
}

#[test]
fn removing_a_member_withdraws_grants_naming_its_actor() {
    let fixture = Fixture::new();
    let paths = [fixture.base_path.as_str(), fixture.other_path.as_str()];
    let base = paths[0].to_owned();

    assert_eq!(
        grants_naming(&fixture.vault, fixture.actor_a).len(),
        1,
        "actor=agent {:?}; expected its one owner-agent Grant before the removal",
        fixture.actor_a,
    );
    assert_eq!(
        slip_reads(&fixture, &fixture.slip_a, &paths),
        vec![base.clone()],
        "actor=agent {:?}; expected its credential to read [{}] under its Grant before the removal",
        fixture.actor_a,
        base,
    );

    let _removed = fixture
        .vault
        .remove_shared_member(&fixture.owner_proof, SHARED, fixture.member_a, None)
        .expect("the Owner removes member A");
    assert!(
        grants_naming(&fixture.vault, fixture.member_a).is_empty(),
        "member={:?}; expected the removal to take A's membership Grant",
        fixture.member_a,
    );
    assert!(
        grants_naming(&fixture.vault, fixture.actor_a).is_empty(),
        "actor=agent {:?}; expected the removal to withdraw the Grant naming A's roster actor",
        fixture.actor_a,
    );
    assert!(
        slip_reads(&fixture, &fixture.slip_a, &paths).is_empty(),
        "actor=agent {:?}; expected A's actor's credential to read nothing once its Grant is withdrawn",
        fixture.actor_a,
    );
}

#[test]
fn removing_a_member_keeps_grants_naming_another_members_actor() {
    let fixture = Fixture::new();
    let paths = [fixture.base_path.as_str(), fixture.other_path.as_str()];
    let base = paths[0].to_owned();

    let _removed = fixture
        .vault
        .remove_shared_member(&fixture.owner_proof, SHARED, fixture.member_a, None)
        .expect("the Owner removes member A");
    assert_eq!(
        grants_naming(&fixture.vault, fixture.member_b).len(),
        1,
        "member={:?}; expected B's membership Grant to stand after A is removed",
        fixture.member_b,
    );
    assert_eq!(
        grants_naming(&fixture.vault, fixture.actor_b).len(),
        1,
        "actor=agent {:?}; expected B's actor's Grant to stand after A is removed",
        fixture.actor_b,
    );
    assert_eq!(
        slip_reads(&fixture, &fixture.slip_b, &paths),
        vec![base.clone()],
        "actor=agent {:?}; expected B's actor's credential to still read [{}] after A is removed",
        fixture.actor_b,
        base,
    );
}

#[test]
fn role_change_that_keeps_a_member_keeps_its_actors_grants() {
    let fixture = Fixture::new();
    let paths = [fixture.base_path.as_str(), fixture.other_path.as_str()];
    let base = paths[0].to_owned();

    let _moved = fixture
        .vault
        .change_shared_member_role(
            &fixture.owner_proof,
            SHARED,
            fixture.member_a,
            Role::Viewer,
            None,
        )
        .expect("the Owner re-roles member A");
    assert_eq!(
        grants_naming(&fixture.vault, fixture.actor_a).len(),
        1,
        "actor=agent {:?}; expected A's actor's Grant to stand after a role change that keeps A",
        fixture.actor_a,
    );
    assert_eq!(
        slip_reads(&fixture, &fixture.slip_a, &paths),
        vec![base.clone()],
        "actor=agent {:?}; expected A's actor's credential to still read [{}] after a role change that keeps A",
        fixture.actor_a,
        base,
    );
}
