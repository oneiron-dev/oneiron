// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! A stored world-access grant starts or stops governing only by a live
//! vault owner (ARCH-0067 #tiers: "a grant = an owner-tiered-confirm
//! receipt", "the agent can never self-widen it").
//!
//! [WORLD-ACCESS-PRESTAGED-GRANT-APPROVAL]: the claim doors take a grant only
//! of a live owner's writing, but an approval of a STORED proposal wrote the
//! approved row past them. A grant proposal another writer staged (before the
//! doors refused it, or through a raw door) governed its subject once the
//! owner or a holder approved it. The claim put admission now meets every
//! approval of a stored grant with its stamped writer.
//!
//! [WORLD-ACCESS-GRANT-RETRACT-BY-FORMER-OWNER-AUTHOR]: a co-owner who wrote
//! a grant and was then made an Admin kept its author's retract. With a
//! second grant in force about the agent, closing the narrower one widened
//! the agent to the other. The same admission now takes a close of a
//! governing grant only from a live owner, when the door stamped its closer;
//! the stale mark, which writes with no closer, judges its caller at its door.
//!
//! [WORLD-ACCESS-GRANT-DELETE-BY-DELETE-AUTHORITY] (the lead's RULING
//! WORLD-ACCESS-GRANT-DELETE = A, 15 Nov: "deleting a restriction IS a
//! widening"): an agent with a live delete Grant, or an Admin in scope,
//! deleted the owner's grant about an agent, which then read base reality.
//! The delete authority now leaves a world-access row to a live owner,
//! whatever role or Grant another caller holds. The lead's generalization
//! ("any delete of a row whose removal widens someone's access or authority
//! is judged as a widen") is shown on one more kind: a do-not-contact bar.
//!
//! Grants and proposals land through the cfg door #7793 added
//! (`test_doors::world_access`), stamped with their writer's envelope as the
//! claim doors stamp it; every approval, retract and delete goes through the
//! Memory doors behind `vault.claims.*` and `vault.delete`.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test world_access_state_change`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::agent_def::AgentCeiling;
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, VerifiedSlip};
use oneiron::consent::{AuthenticatedOwner, consent_receipt_grant_ref};
use oneiron::federation::{FederationGrantRole, InitialSharedMember, Scope, ScopeAxis};
use oneiron::memory::{
    ClaimDemoteActionInput, ClaimDemoteRequest, ClaimDemoteView, ClaimInput,
    ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest, ClaimSettlement,
    MEMORY_CODE_FORBIDDEN, MemoryAuthoringAction, MemoryError, MemoryResult, SafeDeleteReason,
    resolve_entity_ref,
};
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::world_access::put_world_access_row;
use oneiron::test_support::bind_host_owner;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::write_envelope::cohort_claims::{
    CommDoNotContactValue, DO_NOT_CONTACT_SCOPE_ALL, PREDICATE_COMM_DO_NOT_CONTACT,
    encode_do_not_contact_value,
};
use oneiron::write_envelope::{
    WriteActor, WriteEnvelope, WriteProvenance, write_envelope_evidence,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, PREDICATE_WORLD_ACCESS_ALLOWED_SET, ResolvedWorldAuthority,
    TimeRange, Vault, VaultConfig, WorldAuthoritySet, world_access_claim_body,
};
use serde_json::{Value, json};

const LEARNED_AT: u64 = 1_780_000_000;

/// The shared vault id the former-owner tests share the vault under.
const SHARED: u64 = 44;

/// The shared vault id the Admin's delete tests share the vault under.
const SHARED_WITH_ADMIN: u64 = 45;

/// The refusal a delete below the owner gives a record that is authority.
const AUTHORITY_ROW: &str = "authority_row:";

/// The refusal an approval gives a grant no live owner wrote.
const NOT_AN_OWNER: &str = "world access grant must be written by a vault owner";

/// The refusal a close of a governing grant gives a closer who is no live
/// owner.
const NOT_AN_OWNERS_CLOSE: &str = "world access grant must be closed by a vault owner";

/// A vault rooted under a host (an owner's native Grant needs a rooted vault)
/// with the shipped default manifest; an agent the grants are about, granted
/// read and an Auto ceiling; a proposer agent, the other writer; a holder
/// agent the owner may give a review Grant; and one WORLD.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    proposer: EntityId,
    holder: EntityId,
    world: EntityId,
    facet: EntityId,
    owner_proof: AuthenticatedOwner,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let issuer =
            HostSlipIssuer::from_secret(b"world-access-state-change").expect("fixture host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("the host root binds the owner");
        let agent = vault
            .ensure_agent_principal("world-state-agent")
            .expect("agent");
        let proposer = vault
            .ensure_agent_principal("world-state-proposer")
            .expect("proposer");
        let holder = vault
            .ensure_agent_principal("world-state-holder")
            .expect("holder");
        let facet = vault.default_facet().expect("default facet");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        vault
            .grant_agent_principal(&owner_proof, &agent.to_hex(), AgentCeiling::Auto)
            .expect("the owner grants the agent read and an Auto ceiling");
        vault
            .grant_agent_principal(&owner_proof, &holder.to_hex(), AgentCeiling::Auto)
            .expect("the owner grants the holder read and an Auto ceiling");
        let world = EntityId::now();
        vault
            .put_entity(
                &world,
                ENTITY_TYPE_WORLD,
                at(LEARNED_AT),
                LEARNED_AT,
                b"world",
            )
            .expect("a WORLD");
        Self {
            vault,
            owner,
            agent,
            proposer,
            holder,
            world,
            facet,
            owner_proof,
            _directory: directory,
        }
    }

    /// The agent's confinement to the WORLD alone.
    fn confinement(&self) -> WorldAuthoritySet {
        WorldAuthoritySet::new(false, [self.world]).unwrap()
    }

    /// A grant of `set` to the agent at `approval`, stamped with `writer`'s
    /// envelope as the claim doors stamp a row, landed through the cfg door
    /// at a fresh id. Returns that id.
    fn stamped_grant(
        &self,
        writer: WriteActor,
        approval: ClaimApprovalStatus,
        set: &WorldAuthoritySet,
    ) -> EntityId {
        let mut body = world_access_claim_body(
            PREDICATE_WORLD_ACCESS_ALLOWED_SET,
            self.agent,
            set,
            ClaimSource::UserStated,
            approval,
            None,
            None,
        )
        .unwrap();
        let envelope = WriteEnvelope::new(
            writer,
            ClaimSource::UserStated,
            WriteProvenance::new(rmpv::Value::from("world-state-change-test")).unwrap(),
            approval,
        );
        body.evidence = Some(write_envelope_evidence(&envelope, None));
        body.scope_facet = self.facet;
        let id = EntityId::now();
        put_world_access_row(&self.vault, &id, &body, at(LEARNED_AT), LEARNED_AT)
            .expect("a stamped grant row");
        id
    }

    /// The owner's `vault.claims.review` then `vault.claims.settle`
    /// (approve) of proposal `id`, on its own handle.
    fn owner_approves(&self, id: EntityId) -> MemoryResult<ClaimSettlement> {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        let review = memory.claim_review(&ClaimProposalReviewRequest {
            claim_ref: id.to_hex(),
            grant_ref: None,
        })?;
        memory.claim_settle(&ClaimSettleRequest {
            claim_ref: id.to_hex(),
            review_id: review.review_id,
            decision: ClaimSettleDecision::Approve,
            grant_ref: None,
        })
    }

    /// The holder's `vault.claims.review` then `vault.claims.settle`
    /// (approve) of proposal `id`, both under the owner's native Grant for
    /// that one proposal.
    fn holder_approves(&self, id: EntityId) -> MemoryResult<ClaimSettlement> {
        let receipt = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .delegate_memory_authoring(
                &self.owner_proof,
                WriteActor::new(self.holder, EdgeActorClass::Agent),
                MemoryAuthoringAction::ReviewClaim,
                id,
            )
            .expect("the owner grants the holder this proposal's review");
        let grant_ref =
            consent_receipt_grant_ref(&receipt).expect("a standing grant names its grant_ref");
        let memory = self.vault.memory(self.holder, EdgeActorClass::Agent);
        let review = memory.claim_review(&ClaimProposalReviewRequest {
            claim_ref: id.to_hex(),
            grant_ref: Some(grant_ref.clone()),
        })?;
        memory.claim_settle(&ClaimSettleRequest {
            claim_ref: id.to_hex(),
            review_id: review.review_id,
            decision: ClaimSettleDecision::Approve,
            grant_ref: Some(grant_ref),
        })
    }

    /// The tiers the agent's reads resolve with no selection.
    fn agent_reads(&self) -> ResolvedWorldAuthority {
        self.vault
            .board_world_authority(Some(self.agent), None)
            .expect("the agent's tiers resolve")
    }

    /// A grant input about the agent with the JSON `value`, in the default
    /// facet, as `vault.claims.propose` takes it.
    fn grant_input(&self, value: Value) -> ClaimInput {
        ClaimInput {
            id: None,
            predicate: PREDICATE_WORLD_ACCESS_ALLOWED_SET.to_owned(),
            subject_ref: self.agent.to_hex(),
            value,
            confidence: 1.0,
            confidence_details: None,
            source: "user_stated".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: Some(json!({ "facet": self.facet.to_hex() })),
            valid_from: None,
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
        }
    }

    /// The owner's grant of base reality and the WORLD to the agent, then a
    /// pause grant the co-owner writes through `vault.claims.propose` while an
    /// owner (approved by the owner when it lands as a proposal). The meet of
    /// the two pauses the agent. Returns the co-owner and its grant's id.
    fn two_grants_the_co_owner_wrote_the_pause(&self) -> (EntityId, EntityId) {
        self.stamped_grant(
            WriteActor::new(self.owner, EdgeActorClass::Human),
            ClaimApprovalStatus::Approved,
            &WorldAuthoritySet::new(true, [self.world]).unwrap(),
        );
        let co_owner = self.share_with_co_owner();
        let receipt = self
            .vault
            .memory(co_owner, EdgeActorClass::Human)
            .claim_propose(&self.grant_input(json!({
                "schema_version": 1,
                "include_base": false,
                "worlds": [],
            })))
            .expect("a live co-owner writes a grant");
        let pause = resolve_entity_ref(&self.vault, &receipt.claim_short_id).expect("grant id");
        if receipt.approval == "proposed" {
            self.owner_approves(pause)
                .expect("the owner approves the co-owner's grant");
        }
        assert_eq!(
            self.agent_reads().allowed_set,
            WorldAuthoritySet::new(false, []).unwrap(),
            "the co-owner's pause governs the agent beside the owner's grant"
        );
        (co_owner, pause)
    }

    /// Shares the vault with a second Owner, who accepts its founding
    /// invitation (as `tests/world_access_claim_doors.rs` does), and returns
    /// it.
    fn share_with_co_owner(&self) -> EntityId {
        let co_owner = EntityId::now();
        self.vault
            .put_entity(
                &co_owner,
                ENTITY_TYPE_PERSON,
                at(LEARNED_AT),
                LEARNED_AT,
                b"human",
            )
            .expect("a live person");
        self.vault
            .initialize_shared_vault(
                &self.owner_proof,
                SHARED,
                None,
                &[
                    InitialSharedMember {
                        member_ref: self.owner,
                        role: Some(FederationGrantRole::Owner),
                    },
                    InitialSharedMember {
                        member_ref: co_owner,
                        role: Some(FederationGrantRole::Owner),
                    },
                ],
                1,
            )
            .expect("a shared vault with two owners");
        let co_owner_proof = self
            .vault
            .authenticate_owner(co_owner, &co_owner.to_hex(), true, GateDecisionId::now())
            .expect("the co-owner's proof");
        let invitation = self
            .vault
            .shared_invitations(&co_owner_proof, SHARED)
            .expect("the co-owner's invitations")
            .into_iter()
            .find(|open| open.role == FederationGrantRole::Owner)
            .expect("the co-owner's founding invitation");
        self.vault
            .accept_shared_invitation(&co_owner_proof, SHARED, &invitation.id)
            .expect("the co-owner accepts");
        assert_eq!(
            self.role_of(co_owner),
            Some(FederationGrantRole::Owner),
            "the co-owner is an Owner"
        );
        co_owner
    }

    /// The owner makes `co_owner` an Admin through `remove_owner`, which runs
    /// at once under its zero wait: `co_owner` is a former owner.
    fn demote_to_admin(&self, co_owner: EntityId) {
        let act = self
            .vault
            .propose_remove_owner(
                &self.owner_proof,
                SHARED,
                co_owner,
                None,
                Some(FederationGrantRole::Admin),
                false,
            )
            .expect("the owner starts remove_owner, the co-owner keeping Admin");
        self.vault
            .execute_completed_shared_act(&self.owner_proof, &act.id, None)
            .expect("remove_owner runs");
        assert_eq!(
            self.role_of(co_owner),
            Some(FederationGrantRole::Admin),
            "the former owner is an Admin"
        );
    }

    /// The role `member` holds in the shared vault now, read from its grant
    /// rows.
    fn role_of(&self, member: EntityId) -> Option<FederationGrantRole> {
        self.vault
            .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
            .expect("grants")
            .into_iter()
            .find_map(|id| {
                let body = self.vault.get(&id).expect("grant row")?;
                let grant = oneiron::federation::decode_federation_grant_body(&body).ok()?;
                (grant.member_ref == member && grant.role != FederationGrantRole::Delegate)
                    .then_some(grant.role)
            })
    }
}

/// The owner's grant confining `agent` to `world`, landed through the cfg
/// door in `facet`. Returns its id.
fn confine(vault: &Vault, agent: EntityId, world: EntityId, facet: EntityId) -> EntityId {
    let mut body = world_access_claim_body(
        PREDICATE_WORLD_ACCESS_ALLOWED_SET,
        agent,
        &WorldAuthoritySet::new(false, [world]).unwrap(),
        ClaimSource::UserStated,
        ClaimApprovalStatus::Approved,
        None,
        None,
    )
    .unwrap();
    body.scope_facet = facet;
    let id = EntityId::now();
    put_world_access_row(vault, &id, &body, at(LEARNED_AT), LEARNED_AT).expect("the owner's grant");
    assert_eq!(
        reads(vault, agent).allowed_set,
        WorldAuthoritySet::new(false, [world]).unwrap(),
        "the owner's grant confines the agent"
    );
    id
}

/// An ordinary Auto claim about `subject` in `facet`, on the owner's raw
/// door. Returns its id.
fn ordinary_claim(vault: &Vault, subject: EntityId, facet: EntityId) -> EntityId {
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("a note"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.scope_facet = facet;
    let id = EntityId::now();
    vault
        .put_claim(&id, &body, at(LEARNED_AT), LEARNED_AT)
        .expect("an ordinary claim");
    id
}

/// A `comm.do_not_contact` bar on every channel and scope about a new
/// PERSON in `facet`, on the owner's raw door. Returns its id.
fn do_not_contact_bar(vault: &Vault, facet: EntityId) -> EntityId {
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            at(LEARNED_AT),
            LEARNED_AT,
            b"human",
        )
        .expect("a live person");
    let mut body = ClaimBody::new(
        PREDICATE_COMM_DO_NOT_CONTACT,
        ClaimSubject::Entity(person),
        encode_do_not_contact_value(&CommDoNotContactValue {
            channel: None,
            scope: DO_NOT_CONTACT_SCOPE_ALL.to_owned(),
        }),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.scope_facet = facet;
    let id = EntityId::now();
    vault
        .put_claim(&id, &body, at(LEARNED_AT), LEARNED_AT)
        .expect("a do-not-contact bar");
    id
}

/// The tiers `agent`'s reads resolve with no selection.
fn reads(vault: &Vault, agent: EntityId) -> ResolvedWorldAuthority {
    vault
        .board_world_authority(Some(agent), None)
        .expect("the agent's tiers resolve")
}

fn deleted(vault: &Vault, id: EntityId) -> bool {
    vault.is_deleted_shell(&id).expect("shell read")
}

/// A personal vault whose owner made an enabled agent with a Grant naming
/// `read` and `delete` (as `tests/delete_authority.rs` makes one), and one
/// WORLD.
struct DeleteFixture {
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    world: EntityId,
    facet: EntityId,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl DeleteFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        // The owner's agent Grant act is carried by this install's live
        // machine profile (FIX 4648).
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
        let agent = agent_with_delete_grant(&vault, &owner_proof);
        let facet = vault.default_facet().expect("default facet");
        let world = a_world(&vault);
        Self {
            vault,
            owner,
            agent,
            world,
            facet,
            _directory: directory,
        }
    }

    /// The agent calls the `vault.delete` verb on `id`.
    fn agent_deletes(&self, id: EntityId) -> Result<Value, MemoryError> {
        invoke(
            &self.vault.memory(self.agent, EdgeActorClass::Agent),
            "vault.delete",
            json!({ "entity_ref": id.to_hex(), "reason": "user_delete" }),
        )
    }
}

/// A rooted shared vault (as `tests/delete_authority.rs` shares one): its
/// owner and an Admin, who acts by the live `human` credential this host
/// mints it; an agent the owner's grant may confine; and one WORLD.
struct AdminFixture {
    vault: Vault,
    issuer: HostSlipIssuer,
    admin: EntityId,
    agent: EntityId,
    world: EntityId,
    facet: EntityId,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl AdminFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        // A delete signs its receipt with this install's key.
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
        let admin = EntityId::now();
        vault
            .put_entity(
                &admin,
                ENTITY_TYPE_PERSON,
                at(LEARNED_AT),
                LEARNED_AT,
                b"human",
            )
            .expect("a live person");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("the owner's proof");
        vault
            .initialize_shared_vault(
                &owner_proof,
                SHARED_WITH_ADMIN,
                None,
                &[
                    InitialSharedMember {
                        member_ref: owner,
                        role: Some(FederationGrantRole::Owner),
                    },
                    InitialSharedMember {
                        member_ref: admin,
                        role: Some(FederationGrantRole::Admin),
                    },
                ],
                1,
            )
            .expect("a shared vault with an Admin");
        let admin_proof = vault
            .authenticate_owner(admin, &admin.to_hex(), true, GateDecisionId::now())
            .expect("the Admin's person proof");
        let invitation = vault
            .shared_invitations(&admin_proof, SHARED_WITH_ADMIN)
            .expect("the Admin's invitations")
            .into_iter()
            .find(|open| open.role == FederationGrantRole::Admin)
            .expect("the Admin's founding invitation");
        vault
            .accept_shared_invitation(&admin_proof, SHARED_WITH_ADMIN, &invitation.id)
            .expect("the Admin accepts");
        let agent = vault
            .ensure_agent_principal("world-state-admin-agent")
            .expect("agent");
        let facet = vault.default_facet().expect("default facet");
        let world = a_world(&vault);
        Self {
            vault,
            issuer,
            admin,
            agent,
            world,
            facet,
            _directory: directory,
        }
    }

    /// The Admin deletes `id` over the live `human` credential this host
    /// mints it, verified as a transport verifies the slip a request
    /// presents.
    fn admin_deletes(&self, id: EntityId) -> Result<bool, MemoryError> {
        let root = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("the host root slip");
        let issued_at = self.vault.capability_slip_now().expect("slip clock");
        let mut claims = root.claims;
        claims.slip_id = [0x5a; 32];
        claims.holder_ref = self.admin.to_hex();
        claims.actor_class = Some("human".into());
        claims.issued_at = issued_at;
        claims.expires_at = issued_at + 3_600;
        claims.ttl_secs = 3_600;
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("the Admin's credential");
        let challenge = b"world-access-state-change";
        let proof = self
            .issuer
            .binding_proof(&slip, challenge)
            .expect("binding proof");
        let credential: VerifiedSlip = self
            .vault
            .verify_capability_slip(&self.issuer.public_key(), &slip, challenge, &proof)
            .expect("a verified credential");
        self.vault
            .memory(self.admin, EdgeActorClass::Human)
            .with_transport_invocation()
            .with_read_proof(&credential)
            .safe_delete(&id.to_hex(), SafeDeleteReason::UserDelete)
            .map(|receipt| receipt.existed)
    }
}

/// One WORLD.
fn a_world(vault: &Vault) -> EntityId {
    let world = EntityId::now();
    vault
        .put_entity(
            &world,
            ENTITY_TYPE_WORLD,
            at(LEARNED_AT),
            LEARNED_AT,
            b"world",
        )
        .expect("a WORLD");
    world
}

/// An enabled agent the owner creates and gives one Grant naming `read` and
/// `delete` over the whole vault.
fn agent_with_delete_grant(vault: &Vault, owner_proof: &AuthenticatedOwner) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        vault,
        owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": "world_state_delete_agent",
                "desc": "World-access delete test agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates an enabled, active agent definition");
    let mut authority_scope = Scope::top();
    authority_scope.verbs =
        ScopeAxis::Some(["read", "delete"].into_iter().map(str::to_owned).collect());
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
    .expect("owner mints the agent a Grant");
    assert!(minted.grant.confers, "the agent's delete Grant confers");
    agent
}

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// What an agent no grant governs reads: base reality, in every tier.
fn ungoverned() -> ResolvedWorldAuthority {
    let base = WorldAuthoritySet::new(true, []).unwrap();
    ResolvedWorldAuthority {
        allowed_set: base.clone(),
        default_subset: base.clone(),
        active_set: base,
        allowed_claim_ids: Vec::new(),
        default_claim_id: None,
    }
}

/// [WORLD-ACCESS-PRESTAGED-GRANT-APPROVAL], the owner's settle: a grant
/// proposal another writer staged about the agent, which the owner then
/// approves. Before this change the approved row confined the agent; the
/// approval now meets the row's writer, who is no owner.
#[test]
fn a_grant_proposal_another_writer_staged_never_governs_once_the_owner_approves() {
    let f = Fixture::new();
    let staged = f.stamped_grant(
        WriteActor::new(f.proposer, EdgeActorClass::Agent),
        ClaimApprovalStatus::Proposed,
        &f.confinement(),
    );

    let approved = f.owner_approves(staged);

    assert_eq!(
        f.agent_reads(),
        ungoverned(),
        "a grant no owner wrote governs nobody (approval: {approved:?})"
    );
    let refused = approved.expect_err("an approval lands a grant of a live owner's writing only");
    assert!(
        refused.message.contains(NOT_AN_OWNER),
        "the refusal names the rule: {refused:?}"
    );
}

/// [WORLD-ACCESS-PRESTAGED-GRANT-APPROVAL], a holder's settle under the
/// owner's review Grant for that one proposal: the same staged grant.
#[test]
fn a_grant_proposal_another_writer_staged_never_governs_once_a_holder_approves() {
    let f = Fixture::new();
    let staged = f.stamped_grant(
        WriteActor::new(f.proposer, EdgeActorClass::Agent),
        ClaimApprovalStatus::Proposed,
        &f.confinement(),
    );

    let approved = f.holder_approves(staged);

    assert_eq!(
        f.agent_reads(),
        ungoverned(),
        "a grant no owner wrote governs nobody (approval: {approved:?})"
    );
    let refused = approved.expect_err("an approval lands a grant of a live owner's writing only");
    assert!(
        refused.message.contains(NOT_AN_OWNER),
        "the refusal names the rule: {refused:?}"
    );
}

/// Control: the owner approves a grant proposal of its own writing, which
/// then confines the agent.
#[test]
fn the_owners_own_grant_proposal_governs_once_approved() {
    let f = Fixture::new();
    let staged = f.stamped_grant(
        WriteActor::new(f.owner, EdgeActorClass::Human),
        ClaimApprovalStatus::Proposed,
        &f.confinement(),
    );

    f.owner_approves(staged)
        .expect("the owner approves its own grant proposal");

    let reads = f.agent_reads();
    assert_eq!(reads.allowed_set, f.confinement());
    assert_eq!(reads.allowed_claim_ids, vec![staged]);
}

/// Control: a holder approves a grant proposal of the owner's writing under
/// the owner's review Grant for it. The approver is its own door's to judge;
/// the writer is a live owner, so the grant governs.
#[test]
fn a_holder_approving_the_owners_grant_proposal_lands_it() {
    let f = Fixture::new();
    let staged = f.stamped_grant(
        WriteActor::new(f.owner, EdgeActorClass::Human),
        ClaimApprovalStatus::Proposed,
        &f.confinement(),
    );

    f.holder_approves(staged)
        .expect("the holder's approval lands under the owner's Grant");

    let reads = f.agent_reads();
    assert_eq!(reads.allowed_set, f.confinement());
    assert_eq!(reads.allowed_claim_ids, vec![staged]);
}

/// [WORLD-ACCESS-GRANT-RETRACT-BY-FORMER-OWNER-AUTHOR]: the co-owner wrote a
/// pause grant beside the owner's wider grant, and the owner then made it an
/// Admin. Before this change its author's retract closed the pause, and the
/// agent read the WORLD and base reality again; a close of a governing grant
/// now needs a live owner.
#[test]
fn a_former_owner_never_retracts_the_grant_it_wrote() {
    let f = Fixture::new();
    let (former, pause) = f.two_grants_the_co_owner_wrote_the_pause();
    f.demote_to_admin(former);

    let retracted = f
        .vault
        .memory(former, EdgeActorClass::Human)
        .claim_retract(&pause.to_hex());

    assert_eq!(
        f.agent_reads().allowed_set,
        WorldAuthoritySet::new(false, []).unwrap(),
        "the pause still governs the agent (retract: {retracted:?})"
    );
    let stored = f
        .vault
        .get_claim(&pause)
        .expect("claim read")
        .expect("the pause");
    assert_eq!(stored.lifecycle, ClaimLifecycleStatus::Active);
    let refused = retracted.expect_err("a close of a grant needs a live owner");
    assert!(
        refused.message.contains(NOT_AN_OWNERS_CLOSE),
        "the refusal names the rule: {refused:?}"
    );
}

/// Control: while still an owner, the co-owner retracts the pause it wrote,
/// and the agent reads the owner's wider grant.
#[test]
fn a_live_co_owner_retracts_the_grant_it_wrote() {
    let f = Fixture::new();
    let (co_owner, pause) = f.two_grants_the_co_owner_wrote_the_pause();

    f.vault
        .memory(co_owner, EdgeActorClass::Human)
        .claim_retract(&pause.to_hex())
        .expect("a live owner retracts its own grant");

    assert_eq!(
        f.agent_reads().allowed_set,
        WorldAuthoritySet::new(true, [f.world]).unwrap(),
        "the agent reads the owner's grant alone"
    );
}

/// `actor`'s `vault.claims.demote` of `id` to the stale rung, on its own
/// handle.
fn marks_stale(f: &Fixture, actor: EntityId, id: EntityId) -> MemoryResult<ClaimDemoteView> {
    f.vault
        .memory(actor, EdgeActorClass::Human)
        .claim_demote(&ClaimDemoteRequest {
            claim_ref: id.to_hex(),
            action: ClaimDemoteActionInput::Stale,
        })
}

/// [WORLD-ACCESS-GRANT-RETRACT-BY-FORMER-OWNER-AUTHOR], the stale mark (Astra
/// review census-l2-wa-state-change F2): the demote door admits the grant's
/// author and wrote the mark with no closer, so a former owner's stale mark
/// of the pause it wrote took it out of the fold, as its retract did, and the
/// agent read the WORLD and base reality again.
#[test]
fn a_former_owner_never_marks_the_grant_it_wrote_stale() {
    let f = Fixture::new();
    let (former, pause) = f.two_grants_the_co_owner_wrote_the_pause();
    f.demote_to_admin(former);

    let marked = marks_stale(&f, former, pause);

    assert_eq!(
        f.agent_reads().allowed_set,
        WorldAuthoritySet::new(false, []).unwrap(),
        "the pause still governs the agent (stale mark: {marked:?})"
    );
    let stored = f
        .vault
        .get_claim(&pause)
        .expect("claim read")
        .expect("the pause");
    assert!(!stored.stale, "the pause is not stale");
    let refused = marked.expect_err("a stale mark of a grant needs a live owner");
    assert!(
        refused.message.contains(NOT_AN_OWNERS_CLOSE),
        "the refusal names the rule: {refused:?}"
    );
}

/// Control: while still an owner, the co-owner marks the pause it wrote
/// stale, and the agent reads the owner's wider grant.
#[test]
fn a_live_co_owner_marks_the_grant_it_wrote_stale() {
    let f = Fixture::new();
    let (co_owner, pause) = f.two_grants_the_co_owner_wrote_the_pause();

    let marked = marks_stale(&f, co_owner, pause).expect("a live owner marks its own grant stale");

    assert!(marked.stale, "the pause carries the stale rung");
    assert_eq!(
        f.agent_reads().allowed_set,
        WorldAuthoritySet::new(true, [f.world]).unwrap(),
        "the agent reads the owner's grant alone"
    );
}

/// [WORLD-ACCESS-GRANT-DELETE-BY-DELETE-AUTHORITY]: an agent with a live
/// delete Grant over the whole vault deletes the owner's grant confining it.
/// Before this change the delete landed and the agent read base reality; a
/// world-access row is now the live owner's alone to delete.
#[test]
fn an_agents_delete_grant_never_deletes_its_confinement() {
    let f = DeleteFixture::new();
    let grant = confine(&f.vault, f.agent, f.world, f.facet);

    let result = f.agent_deletes(grant);

    assert_eq!(
        reads(&f.vault, f.agent).allowed_set,
        WorldAuthoritySet::new(false, [f.world]).unwrap(),
        "the owner's grant still confines the agent (delete: {result:?})"
    );
    assert!(!deleted(&f.vault, grant), "the refused grant is untouched");
    let refused = result.expect_err("an agent never deletes a world-access row");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert!(
        refused.message.starts_with(AUTHORITY_ROW),
        "the refusal names its reason: {refused:?}"
    );
}

/// Control, and the agent red's precondition: the same agent's delete Grant
/// deletes an ordinary CLAIM about it in the same facet.
#[test]
fn the_same_agent_deletes_an_ordinary_claim_in_that_facet() {
    let f = DeleteFixture::new();
    let note = ordinary_claim(&f.vault, f.agent, f.facet);

    let receipt = f
        .agent_deletes(note)
        .unwrap_or_else(|error| panic!("an agent under a delete Grant deletes: {error:?}"));

    assert_eq!(receipt["existed"], true, "{receipt}");
    assert!(deleted(&f.vault, note), "the claim is a deleted shell");
}

/// [WORLD-ACCESS-GRANT-DELETE-BY-DELETE-AUTHORITY], the Admin: an Admin of
/// a shared vault deletes, in scope, the owner's grant confining an agent.
/// Before this change DEL-2's in-scope delete landed and the agent read base
/// reality; a world-access row is authority, not an item in scope.
#[test]
fn an_admin_never_deletes_the_owners_grant_in_scope() {
    let f = AdminFixture::new();
    let grant = confine(&f.vault, f.agent, f.world, f.facet);

    let result = f.admin_deletes(grant);

    assert_eq!(
        reads(&f.vault, f.agent).allowed_set,
        WorldAuthoritySet::new(false, [f.world]).unwrap(),
        "the owner's grant still confines the agent (delete: {result:?})"
    );
    assert!(!deleted(&f.vault, grant), "the refused grant is untouched");
    let refused = result.expect_err("an Admin never deletes a world-access row");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert!(
        refused.message.starts_with(AUTHORITY_ROW),
        "the refusal names its reason: {refused:?}"
    );
}

/// The lead's generalization of [WORLD-ACCESS-GRANT-DELETE-BY-DELETE-AUTHORITY]:
/// an Admin deletes, in scope, a do-not-contact bar on a person. Before this
/// change DEL-2's in-scope delete landed and sends to that person were open
/// again; the bar is a restriction, so it is the live owner's to delete.
#[test]
fn an_admin_never_deletes_a_do_not_contact_bar_in_scope() {
    let f = AdminFixture::new();
    let bar = do_not_contact_bar(&f.vault, f.facet);

    let result = f.admin_deletes(bar);

    assert!(
        !deleted(&f.vault, bar),
        "the bar still stands (delete: {result:?})"
    );
    let refused = result.expect_err("an Admin never deletes a restriction");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert!(
        refused.message.starts_with(AUTHORITY_ROW),
        "the refusal names its reason: {refused:?}"
    );
}

/// Control, and the Admin red's precondition: the Admin deletes an ordinary
/// CLAIM in the same facet, in scope, as DEL-2 allows.
#[test]
fn the_admin_deletes_an_ordinary_claim_in_scope() {
    let f = AdminFixture::new();
    let note = ordinary_claim(&f.vault, f.agent, f.facet);

    let existed = f
        .admin_deletes(note)
        .unwrap_or_else(|error| panic!("an Admin deletes in scope: {error:?}"));

    assert!(existed);
    assert!(deleted(&f.vault, note), "the claim is a deleted shell");
}

/// Control: the owner deletes its own grant, and the agent reads base
/// reality.
#[test]
fn the_owner_deletes_its_grant() {
    let f = DeleteFixture::new();
    let grant = confine(&f.vault, f.agent, f.world, f.facet);

    let receipt = f
        .vault
        .memory(f.owner, EdgeActorClass::Human)
        .safe_delete(&grant.to_hex(), SafeDeleteReason::UserDelete)
        .expect("the owner deletes anything");

    assert!(receipt.existed);
    assert!(deleted(&f.vault, grant), "the grant is a deleted shell");
    assert_eq!(reads(&f.vault, f.agent), ungoverned());
}
