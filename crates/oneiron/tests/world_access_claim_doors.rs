// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The generic claim doors and the two world-access tiers (ARCH-0067 #tiers:
//! "a grant = an owner-tiered-confirm receipt", "the agent can never
//! self-widen it"; a DEFAULT-SUBSET is "owner-set or agent-proposed").
//!
//! [WORLD-ACCESS-GENERIC-DOOR-UNDECODABLE]: a claim door builds its value from
//! JSON, which has no binary world id, so a default an agent wrote about
//! itself there landed, counted, and then failed every read of that agent
//! closed. The door now refuses an in-force world-access row whose value the
//! fold cannot read, and still takes one it can.
//!
//! [WORLD-ACCESS-GRANT-HOLDER-SETTLE]: another writer could stage a
//! user-stated grant about an agent, and a holder approving it under the
//! owner's review Grant for that one claim made it govern the agent with no
//! owner decision on the grant. The door now takes a grant from a vault
//! owner only.
//!
//! Both call sites take a grant only of a LIVE owner's writing: the claim
//! candidate door (its envelope actor) and the save of an off-record room
//! (the writer the staged row keeps). Each is shown refusing an agent and a
//! former owner: a co-owner of a shared vault whom the other owner made an
//! Admin through `remove_owner`.
//!
//! The owner grant that puts the agent under world-access law lands through
//! the cfg door #7793 added (`test_doors::world_access`); every other write
//! goes through the Memory claim doors behind `vault.claims.*`.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test world_access_claim_doors`.
#![cfg(oneiron_test_support)]

use oneiron::agent_def::AgentCeiling;
use oneiron::authority::HostSlipIssuer;
use oneiron::claim::base_world_id;
use oneiron::consent::{AuthenticatedOwner, consent_receipt_grant_ref};
use oneiron::federation::{FederationGrantRole, InitialSharedMember};
use oneiron::memory::{
    AllRelationships, ClaimInput, ClaimProposalReviewRequest, ClaimRelationships, ClaimScope,
    ClaimSettleDecision, ClaimSettleRequest, ClaimSettlementVerdict, MemoryAuthoringAction,
    MemoryResult, ScopedClaimInput, resolve_entity_ref,
};
use oneiron::off_record::{OffRecordBackendClass, OffRecordSession};
use oneiron::registry::{
    ENTITY_TYPE_EVENT, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::world_access::put_world_access_row;
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, PREDICATE_WORLD_ACCESS_ALLOWED_SET,
    PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET, ResolvedWorldAuthority, TimeRange, Vault, VaultConfig,
    WorldAuthoritySet, WriteActor, world_access_claim_body,
};
use serde_json::{Value, json};

const LEARNED_AT: u64 = 1_780_000_000;

/// The shared vault id the former-owner tests share the vault under.
const SHARED: u64 = 42;

/// The refusal both call sites give a grant no live owner wrote.
const NOT_AN_OWNER: &str = "world access grant must be written by a vault owner";

/// A vault rooted under a host (an owner's native Grant needs a rooted
/// vault) with the shipped default manifest; an agent whose ceiling the owner
/// set to Auto, so its own claims land Auto; a proposer the owner granted read
/// and propose; a holder the owner granted an Auto ceiling; and one WORLD.
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
        vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let issuer =
            HostSlipIssuer::from_secret(b"world-access-claim-doors").expect("fixture host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("the host root binds the owner");
        let agent = vault
            .ensure_agent_principal("world-doors-agent")
            .expect("agent");
        let proposer = vault
            .ensure_agent_principal("world-doors-proposer")
            .expect("proposer");
        let holder = vault
            .ensure_agent_principal("world-doors-holder")
            .expect("holder");
        let facet = vault.default_facet().expect("default facet");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        vault
            .grant_agent_principal(&owner_proof, &agent.to_hex(), AgentCeiling::Auto)
            .expect("the owner grants the agent read and an Auto ceiling");
        vault
            .grant_foreign_principal(&owner_proof, &proposer.to_hex())
            .expect("the owner grants the proposer read and propose");
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

    /// The owner's grant of base reality and the WORLD to the agent, landed
    /// through the cfg door: it puts the agent under world-access law.
    fn grant_agent_the_world(&self) {
        let mut body = world_access_claim_body(
            PREDICATE_WORLD_ACCESS_ALLOWED_SET,
            self.agent,
            &WorldAuthoritySet::new(true, [self.world]).unwrap(),
            ClaimSource::UserStated,
            ClaimApprovalStatus::Approved,
            None,
            None,
        )
        .unwrap();
        body.scope_facet = self.facet;
        put_world_access_row(
            &self.vault,
            &EntityId::now(),
            &body,
            at(LEARNED_AT),
            LEARNED_AT,
        )
        .expect("the owner's grant");
    }

    /// A claim input about `subject` under `predicate` with `value`.
    fn input(&self, predicate: &str, subject: EntityId, value: Value, source: &str) -> ClaimInput {
        ClaimInput {
            id: None,
            predicate: predicate.to_owned(),
            subject_ref: subject.to_hex(),
            value,
            confidence: 1.0,
            confidence_details: None,
            source: source.to_owned(),
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

    /// The agent writes its own default through `vault.claims.upsert`'s door.
    fn agent_writes_its_default(&self, value: Value) -> MemoryResult<String> {
        self.vault
            .memory(self.agent, EdgeActorClass::Agent)
            .claim_upsert(&self.input(
                PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET,
                self.agent,
                value,
                "observed",
            ))
            .map(|receipt| receipt.approval)
    }

    /// The tiers the agent's reads resolve with no selection.
    fn agent_reads(&self) -> oneiron::Result<ResolvedWorldAuthority> {
        self.vault.board_world_authority(Some(self.agent), None)
    }

    /// The owner's native Grant: the holder may review and settle this one
    /// proposal. Returns its 64-hex grant_ref.
    fn grant_review(&self, id: EntityId) -> String {
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
        consent_receipt_grant_ref(&receipt).expect("a standing grant names its grant_ref")
    }

    /// The holder's `vault.claims.review` then `vault.claims.settle`
    /// (approve), both under the owner's Grant for this one proposal.
    fn holder_approves(&self, id: EntityId) {
        let grant_ref = self.grant_review(id);
        let memory = self.vault.memory(self.holder, EdgeActorClass::Agent);
        let review = memory
            .claim_review(&ClaimProposalReviewRequest {
                claim_ref: id.to_hex(),
                grant_ref: Some(grant_ref.clone()),
            })
            .expect("the holder reviews under its Grant");
        let settled = memory
            .claim_settle(&ClaimSettleRequest {
                claim_ref: id.to_hex(),
                review_id: review.review_id,
                decision: ClaimSettleDecision::Approve,
                grant_ref: Some(grant_ref),
            })
            .expect("the holder's approval lands under its Grant");
        assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
    }

    /// Shares the vault with a second Owner, who accepts its founding
    /// invitation (as `tests/admin_is_not_steward.rs` does), and returns it.
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
    /// rows (as `tests/admin_is_not_steward.rs` reads it).
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

    /// An off-record room (roomless, local), as the save pins enter one
    /// (`tests/gate_pins_put_pipeline.rs`).
    fn room(&self, name: &str) -> OffRecordSession<'_> {
        self.vault
            .off_record_session_vault()
            .enter(name, OffRecordBackendClass::Local)
            .expect("enter the room")
    }

    /// `writer` stages a user-stated grant about the agent in `room`
    /// (`vault.claims.upsert` in a session), at sensitivity 2 so it stages
    /// proposed. Staging runs the Gate, not the base-reality write rules, so
    /// it stages on main and on this head alike. Returns the row's id.
    fn stage_grant_in_room(
        &self,
        room: &OffRecordSession<'_>,
        writer: EntityId,
        class: EdgeActorClass,
    ) -> EntityId {
        let project = EntityId::now();
        self.vault
            .put_entity(
                &project,
                ENTITY_TYPE_EVENT,
                at(LEARNED_AT),
                LEARNED_AT,
                &rmp_serde::to_vec_named(&json!({ "name": "world doors project" }))
                    .expect("encode the project row"),
            )
            .expect("a project row");
        let claim = EntityId::now();
        self.vault
            .memory(writer, class)
            .claim_upsert_in_session(
                room,
                &ScopedClaimInput {
                    id: Some(claim.to_hex()),
                    predicate: PREDICATE_WORLD_ACCESS_ALLOWED_SET.to_owned(),
                    subject_ref: self.agent.to_hex(),
                    value: json_worlds(false, &[]),
                    confidence: 1.0,
                    source: "user_stated".to_owned(),
                    scope: ClaimScope {
                        world_id: base_world_id().to_hex(),
                        scope_facet_id: self.facet.to_hex(),
                        scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                        scope_project_id: project.to_hex(),
                    },
                    sensitivity: Some(2),
                    evidence_turn_refs: Vec::new(),
                    valid_from: None,
                    valid_to: None,
                    occurred_at: Some(LEARNED_AT),
                    learned_at: Some(LEARNED_AT),
                    salience: None,
                },
            )
            .expect("the writer stages a grant in the room");
        claim
    }

    /// The owner saves `claim` from `room` (`vault.off_record.artifacts.save`);
    /// when the save lands it, a holder approves the saved proposal under the
    /// owner's review Grant, as a staged grant would go on to be approved.
    fn owner_saves_then_holder_approves(
        &self,
        room: &OffRecordSession<'_>,
        claim: EntityId,
    ) -> oneiron::Result<oneiron::off_record::PromoteOutcome> {
        let saved = room.save_artifact_as(&self.owner_proof, &claim.to_hex());
        if saved.is_ok()
            && self
                .vault
                .get_claim(&claim)
                .expect("read the saved row")
                .is_some_and(|body| body.approval == ClaimApprovalStatus::Proposed)
        {
            self.holder_approves(claim);
        }
        saved
    }
}

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// A world-access value with base reality and `worlds` as the JSON doors
/// spell ids: hex strings, which the strict value never reads.
fn json_worlds(include_base: bool, worlds: &[EntityId]) -> Value {
    json!({
        "schema_version": 1,
        "include_base": include_base,
        "worlds": worlds.iter().map(EntityId::to_hex).collect::<Vec<_>>(),
    })
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

/// [WORLD-ACCESS-GENERIC-DOOR-UNDECODABLE]: an agent the owner granted the
/// WORLD names it as its default through the claim door, as JSON spells it.
/// The fold cannot read a hex world id, so before this change the row landed
/// and every read of the agent failed closed. The door refuses it, and the
/// agent's reads still resolve to its grant.
#[test]
fn an_undecodable_default_from_a_claim_door_never_lands() {
    let f = Fixture::new();
    f.grant_agent_the_world();

    let wrote = f.agent_writes_its_default(json_worlds(true, &[f.world]));

    let reads = f.agent_reads();
    assert!(
        reads.is_ok(),
        "the agent's reads stay open after its default write: {reads:?} (write: {wrote:?})"
    );
    let refused = wrote.expect_err("a default the fold cannot read is refused at the door");
    assert!(
        refused.message.contains("world-access claim value"),
        "the refusal names the value: {refused:?}"
    );
    assert_eq!(
        reads.unwrap().allowed_set,
        WorldAuthoritySet::new(true, [f.world]).unwrap(),
        "the owner's grant still governs the agent's reads"
    );
}

/// Control: a default the fold can read lands through the same door and is
/// the agent's default.
#[test]
fn a_readable_default_from_a_claim_door_lands() {
    let f = Fixture::new();
    f.grant_agent_the_world();

    let approval = f
        .agent_writes_its_default(json_worlds(true, &[]))
        .expect("a default the fold reads lands");

    assert_eq!(
        approval, "auto",
        "the agent's own default lands under its ceiling"
    );
    let reads = f.agent_reads().expect("the agent's reads resolve");
    assert_eq!(
        reads.default_subset,
        WorldAuthoritySet::new(true, []).unwrap()
    );
    assert!(
        reads.default_claim_id.is_some(),
        "the agent's own default counts"
    );
}

/// [WORLD-ACCESS-GRANT-HOLDER-SETTLE]: an agent stages a user-stated grant
/// about another agent, and a holder approves it under the owner's review
/// Grant for that one claim. Before this change the approved row governed the
/// other agent (its reads fell to the staged empty set); the door now takes a
/// grant from a vault owner only, so nothing governs that agent.
#[test]
fn a_grant_another_writer_stages_never_governs() {
    let f = Fixture::new();

    let staged = f
        .vault
        .memory(f.proposer, EdgeActorClass::Agent)
        .claim_propose(&f.input(
            PREDICATE_WORLD_ACCESS_ALLOWED_SET,
            f.agent,
            json_worlds(false, &[]),
            "user_stated",
        ));
    if let Ok(receipt) = &staged {
        let id = resolve_entity_ref(&f.vault, &receipt.claim_short_id).expect("proposal id");
        f.holder_approves(id);
    }

    assert_eq!(
        f.agent_reads().expect("the agent's reads resolve"),
        ungoverned(),
        "a grant no owner wrote governs nobody (staged: {staged:?})"
    );
    let refused = staged.expect_err("the door takes a grant from a vault owner only");
    assert!(
        refused.message.contains(NOT_AN_OWNER),
        "the refusal names the rule: {refused:?}"
    );
}

/// A former owner at the claim door: a co-owner of the shared vault whom the
/// other owner made an Admin stages a user-stated grant about an agent, and a
/// holder approves it under the owner's review Grant. Before this change the
/// approved row governed the agent; the door reads the owner census at the
/// write, so an owner who has left writes no grant.
#[test]
fn a_grant_a_former_owner_stages_never_governs() {
    let f = Fixture::new();
    let former = f.share_with_co_owner();
    f.demote_to_admin(former);

    let staged = f
        .vault
        .memory(former, EdgeActorClass::Human)
        .claim_propose(&f.input(
            PREDICATE_WORLD_ACCESS_ALLOWED_SET,
            f.agent,
            json_worlds(false, &[]),
            "user_stated",
        ));
    if let Ok(receipt) = &staged {
        let id = resolve_entity_ref(&f.vault, &receipt.claim_short_id).expect("proposal id");
        f.holder_approves(id);
    }

    assert_eq!(
        f.agent_reads().expect("the agent's reads resolve"),
        ungoverned(),
        "a grant a former owner wrote governs nobody (staged: {staged:?})"
    );
    let refused = staged.expect_err("the door takes a grant from a live vault owner only");
    assert!(
        refused.message.contains(NOT_AN_OWNER),
        "the refusal names the rule: {refused:?}"
    );
}

/// An agent at the off-record save: an agent stages a user-stated grant about
/// another agent in an off-record room, the owner saves it, and a holder
/// approves the saved row. Before this change the saved row governed the
/// other agent; the save takes a grant only of a live owner's writing (the
/// writer the staged row keeps), and refuses the whole save.
#[test]
fn a_grant_an_agent_stages_in_a_room_is_refused_at_the_save() {
    let f = Fixture::new();
    let room = f.room("world-doors-agent-room");
    let claim = f.stage_grant_in_room(&room, f.proposer, EdgeActorClass::Agent);

    let saved = f.owner_saves_then_holder_approves(&room, claim);

    assert_eq!(
        f.agent_reads().expect("the agent's reads resolve"),
        ungoverned(),
        "a grant an agent staged governs nobody (save: {saved:?})"
    );
    let refused = saved.expect_err("the save takes a grant only of a live owner's writing");
    assert!(
        refused.to_string().contains(NOT_AN_OWNER),
        "the refusal names the rule: {refused}"
    );
    assert!(
        f.vault.get_claim(&claim).expect("read").is_none(),
        "the refused save lands nothing"
    );
}

/// A former owner at the off-record save: a co-owner stages a user-stated
/// grant about an agent in an off-record room while an Owner, the other
/// owner makes it an Admin, then saves the room. Before this change the saved
/// row governed the agent once a holder approved it; the save reads the
/// owner census at the save, so the grant of an owner who has left is
/// refused.
#[test]
fn a_grant_a_former_owner_staged_in_a_room_is_refused_at_the_save() {
    let f = Fixture::new();
    let former = f.share_with_co_owner();
    let room = f.room("world-doors-former-owner-room");
    let claim = f.stage_grant_in_room(&room, former, EdgeActorClass::Human);
    f.demote_to_admin(former);

    let saved = f.owner_saves_then_holder_approves(&room, claim);

    assert_eq!(
        f.agent_reads().expect("the agent's reads resolve"),
        ungoverned(),
        "a grant a former owner staged governs nobody (save: {saved:?})"
    );
    let refused = saved.expect_err("the save takes a grant only of a live owner's writing");
    assert!(
        refused.to_string().contains(NOT_AN_OWNER),
        "the refusal names the rule: {refused}"
    );
    assert!(
        f.vault.get_claim(&claim).expect("read").is_none(),
        "the refused save lands nothing"
    );
}

/// Control: the owner's own grant staged in a room lands through the save.
#[test]
fn the_owners_grant_from_a_room_save_lands() {
    let f = Fixture::new();
    let room = f.room("world-doors-owner-room");
    let claim = f.stage_grant_in_room(&room, f.owner, EdgeActorClass::Human);

    let outcome = room
        .save_artifact_as(&f.owner_proof, &claim.to_hex())
        .expect("the owner's room save lands the owner's grant");

    assert!(
        outcome.replayed.contains(&claim),
        "the save names the grant: {:?}",
        outcome.replayed
    );
}

/// Control: the owner's own grant through the same door still lands.
#[test]
fn the_owners_grant_from_a_claim_door_lands() {
    let f = Fixture::new();

    let receipt = f
        .vault
        .memory(f.owner, EdgeActorClass::Human)
        .claim_upsert(&f.input(
            PREDICATE_WORLD_ACCESS_ALLOWED_SET,
            f.agent,
            json_worlds(true, &[]),
            "user_stated",
        ))
        .expect("the owner's grant lands through the claim door");

    assert_eq!(receipt.approval, "auto", "the owner's claim lands");
}
