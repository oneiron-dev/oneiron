// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! [UNROOTED-SHARED-OWNER-VERB-IGNORES-CENSUS] (Engine RULING 15 Nov 13:13,
//! UNROOTED-OWNER-CENSUS = A): on a vault with no authority root, the
//! owner-verb rule passed the embedded owner on its actor id and a live
//! PERSON alone. So on an unrooted vault shared with a co-owner, an embedded
//! owner whom the co-owner made an Admin through `remove_owner` still passed
//! every owner verb: the inbox approval of a pending user-stated ALLOWED-SET
//! grant, which then governs the agent it names, and the retraction of a
//! claim another member wrote. The rule now reads the vault's live owner
//! census: a shared vault's live Owner-role members, and on a personal vault
//! the live embedded owner, as before.
//!
//! [UNROOTED-EMBEDDED-OWNER-SHORTCUTS-SKIP-CENSUS] (Engine RULING 15 Nov
//! 15:07): three doors still took the embedded owner on its actor id alone,
//! with no owner check, so the demoted embedded owner kept them: the read-lane
//! owner key and the write standing every door reads from it
//! (`Memory::is_vault_owner`), with its revalidation on each read; the
//! room-role Owner arm, which let it delegate roles in rooms it never
//! created; and the disclosure VaultOwner party, which adds no term to a
//! room's meet. Each now reads the same census once the vault holds a
//! shared-vault creation.
//!
//! Every vault here is unrooted (no host root), as in
//! `tests/admin_is_not_steward.rs`, whose shared-vault steps these follow.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test unrooted_shared_owner_census`.

use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation::{ConversationBody, ConversationKind, RoomRole};
use oneiron::disclosure::RoomParty;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::inbox::compilation_target::CompilationTarget;
use oneiron::memory::ClaimInput;
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD};
use oneiron::store::GateDecisionId;
use oneiron::write_envelope::claim_body::encode_claim_body;
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, PREDICATE_WORLD_ACCESS_ALLOWED_SET,
    ResolvedWorldAuthority, TimeRange, Vault, VaultConfig, WorldAuthoritySet, WriteActor,
    world_access_claim_body,
};
use serde_json::{Value, json};

const SHARED: u64 = 42;

/// The event time the inbox approvals are stamped with.
const APPROVED_AT: u64 = 1_780_000_010;

/// How the inbox refuses an approval by someone who is no owner.
const NOT_THE_OWNER: &str = "an owner write requires the vault's owner";

/// How the owner-verb rule refuses an embedded owner the census does not name.
const NOT_A_LIVE_OWNER: &str = "is not a live Owner of this shared vault";

fn at() -> TimeRange {
    TimeRange { start: 1, end: 1 }
}

fn person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, at(), 1, b"human")
        .expect("a live person");
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// The role `member` holds in the shared vault now, read from its grant rows.
fn role_of(vault: &Vault, member: EntityId) -> Option<Role> {
    vault
        .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
        .expect("grants")
        .into_iter()
        .find_map(|id| {
            let body = vault.get(&id).expect("grant row")?;
            let grant = oneiron::federation::decode_federation_grant_body(&body).ok()?;
            (grant.member_ref == member && grant.role != Role::Delegate).then_some(grant.role)
        })
}

/// What an actor no grant governs reads: base reality, in every tier.
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

/// An unrooted vault with its embedded owner, an agent and one WORLD.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    world: EntityId,
    facet: EntityId,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::default()).expect("open vault");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let agent = vault
            .ensure_agent_principal("unrooted-census-agent")
            .expect("agent");
        let world = EntityId::now();
        vault
            .put_entity(&world, ENTITY_TYPE_WORLD, at(), 1, b"world")
            .expect("a WORLD");
        let facet = vault.default_facet().expect("default facet");
        Self {
            vault,
            owner,
            agent,
            world,
            facet,
            _directory: directory,
        }
    }

    /// Shares the vault with a second Owner, who accepts its founding
    /// invitation, and returns it.
    fn share_with_co_owner(&self) -> EntityId {
        let co_owner = EntityId::now();
        person(&self.vault, co_owner);
        self.vault
            .initialize_shared_vault(
                &proof(&self.vault, self.owner),
                SHARED,
                None,
                &[
                    InitialSharedMember {
                        member_ref: self.owner,
                        role: Some(Role::Owner),
                    },
                    InitialSharedMember {
                        member_ref: co_owner,
                        role: Some(Role::Owner),
                    },
                ],
                1,
            )
            .expect("a shared vault with two owners");
        let co_owner_proof = proof(&self.vault, co_owner);
        let invitation = self
            .vault
            .shared_invitations(&co_owner_proof, SHARED)
            .expect("the co-owner's invitations")
            .into_iter()
            .find(|open| open.role == Role::Owner)
            .expect("the co-owner's founding invitation");
        self.vault
            .accept_shared_invitation(&co_owner_proof, SHARED, &invitation.id)
            .expect("the co-owner accepts");
        assert_eq!(role_of(&self.vault, co_owner), Some(Role::Owner));
        assert_eq!(role_of(&self.vault, self.owner), Some(Role::Owner));
        co_owner
    }

    /// The co-owner makes the embedded owner an Admin through
    /// `remove_owner`, which runs at once under its zero wait.
    fn co_owner_demotes_the_embedded_owner(&self, co_owner: EntityId) {
        let co_owner_proof = proof(&self.vault, co_owner);
        let act = self
            .vault
            .propose_remove_owner(
                &co_owner_proof,
                SHARED,
                self.owner,
                None,
                Some(Role::Admin),
                false,
            )
            .expect("the co-owner starts remove_owner, the embedded owner keeping Admin");
        self.vault
            .execute_completed_shared_act(&co_owner_proof, &act.id, None)
            .expect("remove_owner runs");
        assert_eq!(
            role_of(&self.vault, self.owner),
            Some(Role::Admin),
            "the embedded owner is an Admin now"
        );
        assert_eq!(role_of(&self.vault, co_owner), Some(Role::Owner));
    }

    /// A claim input about `subject` under `predicate`, in the default facet.
    fn input(&self, predicate: &str, subject: EntityId, value: Value, source: &str) -> ClaimInput {
        ClaimInput {
            id: Some(EntityId::now().to_hex()),
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

    /// `writer` proposes a user-stated grant about the agent through the
    /// claim door; it waits in the inbox. Returns its id.
    fn propose_a_grant(&self, writer: EntityId) -> EntityId {
        let input = self.input(
            PREDICATE_WORLD_ACCESS_ALLOWED_SET,
            self.agent,
            json!({ "schema_version": 1, "include_base": true, "worlds": [] }),
            "user_stated",
        );
        let claim = EntityId::from_hex(input.id.as_deref().unwrap()).unwrap();
        let receipt = self
            .vault
            .memory(writer, EdgeActorClass::Human)
            .claim_propose(&input)
            .expect("the writer proposes a grant about the agent");
        assert_eq!(receipt.approval, "proposed", "the grant waits for consent");
        assert!(self.pending(claim), "the grant waits in the inbox");
        claim
    }

    /// Whether `claim` still waits in the inbox.
    fn pending(&self, claim: EntityId) -> bool {
        self.vault
            .pending_gate_consents(1_000)
            .expect("read the inbox")
            .iter()
            .any(|row| row.claim_id == *claim.as_bytes())
    }

    /// The set the inbox edit grants the agent: the WORLD, without base
    /// reality.
    fn granted(&self) -> WorldAuthoritySet {
        WorldAuthoritySet::new(false, [self.world]).unwrap()
    }

    /// `approver` approves the pending grant in the inbox, with the edit
    /// that names the WORLD as the fold reads it
    /// (`Vault::approve_inbox_member_with_edit_as_at`).
    fn approve(&self, approver: EntityId, claim: EntityId) -> oneiron::Result<()> {
        let readable = world_access_claim_body(
            PREDICATE_WORLD_ACCESS_ALLOWED_SET,
            self.agent,
            &self.granted(),
            ClaimSource::UserStated,
            ClaimApprovalStatus::Approved,
            None,
            None,
        )
        .unwrap()
        .value;
        let mut edited = self
            .vault
            .get_claim(&claim)
            .expect("read the proposal")
            .expect("the proposal");
        edited.value = readable;
        let edited = encode_claim_body(&edited).expect("encode the edit");
        self.vault
            .approve_inbox_member_with_edit_as_at(
                WriteActor::new(approver, EdgeActorClass::Human),
                &claim,
                &edited,
                &CompilationTarget::Fallback,
                APPROVED_AT,
            )
            .map(|_| ())
    }

    /// The tiers the agent's reads resolve with no selection.
    fn agent_reads(&self) -> ResolvedWorldAuthority {
        self.vault
            .board_world_authority(Some(self.agent), None)
            .expect("the agent's reads resolve")
    }

    /// An ordinary room `creator` opens with the embedded owner and a new
    /// PERSON as its members. Returns the room and that PERSON.
    fn room_created_by(&self, creator: EntityId) -> (EntityId, EntityId) {
        let member = EntityId::now();
        person(&self.vault, member);
        let room = EntityId::now();
        self.vault
            .create_conversation(
                room,
                &ConversationBody {
                    kind: ConversationKind::Group,
                    member_ids: vec![self.owner, member],
                    ..Default::default()
                },
                WriteActor::new(creator, EdgeActorClass::Human),
                self.vault.now_recorded_at(),
            )
            .expect("another person opens a room with the embedded owner in it");
        (room, member)
    }

    /// The embedded owner makes `member` an Admin of `room`.
    fn owner_sets_admin(&self, room: EntityId, member: EntityId) -> oneiron::Result<()> {
        self.vault.set_room_role(
            room,
            member,
            RoomRole::Admin,
            WriteActor::new(self.owner, EdgeActorClass::Human),
        )
    }

    /// How a room's meet classes the embedded owner.
    fn owner_party(&self) -> RoomParty {
        let parties = self
            .vault
            .room_parties(&[self.owner])
            .expect("the room parties read");
        let entries = self
            .vault
            .room_party_entries(&[self.owner])
            .expect("the room party entries read");
        assert_eq!(
            parties[0], entries[0].party,
            "both readers class the embedded owner alike"
        );
        parties[0]
    }
}

/// The finding: the co-owner makes the embedded owner an Admin while a grant
/// waits in the inbox, and the former owner approves it there. Before this
/// change the approval landed and the grant governed the agent. The rule now
/// reads the census, so the approval is refused and the grant still waits.
#[test]
fn an_owner_the_co_owner_made_an_admin_approves_no_grant() {
    let f = Fixture::new();
    let co_owner = f.share_with_co_owner();
    let claim = f.propose_a_grant(co_owner);
    f.co_owner_demotes_the_embedded_owner(co_owner);

    let approved = f.approve(f.owner, claim);

    assert_eq!(
        f.agent_reads(),
        ungoverned(),
        "a grant a former owner approves governs nobody (approval: {approved:?})"
    );
    let refused = approved.expect_err("the inbox refuses a former owner's approval");
    assert!(
        refused.to_string().contains(NOT_THE_OWNER),
        "the refusal names the rule: {refused:?}"
    );
    assert!(f.pending(claim), "the grant still waits in the inbox");
    let owner_verb = f
        .vault
        .memory(f.owner, EdgeActorClass::Human)
        .verify_owner()
        .expect_err("the owner-verb rule refuses the former owner");
    assert!(
        owner_verb.message.contains(NOT_A_LIVE_OWNER),
        "the refusal names the census: {owner_verb:?}"
    );
}

/// A second owner verb: the former owner retracts a claim the co-owner
/// wrote. Before this change the retraction landed as the owner's; it is now
/// refused, as every owner verb is.
#[test]
fn an_owner_the_co_owner_made_an_admin_retracts_no_one_elses_claim() {
    let f = Fixture::new();
    let co_owner = f.share_with_co_owner();
    let input = f.input("profile.note", f.agent, json!("a note"), "user_stated");
    let claim = input.id.clone().unwrap();
    f.vault
        .memory(co_owner, EdgeActorClass::Human)
        .claim_propose(&input)
        .expect("the co-owner writes a claim");
    f.co_owner_demotes_the_embedded_owner(co_owner);

    let retracted = f
        .vault
        .memory(f.owner, EdgeActorClass::Human)
        .claim_retract(&claim);

    let refused = retracted.expect_err("a former owner retracts no claim another member wrote");
    assert!(
        refused.message.contains(NOT_A_LIVE_OWNER),
        "the refusal names the census: {refused:?}"
    );
}

/// Control: on the same shared vault, the embedded owner who is still an
/// Owner approves the grant in the inbox, and it governs the agent.
#[test]
fn an_owner_still_an_owner_approves_the_grant() {
    let f = Fixture::new();
    let co_owner = f.share_with_co_owner();
    let claim = f.propose_a_grant(co_owner);

    f.approve(f.owner, claim)
        .expect("a live Owner's approval lands");

    let reads = f.agent_reads();
    assert_eq!(reads.allowed_set, f.granted(), "the approved grant governs");
    assert_eq!(reads.allowed_claim_ids, vec![claim]);
    assert!(!f.pending(claim), "the approval closes the inbox row");
    f.vault
        .memory(f.owner, EdgeActorClass::Human)
        .verify_owner()
        .expect("a live Owner passes the owner-verb rule");
}

/// Control: a personal unrooted vault keeps today's pass for its live
/// embedded owner, and still refuses another person.
#[test]
fn a_personal_vaults_owner_passes_as_before() {
    let f = Fixture::new();
    let other = EntityId::now();
    person(&f.vault, other);

    f.vault
        .memory(f.owner, EdgeActorClass::Human)
        .verify_owner()
        .expect("the embedded owner of a personal vault passes");
    let refused = f
        .vault
        .memory(other, EdgeActorClass::Human)
        .verify_owner()
        .expect_err("another person is no owner");
    assert!(
        refused.message.contains("this vault has no authority root"),
        "an unrooted vault names its missing root: {refused:?}"
    );
}

/// Door (a), the owner key's mint: the former owner's read lane is no
/// longer the vault owner's, so the write standing every door reads from
/// `is_vault_owner` (about 45 sites) and its read key are a member's.
#[test]
fn an_owner_the_co_owner_made_an_admin_holds_no_owner_key() {
    let f = Fixture::new();
    let co_owner = f.share_with_co_owner();
    f.co_owner_demotes_the_embedded_owner(co_owner);

    let memory = f.vault.memory(f.owner, EdgeActorClass::Human);

    assert!(
        !memory.is_vault_owner().expect("the owner check reads"),
        "a former owner's read lane is no vault owner's"
    );
    let key = memory.read_key().expect("the former owner's read key");
    assert!(
        !key.reads_as_vault_owner(),
        "a former owner's read key is no owner key"
    );
}

/// Door (a), the owner key's revalidation: an owner key minted while the
/// embedded owner was an Owner reads nothing once the co-owner made it an
/// Admin, as a key kept past its owner's revocation does.
#[test]
fn an_owner_key_kept_past_the_demotion_reads_nothing() {
    let f = Fixture::new();
    let co_owner = f.share_with_co_owner();
    let key = f
        .vault
        .memory(f.owner, EdgeActorClass::Human)
        .read_key()
        .expect("the owner's read key");
    assert!(
        key.reads_as_vault_owner(),
        "a live Owner reads with the owner key"
    );
    f.co_owner_demotes_the_embedded_owner(co_owner);

    let read = f.vault.scoped_read(key).is_entity_readable(&f.world);

    let refused = read.expect_err("an owner key kept past its holder's demotion reads nothing");
    assert!(
        format!("{refused:?}").contains(NOT_A_LIVE_OWNER),
        "the refusal names the census: {refused:?}"
    );
}

/// Door (b), the room-role Owner arm: in a room the co-owner opened, the
/// former owner is a plain member, so it delegates no role there.
#[test]
fn an_owner_the_co_owner_made_an_admin_sets_no_room_role() {
    let f = Fixture::new();
    let co_owner = f.share_with_co_owner();
    let (room, member) = f.room_created_by(co_owner);
    f.co_owner_demotes_the_embedded_owner(co_owner);

    let set = f.owner_sets_admin(room, member);

    let refused = set.expect_err("a former owner delegates no role in the co-owner's room");
    assert!(
        format!("{refused:?}").contains("ConversationDenied"),
        "the room door refuses it: {refused:?}"
    );
}

/// Door (c), the disclosure VaultOwner party: a room's meet classes the
/// former owner as any other member, never as the vault owner who adds no
/// term; the co-owner still classes VaultOwner.
#[test]
fn an_owner_the_co_owner_made_an_admin_is_no_owner_party() {
    let f = Fixture::new();
    let co_owner = f.share_with_co_owner();
    f.co_owner_demotes_the_embedded_owner(co_owner);

    assert_ne!(
        f.owner_party(),
        RoomParty::VaultOwner,
        "a former owner is no vault owner in a room's meet"
    );
    let co_owner_party = f
        .vault
        .room_parties(&[co_owner])
        .expect("the room parties read");
    assert_eq!(co_owner_party, vec![RoomParty::VaultOwner]);
}

/// Control: on the same shared vault, the embedded owner who is still an
/// Owner keeps all three: the owner key, which still reads, the room-role
/// Owner arm in the co-owner's room, and the VaultOwner party.
#[test]
fn an_owner_still_an_owner_keeps_its_shortcuts() {
    let f = Fixture::new();
    let co_owner = f.share_with_co_owner();
    let (room, member) = f.room_created_by(co_owner);

    let memory = f.vault.memory(f.owner, EdgeActorClass::Human);
    assert!(memory.is_vault_owner().expect("the owner check reads"));
    let key = memory.read_key().expect("the owner's read key");
    assert!(
        key.reads_as_vault_owner(),
        "a live Owner reads with the owner key"
    );
    f.vault
        .scoped_read(key)
        .is_entity_readable(&f.world)
        .expect("a live Owner's key still reads");
    f.owner_sets_admin(room, member)
        .expect("a live Owner delegates a role in the co-owner's room");
    assert_eq!(f.owner_party(), RoomParty::VaultOwner);
}

/// Control: a personal unrooted vault's embedded owner keeps all three as
/// before, the room-role arm in a room another person opened included.
#[test]
fn a_personal_vaults_owner_keeps_its_shortcuts() {
    let f = Fixture::new();
    let other = EntityId::now();
    person(&f.vault, other);
    let (room, member) = f.room_created_by(other);

    let memory = f.vault.memory(f.owner, EdgeActorClass::Human);
    assert!(memory.is_vault_owner().expect("the owner check reads"));
    let key = memory.read_key().expect("the owner's read key");
    assert!(
        key.reads_as_vault_owner(),
        "the embedded owner reads with the owner key"
    );
    f.vault
        .scoped_read(key)
        .is_entity_readable(&f.world)
        .expect("the embedded owner's key reads");
    f.owner_sets_admin(room, member)
        .expect("the embedded owner delegates a role in another person's room");
    assert_eq!(f.owner_party(), RoomParty::VaultOwner);
}
