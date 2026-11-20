//! [EMBEDDED-OWNER-EXEMPTION-IGNORES-SHARED-OWNER-CENSUS]: the owner's
//! relationship exemption (`owner_exemption_holds_in_txn`, the one predicate
//! behind `exempt_while_owner` that the read lane and every door share) held
//! for the embedded owner on the owner check's embedded-owner shortcut. On a
//! rooted shared vault that shortcut held for every embedded owner, so one
//! whom the co-Owner made an Admin still read a relationship's rows as the
//! owner does: through its native key and through its saved question's
//! basis-less lane, whose asker and source readers each prove the exemption
//! at every read. The shortcut now holds on any vault with a shared-vault
//! creation only while the live owner census names the embedded owner
//! (#8133 for an unrooted vault, #9250 for a rooted one), and the exemption
//! goes with it.
//!
//! Every vault here is rooted, as in `tests/rooted_embedded_owner_shortcuts.rs`,
//! whose sharing steps these follow; the saved question's readers are those
//! of `tests/saved_source_owner_exemption.rs`. The embedded owner witnesses a
//! MESSAGE in a relationship no PERSON is a member of and no grant names.
//! While it is an Owner of the shared vault, its native key and its saved
//! question's asker and source readers read that MESSAGE; once the co-Owner
//! makes it an Admin, none of them does. Its unscoped rows stay judged on
//! the Admin's own grants, as its native key reads them; no case here pins
//! them. A narrower credential of its own needs no case: the demotion
//! revokes every slip it holds (a move down in rank, `move_revokes_slips`).
//!
//! Before #9250 (main 7340b846927) the shortcut held on any rooted vault, so
//! the two demoted cases read the MESSAGE there.
//! Guard: `an_owner_still_an_owner_of_the_shared_vault_keeps_the_exemption`.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test demoted_owner_relationship_exemption`.

#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::claim::{FrozenReadLane, ScopedRead};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::question_saved_lane::{
    question_read, saved_question_reader, saved_source_reader,
};
use oneiron::test_support::bind_host_owner;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

const SHARED: u64 = 47;

fn at() -> TimeRange {
    TimeRange { start: 1, end: 1 }
}

fn person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, at(), 1, b"human")
        .expect("a live person");
    id
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

/// Whether `lane` point-reads `row`; the text names the answer.
fn reads(lane: &ScopedRead<'_>, row: EntityId) -> (bool, String) {
    let read = lane
        .get_entity_parts_with_receipt(&row, None)
        .map(|read| read.value.is_some());
    (matches!(read, Ok(true)), format!("point={read:?}"))
}

/// A rooted vault whose embedded owner the host root binds and which
/// witnessed one MESSAGE in a relationship no PERSON is a member of and no
/// grant names; shared with a second Owner, the co-Owner, the embedded owner
/// being its first Owner.
struct Shared {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    co_owner: EntityId,
    relationship_message: EntityId,
    // Dropped after the vault.
    _dir: tempfile::TempDir,
}

impl Shared {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        // Every owner act is carried by this install's live machine profile.
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
        let relationship_message = witness_relationship_message(&vault, owner);
        let co_owner = share_with_co_owner(&vault, &issuer, owner);
        Self {
            vault,
            issuer,
            owner,
            co_owner,
            relationship_message,
            _dir: dir,
        }
    }

    /// The co-Owner makes the embedded owner an Admin through
    /// `remove_owner`, which runs at once; the host root signs it, as in
    /// `tests/rooted_embedded_owner_shortcuts.rs`.
    fn co_owner_demotes_the_owner(&self) {
        let co_owner_proof = proof(&self.vault, self.co_owner);
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
            .expect("the co-Owner starts remove_owner, the embedded owner keeping Admin");
        self.vault
            .execute_completed_shared_act(&co_owner_proof, &act.id, Some(&self.issuer))
            .expect("remove_owner runs");
        assert_eq!(
            role_of(&self.vault, self.owner),
            Some(Role::Admin),
            "the embedded owner is an Admin now"
        );
        assert_eq!(role_of(&self.vault, self.co_owner), Some(Role::Owner));
    }

    /// What the embedded owner's native key reads of the relationship
    /// MESSAGE: the key every read verb on its unbound handle reads under.
    fn native_key_reads(&self) -> (bool, String) {
        match self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .read_key()
        {
            Ok(key) => reads(&self.vault.scoped_read(key), self.relationship_message),
            Err(error) => (false, format!("key={error:?}")),
        }
    }

    /// What the embedded owner's saved question, saved on its own basis-less
    /// lane, reads of the relationship MESSAGE through its asker reader.
    fn saved_question_asker_reads(&self) -> (bool, String) {
        match saved_question_reader(&self.vault, self.owner, &FrozenReadLane::principal()) {
            Ok(key) => reads(&question_read(&self.vault, key), self.relationship_message),
            Err(error) => (false, format!("rebuild={error:?}")),
        }
    }

    /// What the same saved question source-reads of the relationship
    /// MESSAGE (its refresh, artifact and wake reads).
    fn saved_question_source_reads(&self) -> (bool, String) {
        match saved_source_reader(&self.vault, self.owner, &FrozenReadLane::principal()) {
            Ok(key) => reads(&question_read(&self.vault, key), self.relationship_message),
            Err(error) => (false, format!("rebuild={error:?}")),
        }
    }

    /// What the saved question's two readers read of the relationship
    /// MESSAGE, each named.
    fn saved_question_reads(&self) -> [(&'static str, (bool, String)); 2] {
        [
            ("asker reader", self.saved_question_asker_reads()),
            ("source reader", self.saved_question_source_reads()),
        ]
    }
}

/// `author`'s turn of one MESSAGE, witnessed as the human it is, in a
/// relationship no PERSON is a member of and no grant names.
fn witness_relationship_message(vault: &Vault, author: EntityId) -> EntityId {
    let relationship_message = EntityId::now();
    vault
        .memory(author, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: None,
            thread_audience: None,
            project: None,
            occurred_at: 1,
            messages: vec![WitnessMessage {
                id: Some(relationship_message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".to_owned(),
                content: "The allotment committee meets on Thursday.".to_owned(),
                parts: None,
                metadata: Some(json!({ "rel": EntityId::now().to_hex() })),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            assertions: Default::default(),
        })
        .expect("the author's turn lands");
    relationship_message
}

/// Shares the vault with the embedded owner as its Owner, and adds a second
/// Owner, whom it returns; the add is instant.
fn share_with_co_owner(vault: &Vault, issuer: &HostSlipIssuer, owner: EntityId) -> EntityId {
    vault
        .initialize_shared_vault(
            &proof(vault, owner),
            SHARED,
            None,
            &[InitialSharedMember {
                member_ref: owner,
                role: Some(Role::Owner),
            }],
            1,
        )
        .expect("a shared vault");
    let co_owner = person(vault);
    let owner_proof = proof(vault, owner);
    let act = vault
        .propose_add_owner(&owner_proof, SHARED, co_owner)
        .expect("the owner starts add_owner");
    vault
        .execute_completed_shared_act(&owner_proof, &act.id, Some(issuer))
        .expect("add_owner runs at once");
    assert_eq!(role_of(vault, owner), Some(Role::Owner));
    assert_eq!(role_of(vault, co_owner), Some(Role::Owner));
    co_owner
}

/// Control: on the same shared vault, the embedded owner who is still an
/// Owner keeps the exemption on each lane.
#[test]
fn an_owner_still_an_owner_of_the_shared_vault_keeps_the_exemption() {
    let f = Shared::new();

    let (read, seen) = f.native_key_reads();
    assert!(
        read,
        "actor=the embedded owner, still an Owner; expected its native key to read the MESSAGE in a relationship it holds no grant in; seen {seen}"
    );
    for (lane, (read, seen)) in f.saved_question_reads() {
        assert!(
            read,
            "actor=the embedded owner, still an Owner; expected its basis-less saved question's {lane} to read the MESSAGE in a relationship it holds no grant in; seen {seen}"
        );
    }
}

/// The native key: once the co-Owner made the embedded owner an Admin, its
/// read key is a member's, which reads a relationship's rows only on a grant.
#[test]
fn a_demoted_owners_native_key_reads_no_relationship_message() {
    let f = Shared::new();
    let (read, seen) = f.native_key_reads();
    assert!(
        read,
        "precondition: an Owner's native key reads the relationship MESSAGE; seen {seen}"
    );
    f.co_owner_demotes_the_owner();

    let (read, seen) = f.native_key_reads();

    assert!(
        !read,
        "actor=the embedded owner a co-Owner made an Admin; expected its native key to read no MESSAGE in a relationship it holds no grant in; seen {seen}"
    );
}

/// The basis-less saved question, the row's own lane: its asker reader and
/// its source reader each prove the exemption at every read, so once the
/// embedded owner is an Admin neither reads the relationship MESSAGE.
#[test]
fn a_demoted_owners_saved_question_reads_no_relationship_message() {
    let f = Shared::new();
    for (lane, (read, seen)) in f.saved_question_reads() {
        assert!(
            read,
            "precondition: an Owner's basis-less saved question's {lane} reads the relationship MESSAGE; seen {seen}"
        );
    }
    f.co_owner_demotes_the_owner();

    for (lane, (read, seen)) in f.saved_question_reads() {
        assert!(
            !read,
            "actor=the embedded owner a co-Owner made an Admin; expected its basis-less saved question's {lane} to read no MESSAGE in a relationship it holds no grant in; seen {seen}"
        );
    }
}
