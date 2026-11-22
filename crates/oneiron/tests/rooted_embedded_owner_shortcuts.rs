//! [ROOTED-EMBEDDED-OWNER-SHORTCUTS-SKIP-CENSUS] (rooted twin of
//! [UNROOTED-EMBEDDED-OWNER-SHORTCUTS-SKIP-CENSUS], closed by #8133; intent:
//! UNROOTED-OWNER-CENSUS = A and CLAIM-RETRACT-ADMIN-SCOPE = A): the embedded
//! owner's shortcuts past the owner-binding check held on every ROOTED vault,
//! so on a rooted shared vault an embedded owner who was no longer an Owner
//! kept them. It handed ownership on and stayed as Admin, or a co-Owner made
//! it an Admin, and it still read as the vault owner: the read-lane owner key
//! and the write standing every door reads from it (`Memory::is_vault_owner`),
//! the same key's revalidation on each read, and the disclosure VaultOwner
//! party, which adds no term to a room's meet. Since #9218 the owner verbs
//! refuse that actor (binding and census), so the two rules disagreed. The
//! shortcuts now read the live owner census on any vault that holds a
//! shared-vault creation, rooted or not; a personal vault keeps them.
//!
//! The room-role Owner arm and the source-audience owner PERSON never took
//! the shortcut on a rooted vault (`conversation::roles` asks the owner
//! binding and census there, and `source_audience` names no owner PERSON),
//! so no case here covers them.
//!
//! Red on the base (#9218's head):
//! `an_owner_who_handed_ownership_on_holds_no_owner_key`,
//! `an_owner_the_co_owner_made_an_admin_holds_no_owner_key`,
//! `an_owner_key_kept_past_the_handover_reads_nothing` and
//! `an_owner_who_handed_ownership_on_is_no_owner_party`.
//! Guards (pass on the base too): `an_owner_still_an_owner_keeps_its_shortcuts`,
//! `a_live_owner_whose_binding_moved_keeps_its_own_device_lane` and
//! `a_rooted_personal_vaults_owner_keeps_its_shortcuts`.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test rooted_embedded_owner_shortcuts`.

#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::disclosure::RoomParty;
use oneiron::error::ClaimError;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

const SHARED: u64 = 46;

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

/// A rooted vault whose embedded owner the host root binds, and one WORLD
/// the owner key reads. [`Rooted::share`] makes it a shared vault.
struct Rooted {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    world: EntityId,
}

impl Rooted {
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
        let world = EntityId::now();
        vault
            .put_entity(&world, ENTITY_TYPE_WORLD, at(), 1, b"world")
            .expect("a WORLD");
        Self {
            _dir: dir,
            vault,
            issuer,
            owner,
            world,
        }
    }

    /// Shares the vault with the embedded owner as its Owner, and adds a
    /// second Owner, whom it returns; the add is instant.
    fn share(&self) -> EntityId {
        self.vault
            .initialize_shared_vault(
                &proof(&self.vault, self.owner),
                SHARED,
                None,
                &[InitialSharedMember {
                    member_ref: self.owner,
                    role: Some(Role::Owner),
                }],
                1,
            )
            .expect("a shared vault");
        let co_owner = person(&self.vault);
        let owner_proof = proof(&self.vault, self.owner);
        let act = self
            .vault
            .propose_add_owner(&owner_proof, SHARED, co_owner)
            .expect("the owner starts add_owner");
        self.vault
            .execute_completed_shared_act(&owner_proof, &act.id, Some(&self.issuer))
            .expect("add_owner runs at once");
        assert_eq!(role_of(&self.vault, self.owner), Some(Role::Owner));
        assert_eq!(role_of(&self.vault, co_owner), Some(Role::Owner));
        co_owner
    }

    /// The embedded owner hands ownership to a new Owner and stays as
    /// Admin. The host root signs the handover, so it revokes the host
    /// root's binding of the embedded owner; the root key stays.
    fn owner_hands_ownership_on(&self) {
        let successor = person(&self.vault);
        let owner_proof = proof(&self.vault, self.owner);
        let act = self
            .vault
            .propose_transfer_ownership(&owner_proof, SHARED, successor, Some(Role::Admin))
            .expect("the owner starts transfer_ownership");
        self.vault
            .execute_completed_shared_act(&owner_proof, &act.id, Some(&self.issuer))
            .expect("the transfer runs at once");
        assert_eq!(
            role_of(&self.vault, self.owner),
            Some(Role::Admin),
            "the embedded owner is an Admin now"
        );
    }

    /// The co-Owner makes the embedded owner an Admin through
    /// `remove_owner`, which runs at once; the host root signs it, as in
    /// [`Self::owner_hands_ownership_on`].
    fn co_owner_demotes_the_owner(&self, co_owner: EntityId) {
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
            .expect("the co-Owner starts remove_owner, the embedded owner keeping Admin");
        self.vault
            .execute_completed_shared_act(&co_owner_proof, &act.id, Some(&self.issuer))
            .expect("remove_owner runs");
        assert_eq!(
            role_of(&self.vault, self.owner),
            Some(Role::Admin),
            "the embedded owner is an Admin now"
        );
        assert_eq!(role_of(&self.vault, co_owner), Some(Role::Owner));
    }

    /// How a room's meet classes the embedded owner; both readers agree.
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

    /// Asserts the embedded owner's read lane is the vault owner's: the
    /// owner check, an owner read key, and that key reading the WORLD.
    fn assert_owner_lane(&self, why: &str) {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        assert!(
            memory.is_vault_owner().expect("the owner check reads"),
            "{why}"
        );
        let key = memory.read_key().expect("the owner's read key");
        assert!(key.reads_as_vault_owner(), "{why}: an owner read key");
        assert!(
            self.vault
                .scoped_read(key)
                .is_entity_readable(&self.world)
                .expect("the owner key reads"),
            "{why}: the owner key reads the WORLD"
        );
    }

    /// Asserts the embedded owner's read lane is no vault owner's: neither
    /// the owner check nor its read key.
    fn assert_no_owner_lane(&self, why: &str) {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        assert!(
            !memory.is_vault_owner().expect("the owner check reads"),
            "{why}: no vault owner"
        );
        let key = memory.read_key().expect("the former owner's read key");
        assert!(!key.reads_as_vault_owner(), "{why}: no owner read key");
    }
}

/// Door (a), the owner key's mint: the embedded owner handed ownership on
/// and is an Admin, so its read lane, and the write standing about 45 doors
/// read from `is_vault_owner`, is a member's. Before the fix a rooted vault
/// gave it the owner's.
#[test]
fn an_owner_who_handed_ownership_on_holds_no_owner_key() {
    let f = Rooted::new();
    f.share();
    f.owner_hands_ownership_on();

    f.assert_no_owner_lane("an embedded owner who handed ownership on");
}

/// Door (a) again, the row's own case: a co-Owner made the embedded owner an
/// Admin.
#[test]
fn an_owner_the_co_owner_made_an_admin_holds_no_owner_key() {
    let f = Rooted::new();
    let co_owner = f.share();
    f.co_owner_demotes_the_owner(co_owner);

    f.assert_no_owner_lane("an embedded owner a co-Owner made an Admin");
}

/// Door (a), the owner key's revalidation: an owner key minted while the
/// embedded owner was an Owner reads nothing once it handed ownership on,
/// as a key kept past its owner's revocation does.
#[test]
fn an_owner_key_kept_past_the_handover_reads_nothing() {
    let f = Rooted::new();
    f.share();
    let key = f
        .vault
        .memory(f.owner, EdgeActorClass::Human)
        .read_key()
        .expect("the owner's read key");
    assert!(
        key.reads_as_vault_owner(),
        "a live Owner reads with the owner key"
    );
    f.owner_hands_ownership_on();

    let read = f.vault.scoped_read(key).is_entity_readable(&f.world);

    let refused = read.expect_err("an owner key kept past its holder's handover reads nothing");
    assert!(
        matches!(
            refused,
            oneiron::Error::Claim(ClaimError::ScopedReadOwnerNotLive(_))
        ),
        "the key's owner is no longer live: {refused:?}"
    );
}

/// Door (c), the disclosure VaultOwner party: a room's meet classes the
/// embedded owner who handed ownership on as any other member, never as the
/// vault owner who adds no term.
#[test]
fn an_owner_who_handed_ownership_on_is_no_owner_party() {
    let f = Rooted::new();
    f.share();
    f.owner_hands_ownership_on();

    assert_ne!(
        f.owner_party(),
        RoomParty::VaultOwner,
        "a former owner is no vault owner in a room's meet"
    );
}

/// Guard: on the same rooted shared vault, the embedded owner who is still
/// an Owner keeps all of them: the owner check, the owner key, which still
/// reads, and the VaultOwner party.
#[test]
fn an_owner_still_an_owner_keeps_its_shortcuts() {
    let f = Rooted::new();
    f.share();

    f.assert_owner_lane("a live Owner");
    assert_eq!(f.owner_party(), RoomParty::VaultOwner);
}

/// Guard: the shortcut asks the census, not the binding. The embedded owner
/// is still an Owner while the host key is bound to another person, so its
/// own-device read lane stays the owner's: a separately bound root does not
/// make it a peer.
#[test]
fn a_live_owner_whose_binding_moved_keeps_its_own_device_lane() {
    let f = Rooted::new();
    f.share();
    let other = person(&f.vault);
    bind_host_actor(&f.vault, &f.issuer, other, "human")
        .expect("the host key bound to another person, which ends the owner's binding");

    f.assert_owner_lane("a live Owner with no binding of its own");
    assert_eq!(f.owner_party(), RoomParty::VaultOwner);
}

/// Guard: a rooted personal vault's embedded owner keeps them as before.
#[test]
fn a_rooted_personal_vaults_owner_keeps_its_shortcuts() {
    let f = Rooted::new();

    f.assert_owner_lane("a personal vault's embedded owner");
    assert_eq!(f.owner_party(), RoomParty::VaultOwner);
}
