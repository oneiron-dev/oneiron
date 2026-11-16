//! L7-31 (ARCH-0040 #stale-stamp-open): the raw root moves sweep the
//! federation stale stamps after their commit, as every other authority
//! commit does (H213). A Connect pact between two hosted vaults goes
//! terminal; a foreign world is then registered to it in a write that sweeps
//! nothing, so the world owes a stamp. Each move stores that stamp before it
//! returns:
//! - `Vault::re_root_host`, the host root's own move;
//! - `Vault::re_root_authority`, the move `recover_cloud_account` makes;
//! - `Vault::apply_signed_re_root`, a move signed on another vault that
//!   holds the same authority (`recover_vaults_independently`).
//!
//! An owner that commits an authority row in a raw write transaction with no
//! watch (`Vault::mint_capability_slip`, one of the 51 the L7-31 read map
//! found) leaves the stamp to the next watched commit on its thread, of any
//! kind (Engine RULING NEXT-ROW-9 = A, Fri 13 Nov 19:43 JST).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test re_root_stale_sweep`.

use std::sync::Arc;

use oneiron::authority::{
    AuthorityVaultId, FederationPactStatus, HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::entity_id::ForeignWorldId;
use oneiron::federation::{FederationStaleReason, foreign_world_stale_stamp};
use oneiron::inquiry::InquiryEdgeRequest;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::re_root_stale_sweep::{
    re_root_authority_as_host, register_foreign_world_for_pact,
};
use oneiron::{EntityId, Vault, VaultConfig};

/// The company's name, as the member's inquiry edge reads it.
const COMPANY: &str = "Acme";
/// The member's name, as the company's reciprocal grant reads it.
const MEMBER: &str = "owen";
/// The seed of the key each move gives the root.
const NEXT_ROOT_SEED: u8 = 0x33;
/// The foreign world the severed pact delivered (foreign id range).
const WORLD_SEED: u8 = 0xF6;
/// A second world the pact delivered, registered by the watched commit.
const OTHER_WORLD_SEED: u8 = 0xF7;

/// One rooted vault with its owner bound to its own host.
struct Side {
    vault: Vault,
    proof: AuthenticatedOwner,
    issuer: HostSlipIssuer,
    vault_id: AuthorityVaultId,
    _dir: tempfile::TempDir,
}

/// A vault rooted under a host of its own (`seed`), its engine machines and
/// install profile provisioned and its owner bound, as a host does.
fn side(seed: u8) -> Side {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = HostSlipIssuer::from_seed(&[seed; HOST_ISSUER_SEED_BYTES]).expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("owner bound");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let vault_id = vault
        .authority_fold()
        .expect("authority fold")
        .vault_id
        .expect("a rooted vault has an id");
    Side {
        vault,
        proof,
        issuer,
        vault_id,
        _dir: dir,
    }
}

/// The member and the company make a Connect pact Active, as
/// `tests/inquiry_edge.rs` does, and the member then disconnects it. Returns
/// the pact's id, the same on both logs.
fn severed_pact(member: &Side, company: &Side) -> [u8; 32] {
    let edge = member
        .vault
        .mint_inquiry_edge(
            &member.proof,
            &InquiryEdgeRequest::member_defaults(company.vault_id, COMPANY),
        )
        .expect("the member mints the inquiry edge");
    let reciprocal = company
        .vault
        .mint_inquiry_edge_reciprocal_grant(&company.proof, member.vault_id, MEMBER)
        .expect("the company Owner mints the reciprocal grant");
    let offer = member
        .vault
        .propose_connect_as(
            &member.proof,
            &member.issuer,
            edge.grant,
            company.vault_id,
            edge.pact_direction().expect("the edge's direction"),
            reciprocal
                .pact_direction()
                .expect("the reciprocal grant's direction"),
        )
        .expect("the member offers the Connect");
    let (_, counter) = company
        .vault
        .accept_connect_as(&company.proof, &company.issuer, reciprocal.grant, &offer)
        .expect("the company Owner accepts");
    let (pact, _) = member
        .vault
        .accept_connect_as(&member.proof, &member.issuer, edge.grant, &counter)
        .expect("the member accepts the company's half");
    assert_eq!(pact.status, FederationPactStatus::Active);
    let severed = member
        .vault
        .disconnect_connect_as(&member.proof, &member.issuer, offer.pact_id)
        .expect("the member disconnects");
    assert_eq!(severed.status, FederationPactStatus::Disconnected);
    offer.pact_id
}

/// Registers the world to the dead pact in `vault`, in a write that sweeps
/// nothing, so the world owes a stamp no row has stored yet.
fn owe_a_stamp(vault: &Vault, pact_id: [u8; 32]) -> EntityId {
    let world = ForeignWorldId::from_entity_id(
        EntityId::from_bytes([WORLD_SEED; 16]).expect("valid world id"),
    )
    .expect("the seed sits in the foreign world id range");
    register_foreign_world_for_pact(vault, &pact_id, world).expect("the world registers");
    assert!(
        foreign_world_stale_stamp(vault, world.entity_id())
            .expect("stamp read")
            .is_none(),
        "control: the registration sweeps nothing, so no stamp is stored yet"
    );
    world.entity_id()
}

/// The stamp the move's own commit must have stored.
fn assert_stamped(vault: &Vault, world: EntityId, door: &str) {
    let stamp = foreign_world_stale_stamp(vault, world)
        .expect("stamp read")
        .unwrap_or_else(|| panic!("{door} returned with the severed pact's world still unstamped"));
    assert_eq!(stamp.reason, FederationStaleReason::Disconnected);
}

fn next_root() -> HostSlipIssuer {
    HostSlipIssuer::from_seed(&[NEXT_ROOT_SEED; HOST_ISSUER_SEED_BYTES]).expect("next host root")
}

#[test]
fn a_host_re_root_stores_the_stale_stamp_it_owes_before_it_returns() {
    let member = side(0x11);
    let company = side(0x22);
    let pact_id = severed_pact(&member, &company);
    let world = owe_a_stamp(&member.vault, pact_id);

    member
        .vault
        .re_root_host(&member.issuer, &next_root())
        .expect("the host root moves");
    assert_stamped(&member.vault, world, "re_root_host");
}

#[test]
fn a_raw_root_move_stores_the_stale_stamp_it_owes_before_it_returns() {
    let member = side(0x11);
    let company = side(0x22);
    let pact_id = severed_pact(&member, &company);
    let world = owe_a_stamp(&member.vault, pact_id);

    re_root_authority_as_host(&member.vault, &member.issuer, &next_root()).expect("the root moves");
    assert_stamped(&member.vault, world, "re_root_authority");
}

#[test]
fn a_root_move_signed_elsewhere_stores_the_stale_stamp_it_owes_before_it_returns() {
    let member = side(0x11);
    let company = side(0x22);
    let pact_id = severed_pact(&member, &company);
    // A second vault holding the member's authority, as a recovery target
    // does: the import sweeps, but no world is registered there yet.
    let receiver_dir = tempfile::tempdir().expect("receiver directory");
    let receiver = Vault::open_owned(receiver_dir.path(), VaultConfig::default())
        .expect("fresh receiver vault");
    receiver
        .import_signed_authority_history(
            &member
                .vault
                .export_signed_authority_history()
                .expect("the member's history"),
        )
        .expect("the receiver holds the member's authority");
    let world = owe_a_stamp(&receiver, pact_id);

    let moved = re_root_authority_as_host(&member.vault, &member.issuer, &next_root())
        .expect("the member's root signs the move");
    receiver
        .apply_signed_re_root(&moved)
        .expect("the move signed on the member applies on the receiver");
    assert_stamped(&receiver, world, "apply_signed_re_root");
}

/// The host mints the owner a person credential: `mint_capability_slip`
/// stages an authority row in a raw write transaction and commits it with no
/// watch of its own.
fn mint_owner_credential(side: &Side) {
    let owner = side
        .vault
        .ensure_embedded_owner_actor()
        .expect("owner actor");
    let root = side
        .vault
        .ensure_host_root_slip(&side.issuer)
        .expect("the host root slip");
    let issued_at = side.vault.capability_slip_now().expect("slip clock");
    let mut claims = root.claims;
    claims.slip_id = [0x5C; 32];
    claims.holder_ref = owner.to_hex();
    claims.actor_class = Some("human".into());
    claims.issued_at = issued_at;
    claims.expires_at = issued_at + 3_600;
    claims.ttl_secs = 3_600;
    side.vault
        .mint_capability_slip(&side.issuer, claims)
        .expect("the owner's credential");
}

/// The unwatched mint sweeps nothing itself; the next watched commit on the
/// thread, here a grouped write that registers a second world, stores the
/// stamp the mint's commit owed. Red on the stack head before this fix: that
/// commit's watch held the mint's note aside and handed it back at its drop,
/// so no sweep ran until the vault's next open.
#[test]
fn an_unwatched_authority_commit_is_swept_by_the_next_watched_commit() {
    let member = side(0x11);
    let company = side(0x22);
    let pact_id = severed_pact(&member, &company);
    let world = owe_a_stamp(&member.vault, pact_id);

    mint_owner_credential(&member);
    assert!(
        foreign_world_stale_stamp(&member.vault, world)
            .expect("stamp read")
            .is_none(),
        "control: the unwatched mint sweeps nothing on its own"
    );
    let other = ForeignWorldId::from_entity_id(
        EntityId::from_bytes([OTHER_WORLD_SEED; 16]).expect("valid world id"),
    )
    .expect("the seed sits in the foreign world id range");
    register_foreign_world_for_pact(&member.vault, &pact_id, other)
        .expect("the second world registers in a watched write");
    assert_stamped(&member.vault, world, "the next watched commit");
}
