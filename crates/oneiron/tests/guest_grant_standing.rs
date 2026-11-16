//! A guest's Grant comes only from the counted act that gives it (pass 28 R3c, RULING
//! R3C-GUEST-GIVING-ACT = A), never from its row.
//!
//! An Ask guest's Grant is given with its ask, a Connect guest's at its owner's mint, each by
//! the general grant act in the writer's transaction; a Connect guest's stands only while one
//! Active operative pact with its peer binds it too. A bare Ask guest row makes no payer and
//! mints no slip; a Connect row widened in place under its pact mints no slip; the owner's
//! Connect mint gives its Grant by a counted act. A bare Connect row with no pact, a row put
//! back after its revoke and the honest pacted Grant keep reading as before.
//!
//! Runs on public paths and the test doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test guest_grant_standing`.
#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationDirectionScope, FederationGrant, FederationGrantRole as Role, InitialSharedMember,
    Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling, decode_federation_grant_body_keyed,
    selector_range_of,
};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::grant_act::{put_keyed_member_grant, put_unkeyed_member_grant};
use oneiron::test_doors::grant_standing::{grant_line, grant_row};
use oneiron::test_support::provision_act_carrier;
use oneiron::{EntityId, Vault, VaultConfig};

const SHARED: u64 = 42;

fn person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// A guest's own binding key, apart from every host key.
fn holder_key() -> [u8; 32] {
    HostSlipIssuer::from_seed(&[0x44; HOST_ISSUER_SEED_BYTES])
        .expect("the guest's binding key")
        .binding_key()
}

/// One shared vault whose install carries acts: its host issuer and its owner.
struct SharedVault {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    _dir: tempfile::TempDir,
}

impl SharedVault {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
        let (issuer, owner) = provision_act_carrier(&vault);
        vault
            .initialize_shared_vault(
                &proof(&vault, owner),
                SHARED,
                None,
                &[InitialSharedMember {
                    member_ref: owner,
                    role: Some(Role::Owner),
                }],
                vault.now_recorded_at(),
            )
            .expect("a shared vault");
        Self {
            vault,
            issuer,
            owner,
            _dir: dir,
        }
    }

    /// An Ask guest's Grant for a fresh companion, put at a fresh id with no act: a forged
    /// row. Answers its id and its companion.
    fn put_bare_ask_row(&self) -> (EntityId, EntityId) {
        let companion = EntityId::now();
        person(&self.vault, companion);
        let guest = EntityId::now();
        person(&self.vault, guest);
        let grant = FederationGrant::ask_guest(
            EntityId::now(),
            companion,
            guest,
            self.owner,
            BTreeSet::from([EntityId::now()]),
        )
        .expect("an Ask guest's Grant");
        let id = EntityId::now();
        put_unkeyed_member_grant(&self.vault, id, &grant).expect("a bare row lands");
        (id, companion)
    }

    fn mint_slip(&self, grant: EntityId) -> oneiron::Result<()> {
        self.vault
            .mint_guest_slip(
                &proof(&self.vault, self.owner),
                &self.issuer,
                grant,
                Some(holder_key()),
                self.vault.now_recorded_at() + 3_600,
                None,
            )
            .map(drop)
    }
}

/// Catches a bare Ask guest row making its companion a booking's payer: the payer's Ask arm
/// read the row alone (pass 28 R3c, site map Q2-A10).
#[test]
fn a_bare_ask_guest_row_makes_no_payer() {
    let shared = SharedVault::open();
    let (id, companion) = shared.put_bare_ask_row();
    let companion_proof = proof(&shared.vault, companion);

    assert_eq!(
        shared
            .vault
            .booking_payer_grant(&companion_proof)
            .expect("payer read"),
        None,
        "a bare Ask guest row makes no payer"
    );
    assert!(
        !shared
            .vault
            .booking_payer_grant_stands(&companion_proof, id)
            .expect("payer recheck"),
        "a bare Ask guest row stands for no payer"
    );
}

/// Catches a bare Ask guest row minting its guest a slip: the slip mint read the row alone
/// (pass 28 R3c, site map Q2-A7).
#[test]
fn a_bare_ask_guest_row_mints_no_slip() {
    let shared = SharedVault::open();
    let (id, _) = shared.put_bare_ask_row();

    assert!(
        shared.mint_slip(id).is_err(),
        "a bare Ask guest row mints no slip"
    );
}

/// Guard: a guest row put back after the owner revoked it confers nothing, before pass 28
/// R3c (the local withdrawal marker) and after (the revoke's counted end).
#[test]
fn an_ask_guest_row_put_back_after_its_revoke_confers_nothing() {
    let shared = SharedVault::open();
    let (id, companion) = shared.put_bare_ask_row();
    let body = grant_row(&shared.vault, id)
        .expect("row read")
        .expect("FIXTURE: the row is live");
    let (grant, _) = decode_federation_grant_body_keyed(&body).expect("the row decodes");
    shared
        .vault
        .revoke_guest_access(&proof(&shared.vault, shared.owner), &shared.issuer, id)
        .expect("the owner revokes the guest");
    put_unkeyed_member_grant(&shared.vault, id, &grant).expect("the row is put back");

    assert_eq!(
        shared
            .vault
            .booking_payer_grant(&proof(&shared.vault, companion))
            .expect("payer read"),
        None,
        "a put-back Ask guest row makes no payer"
    );
    assert!(
        shared.mint_slip(id).is_err(),
        "a put-back Ask guest row mints no slip"
    );
}

const T0_EXPIRY_SECS: u64 = 30 * 24 * 3_600;

/// One rooted, owner-bound vault whose install carries acts, for a Connect pact.
struct ConnectVault {
    vault: Vault,
    issuer: HostSlipIssuer,
    proof: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl ConnectVault {
    fn open(seed: u8) -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = HostSlipIssuer::from_seed(&[seed; HOST_ISSUER_SEED_BYTES])
            .expect("independent host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile");
        let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
        let proof = proof(&vault, owner);
        Self {
            vault,
            issuer,
            proof,
            _dir: dir,
        }
    }

    fn vault_id(&self) -> oneiron::authority::AuthorityVaultId {
        self.vault
            .authority_fold()
            .expect("fold")
            .vault_id
            .expect("vault root")
    }

    fn mint_slip(&self, grant: EntityId) -> oneiron::Result<()> {
        self.vault
            .mint_guest_slip(
                &self.proof,
                &self.issuer,
                grant,
                Some(holder_key()),
                self.vault.now_recorded_at() + 3_600,
                None,
            )
            .map(drop)
    }
}

/// The smallest ordinary read/propose Connect slice, over one named WORLD.
fn connect_scope(world: EntityId) -> Scope {
    Scope {
        worlds: ScopeAxis::Some(BTreeSet::from([ScopeId(world)])),
        facets: ScopeAxis::Bottom,
        bands: ScopeAxis::Some(BTreeSet::from([ENTITY_TYPE_CLAIM])),
        audience: ScopeAxis::Some(BTreeSet::from([ScopeId(
            oneiron::claim::default_project_id(),
        )])),
        verbs: ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "propose".to_owned()])),
        sensitivity: SensitivityCeiling::AtMost(Sensitivity::Public),
    }
}

/// This fixture's one CLAIM band projects to its declared replication range.
fn pact_direction(scope: &Scope) -> FederationDirectionScope {
    FederationDirectionScope {
        worlds: scope.worlds.clone(),
        facets: scope.facets.clone(),
        bands: ScopeAxis::Some(BTreeSet::from([
            selector_range_of(ENTITY_TYPE_CLAIM).expect("CLAIM replication range")
        ])),
    }
}

/// Two vaults whose owners minted each other a Connect guest Grant and made the pact Active:
/// the local vault, the peer and the local Grant's id.
fn pacted_connect() -> (ConnectVault, ConnectVault, EntityId) {
    let local = ConnectVault::open(0x11);
    let peer = ConnectVault::open(0x22);
    let (local_id, peer_id) = (local.vault_id(), peer.vault_id());
    let now = local.vault.now_recorded_at();
    let local_world = local
        .vault
        .create_world(&local.proof, "Connect guest standing", now)
        .expect("local named WORLD");
    let peer_world = peer
        .vault
        .create_world(&peer.proof, "Reciprocal guest standing", now)
        .expect("peer named WORLD");
    let grant = local
        .vault
        .mint_connect_grant(
            &local.proof,
            peer_id,
            connect_scope(local_world),
            Some(now + T0_EXPIRY_SECS),
            None,
        )
        .expect("the local owner's Connect guest Grant");
    let reciprocal = peer
        .vault
        .mint_connect_grant(&peer.proof, local_id, connect_scope(peer_world), None, None)
        .expect("the peer owner's Connect guest Grant");
    let offer = local
        .vault
        .propose_connect_as(
            &local.proof,
            &local.issuer,
            grant.grant,
            peer_id,
            pact_direction(&grant.resolved_scope),
            pact_direction(&reciprocal.resolved_scope),
        )
        .expect("local owner offers the pact");
    let (_, counter) = peer
        .vault
        .accept_connect_as(&peer.proof, &peer.issuer, reciprocal.grant, &offer)
        .expect("peer owner accepts");
    local
        .vault
        .accept_connect_as(&local.proof, &local.issuer, grant.grant, &counter)
        .expect("local owner accepts the peer's half");
    (local, peer, grant.grant)
}

/// Catches the owner's Connect mint writing its Grant with no act: before pass 28 R3c the
/// row was the only record of the giving.
#[test]
fn the_owners_connect_mint_gives_its_grant_by_a_counted_act() {
    let local = ConnectVault::open(0x11);
    let peer = ConnectVault::open(0x22);
    let now = local.vault.now_recorded_at();
    let world = local
        .vault
        .create_world(&local.proof, "Connect guest standing", now)
        .expect("local named WORLD");
    let grant = local
        .vault
        .mint_connect_grant(
            &local.proof,
            peer.vault_id(),
            connect_scope(world),
            None,
            None,
        )
        .expect("the owner's Connect guest Grant");

    let line = grant_line(&local.vault, grant.grant).expect("line read");
    assert!(
        matches!(line, Some((Some(_), false))),
        "the owner's mint gives the Connect Grant by a counted act: {line:?}"
    );
}

/// Guard: the honest Connect Grant, given by its owner's mint and bound by its Active pact,
/// mints its guest a slip before and after pass 28 R3c.
#[test]
fn an_honest_connect_grant_under_its_pact_mints_a_slip() {
    let (local, _peer, grant) = pacted_connect();

    local
        .mint_slip(grant)
        .expect("the pacted Connect Grant mints its guest a slip");
}

/// Catches a Connect row widened in place under its Active pact still minting a slip: the
/// pact never stated the row's expiry, so the slip mint read the wider row alone.
#[test]
fn a_connect_grant_widened_in_place_under_its_pact_mints_no_slip() {
    let (local, _peer, grant) = pacted_connect();
    let body = grant_row(&local.vault, grant)
        .expect("row read")
        .expect("FIXTURE: the pacted Grant is live");
    let (mut wider, terms_key) = decode_federation_grant_body_keyed(&body).expect("decodes");
    assert!(
        wider.expires_at.is_some(),
        "FIXTURE: the Grant was minted with an end"
    );
    wider.expires_at = None;
    match terms_key {
        Some(key) => put_keyed_member_grant(&local.vault, grant, &wider, &key),
        None => put_unkeyed_member_grant(&local.vault, grant, &wider),
    }
    .expect("the row is widened in place");

    assert!(
        local.mint_slip(grant).is_err(),
        "a Connect row widened in place mints no slip"
    );
}

/// Guard: a Connect row no pact binds mints no slip, before pass 28 R3c (the pact gate) and
/// after (no counted giving, and no pact).
#[test]
fn a_bare_connect_row_with_no_pact_mints_no_slip() {
    let (local, _peer, grant) = pacted_connect();
    let body = grant_row(&local.vault, grant)
        .expect("row read")
        .expect("FIXTURE: the pacted Grant is live");
    let (copy, _) = decode_federation_grant_body_keyed(&body).expect("decodes");
    let bare = EntityId::now();
    put_unkeyed_member_grant(&local.vault, bare, &copy).expect("a bare copy lands");

    assert!(
        local.mint_slip(bare).is_err(),
        "a Connect row no pact binds mints no slip"
    );
}
