//! A Connect pact offer binds only a Connect guest Grant its owner's counted mint gives (FIX
//! CONNECT-PROPOSE-AND-CARRY-READ-GRANT-ROW-ALONE; review #8855 P3-1).
//!
//! The owner's propose, re-scope and accept doors checked the Grant row's shape and scope
//! alone, so a Connect row no counted act gives (a bare copy), or a pacted row widened in place,
//! backed a pact offer whose terms no act gave: the pact then never conferred, or its outbound
//! scope differed from the giving. Now the doors also ask the fold for the row's counted giving
//! in its guest family, with no counted end and the giving's terms. The owner's counted Grant
//! still backs its offer.
//!
//! Runs on public paths and the test doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test connect_grant_offer_through_fold`.
#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationDirectionScope, Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling,
    decode_federation_grant_body_keyed, selector_range_of,
};
use oneiron::registry::ENTITY_TYPE_CLAIM;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::grant_act::{put_keyed_member_grant, put_unkeyed_member_grant};
use oneiron::test_doors::grant_standing::grant_row;
use oneiron::{EntityId, Vault, VaultConfig};

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

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

    fn world(&self, name: &str) -> EntityId {
        self.vault
            .create_world(&self.proof, name, self.vault.now_recorded_at())
            .expect("a named WORLD")
    }
}

/// The smallest ordinary read/propose Connect slice, over the named WORLDs `worlds`.
fn connect_scope(worlds: &[EntityId]) -> Scope {
    Scope {
        worlds: ScopeAxis::Some(worlds.iter().map(|world| ScopeId(*world)).collect()),
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

/// Two vaults whose owners minted each other a Connect guest Grant, no pact yet: the local
/// vault, the peer, each Grant's id, the local Grant's scope and the peer Grant's scope.
struct Minted {
    local: ConnectVault,
    peer: ConnectVault,
    grant: EntityId,
    reciprocal: EntityId,
    outbound: Scope,
    inbound: Scope,
}

fn minted_connect() -> Minted {
    let local = ConnectVault::open(0x11);
    let peer = ConnectVault::open(0x22);
    let (local_id, peer_id) = (local.vault_id(), peer.vault_id());
    let local_world = local.world("Connect offer");
    let peer_world = peer.world("Reciprocal offer");
    let grant = local
        .vault
        .mint_connect_grant(
            &local.proof,
            peer_id,
            connect_scope(&[local_world]),
            None,
            None,
        )
        .expect("the local owner's Connect guest Grant");
    let reciprocal = peer
        .vault
        .mint_connect_grant(
            &peer.proof,
            local_id,
            connect_scope(&[peer_world]),
            None,
            None,
        )
        .expect("the peer owner's Connect guest Grant");
    Minted {
        local,
        peer,
        grant: grant.grant,
        reciprocal: reciprocal.grant,
        outbound: grant.resolved_scope,
        inbound: reciprocal.resolved_scope,
    }
}

impl Minted {
    /// The local owner's offer of a pact over `grant` for the minted scopes.
    fn propose(&self, grant: EntityId) -> oneiron::Result<oneiron::authority::ConnectOffer> {
        self.local.vault.propose_connect_as(
            &self.local.proof,
            &self.local.issuer,
            grant,
            self.peer.vault_id(),
            pact_direction(&self.outbound),
            pact_direction(&self.inbound),
        )
    }
}

#[test]
fn a_connect_row_no_counted_act_gives_backs_no_pact_offer() {
    let minted = minted_connect();
    let body = grant_row(&minted.local.vault, minted.grant)
        .expect("row read")
        .expect("FIXTURE: the minted Grant is live");
    let (copy, _) = decode_federation_grant_body_keyed(&body).expect("decodes");
    let bare = EntityId::now();
    put_unkeyed_member_grant(&minted.local.vault, bare, &copy).expect("a bare copy lands");

    assert!(
        minted.propose(bare).is_err(),
        "a Connect row no counted act gives backs no pact offer"
    );
}

/// Guard: the owner's Connect Grant, given by his counted mint, backs his pact offer.
#[test]
fn the_owners_counted_connect_grant_backs_his_pact_offer() {
    let minted = minted_connect();

    minted
        .propose(minted.grant)
        .expect("the counted Connect Grant backs the owner's offer");
}

#[test]
fn a_pacted_connect_grant_widened_in_place_backs_no_wider_rescope_offer() {
    let minted = minted_connect();
    let (local, peer) = (&minted.local, &minted.peer);
    let offer = minted
        .propose(minted.grant)
        .expect("local owner offers the pact");
    let (_, counter) = peer
        .vault
        .accept_connect_as(&peer.proof, &peer.issuer, minted.reciprocal, &offer)
        .expect("peer owner accepts");
    local
        .vault
        .accept_connect_as(&local.proof, &local.issuer, minted.grant, &counter)
        .expect("local owner accepts the peer's half");
    let fold = local.vault.authority_fold().expect("local fold");
    let (pact_id, state) = fold
        .federation_pacts
        .iter()
        .find(|(_, state)| state.grant_ref == minted.grant)
        .map(|(id, state)| (*id, state.clone()))
        .expect("FIXTURE: the pact over the local Grant");

    // The owner's row is widened in place to one more WORLD, with no new giving.
    let more = local.world("Widened in place");
    let body = grant_row(&local.vault, minted.grant)
        .expect("row read")
        .expect("FIXTURE: the pacted Grant is live");
    let (mut wider, terms_key) = decode_federation_grant_body_keyed(&body).expect("decodes");
    let mut worlds = match &wider.authority_scope.worlds {
        ScopeAxis::Some(worlds) => worlds.clone(),
        other => panic!("FIXTURE: the Grant names its WORLDs: {other:?}"),
    };
    worlds.insert(ScopeId(more));
    wider.authority_scope.worlds = ScopeAxis::Some(worlds);
    match terms_key {
        Some(key) => put_keyed_member_grant(&local.vault, minted.grant, &wider, &key),
        None => put_unkeyed_member_grant(&local.vault, minted.grant, &wider),
    }
    .expect("the row is widened in place");

    let mut scope = state.pact_scope.clone();
    let widened = pact_direction(&wider.authority_scope);
    if local.vault_id() <= state.peer_vault_id {
        scope.lo_to_hi = widened;
    } else {
        scope.hi_to_lo = widened;
    }
    assert!(
        local
            .vault
            .propose_connect_rescope_as(
                &local.proof,
                &local.issuer,
                pact_id,
                state.pact_epoch + 1,
                scope,
            )
            .is_err(),
        "a Connect row widened in place backs no re-scope offer to its wider WORLDs"
    );
}
