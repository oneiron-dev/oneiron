//! A sync selector stands on a Grant the fold stands behind (pass 28 R3d, FIX
//! GRANT-UNPACTED-LEGACY-ALLOW).
//!
//! A Grant row confers nothing by itself: before R3d the selector door read the row alone,
//! and the pact gate let every Grant no pact binds pass (the "Unpacted legacy-allow"). A
//! member row no counted act gives, one put back after its counted end and one widened in
//! place backed a selector export, and a Connect guest row widened in place under its Active
//! pact did too, since the pact never states the row's terms. The honest member's and the
//! honest Connect guest's selectors stay authorized.
//!
//! Runs on public paths and the test doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test selector_grant_standing`.
#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::entity_id::LocalWorldId;
use oneiron::federation::{
    FederationDirectionScope, FederationGrant, FederationGrantRole as Role, FederationGrantScope,
    InitialSharedMember, Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling,
    decode_federation_grant_body, decode_federation_grant_body_keyed, selector_range_of,
};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::sync::{SyncSelector, SyncSelectorWorld, authorize_sync_selector};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::grant_act::{put_keyed_member_grant, put_unkeyed_member_grant};
use oneiron::test_doors::grant_standing::{grant_row, standing_member_grant_act};
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

/// A fresh vault whose install carries acts, and its owner.
fn carrier_vault() -> (tempfile::TempDir, Vault, HostSlipIssuer, EntityId) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let (issuer, owner) = provision_act_carrier(&vault);
    (dir, vault, issuer, owner)
}

/// `owner` shares the vault as its Owner, and `member` accepts its founding invitation at
/// `role`.
fn share_with(vault: &Vault, owner: EntityId, member: EntityId, role: Role) {
    person(vault, member);
    vault
        .initialize_shared_vault(
            &proof(vault, owner),
            SHARED,
            None,
            &[
                InitialSharedMember {
                    member_ref: owner,
                    role: Some(Role::Owner),
                },
                InitialSharedMember {
                    member_ref: member,
                    role: Some(role),
                },
            ],
            vault.now_recorded_at(),
        )
        .expect("a shared vault");
    let member_proof = proof(vault, member);
    let invitation = vault
        .shared_invitations(&member_proof, SHARED)
        .expect("invitations")
        .into_iter()
        .find(|open| open.role == role)
        .expect("the founding invitation");
    vault
        .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
        .expect("the member accepts");
}

/// `member`'s membership Grant row in the shared vault: its id and terms.
fn member_row(vault: &Vault, member: EntityId) -> Option<(EntityId, FederationGrant)> {
    vault
        .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
        .expect("grants")
        .into_iter()
        .find_map(|id| {
            let body = vault.get(&id).expect("grant row")?;
            let grant = decode_federation_grant_body(&body).ok()?;
            (grant.member_ref == member
                && grant.role != Role::Delegate
                && grant.scope == FederationGrantScope::vault(SHARED))
            .then_some((id, grant))
        })
}

/// The act row `id` stands on now as a member's Grant.
fn standing(vault: &Vault, id: EntityId) -> Option<[u8; 32]> {
    standing_member_grant_act(vault, id, vault.now_recorded_at()).expect("standing read")
}

/// A member lane's selector over the whole vault, under Grant `grant` held by `member`.
fn member_selector(grant: EntityId, member: EntityId) -> SyncSelector {
    SyncSelector::new(
        grant,
        member,
        SyncSelectorWorld::All,
        Vec::new(),
        Vec::new(),
    )
}

/// Whether the shared vault's selector door authorizes `selector`.
fn authorizes(vault: &Vault, selector: &SyncSelector) -> bool {
    authorize_sync_selector(vault, FederationGrantScope::vault(SHARED), selector).is_ok()
}

/// Guard: the honest member, whose row stands on its counted giving, keeps its selector
/// before and after pass 28 R3d.
#[test]
fn an_honest_members_selector_is_authorized() {
    let (_dir, vault, _, owner) = carrier_vault();
    let member = EntityId::now();
    share_with(&vault, owner, member, Role::Member);
    let (grant, _) = member_row(&vault, member).expect("the member's grant");
    assert!(
        standing(&vault, grant).is_some(),
        "FIXTURE: the member's row stands on its giving"
    );

    authorize_sync_selector(
        &vault,
        FederationGrantScope::vault(SHARED),
        &member_selector(grant, member),
    )
    .expect("the honest member's selector is authorized");
}

/// Catches a bare member row backing a selector: no counted act gives it and no pact binds
/// it, so the pact gate's legacy-allow let it export under its own terms.
#[test]
fn a_bare_member_row_backs_no_selector() {
    let (_dir, vault, _, owner) = carrier_vault();
    let member = EntityId::now();
    share_with(&vault, owner, member, Role::Member);
    let (_, member_grant) = member_row(&vault, member).expect("the member's grant");
    let forger = EntityId::now();
    person(&vault, forger);
    let mut forged = member_grant;
    forged.member_ref = forger;
    let id = EntityId::now();
    put_unkeyed_member_grant(&vault, id, &forged).expect("a bare row lands");
    assert_eq!(
        standing(&vault, id),
        None,
        "FIXTURE: the bare row stands on no giving"
    );

    assert!(
        !authorizes(&vault, &member_selector(id, forger)),
        "a bare member row backs no selector"
    );
}

/// Catches a removed member's row, put back after its counted end, backing a selector
/// again: no selector reader read the line's end or the withdrawal marker.
#[test]
fn a_removed_members_put_back_row_backs_no_selector() {
    let (_dir, vault, issuer, owner) = carrier_vault();
    let member = EntityId::now();
    share_with(&vault, owner, member, Role::Member);
    let (grant, _) = member_row(&vault, member).expect("the member's grant");
    let old_body = grant_row(&vault, grant)
        .expect("row read")
        .expect("the live Member row");
    assert!(
        authorizes(&vault, &member_selector(grant, member)),
        "FIXTURE: the member's row backs its selector before the removal"
    );

    vault
        .remove_shared_member(&proof(&vault, owner), SHARED, member, Some(&issuer))
        .expect("the owner removes the member");
    assert!(
        member_row(&vault, member).is_none(),
        "FIXTURE: the removal drops the member's row"
    );
    let (old_grant, old_key) = decode_federation_grant_body_keyed(&old_body).expect("old body");
    let old_key = old_key.expect("the Member row was keyed by its giving");
    put_keyed_member_grant(&vault, grant, &old_grant, &old_key).expect("the old row put back");
    assert_eq!(
        standing(&vault, grant),
        None,
        "FIXTURE: the put-back row stands for nothing"
    );

    assert!(
        !authorizes(&vault, &member_selector(grant, member)),
        "a removed member's put-back row backs no selector"
    );
}

/// Catches a member row widened in place backing a selector: the door read the wider row's
/// role and terms alone, never what the counted giving stated.
#[test]
fn a_member_row_widened_in_place_backs_no_selector() {
    let (_dir, vault, _, owner) = carrier_vault();
    let viewer = EntityId::now();
    share_with(&vault, owner, viewer, Role::Viewer);
    let (grant, _) = member_row(&vault, viewer).expect("the viewer's grant");
    assert!(
        authorizes(&vault, &member_selector(grant, viewer)),
        "FIXTURE: the viewer's own row backs its selector"
    );
    let body = grant_row(&vault, grant)
        .expect("row read")
        .expect("the live Viewer row");
    let (mut wider, terms_key) = decode_federation_grant_body_keyed(&body).expect("decodes");
    wider.role = Role::Owner;
    match terms_key {
        Some(key) => put_keyed_member_grant(&vault, grant, &wider, &key),
        None => put_unkeyed_member_grant(&vault, grant, &wider),
    }
    .expect("the row is widened in place");
    assert_eq!(
        standing(&vault, grant),
        None,
        "FIXTURE: the widened row is not what its giving stated"
    );

    assert!(
        !authorizes(&vault, &member_selector(grant, viewer)),
        "a member row widened in place backs no selector"
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
/// the local vault, the peer, the local Grant's id and its named WORLD.
fn pacted_connect() -> (ConnectVault, ConnectVault, EntityId, EntityId) {
    let local = ConnectVault::open(0x11);
    let peer = ConnectVault::open(0x22);
    let (local_id, peer_id) = (local.vault_id(), peer.vault_id());
    let now = local.vault.now_recorded_at();
    let local_world = local
        .vault
        .create_world(&local.proof, "Connect selector standing", now)
        .expect("local named WORLD");
    let peer_world = peer
        .vault
        .create_world(&peer.proof, "Reciprocal selector standing", now)
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
    (local, peer, grant.grant, local_world)
}

/// The Connect guest's selector over its one named WORLD, and the Grant's scope, read from
/// the Grant row `grant` now holds.
fn connect_selector(
    vault: &Vault,
    grant: EntityId,
    world: EntityId,
) -> (FederationGrantScope, SyncSelector) {
    let body = grant_row(vault, grant)
        .expect("row read")
        .expect("FIXTURE: the Connect Grant is live");
    let row = decode_federation_grant_body(&body).expect("decodes");
    let selector = SyncSelector::new(
        grant,
        row.member_ref,
        SyncSelectorWorld::World(LocalWorldId::try_from(world).expect("a named WORLD")),
        Vec::new(),
        Vec::new(),
    );
    (row.scope, selector)
}

/// Guard: the honest Connect guest Grant, given by its owner's mint and bound by its Active
/// pact, backs its selector before and after pass 28 R3d.
#[test]
fn an_honest_connect_grant_under_its_pact_backs_its_selector() {
    let (local, _peer, grant, world) = pacted_connect();
    let (scope, selector) = connect_selector(&local.vault, grant, world);

    authorize_sync_selector(&local.vault, scope, &selector)
        .expect("the pacted Connect Grant backs its guest's selector");
}

/// Catches a Connect row widened in place under its Active pact backing a selector: the
/// pact never states the row's expiry, so the door read the wider row alone.
#[test]
fn a_connect_grant_widened_in_place_under_its_pact_backs_no_selector() {
    let (local, _peer, grant, world) = pacted_connect();
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
    let (scope, selector) = connect_selector(&local.vault, grant, world);

    assert!(
        authorize_sync_selector(&local.vault, scope, &selector).is_err(),
        "a Connect row widened in place backs no selector"
    );
}
