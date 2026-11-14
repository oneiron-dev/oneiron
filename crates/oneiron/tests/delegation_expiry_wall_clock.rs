//! A delegation's end is wall time (census L7-18). DEC-0006's duration
//! amendment: an envelope the owner hands to a non-owner (a visitor in the
//! room, a client inside an engagement) carries a real duration, and "the
//! interval is a fact about the world, so it ends on wall time".
//! identity.md #slip-clocks keeps the credential's own lifetime on the
//! authority clock, which stops while the vault is closed or its host sleeps.
//! On main a Connect guest grant's end was judged on that authority clock at
//! every slip door, and a brief share's end at its view link, so a host that
//! slept past the deadline still admitted the visitor. Now each is judged no
//! earlier than the recording clock, as the support grant is
//! (`support_admission.rs`).
//!
//! Each test moves only the recording clock (a `ManualClock`, same handle,
//! no authority write after the move) and asserts the authority clock still
//! sits before the deadline. Red on main: the two refusal asserts. Guards
//! (pass on main too): each door admits before the wall deadline.
//! (A person's Delegate at `vault.delete` on a shared vault is already ended
//! on wall time on main, by the membership gate's pact check.)
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test delegation_expiry_wall_clock`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationDirectionScope, Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling,
    selector_range_of,
};
use oneiron::note::TakeTarget;
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use oneiron::share::Share;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::json;

const T0: u64 = 1_800_000_000;
const DELEGATION_END: u64 = T0 + 100;
const SLIP_END: u64 = T0 + 50_000;
const CHALLENGE: &[u8] = b"delegation-expiry-wall-clock";

/// One rooted, owner-bound vault whose recording clock moves independently
/// of the authority clock anchored during bootstrap. The vault drops first.
struct Fixture {
    vault: Vault,
    clock: Arc<ManualClock>,
    issuer: HostSlipIssuer,
    owner: EntityId,
    proof: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open(seed: u8) -> Self {
        let clock = ManualClock::new(T0);
        let dir = tempfile::tempdir().expect("vault directory");
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open(dir.path(), config).expect("vault on its manual clock");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = HostSlipIssuer::from_seed(&[seed; HOST_ISSUER_SEED_BYTES])
            .expect("independent host issuer");
        // A self-hosted Genesis also binds the embedded owner as human.
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile");
        let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
        let proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            clock,
            issuer,
            owner,
            proof,
            _dir: dir,
        }
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

/// Keep the shipped policy (including credential lifetimes), adding only the
/// owner's explicit permission to create a brief share on this channel.
fn permit_brief_share(fixture: &Fixture) {
    let id = oneiron_store::policy_record::default_policy_manifest_id()
        .expect("the default manifest id");
    let bytes = fixture
        .vault
        .get(&id)
        .expect("read default manifest")
        .expect("the shipped manifest is stored");
    let mut manifest: serde_json::Value =
        rmp_serde::from_slice(&bytes).expect("decode shipped manifest");
    manifest["scoped_grants"]
        .as_array_mut()
        .expect("the shipped scoped-grant table")
        .push(json!({
            "actor_ref": fixture.owner.to_hex(),
            "effector": "external:share_brief",
            "scope": oneiron::test_support::effect_preset(),
            "selectors": { "channel": "shared_brief" },
        }));
    oneiron::test_support::put_policy_manifest_bytes(
        &fixture.vault,
        id,
        &rmp_serde::to_vec_named(&manifest).expect("encode share permission"),
    )
    .expect("store the share permission beside the shipped policy");
}

/// A Connect guest's grant ends on wall time even while its slip remains
/// live on the authority clock (DEC-0006 duration; identity.md #slip-clocks).
#[test]
fn a_connect_guest_grant_ends_on_wall_time_at_its_slip_door() {
    let local = Fixture::open(0x11);
    let peer = Fixture::open(0x22);
    let local_id = local
        .vault
        .authority_fold()
        .expect("local fold")
        .vault_id
        .expect("local vault root");
    let peer_id = peer
        .vault
        .authority_fold()
        .expect("peer fold")
        .vault_id
        .expect("peer vault root");
    let local_world = local
        .vault
        .create_world(&local.proof, "Connect delegation clock", T0)
        .expect("local named WORLD");
    let peer_world = peer
        .vault
        .create_world(&peer.proof, "Reciprocal delegation clock", T0)
        .expect("peer named WORLD");
    let grant = local
        .vault
        .mint_connect_grant(
            &local.proof,
            peer_id,
            connect_scope(local_world),
            Some(DELEGATION_END),
            None,
        )
        .expect("Connect guest grant ending at T0 + 100");
    let reciprocal = peer
        .vault
        .mint_connect_grant(&peer.proof, local_id, connect_scope(peer_world), None, None)
        .expect("reciprocal Connect grant");
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
    let holder = HostSlipIssuer::from_seed(&[0x44; HOST_ISSUER_SEED_BYTES])
        .expect("guest's independent binding key");
    let slip = local
        .vault
        .mint_guest_slip(
            &local.proof,
            &local.issuer,
            grant.grant,
            Some(holder.binding_key()),
            SLIP_END,
            None,
        )
        .expect("guest slip outliving its grant");
    let signature = holder
        .binding_proof(&slip, CHALLENGE)
        .expect("guest holder proof");
    let host_key = local.issuer.public_key();

    local.clock.set(T0 + 10);
    let admitted = local
        .vault
        .verify_capability_slip(&host_key, &slip, CHALLENGE, &signature);
    assert!(
        admitted.is_ok(),
        "guard: the active Connect guest verifies before its wall deadline: {admitted:?}"
    );

    // Same handle, no reopen or authority write: only recording time moves.
    local.clock.set(T0 + 10_000);
    assert!(
        local.vault.capability_slip_now().expect("authority clock") < DELEGATION_END,
        "the authority clock must still precede the grant's deadline"
    );
    let refused = local
        .vault
        .verify_capability_slip(&host_key, &slip, CHALLENGE, &signature);
    assert!(
        refused.is_err(),
        "the Connect delegation ends on wall time at its slip door, even though its slip has not expired: {refused:?}"
    );
}

/// A brief recipient's outstanding view link ends on wall time, not the
/// authority clock of pairing (DEC-0006: the interval is a world fact).
#[test]
fn a_brief_share_ends_on_wall_time_at_its_view_link() {
    let fixture = Fixture::open(0x33);
    let recipient = EntityId::now();
    fixture
        .vault
        .put_entity(
            &recipient,
            ENTITY_TYPE_PERSON,
            TimeRange { start: T0, end: T0 },
            T0,
            b"brief recipient",
        )
        .expect("live recipient PERSON");
    let brief = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .author_take(TakeTarget::Subject(recipient), "A brief for the recipient")
        .expect("stored NOTE brief")
        .id_hex;
    permit_brief_share(&fixture);
    let share_id = EntityId::now();
    let share = Share {
        recipient_ref: recipient,
        brief_ref: brief,
        world_refs: BTreeSet::new(),
        facet_refs: BTreeSet::new(),
        include_unscoped: true,
        status: oneiron::access_grant::AccessGrantStatus::Active,
        created_at: T0,
        revoked_at: None,
        expires_at: Some(DELEGATION_END),
        mention: None,
    };
    let issuer = WriteActor::new(fixture.owner, EdgeActorClass::Human);
    fixture
        .vault
        .create_share(&share_id, &issuer, &share)
        .expect("admitted brief share ending at T0 + 100");
    let link = fixture
        .vault
        .issue_share_view_link(
            &fixture.issuer,
            &issuer,
            share_id,
            EdgeActorClass::Human,
            SLIP_END - T0,
        )
        .expect("the recipient's outstanding view link");
    assert!(
        link.expires_at > DELEGATION_END,
        "the pairing link outlives the share"
    );
    let holder_ref = recipient.to_hex();

    fixture.clock.set(T0 + 10);
    assert!(
        fixture
            .vault
            .share_view_pairing_allows_holder(&fixture.issuer, &link.code, &holder_ref)
            .expect("judge the view link before expiry"),
        "guard: the share's view-link door admits its recipient before the wall deadline"
    );

    // This is the read-only pairing preflight, not resolve_share_for_view,
    // whose recording-clock expiry check already passed on main.
    fixture.clock.set(T0 + 10_000);
    assert!(
        fixture
            .vault
            .capability_slip_now()
            .expect("authority clock")
            < DELEGATION_END,
        "the authority clock, and therefore the pairing code, must still be before expiry"
    );
    assert!(
        !fixture
            .vault
            .share_view_pairing_allows_holder(&fixture.issuer, &link.code, &holder_ref)
            .expect("judge the view link after the wall deadline"),
        "the brief delegation ends on wall time at its view-link door, even though the pairing code has not expired"
    );
}
