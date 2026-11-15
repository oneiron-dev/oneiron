//! RESTRICTION-WAVE-10 (owner principle, 16 Nov 00:44: a restriction that is no correctness fix
//! ships as a good default plus an owner opt-out): two owner Setting keys of `deletion`, each
//! defaulting to the behaviour before it.
//! - `deletion.coop_delivery.give_up_secs` (census C97): an undelivered courtesy-delete leg stops
//!   retrying after seven days, unless the owner gives it longer.
//! - `deletion.brief_share.require_confirmed` (census C70): the owner's plain delete of a record
//!   under a live brief share is refused for the confirmed door, unless the owner turns the key
//!   off; then the delete revokes the record's live shares first and goes on. A proof-free
//!   delete names no actor to revoke as, so it keeps the refusal.
//!
//! Red on the base (the Setting primitive with neither key): each test that moves a key fails at
//! its `set_setting`, which names no such key. Guards (green on both): the default behaves as
//! before.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! deletion_setting_keys`.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::access_grant::AccessGrantStatus;
use oneiron::authority::{
    AuthorityVaultId, FederationPactStatus, HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::{CooperativeDeletionDeliveryStatus, CooperativeDeletionTry};
use oneiron::federation::{
    FederationDirectionScope, Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling,
    selector_range_of,
};
use oneiron::note::TakeTarget;
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use oneiron::setting::{SetSetting, SettingCaller};
use oneiron::share::Share;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::{
    EdgeActorClass, EntityId, SafeDeleteReason, TimeRange, Vault, VaultConfig, WriteActor,
};
use serde_json::{Value, json};

const T0: u64 = 1_800_000_000;
const DAY: u64 = 24 * 60 * 60;
const PEER_HOST: &str = "https://peer.example";
const GIVE_UP_KEY: &str = "deletion.coop_delivery.give_up_secs";
const CONFIRM_KEY: &str = "deletion.brief_share.require_confirmed";

/// One rooted, owner-bound vault on a manual recording clock. The vault drops first.
struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    issuer: HostSlipIssuer,
    owner: EntityId,
    proof: AuthenticatedOwner,
    vault_id: AuthorityVaultId,
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
        let vault_id = vault
            .authority_fold()
            .expect("authority fold")
            .vault_id
            .expect("a rooted vault has an id");
        Self {
            vault,
            _clock: clock,
            issuer,
            owner,
            proof,
            vault_id,
            _dir: dir,
        }
    }

    /// The owner sets `key`'s vault row to `value`.
    fn set_key(&self, key: &str, value: Value) {
        self.vault
            .set_setting(
                SettingCaller::Owner(&self.proof),
                SetSetting::vault_value(key, value),
            )
            .unwrap_or_else(|error| panic!("the owner sets {key}: {error}"));
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

/// `local`'s Connect pact with `peer`, made Active and then ended by `local`: the pact id and the
/// epoch a courtesy-delete ask about it may cover.
fn ended_pact(local: &Fixture, peer: &Fixture) -> ([u8; 32], u64) {
    let local_world = local
        .vault
        .create_world(&local.proof, "Courtesy delete", T0)
        .expect("local named WORLD");
    let peer_world = peer
        .vault
        .create_world(&peer.proof, "Courtesy delete peer", T0)
        .expect("peer named WORLD");
    let grant = local
        .vault
        .mint_connect_grant(
            &local.proof,
            peer.vault_id,
            connect_scope(local_world),
            None,
            None,
        )
        .expect("local Connect grant");
    let reciprocal = peer
        .vault
        .mint_connect_grant(
            &peer.proof,
            local.vault_id,
            connect_scope(peer_world),
            None,
            None,
        )
        .expect("reciprocal Connect grant");
    let offer = local
        .vault
        .propose_connect_as(
            &local.proof,
            &local.issuer,
            grant.grant,
            peer.vault_id,
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
    let fold = local.vault.authority_fold().expect("local fold");
    let pact = fold
        .federation_pacts
        .iter()
        .find(|(_, state)| {
            state.peer_vault_id == peer.vault_id && state.status == FederationPactStatus::Active
        })
        .map(|(pact, _)| *pact)
        .expect("local's Active pact with the peer");
    let ended = local
        .vault
        .disconnect_connect_as(&local.proof, &local.issuer, pact)
        .expect("local ends the pact");
    (pact, ended.terminal_epoch.unwrap_or(ended.pact_epoch))
}

/// `local` asks the peer of `pact` to delete what the pact carried, queued at T0, and its first
/// try fails at `at`: the leg's state after that try.
fn failed_first_try_at(
    local: &Fixture,
    pact: [u8; 32],
    cutoff: u64,
    at: u64,
) -> CooperativeDeletionDeliveryStatus {
    let pages = local
        .issuer
        .sign_cooperative_deletion_request(&local.vault, &pact, Vec::new(), cutoff, [0x5a; 16])
        .expect("local signs the ask");
    assert_eq!(pages.len(), 1, "an ask about every world is one page");
    local
        .vault
        .queue_cooperative_deletion_request_as(&local.proof, &pages[0], PEER_HOST, T0)
        .expect("local queues the ask at T0");
    let delivery = local
        .vault
        .claim_cooperative_deletion_delivery("courtesy-delete-test", at, None)
        .expect("claim the next try")
        .expect("the queued leg's try");
    local
        .vault
        .settle_cooperative_deletion_delivery(
            &delivery,
            CooperativeDeletionTry::Failed("the peer host did not answer".to_owned()),
            at,
        )
        .expect("settle the failed try")
}

#[test]
fn a_courtesy_delete_leg_keeps_retrying_past_seven_days_once_the_owner_gives_it_longer() {
    let local = Fixture::open(0x11);
    let peer = Fixture::open(0x22);
    let (pact, cutoff) = ended_pact(&local, &peer);
    local.set_key(GIVE_UP_KEY, json!(30 * DAY));
    assert_eq!(
        failed_first_try_at(&local, pact, cutoff, T0 + 8 * DAY),
        CooperativeDeletionDeliveryStatus::Sent,
        "an eight-day-old leg under a thirty-day give-up retries"
    );
}

#[test]
fn a_courtesy_delete_leg_is_unreachable_after_seven_days_by_default() {
    let local = Fixture::open(0x11);
    let peer = Fixture::open(0x22);
    let (pact, cutoff) = ended_pact(&local, &peer);
    assert_eq!(
        failed_first_try_at(&local, pact, cutoff, T0 + 8 * DAY),
        CooperativeDeletionDeliveryStatus::Unreachable,
        "an eight-day-old leg stops retrying"
    );
}

/// Keep the shipped policy (including credential lifetimes), adding only the owner's explicit
/// permission to create a brief share on this channel.
fn permit_brief_share(fixture: &Fixture) {
    let id = oneiron_store::policy_record::default_policy_manifest_id()
        .expect("the default manifest id");
    let bytes = fixture
        .vault
        .get(&id)
        .expect("read default manifest")
        .expect("the shipped manifest is stored");
    let mut manifest: Value = rmp_serde::from_slice(&bytes).expect("decode shipped manifest");
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

/// The owner's NOTE brief about a live PERSON, shared with that person: the brief's id (hex)
/// and the share's id.
fn shared_brief(fixture: &Fixture) -> (String, EntityId) {
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
    permit_brief_share(fixture);
    let share_id = EntityId::now();
    let share = Share {
        recipient_ref: recipient,
        brief_ref: brief.clone(),
        world_refs: BTreeSet::new(),
        facet_refs: BTreeSet::new(),
        include_unscoped: true,
        status: AccessGrantStatus::Active,
        created_at: T0,
        revoked_at: None,
        expires_at: None,
        mention: None,
    };
    fixture
        .vault
        .create_share(
            &share_id,
            &WriteActor::new(fixture.owner, EdgeActorClass::Human),
            &share,
        )
        .expect("admitted brief share");
    (brief, share_id)
}

fn share_status(fixture: &Fixture, share_id: &EntityId) -> AccessGrantStatus {
    fixture
        .vault
        .get_share(share_id)
        .expect("read the share")
        .expect("the share is stored")
        .status
}

fn is_deleted_shell(fixture: &Fixture, brief: &str) -> bool {
    fixture
        .vault
        .is_deleted_shell(&EntityId::from_hex(brief).expect("brief id"))
        .expect("shell read")
}

#[test]
fn the_owners_delete_revokes_live_brief_shares_once_the_confirm_is_off() {
    let fixture = Fixture::open(0x33);
    let (brief, share_id) = shared_brief(&fixture);
    fixture.set_key(CONFIRM_KEY, json!(false));
    let receipt = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .safe_delete(&brief, SafeDeleteReason::UserDelete)
        .expect("the owner's plain delete goes on");
    assert!(receipt.existed);
    assert!(
        is_deleted_shell(&fixture, &brief),
        "the brief is a deleted shell"
    );
    assert_eq!(
        share_status(&fixture, &share_id),
        AccessGrantStatus::Revoked,
        "the delete revoked the live share first"
    );
}

#[test]
fn the_owners_delete_under_a_live_brief_share_needs_the_confirmed_door_by_default() {
    let fixture = Fixture::open(0x33);
    let (brief, share_id) = shared_brief(&fixture);
    let refused = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .safe_delete(&brief, SafeDeleteReason::UserDelete);
    assert!(
        refused.is_err(),
        "a live share sends the delete to the confirmed door: {refused:?}"
    );
    assert!(!is_deleted_shell(&fixture, &brief), "the brief stays");
    assert_eq!(
        share_status(&fixture, &share_id),
        AccessGrantStatus::Active,
        "the share stays live"
    );
}

#[test]
fn a_proof_free_delete_keeps_the_refusal_with_the_confirm_off() {
    let fixture = Fixture::open(0x33);
    let (brief, share_id) = shared_brief(&fixture);
    fixture.set_key(CONFIRM_KEY, json!(false));
    let refused = fixture
        .vault
        .delete_entity(&EntityId::from_hex(&brief).expect("brief id"));
    assert!(
        refused.is_err(),
        "a delete with no actor revokes nothing and keeps the refusal: {refused:?}"
    );
    assert!(!is_deleted_shell(&fixture, &brief), "the brief stays");
    assert_eq!(
        share_status(&fixture, &share_id),
        AccessGrantStatus::Active,
        "the share stays live"
    );
}
