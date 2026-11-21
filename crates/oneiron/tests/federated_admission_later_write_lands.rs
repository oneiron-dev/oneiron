//! A federation peer's later admitted write to a row's key lands over its
//! earlier one (FIX FEDERATED-ADMISSION-FRESH-DOC-LAMPORT-TIE).
//!
//! Before: every admission authored the peer's update in a fresh Loro doc,
//! whose ops start again at Lamport 0. A window map key keeps the write with
//! the larger (Lamport, peer id), so a later admitted write to a key the
//! earlier admission wrote at a higher op index (more rows before it in its
//! update) lost outright, and at equal counts the peer id decided. The window
//! diff was then empty and B kept the earlier image.
//! After: once a part imports, each key it lost to an earlier admission is
//! written again above every op the window holds, so the later admitted write
//! is the window's last write.
//!
//! - `a_peers_hard_delete_after_a_wider_soft_delete_removes_the_shell`: red on
//!   main (the soft delete rode an update with one more row, so its tombstone
//!   was the admission's second op; the hard delete alone is a first op and
//!   loses: the shell stays), green on the head.
//! - `a_peers_second_image_of_a_claim_lands_over_a_wider_first_delivery`: red
//!   on main (the first delivery wrote C after an earlier row; the second image
//!   rides alone and loses: B keeps the first image), green on the head.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test federated_admission_later_write_lands`.
#![cfg(all(feature = "sync", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use loro::{ExportMode, LoroDoc, LoroValue};
use oneiron::authority::{
    AuthorityVaultId, FederationPactStatus, HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::{TombstoneReason, TombstoneValueV2};
use oneiron::entity_id::LocalWorldId;
use oneiron::federation::{
    FederationDirectionScope, FederationGrantScope, Scope, ScopeAxis, ScopeId, Sensitivity,
    SensitivityCeiling, selector_range_of,
};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::federation_burst::FederationPeer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::types::WindowKey;
use oneiron::sync::{
    ConnectExportRequest, ConnectRejoinStatus, FederationAdmissionRole, SyncClient,
    SyncClientConfig, SyncSelector, SyncSelectorWorld,
};
use oneiron::test_doors::media_vector_replica::stored_row;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange, Vault,
    VaultConfig,
};
use rmpv::Value;

const T0: u64 = 1_800_000_000;
const WINDOW: &str = "2026-03";
const LEARNED_AT: u64 = 1_773_532_800;
const STAMP_KEY: &str = "sensitivity";
const STAMP_PUBLIC: u8 = 0;
const FIRST_VALUE: &str = "lighthouse keeper";
const SECOND_VALUE: &str = "harbour pilot";

/// One rooted, owner-bound vault on a manual recording clock, with the sync
/// manager the Connect doors need. The vault drops before its directory.
#[allow(dead_code)]
struct Fixture {
    vault: Arc<Vault>,
    manager: Arc<WindowManager>,
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
        let dir = tempfile::tempdir().expect("FIXTURE: vault directory");
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Arc::new(Vault::open(dir.path(), config).expect("FIXTURE: vault opens"));
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = HostSlipIssuer::from_seed(&[seed; HOST_ISSUER_SEED_BYTES])
            .expect("FIXTURE: independent host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("FIXTURE: host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("FIXTURE: engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("FIXTURE: this install's machine profile");
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("FIXTURE: owner actor");
        let proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("FIXTURE: owner proof");
        let vault_id = vault
            .authority_fold()
            .expect("FIXTURE: authority fold")
            .vault_id
            .expect("FIXTURE: a rooted vault has an id");
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&vault),
            Arc::new(Materializer::new()),
            "later-write-admission",
        ));
        Self {
            vault,
            manager,
            _clock: clock,
            issuer,
            owner,
            proof,
            vault_id,
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
            selector_range_of(ENTITY_TYPE_CLAIM).expect("FIXTURE: CLAIM replication range")
        ])),
    }
}

/// The Active Connect pact between S (sender, local) and B (receiver, peer):
/// each side's named WORLD, each side's grant, and the pact id in both forms.
#[allow(dead_code)]
struct ActivePact {
    pact: [u8; 32],
    pact_hex: String,
    s_world: EntityId,
    b_world: EntityId,
    s_grant: EntityId,
    b_grant: EntityId,
    b_member: EntityId,
}

fn active_pact(s: &Fixture, b: &Fixture) -> ActivePact {
    let s_world = s
        .vault
        .create_world(&s.proof, "Later write sender", T0)
        .expect("FIXTURE: S named WORLD");
    let b_world = b
        .vault
        .create_world(&b.proof, "Later write receiver", T0)
        .expect("FIXTURE: B named WORLD");
    let s_minted = s
        .vault
        .mint_connect_grant(&s.proof, b.vault_id, connect_scope(s_world), None, None)
        .expect("FIXTURE: S Connect grant");
    let reciprocal = b
        .vault
        .mint_connect_grant(&b.proof, s.vault_id, connect_scope(b_world), None, None)
        .expect("FIXTURE: reciprocal Connect grant");
    let offer = s
        .vault
        .propose_connect_as(
            &s.proof,
            &s.issuer,
            s_minted.grant,
            b.vault_id,
            pact_direction(&s_minted.resolved_scope),
            pact_direction(&reciprocal.resolved_scope),
        )
        .expect("FIXTURE: S owner offers the pact");
    let (_, counter) = b
        .vault
        .accept_connect_as(&b.proof, &b.issuer, reciprocal.grant, &offer)
        .expect("FIXTURE: B owner accepts");
    s.vault
        .accept_connect_as(&s.proof, &s.issuer, s_minted.grant, &counter)
        .expect("FIXTURE: S owner accepts the peer's half");
    let pact = offer.pact_id;
    for (label, vault, peer_id) in [("S", &s.vault, b.vault_id), ("B", &b.vault, s.vault_id)] {
        let fold = vault
            .authority_fold()
            .expect("FIXTURE: authority fold holds the pact");
        let state = fold
            .federation_pacts
            .get(&pact)
            .expect("FIXTURE: the fold holds the pact");
        assert_eq!(
            state.peer_vault_id, peer_id,
            "FIXTURE: {label} pact names its peer vault"
        );
        assert_eq!(
            state.status,
            FederationPactStatus::Active,
            "FIXTURE: {label} pact is Active"
        );
    }
    let pact_hex = pact.iter().map(|byte| format!("{byte:02x}")).collect();
    ActivePact {
        pact,
        pact_hex,
        s_world,
        b_world,
        s_grant: s_minted.grant,
        b_grant: reciprocal.grant,
        b_member: reciprocal.guest_actor,
    }
}

fn at_learned() -> TimeRange {
    TimeRange {
        start: LEARNED_AT,
        end: LEARNED_AT,
    }
}

fn put_person(vault: &Vault, name: &str) -> EntityId {
    let person = EntityId::now();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("name"), Value::from(name))]),
    )
    .expect("FIXTURE: encode PERSON body");
    vault
        .put_entity(&person, ENTITY_TYPE_PERSON, at_learned(), LEARNED_AT, &body)
        .expect("FIXTURE: PERSON lands");
    person
}

/// A claim about `subject` in `world`, stamped public in its scope map.

/// A claim about `subject` in `world`, stamped public in its scope map.
fn put_claim(vault: &Vault, subject: EntityId, world: Option<EntityId>) -> EntityId {
    let id = EntityId::now();
    write_claim(vault, &id, subject, world, FIRST_VALUE);
    id
}

/// Puts `id` as a claim about `subject` in `world` holding `value`, stamped
/// public in its scope map; a put over an existing `id` is its next image.
fn write_claim(
    vault: &Vault,
    id: &EntityId,
    subject: EntityId,
    world: Option<EntityId>,
    value: &str,
) {
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        value.into(),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: claim body builds");
    body.world = world;
    body.scope = Some(Value::Map(vec![(
        Value::from(STAMP_KEY),
        Value::from(STAMP_PUBLIC),
    )]));
    vault
        .put_claim(id, &body, at_learned(), LEARNED_AT)
        .expect("FIXTURE: CLAIM lands");
    let stored = vault
        .get_claim(id)
        .expect("FIXTURE: CLAIM reads back")
        .expect("FIXTURE: claim landed");
    assert_eq!(stored.world, world, "FIXTURE: claim keeps its world");
    assert_eq!(
        stored.value,
        Value::from(value),
        "FIXTURE: claim holds its value"
    );
}

/// S exports its named WORLD's month window, where a CLAIM in that WORLD
/// lives, through the live pact.
fn export_world(
    s: &Fixture,
    pact_hex: &str,
    s_world: EntityId,
) -> (String, Vec<u8>, oneiron::sync::ConnectDelivery) {
    let delivery = export_window(s, pact_hex, &world_window(s_world), s_world);
    let window_key = delivery.body.window_key.clone();
    let update = delivery.body.update.clone();
    (window_key, update, delivery)
}

/// B's bound client for the crafted updates: the same principal, grant, scope
/// and world the rejoin door binds, without its crate-private owner check.
fn bound_client(b: &Fixture, pact: &ActivePact) -> SyncClient {
    let fold = b
        .vault
        .authority_fold()
        .expect("FIXTURE: B fold holds the pact");
    let state = fold
        .federation_pacts
        .get(&pact.pact)
        .expect("FIXTURE: B pact state");
    let peer_vault = state.peer_vault_id;
    let ScopeAxis::Some(worlds) = &state.effective_scope.worlds else {
        panic!("FIXTURE: B pact names its WORLD");
    };
    let world = worlds.first().expect("FIXTURE: B pact WORLD").0;
    let selector = SyncSelector::new(
        pact.b_grant,
        pact.b_member,
        SyncSelectorWorld::World(LocalWorldId::try_from(world).expect("FIXTURE: B WORLD is local")),
        vec![],
        vec![],
    );
    let peer = FederationPeer::authorize(
        &b.vault,
        pact.b_member,
        FederationGrantScope::Connect {
            peer_vault_id: peer_vault,
        },
        &selector,
    )
    .expect("FIXTURE: B binds the live peer");
    let (client, _events) = SyncClient::new(
        Arc::clone(&b.manager),
        SyncClientConfig {
            federation_peer: Some(peer),
            ..Default::default()
        },
    )
    .expect("FIXTURE: bound client opens");
    client
}

/// A crafted update: `base` without the entity rows of `dropped`, plus, when
/// `tombstone` names one, a v2 tombstone for that row with its reason and
/// request id, as the engine writes one.
fn crafted_update(
    base: Option<&[u8]>,
    dropped: &[EntityId],
    tombstone: Option<(EntityId, TombstoneReason, [u8; 16])>,
) -> Vec<u8> {
    let doc = LoroDoc::new();
    if let Some(base) = base {
        doc.import(base).expect("FIXTURE: base update imports");
    }
    for row in dropped {
        doc.get_map("entities")
            .delete(&row.to_hex())
            .expect("FIXTURE: entity row deletes");
    }
    if let Some((id, reason, request_id)) = tombstone {
        let value = TombstoneValueV2 {
            reason,
            deleted_at: T0 + 60,
            request_id,
        }
        .encode()
        .to_vec();
        doc.get_map("tombstones")
            .insert(&id.to_hex(), LoroValue::Binary(value.into()))
            .expect("FIXTURE: tombstone inserts");
    }
    doc.commit();
    doc.export(ExportMode::all_updates())
        .expect("FIXTURE: crafted update exports")
}

fn setup() -> (Fixture, Fixture, ActivePact) {
    let s = Fixture::open(0x11);
    let b = Fixture::open(0x22);
    let pact = active_pact(&s, &b);
    // The minted guest actor is the grant's member: the bound peer speaks as
    // it, under the Connect scope for S.
    assert_ne!(
        pact.b_grant, pact.b_member,
        "FIXTURE: the grant and its guest actor differ"
    );
    (s, b, pact)
}

/// S's month window of its named WORLD, where a CLAIM in that WORLD lives and
/// its delete is published (`deletion/delete/plan.rs`).
fn world_window(world: EntityId) -> String {
    format!("{WINDOW}@{}", world.to_hex())
}

/// S exports `window_key` of its named WORLD through the live pact.
fn export_window(
    s: &Fixture,
    pact_hex: &str,
    window_key: &str,
    s_world: EntityId,
) -> oneiron::sync::ConnectDelivery {
    s.manager
        .open_window(&WindowKey::new(window_key))
        .expect("FIXTURE: S window opens");
    SyncClient::export_connect_window_as(
        &s.manager,
        &s.proof,
        &s.issuer,
        ConnectExportRequest {
            pact: pact_hex.to_owned(),
            window_key: window_key.to_owned(),
            world_ref: s_world,
            facets: vec![],
            bands: vec![],
        },
    )
    .expect("FIXTURE: S exports its WORLD's window")
}

/// The keys of an exported update's entities map.
fn carried_rows(update: &[u8]) -> BTreeSet<String> {
    let doc = LoroDoc::new();
    doc.import(update).expect("FIXTURE: the update imports");
    let mut keys = BTreeSet::new();
    doc.get_map("entities").for_each(|key, _| {
        keys.insert(key.to_owned());
    });
    keys
}

/// B rejoins S's delivery of its WORLD's month window; the rejoin lands.
fn rejoin(b: &Fixture, delivery: oneiron::sync::ConnectDelivery) {
    let rejoined = SyncClient::rejoin_connect_as(&b.manager, &b.proof, delivery)
        .expect("FIXTURE: B rejoins the delivery");
    assert!(
        matches!(rejoined.status, ConnectRejoinStatus::Imported),
        "FIXTURE: the rejoin lands, not defers: {:?}",
        rejoined.status
    );
}

#[test]
fn a_peers_hard_delete_after_a_wider_soft_delete_removes_the_shell() {
    let (s, b, pact) = setup();
    let subject = put_person(&s.vault, "kenji");
    let claim = put_claim(&s.vault, subject, Some(pact.s_world));
    let (window_key, _first_update, delivery) = export_world(&s, &pact.pact_hex, pact.s_world);
    rejoin(&b, delivery);
    let delivered = stored_row(&b.vault, &claim)
        .expect("FIXTURE: B row reads")
        .expect("FIXTURE: B holds the delivered CLAIM");

    // The soft delete rides an update that also brings a new row C2. B's
    // admission writes that row before the tombstone, so the soft tombstone
    // is not the first op its admission authors.
    let second_subject = put_person(&s.vault, "haru");
    let second = put_claim(&s.vault, second_subject, Some(pact.s_world));
    let (_, second_update, _) = export_world(&s, &pact.pact_hex, pact.s_world);
    let soft = crafted_update(
        Some(&second_update),
        &[claim],
        Some((claim, TombstoneReason::UserDelete, [0x5b; 16])),
    );
    let mut client = bound_client(&b, &pact);
    let result =
        client.import_federated_window_update(&window_key, &soft, FederationAdmissionRole::Guest);
    let shell = stored_row(&b.vault, &claim).expect("FIXTURE: B row reads after the soft delete");
    assert!(
        shell
            .as_ref()
            .is_some_and(|shell| shell.len() < delivered.len()),
        "FIXTURE: the live peer's soft delete leaves a shell of C: {result:?}"
    );
    assert!(
        stored_row(&b.vault, &second)
            .expect("FIXTURE: C2 reads after the soft delete")
            .is_some(),
        "FIXTURE: C2 lands beside the soft delete: {result:?}"
    );

    // The hard delete rides alone: its tombstone is the first op its
    // admission authors.
    let hard = crafted_update(
        None,
        &[],
        Some((claim, TombstoneReason::UserHardDelete, [0x5c; 16])),
    );
    let result =
        client.import_federated_window_update(&window_key, &hard, FederationAdmissionRole::Guest);
    assert!(
        stored_row(&b.vault, &claim)
            .expect("FIXTURE: B row reads after the hard delete")
            .is_none(),
        "KEPT-SOFT-DELETED-SHELL: the live peer's later hard delete lost to its earlier soft delete: {result:?}"
    );
}

#[test]
fn a_peers_second_image_of_a_claim_lands_over_a_wider_first_delivery() {
    let (s, b, pact) = setup();
    // X is minted before C, so its key sorts first and the first delivery's
    // admission writes C after X.
    let earlier_subject = put_person(&s.vault, "haru");
    let earlier = put_claim(&s.vault, earlier_subject, Some(pact.s_world));
    let subject = put_person(&s.vault, "kenji");
    let claim = put_claim(&s.vault, subject, Some(pact.s_world));
    assert!(
        earlier.to_hex() < claim.to_hex(),
        "FIXTURE: X's key sorts before C's"
    );
    let (window_key, first_update, delivery) = export_world(&s, &pact.pact_hex, pact.s_world);
    let carried = carried_rows(&first_update);
    assert!(
        carried.contains(&earlier.to_hex()) && carried.contains(&claim.to_hex()),
        "FIXTURE: the first delivery carries X and C"
    );
    rejoin(&b, delivery);
    let first_image = stored_row(&b.vault, &claim)
        .expect("FIXTURE: B row reads")
        .expect("FIXTURE: B holds the first image of C");
    assert!(
        stored_row(&b.vault, &earlier)
            .expect("FIXTURE: B X reads")
            .is_some(),
        "FIXTURE: B holds X"
    );

    // S's next image of C rides alone: C's write is the first op its
    // admission authors.
    write_claim(&s.vault, &claim, subject, Some(pact.s_world), SECOND_VALUE);
    let (_, next_update, _) = export_world(&s, &pact.pact_hex, pact.s_world);
    let second = crafted_update(Some(&next_update), &[earlier], None);
    let carried = carried_rows(&second);
    assert!(
        carried.contains(&claim.to_hex()) && !carried.contains(&earlier.to_hex()),
        "FIXTURE: the second update carries C and not X"
    );
    let mut client = bound_client(&b, &pact);
    let result =
        client.import_federated_window_update(&window_key, &second, FederationAdmissionRole::Guest);
    let second_image = stored_row(&b.vault, &claim)
        .expect("FIXTURE: B row reads after the second image")
        .expect("FIXTURE: B still holds C");
    assert_ne!(
        second_image, first_image,
        "KEPT-FIRST-IMAGE: the live peer's second image of C lost to its first: {result:?}"
    );
    assert!(
        stored_row(&b.vault, &earlier)
            .expect("FIXTURE: B X reads after the second image")
            .is_some(),
        "FIXTURE: B still holds X (the second update only omits it)"
    );
}
