//! A live peer's record tombstone removes the copy its pact delivered
//! (CROSS-VAULT-DELETE-NEVER-ADMITTED = A).
//!
//! Before: a federation peer's update carrying any tombstone was refused
//! whole (`reject_federated_tombstones`), so an owner's delete never reached
//! the copy a live Connect share had delivered; and the sender's Connect
//! delivery carried no tombstone at all.
//! After: on the live peer lane each tombstone the delivering pact proves
//! lands in the part whose window holds its row, and every other tombstone is
//! dropped while the rest of the update lands. The sender's Connect delivery
//! carries the owner's delete of a record row it sent that peer, and no
//! other; a guest document carries none.
//!
//! - `a_live_peers_delete_removes_the_copy_its_pact_delivered`: red on main
//!   (the import is refused whole and C stays), green on the head.
//! - `a_peers_delete_of_a_row_it_never_delivered_keeps_the_row`: guard, green
//!   on both (no delivery ledger row, so the tombstone is dropped).
//! - `a_peers_delete_of_a_topology_row_is_dropped`: guard, green on both (a
//!   membership or topology kind is never admitted).
//! - `a_dropped_tombstone_leaves_the_rest_of_the_update_landing`: red on main
//!   (the whole update is refused, C2 never lands), green on the head.
//! - `an_owners_delete_of_a_row_the_peer_was_sent_removes_its_copy`: red on
//!   the receiver-only head (the next delivery carries no tombstone), green on
//!   the sender's head.
//! - `a_delete_of_a_row_the_peer_was_never_sent_stays_home`: guard, green on
//!   both (no prepared export under the grant listed the row).
//! - `a_guest_document_carries_no_delete`: guard, green on both.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test federated_record_tombstone_admission`.
#![cfg(all(feature = "sync", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use loro::{ExportMode, LoroDoc, LoroValue};
use oneiron::authority::{
    AuthorityVaultId, FederationPactStatus, HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::{DeleteReason, TombstoneReason, TombstoneValueV2};
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
use oneiron::sync::selector::{GuestDocumentShareRequest, share_guest_document_as_owner};
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
            "tombstone-admission",
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
        .create_world(&s.proof, "Tombstone sender", T0)
        .expect("FIXTURE: S named WORLD");
    let b_world = b
        .vault
        .create_world(&b.proof, "Tombstone receiver", T0)
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
fn put_claim(vault: &Vault, subject: EntityId, world: Option<EntityId>) -> EntityId {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        "lighthouse keeper".into(),
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
        .put_claim(&id, &body, at_learned(), LEARNED_AT)
        .expect("FIXTURE: CLAIM lands");
    let stored = vault
        .get_claim(&id)
        .expect("FIXTURE: CLAIM reads back")
        .expect("FIXTURE: claim landed");
    assert_eq!(stored.world, world, "FIXTURE: claim keeps its world");
    assert_eq!(stored.scope, body.scope, "FIXTURE: claim keeps its stamp");
    id
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

/// A crafted update: `base` (or nothing) plus a v2 hard-delete tombstone for
/// each of `ids`, as the engine writes one.
fn tombstone_update(base: Option<&[u8]>, ids: &[EntityId]) -> Vec<u8> {
    let doc = LoroDoc::new();
    if let Some(base) = base {
        doc.import(base).expect("FIXTURE: base update imports");
    }
    for id in ids {
        let value = TombstoneValueV2 {
            reason: TombstoneReason::UserHardDelete,
            deleted_at: T0 + 60,
            request_id: [0x5a; 16],
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

#[test]
fn a_live_peers_delete_removes_the_copy_its_pact_delivered() {
    let (s, b, pact) = setup();
    let subject = put_person(&s.vault, "kenji");
    let claim = put_claim(&s.vault, subject, Some(pact.s_world));
    let (window_key, _first_update, delivery) = export_world(&s, &pact.pact_hex, pact.s_world);
    let rejoined = SyncClient::rejoin_connect_as(&b.manager, &b.proof, delivery)
        .expect("FIXTURE: B rejoins the delivery");
    assert!(
        matches!(rejoined.status, ConnectRejoinStatus::Imported),
        "FIXTURE: the rejoin lands, not defers: {:?}",
        rejoined.status
    );
    assert!(
        stored_row(&b.vault, &claim)
            .expect("FIXTURE: B row reads")
            .is_some(),
        "FIXTURE: B holds the delivered CLAIM"
    );
    let history = b
        .vault
        .federation_delivery_history(&[claim])
        .expect("FIXTURE: delivery history reads");
    assert_eq!(history.len(), 1, "FIXTURE: one delivery record names C");
    assert_eq!(
        history[0].grant_ref, pact.b_grant,
        "FIXTURE: the record names G"
    );
    assert_eq!(
        history[0].source_vault, s.vault_id,
        "FIXTURE: the record names S as its source vault"
    );
    assert_eq!(
        history[0].delivering_pact, pact.pact,
        "FIXTURE: the record names the delivering pact"
    );

    let mut client = bound_client(&b, &pact);
    let update = tombstone_update(None, &[claim]);
    let result =
        client.import_federated_window_update(&window_key, &update, FederationAdmissionRole::Guest);
    assert!(
        stored_row(&b.vault, &claim)
            .expect("FIXTURE: B row reads after the delete")
            .is_none(),
        "KEPT-DELETED-COPY: the live peer's delete left the copy its pact delivered: {result:?}"
    );
}

#[test]
fn a_peers_delete_of_a_row_it_never_delivered_keeps_the_row() {
    let (s, b, pact) = setup();
    let subject = put_person(&s.vault, "kenji");
    let claim = put_claim(&s.vault, subject, Some(pact.s_world));
    let (window_key, _first_update, delivery) = export_world(&s, &pact.pact_hex, pact.s_world);
    let rejoined = SyncClient::rejoin_connect_as(&b.manager, &b.proof, delivery)
        .expect("FIXTURE: B rejoins the delivery");
    assert!(
        matches!(rejoined.status, ConnectRejoinStatus::Imported),
        "FIXTURE: the rejoin lands, not defers: {:?}",
        rejoined.status
    );
    assert!(
        stored_row(&b.vault, &claim)
            .expect("FIXTURE: B row reads")
            .is_some(),
        "FIXTURE: B holds the delivered CLAIM"
    );

    let local_subject = put_person(&b.vault, "yuki");
    let local = put_claim(&b.vault, local_subject, Some(pact.b_world));
    assert!(
        stored_row(&b.vault, &local)
            .expect("FIXTURE: B own row reads")
            .is_some(),
        "FIXTURE: B holds its own CLAIM"
    );
    assert!(
        b.vault
            .federation_delivery_history(&[local])
            .expect("FIXTURE: own history reads")
            .is_empty(),
        "FIXTURE: no delivery record names B's own row"
    );

    let mut client = bound_client(&b, &pact);
    let update = tombstone_update(None, &[local]);
    let result =
        client.import_federated_window_update(&window_key, &update, FederationAdmissionRole::Guest);
    assert!(
        stored_row(&b.vault, &local)
            .expect("FIXTURE: B own row reads after the delete")
            .is_some(),
        "FOREIGN-DELETE: a peer's delete removed a row it never delivered: {result:?}"
    );
}

#[test]
fn a_peers_delete_of_a_topology_row_is_dropped() {
    let (s, b, pact) = setup();
    let subject = put_person(&s.vault, "kenji");
    let claim = put_claim(&s.vault, subject, Some(pact.s_world));
    let (window_key, _first_update, delivery) = export_world(&s, &pact.pact_hex, pact.s_world);
    let rejoined = SyncClient::rejoin_connect_as(&b.manager, &b.proof, delivery)
        .expect("FIXTURE: B rejoins the delivery");
    assert!(
        matches!(rejoined.status, ConnectRejoinStatus::Imported),
        "FIXTURE: the rejoin lands, not defers: {:?}",
        rejoined.status
    );
    assert!(
        stored_row(&b.vault, &claim)
            .expect("FIXTURE: B row reads")
            .is_some(),
        "FIXTURE: B holds the delivered CLAIM"
    );
    assert!(
        stored_row(&b.vault, &pact.b_grant)
            .expect("FIXTURE: B grant reads")
            .is_some(),
        "FIXTURE: B holds its own grant row"
    );

    // The foreign WORLD id S's WORLD lands under here, when the delivery
    // carried its row.
    let fold = b.vault.authority_fold().expect("FIXTURE: B fold reads");
    let foreign = oneiron::federation::pact_foreign_world(&fold, &pact.pact, pact.s_world)
        .expect("FIXTURE: foreign WORLD derives")
        .expect("FIXTURE: the fold names the pact")
        .entity_id();
    let world_reachable = !b
        .vault
        .federation_delivery_history(&[foreign])
        .expect("FIXTURE: WORLD history reads")
        .is_empty()
        && stored_row(&b.vault, &foreign)
            .expect("FIXTURE: foreign WORLD reads")
            .is_some();

    let mut ids = vec![pact.b_grant];
    if world_reachable {
        ids.push(foreign);
    }
    let mut client = bound_client(&b, &pact);
    let update = tombstone_update(None, &ids);
    let result =
        client.import_federated_window_update(&window_key, &update, FederationAdmissionRole::Guest);
    assert!(
        stored_row(&b.vault, &pact.b_grant)
            .expect("FIXTURE: B grant reads after the delete")
            .is_some(),
        "TOPOLOGY-DELETE: a peer's delete removed the grant row: {result:?}"
    );
    if world_reachable {
        assert!(
            stored_row(&b.vault, &foreign)
                .expect("FIXTURE: foreign WORLD reads after the delete")
                .is_some(),
            "TOPOLOGY-DELETE: a peer's delete removed the foreign WORLD row: {result:?}"
        );
    }
}

#[test]
fn a_dropped_tombstone_leaves_the_rest_of_the_update_landing() {
    let (s, b, pact) = setup();
    let subject = put_person(&s.vault, "kenji");
    let claim = put_claim(&s.vault, subject, Some(pact.s_world));
    let (_window_key, _first_update, delivery) = export_world(&s, &pact.pact_hex, pact.s_world);
    let rejoined = SyncClient::rejoin_connect_as(&b.manager, &b.proof, delivery)
        .expect("FIXTURE: B rejoins the first delivery");
    assert!(
        matches!(rejoined.status, ConnectRejoinStatus::Imported),
        "FIXTURE: the first rejoin lands, not defers: {:?}",
        rejoined.status
    );
    assert!(
        stored_row(&b.vault, &claim)
            .expect("FIXTURE: B row reads")
            .is_some(),
        "FIXTURE: B holds the first CLAIM"
    );

    let local_subject = put_person(&b.vault, "yuki");
    let local = put_claim(&b.vault, local_subject, Some(pact.b_world));
    assert!(
        stored_row(&b.vault, &local)
            .expect("FIXTURE: B own row reads")
            .is_some(),
        "FIXTURE: B holds its own CLAIM"
    );

    let second_subject = put_person(&s.vault, "haru");
    let second = put_claim(&s.vault, second_subject, Some(pact.s_world));
    let (window_key, second_update, _) = export_world(&s, &pact.pact_hex, pact.s_world);
    assert!(
        stored_row(&b.vault, &second)
            .expect("FIXTURE: second row reads before the import")
            .is_none(),
        "FIXTURE: B does not hold C2 before the crafted import"
    );

    let mut client = bound_client(&b, &pact);
    let update = tombstone_update(Some(&second_update), &[local]);
    let result =
        client.import_federated_window_update(&window_key, &update, FederationAdmissionRole::Guest);
    assert!(
        stored_row(&b.vault, &second)
            .expect("FIXTURE: second row reads after the import")
            .is_some(),
        "WHOLE-UPDATE-REFUSED: a dropped tombstone refused the rest of the update: {result:?}"
    );
    assert!(
        stored_row(&b.vault, &local)
            .expect("FIXTURE: B own row reads after the import")
            .is_some(),
        "FIXTURE: B still holds its own row after the dropped tombstone"
    );
}

/// S's month window of its named WORLD, where the delete of a CLAIM in that
/// WORLD is published (`deletion/delete/plan.rs`).
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

/// The keys of `doc`'s map `name`.
fn map_keys(doc: &LoroDoc, name: &str) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    doc.get_map(name).for_each(|key, _| {
        keys.insert(key.to_owned());
    });
    keys
}

/// The row ids `doc`'s tombstones map names.
fn tombstone_keys(doc: &LoroDoc) -> BTreeSet<String> {
    map_keys(doc, "tombstones")
}

/// The keys of an exported update's map `name`.
fn carried_keys(update: &[u8], name: &str) -> BTreeSet<String> {
    let doc = LoroDoc::new();
    doc.import(update).expect("FIXTURE: the update imports");
    map_keys(&doc, name)
}

/// The row ids an exported update's tombstones map names.
fn carried_tombstones(update: &[u8]) -> BTreeSet<String> {
    carried_keys(update, "tombstones")
}

/// The row ids S's own `window_key` window holds tombstones of.
fn window_tombstones(s: &Fixture, window_key: &str) -> BTreeSet<String> {
    let window = s
        .manager
        .open_window(&WindowKey::new(window_key))
        .expect("FIXTURE: S window opens");
    tombstone_keys(&window.doc)
}

/// S's CLAIM in its WORLD, sent to B by a Connect delivery of the WORLD's
/// month window, where the CLAIM lives and its delete is published
/// (`deletion/delete/plan.rs`), with that window's key.
fn sent_claim(s: &Fixture, b: &Fixture, pact: &ActivePact) -> (String, EntityId) {
    let subject = put_person(&s.vault, "kenji");
    let claim = put_claim(&s.vault, subject, Some(pact.s_world));
    let window_key = world_window(pact.s_world);
    let delivery = export_window(s, &pact.pact_hex, &window_key, pact.s_world);
    assert!(
        carried_keys(&delivery.body.update, "entities").contains(&claim.to_hex()),
        "FIXTURE: the first delivery carries the CLAIM"
    );
    let rejoined = SyncClient::rejoin_connect_as(&b.manager, &b.proof, delivery)
        .expect("FIXTURE: B rejoins the first delivery");
    assert!(
        matches!(rejoined.status, ConnectRejoinStatus::Imported),
        "FIXTURE: the first rejoin lands, not defers: {:?}",
        rejoined.status
    );
    assert!(
        stored_row(&b.vault, &claim)
            .expect("FIXTURE: B row reads")
            .is_some(),
        "FIXTURE: B holds the CLAIM S sent"
    );
    (window_key, claim)
}

/// S's owner hard-deletes `id`; S holds no row of it after.
fn hard_delete(s: &Fixture, id: &EntityId) {
    let outcome = s
        .vault
        .delete_entity_with_reason_as_owner(&s.proof, id, DeleteReason::UserHardDelete)
        .expect("FIXTURE: S owner hard-deletes the row");
    assert!(outcome.existed, "FIXTURE: the deleted row existed");
    assert!(
        stored_row(&s.vault, id)
            .expect("FIXTURE: S row reads after its delete")
            .is_none(),
        "FIXTURE: S holds no row after its hard delete"
    );
}

#[test]
fn an_owners_delete_of_a_row_the_peer_was_sent_removes_its_copy() {
    let (s, b, pact) = setup();
    let (window_key, claim) = sent_claim(&s, &b, &pact);
    hard_delete(&s, &claim);
    assert!(
        window_tombstones(&s, &window_key).contains(&claim.to_hex()),
        "FIXTURE: S's window holds the CLAIM's tombstone"
    );

    let delivery = export_window(&s, &pact.pact_hex, &window_key, pact.s_world);
    let carried = carried_tombstones(&delivery.body.update);
    assert!(
        carried.contains(&claim.to_hex()),
        "NO-DELETE-SENT: S's next delivery under the live pact omits its owner's delete of a row \
         it sent B: {carried:?}"
    );
    let rejoined = SyncClient::rejoin_connect_as(&b.manager, &b.proof, delivery)
        .expect("B rejoins the delivery that carries the delete");
    assert!(
        matches!(rejoined.status, ConnectRejoinStatus::Imported),
        "the delete's delivery lands, not defers: {:?}",
        rejoined.status
    );
    assert!(
        stored_row(&b.vault, &claim)
            .expect("FIXTURE: B row reads after the delete")
            .is_none(),
        "KEPT-DELETED-COPY: B keeps its copy of a row S's owner deleted"
    );
}

#[test]
fn a_delete_of_a_row_the_peer_was_never_sent_stays_home() {
    let (s, b, pact) = setup();
    let (window_key, claim) = sent_claim(&s, &b, &pact);
    let unsent_subject = put_person(&s.vault, "haru");
    let unsent = put_claim(&s.vault, unsent_subject, Some(pact.s_world));
    hard_delete(&s, &claim);
    hard_delete(&s, &unsent);
    assert!(
        window_tombstones(&s, &window_key).contains(&unsent.to_hex()),
        "FIXTURE: S's window holds the unsent CLAIM's tombstone"
    );

    let delivery = export_window(&s, &pact.pact_hex, &window_key, pact.s_world);
    let carried = carried_tombstones(&delivery.body.update);
    assert!(
        !carried.contains(&unsent.to_hex()),
        "LEAK: S's delivery names the delete of a row it never sent B: {carried:?}"
    );
}

#[test]
fn a_guest_document_carries_no_delete() {
    let (s, b, pact) = setup();
    let (window_key, claim) = sent_claim(&s, &b, &pact);
    hard_delete(&s, &claim);
    assert!(
        window_tombstones(&s, &window_key).contains(&claim.to_hex()),
        "FIXTURE: S's window holds the CLAIM's tombstone"
    );

    let (document, _) = share_guest_document_as_owner(
        &s.manager,
        &s.proof,
        &s.issuer,
        &GuestDocumentShareRequest {
            grant_ref: pact.s_grant,
            world_ref: pact.s_world,
            window_key,
            facets: vec![],
            bands: vec![],
        },
    )
    .expect("FIXTURE: S shares its WORLD's window as a guest document");
    let carried = carried_tombstones(&document.envelope.body.update);
    assert!(
        carried.is_empty(),
        "GUEST-DOCUMENT-DELETE: a guest document carries a tombstone: {carried:?}"
    );
}
