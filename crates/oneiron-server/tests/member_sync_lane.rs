//! The client half of the selector-only member lane (MEMBER-SYNC PR 2, D7-D8).
//!
//! T1 runs a real HOME (the PR 1 shared-vault 42 fixture) against a real
//! `SyncConnection` built exactly as `open_lane` builds a `Member` lane
//! (`crates/oneiron-server/src/shared_envs.rs`, MEMBER-SYNC P1): `Opened`,
//! the slip's transport credential binding the transport and the NOTE session
//! alike, the `All` selector from the slip's own claims, `member_lane: true`.
//! The client env holds no copy of the grant (MEMBER-SYNC D8: HOME proves the
//! grant at the upgrade, so a fresh env starts).
//!
//! It asserts: a `Synced` event; the granted window's thin index entry lands
//! in the client vault (`residence_index`, an `ri:w:` row, not a materialized
//! body); the client stores no root document (`server_windows` stays empty);
//! and no close, error or disconnect after `Synced` over a run covering the
//! steady-loop housekeeping tick (`EPHEMERAL_HOUSEKEEPING_INTERVAL_SECS = 1`,
//! `crates/oneiron/src/sync/connection/session.rs:42`; this test observes
//! 2.5 s after `Synced`).
//!
//! T4 (`a_member_upgrade_under_a_world_bounded_pact_is_refused_with_its_reason`)
//! is UNTESTED: no public or `test-hooks` fixture binds an `Active` pact with
//! a world ceiling to the member grant (see the build report). No new door.
//!
//! The lane header value is a wire string, not a server internal, as in PR 1.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope, ScopeAxis,
    ScopeId, SharedVaultPreset,
};
use oneiron::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD,
};
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::client::NoteSyncSession;
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::server_state::persist_window_snapshot;
use oneiron::sync::window::reverse_rematerialize;
use oneiron::sync::{
    ConnectionConfig, OpenedItem, SyncClient, SyncClientConfig, SyncConnection, SyncEvent,
    SyncResidenceMode, SyncSelector, SyncSelectorWorld, SyncTransportCredential, WindowKey,
    WindowManager, put_selector_test_federation_grant,
};
use oneiron::write_envelope::claim_body::{decode_claim_body, encode_claim_body};
use oneiron::{DeleteReason, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::json;

/// Runs `test` on a thread with room for the engine's sync futures, on a
/// multi-thread runtime with room for the served HOME beside the lane.
fn run_on_engine_stack<F, Fut>(test: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    let driver = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .unwrap()
                .block_on(test());
        })
        .unwrap();
    if let Err(panic) = driver.join() {
        std::panic::resume_unwind(panic);
    }
}

/// A live PERSON row named `name` (MEMBER-SYNC fixture person `yuki`).
fn person(vault: &Vault, name: &str) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&json!({"name": name})).unwrap(),
        )
        .unwrap();
    id
}

/// A caller presentation: the minted slip and its holder key.
struct Caller {
    slip: CapabilitySlip,
    key: SigningKey,
}

/// Mints a human slip for `holder` naming `grant`, carrying the grant whole
/// (no record or channel caveat), as the PR 1 member fixture does.
fn mint(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    root: &CapabilitySlip,
    holder: EntityId,
    grant: Option<(EntityId, &FederationGrant)>,
    class: &str,
) -> Caller {
    let key = SigningKey::from_bytes(blake3::hash(EntityId::now().as_bytes()).as_bytes());
    let mut claims = root.claims.clone();
    claims.slip_id = *blake3::hash(EntityId::now().as_bytes()).as_bytes();
    claims.parent_id = None;
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some(class.to_owned());
    claims.org_ref = None;
    claims.binding_key = key.verifying_key().to_bytes();
    claims.single_use = false;
    claims.records = BTreeSet::new();
    claims.channels.clear();
    claims.grant_ref = grant.map(|(id, _)| id.to_hex());
    if let Some((_, grant)) = grant {
        claims.scope = grant.authority_scope.clone();
    }
    Caller {
        slip: vault.mint_capability_slip(issuer, claims).unwrap(),
        key,
    }
}

/// The HOME side of T1: a shared vault 42 with one member grant, one granted
/// window in the client's current month holding one facet, one far window the
/// catalogue months never name, and a served sync endpoint.
struct Fixture {
    task: tokio::task::JoinHandle<()>,
    url: String,
    vault: Arc<Vault>,
    grant_id: EntityId,
    caller: Caller,
    window: WindowKey,
    other_window: WindowKey,
    item: EntityId,
    other_item: EntityId,
    _dir: tempfile::TempDir,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Builds the HOME: shared vault 42, member `yuki`, whole-grant human slip,
/// the granted window at the current month of the vault's recorded clock
/// (the months the member catalogue asks are current plus previous, so the
/// granted rows are asked for) and a far window at `2020-01` the catalogue
/// never names.
async fn fixture() -> Fixture {
    world_fixture(0).await.fx
}

/// The member lane's client configuration, built exactly as `open_lane` builds
/// a `Member` lane (`crates/oneiron-server/src/shared_envs.rs`, MEMBER-SYNC
/// P1): `Opened`, the slip's transport credential binding the transport and
/// the NOTE session alike, the `All` selector from the slip's own claims
/// (`grant_ref`, `holder_ref`, MEMBER-SYNC D8), `member_lane: true`. The ids
/// come from the slip's claims as `lane_reach_of` reads them, not from the
/// fixture's copies, so the config proves the slip carries the grant.
fn member_lane_client_config(url: String, caller: &Caller) -> SyncClientConfig {
    let token = caller.slip.to_token().unwrap();
    let key = caller.key.clone();
    let grant = EntityId::from_hex(
        caller
            .slip
            .claims
            .grant_ref
            .as_deref()
            .expect("the lane slip names its grant"),
    )
    .expect("the lane slip's grant_ref is an entity id");
    let holder = EntityId::from_hex(&caller.slip.claims.holder_ref)
        .expect("the lane slip's holder is an actor");
    SyncClientConfig {
        server_url: url,
        residence_mode: SyncResidenceMode::Opened,
        transport_credential: Some(SyncTransportCredential::new(token.clone(), key.clone())),
        note_session: Some(NoteSyncSession::new(token, key)),
        residence_selector: Some(SyncSelector::new(
            grant,
            holder,
            SyncSelectorWorld::All,
            Vec::new(),
            Vec::new(),
        )),
        member_lane: true,
        ..SyncClientConfig::default()
    }
}

#[test]
fn a_member_lane_syncs_its_granted_window_and_stays_up() {
    run_on_engine_stack(|| async {
        let fx = fixture().await;
        // A fresh env holds no copy of the grant (MEMBER-SYNC D8): HOME proves
        // it at the upgrade, so the lane starts without a local read.
        let client_dir = tempfile::tempdir().unwrap();
        let client_vault = Arc::new(Vault::open(client_dir.path(), VaultConfig::device()).unwrap());
        assert!(
            client_vault.get_raw(&fx.grant_id).unwrap().is_none(),
            "the client env starts with no copy of its grant"
        );
        // The lane's own manager over its own vault, as `open_lane` builds it:
        // a fresh materializer with the shared vault's lease scope, attached.
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&client_vault),
            Arc::new(Materializer::with_lease_vault_id(42)),
            "yuki",
        ));
        manager.attach_to_vault();
        let config = member_lane_client_config(fx.url.clone(), &fx.caller);
        let probe_config = SyncClientConfig {
            server_url: fx.url.clone(),
            ..SyncClientConfig::default()
        };
        let connection = Arc::new(
            SyncConnection::new(
                Arc::clone(&manager),
                ConnectionConfig {
                    client_config: config,
                    auto_reconnect: true,
                },
            )
            .unwrap(),
        );
        // The run's events by `Debug` form, the first `Synced` signal, and
        // a signal on a disconnect, error or refused upgrade after it.
        let events = Arc::new(Mutex::new(Vec::new()));
        let synced = Arc::new(tokio::sync::Notify::new());
        let trouble = Arc::new(tokio::sync::Notify::new());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let run_handle = tokio::spawn({
            let connection = Arc::clone(&connection);
            let events = Arc::clone(&events);
            let synced = Arc::clone(&synced);
            let trouble = Arc::clone(&trouble);
            let mut synced_seen = false;
            async move {
                connection
                    .run_observed(shutdown_rx, move |event: SyncEvent| {
                        let debug = format!("{event:?}");
                        if debug == "StatusChanged(Synced)" {
                            synced_seen = true;
                            synced.notify_one();
                        } else if synced_seen
                            && (debug == "StatusChanged(Disconnected)"
                                || debug.starts_with("Error(")
                                || debug.starts_with("Upgrade"))
                        {
                            trouble.notify_one();
                        }
                        events.lock().expect("event sink").push(debug);
                    })
                    .await
            }
        });
        tokio::time::timeout(Duration::from_secs(30), synced.notified())
            .await
            .expect("the member lane reaches Synced");
        // After `Synced` the lane stays up over the steady-loop housekeeping
        // tick (`EPHEMERAL_HOUSEKEEPING_INTERVAL_SECS = 1`,
        // `crates/oneiron/src/sync/connection/session.rs:42`): 2.5 s covers
        // two ticks, so a forbidden steady frame would have closed the lane.
        // The wait ends early on such a close; the events below show it.
        let _ = tokio::time::timeout(Duration::from_millis(2_500), trouble.notified()).await;
        let observed: Vec<String> = events.lock().expect("event sink").clone();
        let synced_at = observed
            .iter()
            .position(|event| event == "StatusChanged(Synced)")
            .expect("a Synced event");
        let after_synced = &observed[synced_at..];
        assert!(
            !after_synced
                .iter()
                .any(|event| event == "StatusChanged(Disconnected)"),
            "no disconnect after Synced over the observation (events: {observed:?})"
        );
        assert!(
            !after_synced.iter().any(|event| event.starts_with("Error(")),
            "no error after Synced over the observation (events: {observed:?})"
        );
        assert!(
            !after_synced
                .iter()
                .any(|event| event.starts_with("UpgradeForbidden")),
            "no forbidden upgrade after Synced (events: {observed:?})"
        );
        assert!(
            !after_synced
                .iter()
                .any(|event| event == "UpgradeUnauthorized"),
            "no unauthorized upgrade after Synced (events: {observed:?})"
        );
        let _ = shutdown_tx.send(());
        tokio::time::timeout(Duration::from_secs(20), run_handle)
            .await
            .expect("the run ends on its shutdown")
            .expect("the run task ends")
            .expect("the run ends cleanly");
        // The granted window's thin index entry landed: an `ri:w:` row, not a
        // materialized body. The far window the catalogue months never name
        // stays unindexed.
        let index = connection.residence_index().expect("the thin index");
        let granted = index
            .iter()
            .find(|window| window.window == fx.window)
            .expect("the granted window is indexed");
        assert!(
            granted
                .items
                .iter()
                .any(|entry| entry.entity_id == fx.item.to_hex()),
            "the granted item is indexed (index: {index:?})"
        );
        assert!(
            !index.iter().any(|window| window.window == fx.other_window),
            "the far window stays unindexed (index: {index:?})"
        );
        // No root document: a fresh client over the same vault reads no
        // windows from its root, and the vault holds neither a `d:root`
        // snapshot nor a pending `u:root:*` update, so not even an empty
        // root was stored. No full window loaded, no vault body row: the
        // thin index entry stays metadata only.
        let (probe, _probe_events) =
            SyncClient::new(Arc::clone(&manager), probe_config).expect("a probe client");
        assert!(
            probe.server_windows().is_empty(),
            "the member lane stores no root document"
        );
        assert!(
            client_vault.sync_state_get("d:root").unwrap().is_none(),
            "the member lane stores no root snapshot"
        );
        assert!(
            client_vault
                .sync_state_keys_with_prefix("u:root:")
                .unwrap()
                .is_empty(),
            "the member lane stores no pending root update"
        );
        assert!(
            manager.loaded_keys().is_empty(),
            "the member lane loads no full window"
        );
        assert!(
            client_vault.get_raw(&fx.item).unwrap().is_none(),
            "the thin index entry is metadata only, not a vault body"
        );
        assert!(
            client_vault.get_raw(&fx.grant_id).unwrap().is_none(),
            "the client env still holds no copy of its grant"
        );
        assert!(
            !index.iter().any(|window| window
                .items
                .iter()
                .any(|entry| entry.entity_id == fx.other_item.to_hex())),
            "the far item stays unindexed (index: {index:?})"
        );
        // HOME is unchanged by the lane: its grant and rows still stand.
        assert!(
            fx.vault.get_raw(&fx.grant_id).unwrap().is_some(),
            "HOME keeps the member grant"
        );
        assert!(
            fx.vault.get_raw(&fx.item).unwrap().is_some(),
            "HOME keeps the granted row"
        );
    });
}

/// A world window's public claim over `subject`, reading `value` (as the
/// socket fixture's).
fn public_world_claim(subject: EntityId, world: EntityId, value: &str) -> ClaimBody {
    let mut claim = ClaimBody::new(
        "member_sync.fixture",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(value),
        0.8,
        // A residence index reads only surfaceable claims (Auto or Approved).
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    claim.world = Some(world);
    claim.scope = Some(rmpv::Value::Map(vec![(
        rmpv::Value::from("sensitivity"),
        rmpv::Value::from("public"),
    )]));
    claim
}

/// One world window of a world HOME: the world, its current-month window and
/// the claim the window holds.
struct WorldData {
    world: EntityId,
    window: WindowKey,
    item: EntityId,
}

/// A [`Fixture`] HOME plus world windows in its current month, each holding
/// one public claim, before the server starts (the server lists only windows
/// its root names, so worlds must exist before it boots).
struct WorldFixture {
    fx: Fixture,
    member: EntityId,
    worlds: Vec<WorldData>,
}

/// [`fixture`] with `world_count` world windows in its current month, each
/// holding one public claim reading `"before"`, under a whole member grant.
async fn world_fixture(world_count: usize) -> WorldFixture {
    world_fixture_under(
        world_count,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    )
    .await
}

/// [`world_fixture`] under a member grant of `role` and `preset` (a
/// read-only member is a `Viewer` under `ReadOnly`).
async fn world_fixture_under(
    world_count: usize,
    role: FederationGrantRole,
    preset: FederationGrantPreset,
) -> WorldFixture {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().unwrap();
    let issuer = vault.bootstrap_host_slip_issuer().unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    vault.provision_engine_machine_identities(&issuer).unwrap();
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .unwrap();
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .unwrap();
    vault
        .initialize_shared_vault(
            &proof,
            42,
            Some(SharedVaultPreset::Team),
            &[],
            vault.now_recorded_at(),
        )
        .unwrap();
    let member = person(&vault, "yuki");
    let grant_id = EntityId::now();
    let grant = FederationGrant::new(FederationGrantScope::vault(42), member, role, preset);
    put_selector_test_federation_grant(&vault, &grant_id, &grant, vault.now_recorded_at()).unwrap();
    let caller = mint(
        &vault,
        &issuer,
        &root,
        member,
        Some((grant_id, &grant)),
        "human",
    );
    // The vault's recorded clock, not a wall read: the current month, as the
    // member catalogue asks it.
    let now_secs = vault.now_recorded_at();
    let window = WindowKey::from_timestamp(now_secs);
    let other_window = WindowKey::try_new("2020-01").unwrap();
    let at = window.start_timestamp().unwrap() + 86_400;
    let other_at = other_window.start_timestamp().unwrap() + 86_400;
    let item = EntityId::now();
    let other_item = EntityId::now();
    vault
        .put_entity(
            &item,
            ENTITY_TYPE_FACET,
            TimeRange { start: at, end: at },
            at,
            &rmp_serde::to_vec_named(&json!({"title": "Granted facet"})).unwrap(),
        )
        .unwrap();
    vault
        .put_entity(
            &other_item,
            ENTITY_TYPE_FACET,
            TimeRange {
                start: other_at,
                end: other_at,
            },
            other_at,
            &rmp_serde::to_vec_named(&json!({"title": "Far facet"})).unwrap(),
        )
        .unwrap();
    let mut worlds = Vec::new();
    for nth in 0..world_count {
        let world = EntityId::now();
        vault
            .put_entity(
                &world,
                ENTITY_TYPE_WORLD,
                TimeRange { start: 1, end: 1 },
                1,
                &rmp_serde::to_vec_named(&json!({"title": format!("World {nth}")})).unwrap(),
            )
            .unwrap();
        let world_item = EntityId::now();
        let claim = public_world_claim(member, world, "before");
        vault
            .put_entity(
                &world_item,
                ENTITY_TYPE_CLAIM,
                TimeRange { start: at, end: at },
                at,
                &encode_claim_body(&claim).unwrap(),
            )
            .unwrap();
        // The public helper uses this vault's actual keystore issuer, not the test default.
        vault
            .keep_world_on_this_machine_under_for_test(&issuer, world, false)
            .unwrap();
        let world_window = WindowKey::for_world(at, world);
        worlds.push(WorldData {
            world,
            window: world_window,
            item: world_item,
        });
    }
    for key in [&window, &other_window]
        .into_iter()
        .chain(worlds.iter().map(|data| &data.window))
    {
        let doc = create_window_doc("home", key);
        reverse_rematerialize(&vault, &doc, key).unwrap();
        persist_window_snapshot(&vault, key, &doc).unwrap();
    }
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("member-sync-lane".into()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/ws", listener.local_addr().unwrap());
    let app = build_app(server);
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    WorldFixture {
        fx: Fixture {
            task,
            url,
            vault,
            grant_id,
            caller,
            window,
            other_window,
            item,
            other_item,
            _dir: dir,
        },
        member,
        worlds,
    }
}

/// A fresh member env: its vault, window manager and lane config, as the
/// existing test builds them.
struct MemberClient {
    vault: Arc<Vault>,
    manager: Arc<WindowManager>,
    config: SyncClientConfig,
    _dir: tempfile::TempDir,
}

fn member_client(url: String, caller: &Caller) -> MemberClient {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::with_lease_vault_id(42)),
        "yuki",
    ));
    manager.attach_to_vault();
    let config = member_lane_client_config(url, caller);
    MemberClient {
        vault,
        manager,
        config,
        _dir: dir,
    }
}

/// One lane session over `manager`: runs until `Synced`, or up to 30 s, then
/// shuts the run down cleanly and reports whether it synced. A second call
/// reconnects over the same vault state (markers, thin rows, index).
async fn run_lane(manager: &Arc<WindowManager>, config: &SyncClientConfig) -> bool {
    let connection = Arc::new(
        SyncConnection::new(
            Arc::clone(manager),
            ConnectionConfig {
                client_config: config.clone(),
                auto_reconnect: true,
            },
        )
        .unwrap(),
    );
    let synced = Arc::new(tokio::sync::Notify::new());
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run_handle = tokio::spawn({
        let connection = Arc::clone(&connection);
        let synced = Arc::clone(&synced);
        async move {
            connection
                .run_observed(shutdown_rx, move |event: SyncEvent| {
                    if format!("{event:?}") == "StatusChanged(Synced)" {
                        synced.notify_one();
                    }
                })
                .await
        }
    });
    let reached = tokio::time::timeout(Duration::from_secs(30), synced.notified())
        .await
        .is_ok();
    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(20), run_handle)
        .await
        .expect("the run ends on its shutdown")
        .expect("the run task ends")
        .expect("the run ends cleanly");
    reached
}

/// The lane's doors (touch, promote, open, index) over `manager` without a
/// running session: each call dials its own RPC.
fn lane_connection(manager: &Arc<WindowManager>, config: &SyncClientConfig) -> SyncConnection {
    SyncConnection::new(
        Arc::clone(manager),
        ConnectionConfig {
            client_config: config.clone(),
            auto_reconnect: false,
        },
    )
    .unwrap()
}

/// Waits until HOME's live mirror threads a local commit into `window`'s
/// doc: the mirror runs off the writer, so `u:w:` rows past `before` prove
/// the window holds the edit before the member reconnects. Bounded; the
/// yield paces the poll without a sleep.
async fn wait_home_window_update(vault: &Vault, window: &WindowKey, before: usize) {
    let prefix = format!("u:w:{window}:");
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if vault.sync_state_keys_with_prefix(&prefix).unwrap().len() > before {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("HOME's edit reaches its window before the member reconnects");
}

/// The member's read of `item`'s claim value through its open door, when the
/// open lands on the resident row.
async fn member_claim_value(
    connection: &SyncConnection,
    window: &WindowKey,
    item: EntityId,
) -> Option<String> {
    match connection.open_item(window, item).await {
        Ok(OpenedItem::Resident { raw, .. }) => {
            decode_claim_body(raw.get(ENTITY_METADATA_HEADER_LEN..)?, false)
                .ok()?
                .value
                .as_str()
                .map(str::to_owned)
        }
        _ => None,
    }
}

/// Review round 1 of #8364 (P1-1): a promoted world window catches up on
/// reconnect. The member promotes it, syncs, disconnects; HOME edits its
/// claim; the member reconnects and reads the new value after `Synced`.
/// red at 40cf5d7d8818: the reconnect's promotion is granted but no VV is
/// ever asked (a world window's VV waits for a root the lane never gets), so
/// the member still reads the old value after `Synced`.
#[test]
fn a_promoted_world_window_catches_up_on_reconnect() {
    run_on_engine_stack(|| async {
        let home = world_fixture(1).await;
        let data = &home.worlds[0];
        let member = member_client(home.fx.url.clone(), &home.fx.caller);
        let doors = lane_connection(&member.manager, &member.config);
        doors.fetch_item(&data.window, data.item).await.unwrap();
        doors.promote_window(&data.window, data.item).await.unwrap();
        assert!(
            member
                .vault
                .sync_state_get(&format!("rp:w:{}", data.window))
                .unwrap()
                .is_some(),
            "the world window is promoted before the first sync"
        );
        assert!(
            run_lane(&member.manager, &member.config).await,
            "the lane first reaches Synced"
        );
        assert_eq!(
            member_claim_value(&doors, &data.window, data.item)
                .await
                .as_deref(),
            Some("before"),
            "the member reads the promoted claim before HOME's edit"
        );
        // HOME edits the claim while the member is offline; the reconnect
        // starts only once the edit is in HOME's window, so no steady-state
        // invalidation can heal the member mid-session instead of the
        // reconnect's own vector exchange.
        let at = data.window.start_timestamp().unwrap() + 86_400;
        let updates = format!("u:w:{}:", data.window);
        let before = home
            .fx
            .vault
            .sync_state_keys_with_prefix(&updates)
            .unwrap()
            .len();
        let edited = public_world_claim(home.member, data.world, "after");
        home.fx
            .vault
            .put_entity(
                &data.item,
                ENTITY_TYPE_CLAIM,
                TimeRange { start: at, end: at },
                at,
                &encode_claim_body(&edited).unwrap(),
            )
            .unwrap();
        wait_home_window_update(&home.fx.vault, &data.window, before).await;
        assert!(
            run_lane(&member.manager, &member.config).await,
            "the lane reconnects to Synced"
        );
        // The catch-up delta lands in the reconnect's own exchange, before
        // `Synced`; the bounded poll absorbs only a slow import.
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if member_claim_value(&doors, &data.window, data.item)
                    .await
                    .as_deref()
                    == Some("after")
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the member reads the edited claim after reconnect");
        assert_eq!(
            member_claim_value(&doors, &data.window, data.item)
                .await
                .as_deref(),
            Some("after"),
            "the member reads the edited claim after reconnect"
        );
    });
}

/// Review round 1 of #8364 (P1-2, lane): a promotion the grant no longer
/// covers leaves the lane syncing. Window A is promoted, then HOME narrows
/// the grant to window B's world while the member is offline; the reconnect
/// answers A's promotion refused with the socket kept, reaches `Synced`, and
/// B is indexed.
/// red at 40cf5d7d8818: the refused promotion closes the socket with
/// DECODE_ERROR before the catalogue runs, so the lane never reaches
/// `Synced` and B is never indexed.
#[test]
fn a_promotion_the_grant_no_longer_covers_leaves_the_lane_syncing() {
    run_on_engine_stack(|| async {
        let home = world_fixture(2).await;
        let a = &home.worlds[0];
        let b = &home.worlds[1];
        let member = member_client(home.fx.url.clone(), &home.fx.caller);
        let doors = lane_connection(&member.manager, &member.config);
        doors.fetch_item(&a.window, a.item).await.unwrap();
        doors.promote_window(&a.window, a.item).await.unwrap();
        assert!(
            member
                .vault
                .sync_state_get(&format!("rp:w:{}", a.window))
                .unwrap()
                .is_some(),
            "window A is promoted before the grant narrows"
        );
        // HOME narrows the member's grant to B's world while the member is
        // offline; the slip minted under the whole grant still opens the lane.
        let mut narrowed = FederationGrant::new(
            FederationGrantScope::vault(42),
            home.member,
            FederationGrantRole::Member,
            FederationGrantPreset::Member,
        );
        narrowed.authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(b.world)]));
        put_selector_test_federation_grant(
            &home.fx.vault,
            &home.fx.grant_id,
            &narrowed,
            home.fx.vault.now_recorded_at(),
        )
        .unwrap();
        assert!(
            run_lane(&member.manager, &member.config).await,
            "the lane reaches Synced past the refused promotion"
        );
        let index = doors.residence_index().unwrap();
        let b_window = index
            .iter()
            .find(|window| window.window == b.window)
            .expect("window B is indexed");
        assert!(
            b_window
                .items
                .iter()
                .any(|entry| entry.entity_id == b.item.to_hex()),
            "B's item is indexed (index: {index:?})"
        );
        assert!(
            !index.iter().any(|window| window.window == a.window),
            "window A stays unindexed (index: {index:?})"
        );
    });
}

/// Review round 1 of #8364 (P1-3, lane): a thin copy HOME hard-deleted is
/// purged on reconnect. The member opens an item without promoting it, so a
/// thin copy is cached, and disconnects; HOME hard-deletes it; the member
/// reconnects and opening the item no longer serves the old body.
/// red at 40cf5d7d8818: the reconnect takes no tombstone id set (its windows
/// come from a root the lane never holds, and the RPC is barred), so the
/// thin cache still serves the old body.
#[test]
fn a_thin_copy_home_hard_deleted_is_purged_on_reconnect() {
    run_on_engine_stack(|| async {
        let fx = fixture().await;
        let member = member_client(fx.url.clone(), &fx.caller);
        assert!(
            run_lane(&member.manager, &member.config).await,
            "the lane first reaches Synced"
        );
        let doors = lane_connection(&member.manager, &member.config);
        let opened = doors.open_item(&fx.window, fx.item).await.unwrap();
        assert!(
            matches!(opened, OpenedItem::Thin(_)),
            "the first open caches a thin copy"
        );
        let thin_key = format!("ro:e:{}", fx.item.to_hex());
        assert!(
            member.vault.sync_state_get(&thin_key).unwrap().is_some(),
            "the thin copy is cached"
        );
        // HOME hard-deletes the item while the member is offline.
        assert!(
            fx.vault
                .delete_entity_with_reason(&fx.item, DeleteReason::UserHardDelete)
                .unwrap()
                .existed,
            "HOME hard-deletes the touched item"
        );
        assert!(
            run_lane(&member.manager, &member.config).await,
            "the lane reconnects to Synced"
        );
        assert!(
            doors.open_item(&fx.window, fx.item).await.is_err(),
            "the purged open is refused"
        );
        assert!(
            member.vault.sync_state_get(&thin_key).unwrap().is_none(),
            "the thin row is gone"
        );
        assert!(
            member
                .vault
                .sync_state_get(&format!("ri:b:{}", fx.item.to_hex()))
                .unwrap()
                .is_none(),
            "the thin body is gone"
        );
    });
}

/// One lane session left running: its events by `Debug` form, a signal on
/// its first `Synced`, and one on each disconnect or error after it.
struct LiveLane {
    events: Arc<Mutex<Vec<String>>>,
    synced: Arc<tokio::sync::Notify>,
    trouble: Arc<tokio::sync::Notify>,
    shutdown: tokio::sync::oneshot::Sender<()>,
    run: tokio::task::JoinHandle<()>,
}

impl LiveLane {
    /// Starts a session over `manager` that reconnects as `open_lane`'s does.
    fn start(manager: &Arc<WindowManager>, config: &SyncClientConfig) -> Self {
        let connection = Arc::new(
            SyncConnection::new(
                Arc::clone(manager),
                ConnectionConfig {
                    client_config: config.clone(),
                    auto_reconnect: true,
                },
            )
            .unwrap(),
        );
        let events = Arc::new(Mutex::new(Vec::new()));
        let synced = Arc::new(tokio::sync::Notify::new());
        let trouble = Arc::new(tokio::sync::Notify::new());
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn({
            let events = Arc::clone(&events);
            let synced = Arc::clone(&synced);
            let trouble = Arc::clone(&trouble);
            let mut synced_seen = false;
            async move {
                connection
                    .run_observed(shutdown_rx, move |event: SyncEvent| {
                        let debug = format!("{event:?}");
                        if debug == "StatusChanged(Synced)" {
                            synced_seen = true;
                            synced.notify_one();
                        } else if synced_seen
                            && (debug == "StatusChanged(Disconnected)"
                                || debug.starts_with("Error("))
                        {
                            trouble.notify_one();
                        }
                        events.lock().expect("event sink").push(debug);
                    })
                    .await
                    .expect("the run ends cleanly");
            }
        });
        Self {
            events,
            synced,
            trouble,
            shutdown,
            run,
        }
    }

    /// Waits (bounded) for the session's first `Synced`.
    async fn wait_synced(&self) {
        tokio::time::timeout(Duration::from_secs(30), self.synced.notified())
            .await
            .expect("the member lane reaches Synced");
    }

    /// Whether a disconnect or an error follows `Synced` within `wait`.
    async fn troubled_within(&self, wait: Duration) -> bool {
        tokio::time::timeout(wait, self.trouble.notified())
            .await
            .is_ok()
    }

    /// The session's events from its first `Synced` on.
    fn events_after_synced(&self) -> Vec<String> {
        let observed = self.events.lock().expect("event sink").clone();
        let synced_at = observed
            .iter()
            .position(|event| event == "StatusChanged(Synced)")
            .unwrap_or(observed.len());
        observed[synced_at..].to_vec()
    }

    /// Shuts the session down and waits (bounded) for its run to end.
    async fn stop(self) {
        let _ = self.shutdown.send(());
        tokio::time::timeout(Duration::from_secs(20), self.run)
            .await
            .expect("the run ends on its shutdown")
            .expect("the run task ends");
    }
}

/// Review round 2 of #8364 (P1-1): a read-only member keeps its socket
/// through a promoted window's round. The member's grant reads and never
/// writes (`Viewer` under `ReadOnly`); it promotes a world window, then a
/// session connects: the promotion is granted, the vectors are exchanged,
/// and the lane stays up after `Synced`, since it sends no update HOME's
/// vector already covers.
/// red at ce3d32b70e9: the member answers HOME's vector with an empty
/// update, HOME judges it a write the grant does not hold and closes the
/// socket (`RpcNoPrincipal`), so a disconnect follows (or `Synced` never
/// comes).
#[test]
fn a_read_only_member_keeps_its_socket_through_a_promoted_window_round() {
    run_on_engine_stack(|| async {
        let home = world_fixture_under(
            1,
            FederationGrantRole::Viewer,
            FederationGrantPreset::ReadOnly,
        )
        .await;
        let data = &home.worlds[0];
        let member = member_client(home.fx.url.clone(), &home.fx.caller);
        let doors = lane_connection(&member.manager, &member.config);
        doors.fetch_item(&data.window, data.item).await.unwrap();
        doors.promote_window(&data.window, data.item).await.unwrap();
        assert!(
            member
                .vault
                .sync_state_get(&format!("rp:w:{}", data.window))
                .unwrap()
                .is_some(),
            "the read-only member's world window is promoted"
        );
        let lane = LiveLane::start(&member.manager, &member.config);
        lane.wait_synced().await;
        // The promoted window's request, grant and vector exchange run over
        // localhost within milliseconds of the connect; 5 s bounds the wait
        // for a close that must not come.
        let troubled = lane.troubled_within(Duration::from_secs(5)).await;
        let after = lane.events_after_synced();
        lane.stop().await;
        assert!(
            !troubled,
            "no disconnect or error after Synced (events: {after:?})"
        );
        assert_eq!(
            member_claim_value(&doors, &data.window, data.item)
                .await
                .as_deref(),
            Some("before"),
            "the read-only member still reads its promoted claim"
        );
    });
}

/// Review round 2 of #8364 (P1-3): a thin copy HOME soft-deleted is dropped
/// on reconnect. The member opens an item without promoting it, so a thin
/// copy (`ro:e:`, `ri:b:`) is cached, and disconnects; HOME soft-deletes the
/// item (`UserDelete`); the reconnect takes the soft tombstone and drops the
/// thin copy, writing no hard-delete marker (`dt:`).
/// red at ce3d32b70e9: a soft tombstone with no full local row is skipped as
/// done, so the thin body (`ri:b:`) stays and the next open serves it.
#[test]
fn a_soft_deleted_thin_copy_is_dropped_on_reconnect() {
    run_on_engine_stack(|| async {
        let fx = fixture().await;
        let member = member_client(fx.url.clone(), &fx.caller);
        assert!(
            run_lane(&member.manager, &member.config).await,
            "the lane first reaches Synced"
        );
        let doors = lane_connection(&member.manager, &member.config);
        let opened = doors.open_item(&fx.window, fx.item).await.unwrap();
        assert!(
            matches!(opened, OpenedItem::Thin(_)),
            "the first open caches a thin copy"
        );
        let hex = fx.item.to_hex();
        let thin_key = format!("ro:e:{hex}");
        let body_key = format!("ri:b:{hex}");
        assert!(
            member.vault.sync_state_get(&thin_key).unwrap().is_some(),
            "the thin copy is cached"
        );
        assert!(
            member.vault.sync_state_get(&body_key).unwrap().is_some(),
            "the thin body is cached"
        );
        assert!(
            fx.vault
                .delete_entity_with_reason(&fx.item, DeleteReason::UserDelete)
                .unwrap()
                .existed,
            "HOME soft-deletes the opened item"
        );
        assert!(
            run_lane(&member.manager, &member.config).await,
            "the lane reconnects to Synced"
        );
        assert!(
            member.vault.sync_state_get(&body_key).unwrap().is_none(),
            "the thin body is dropped"
        );
        assert!(
            member.vault.sync_state_get(&thin_key).unwrap().is_none(),
            "the thin copy's window row is dropped"
        );
        assert!(
            member
                .vault
                .sync_state_get(&format!("dt:{hex}"))
                .unwrap()
                .is_none(),
            "a soft delete writes no hard-delete marker"
        );
    });
}

/// Review round 2 of #8364 (P1-2): a connected member drops a thin copy HOME
/// hard-deleted, with no reconnect. The member opens an item without
/// promoting it while its session runs; HOME hard-deletes the item; the
/// member lane's own tombstone refresh tick (the sealed relay cadence,
/// `SEALED_RELAY_INTERVAL_SECS = 300`, first round one period after the
/// connect) purges the thin copy. The wait is bounded at 360 s, and the
/// session must stay up throughout, so the purge is the tick's, not a
/// reconnect's.
/// red at ce3d32b70e9: a member lane runs no tombstone refresh while
/// connected, so the thin copy stays until the 360 s wait runs out.
#[test]
fn a_connected_member_drops_a_thin_copy_home_hard_deleted() {
    run_on_engine_stack(|| async {
        let fx = fixture().await;
        let member = member_client(fx.url.clone(), &fx.caller);
        let lane = LiveLane::start(&member.manager, &member.config);
        lane.wait_synced().await;
        let doors = lane_connection(&member.manager, &member.config);
        let opened = doors.open_item(&fx.window, fx.item).await.unwrap();
        assert!(
            matches!(opened, OpenedItem::Thin(_)),
            "the open caches a thin copy"
        );
        let hex = fx.item.to_hex();
        let thin_key = format!("ro:e:{hex}");
        assert!(
            member.vault.sync_state_get(&thin_key).unwrap().is_some(),
            "the thin copy is cached"
        );
        assert!(
            fx.vault
                .delete_entity_with_reason(&fx.item, DeleteReason::UserHardDelete)
                .unwrap()
                .existed,
            "HOME hard-deletes the opened item"
        );
        // A bounded poll paced by an interval: the refresh tick is one
        // sealed relay period (300 s) after the connect.
        let mut poll = tokio::time::interval(Duration::from_millis(500));
        let purged = tokio::time::timeout(Duration::from_secs(360), async {
            loop {
                poll.tick().await;
                if member.vault.sync_state_get(&thin_key).unwrap().is_none() {
                    return;
                }
            }
        })
        .await
        .is_ok();
        let after = lane.events_after_synced();
        lane.stop().await;
        assert!(
            purged,
            "the connected member's thin copy is purged (events: {after:?})"
        );
        assert!(
            !after
                .iter()
                .any(|event| event == "StatusChanged(Disconnected)"),
            "the session stayed up, so no reconnect took the tombstone (events: {after:?})"
        );
        assert!(
            member
                .vault
                .sync_state_get(&format!("ri:b:{hex}"))
                .unwrap()
                .is_none(),
            "the thin body is gone"
        );
    });
}
