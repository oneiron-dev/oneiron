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
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
    SharedVaultPreset,
};
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::client::NoteSyncSession;
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::server_state::persist_window_snapshot;
use oneiron::sync::window::reverse_rematerialize;
use oneiron::sync::{
    ConnectionConfig, SyncClient, SyncClientConfig, SyncConnection, SyncEvent, SyncResidenceMode,
    SyncSelector, SyncSelectorWorld, SyncTransportCredential, WindowKey, WindowManager,
    put_selector_test_federation_grant,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
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
/// the granted window at the wall-clock current month (the months the member
/// catalogue asks are current plus previous, so the granted rows are asked
/// for) and a far window at `2020-01` the catalogue never names.
async fn fixture() -> Fixture {
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
    let grant = FederationGrant::new(
        FederationGrantScope::vault(42),
        member,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    put_selector_test_federation_grant(&vault, &grant_id, &grant, vault.now_recorded_at()).unwrap();
    let caller = mint(
        &vault,
        &issuer,
        &root,
        member,
        Some((grant_id, &grant)),
        "human",
    );
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
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
    for key in [&window, &other_window] {
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
    Fixture {
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
    }
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
        // The run's events by `Debug` form, and the first `Synced` signal.
        let events = Arc::new(Mutex::new(Vec::new()));
        let synced = Arc::new(tokio::sync::Notify::new());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let run_handle = tokio::spawn({
            let connection = Arc::clone(&connection);
            let events = Arc::clone(&events);
            let synced = Arc::clone(&synced);
            async move {
                connection
                    .run_observed(shutdown_rx, move |event: SyncEvent| {
                        let debug = format!("{event:?}");
                        if debug == "StatusChanged(Synced)" {
                            synced.notify_one();
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
        tokio::time::sleep(Duration::from_millis(2_500)).await;
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
