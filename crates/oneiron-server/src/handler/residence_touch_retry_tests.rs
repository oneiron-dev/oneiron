//! A residence touch the home withdrew is asked again on a fresh socket, at
//! most three times in all (SELECTOR-RELEASE-POINT = B: a withdrawn answer
//! is asked again "under the grant as it is then"). The withdrawal is one
//! authority append between the touch answer's queue and its release that
//! leaves the device's grant standing, as the device's own credential
//! renewal did in the 28 Nov nightly (SYNC-04).

use crate::config::SyncServerConfig;
use crate::server::SyncServer;
use crate::test_doors::selector_release::ArmedHook;
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use oneiron::federation::{FederationGrant, FederationGrantPreset, FederationGrantRole};
use oneiron::sync::client::NoteSyncSession;
use oneiron::sync::{
    SyncClient, SyncClientConfig, SyncResidenceMode, SyncSelector, SyncSelectorWorld,
    SyncTransportCredential, TransportError, WindowKey, WindowManager, bridge::Materializer,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Every sync upgrade proves an owner-grade slip with a fresh holder
/// signature; the NOTE session bind then names the actor.
fn transport_credential(server: &SyncServer, jti: &str) -> SyncTransportCredential {
    let (slip, key) = crate::test_credentials::credential(server, &format!("jti={jti}"));
    SyncTransportCredential::new(slip.to_token().unwrap(), key)
}

async fn upgraded_socket(server: &SyncServer, url: &str, jti: &str) -> Socket {
    let mut request = url.into_client_request().unwrap();
    crate::test_credentials::bind_ws_request(server, &mut request, &format!("jti={jti}"));
    tokio_tungstenite::connect_async(request).await.unwrap().0
}

/// Arms `grant_id` in `vault` so that each of the next `times` answers made
/// under it is withdrawn: its hook runs `withdraw`, then arms the next. Each
/// arming is kept in `held` until the test drops it.
fn arm_withdrawals(
    vault: &Arc<Vault>,
    grant_id: EntityId,
    times: usize,
    withdraw: Arc<dyn Fn() + Send + Sync>,
    held: &Arc<Mutex<Vec<ArmedHook>>>,
) {
    if times == 0 {
        return;
    }
    let (next_vault, next_held) = (Arc::clone(vault), Arc::clone(held));
    let armed = crate::test_doors::selector_release::arm(vault, grant_id, move || {
        withdraw();
        arm_withdrawals(&next_vault, grant_id, times - 1, withdraw, &next_held);
    });
    held.lock().unwrap().push(armed);
}

/// What one open of the item did.
struct Opened {
    fetched: Result<(), TransportError>,
    /// The touch answers the home withdrew.
    withdrawn: usize,
    /// The device keeps a thin copy with the home's bytes.
    kept: bool,
}

/// A home holding one item and a device in opened mode under a residence
/// selector: the device enrols, takes the thin index, then opens the item
/// while the home withdraws the next `withdrawals` answers under the grant.
async fn open_after_withdrawals(withdrawals: usize) -> Opened {
    let server_dir = tempfile::tempdir().unwrap();
    let device_dir = tempfile::tempdir().unwrap();
    let server_vault = Arc::new(Vault::open(server_dir.path(), VaultConfig::device()).unwrap());
    let now = oneiron_vault_contract::now_ts();
    let actor = EntityId::now();
    let item = EntityId::now();
    let other_actor = EntityId::now();
    let grant_id = EntityId::now();
    for principal in [actor, other_actor] {
        server_vault
            .put_entity(
                &principal,
                oneiron::registry::ENTITY_TYPE_PERSON,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                b"actor",
            )
            .unwrap();
    }
    let title = rmp_serde::to_vec_named(&serde_json::json!({
        "title": "Current title", "content": "body-not-in-index"
    }))
    .unwrap();
    server_vault
        .put_entity(
            &item,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            &title,
        )
        .unwrap();
    let server = Arc::new(
        crate::test_credentials::server_with_fixture_keystore(
            server_vault.clone(),
            SyncServerConfig {
                auth_secret: Some("residence-phone-root".into()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let scope = crate::handler::selector_grant_scope();
    let grant = FederationGrant::new(
        scope,
        actor,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    oneiron::sync::put_selector_test_federation_grant(&server_vault, &grant_id, &grant, now)
        .unwrap();
    let window = WindowKey::from_timestamp(now);
    server.get_or_create_window(&window).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/ws", listener.local_addr().unwrap());
    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            axum::serve(listener, crate::build_app(server))
                .await
                .unwrap();
        }
    });
    let (slip, key) = crate::test_credentials::credential(
        &server,
        &format!(
            "scope=core:read,core:write;principal_ref={};actor_class=human",
            actor.to_hex()
        ),
    );
    let selector = SyncSelector::new(grant_id, actor, SyncSelectorWorld::All, vec![], vec![]);
    let device = Arc::new(Vault::open(device_dir.path(), VaultConfig::device()).unwrap());
    let manager = Arc::new(WindowManager::new(
        device.clone(),
        Arc::new(Materializer::new()),
        "phone",
    ));
    let config = SyncClientConfig {
        server_url: url.clone(),
        residence_mode: SyncResidenceMode::Opened,
        transport_credential: Some(transport_credential(&server, "residence-phone-transport")),
        note_session: Some(NoteSyncSession::new(slip.to_token().unwrap(), key)),
        residence_selector: Some(selector),
        ..Default::default()
    };
    let (mut client, _events) = SyncClient::new(manager, config).unwrap();
    let mut socket = upgraded_socket(&server, &url, "residence-phone-socket").await;
    for frame in client.generate_initial_sync() {
        socket.send(Message::Binary(frame.into())).await.unwrap();
    }
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !client
            .server_windows()
            .contains(&window.as_str().to_owned())
        {
            let Message::Binary(frame) = socket.next().await.unwrap().unwrap() else {
                continue;
            };
            for reply in client.handle_server_message(&frame).unwrap() {
                socket.send(Message::Binary(reply.into())).await.unwrap();
            }
        }
    })
    .await
    .unwrap();
    drop(socket);
    client.fetch_current_index(now).await.unwrap();
    assert!(
        device
            .sync_state_get(&format!("ri:w:{}:{}", window, item.to_hex()))
            .unwrap()
            .is_some()
    );

    // One withdrawal: a host-issued slip for another actor under the grant
    // (as tests/selector_release_recheck.rs `mint` mints one). It changes
    // the authority fold, so the answer's basis no longer has the same
    // image, and it leaves the grant and the device's own slip standing.
    let issuer = crate::test_credentials::host_issuer(&server);
    let root = server_vault.ensure_host_root_slip(&issuer).unwrap();
    let withdrawn = Arc::new(AtomicUsize::new(0));
    let withdraw: Arc<dyn Fn() + Send + Sync> = Arc::new({
        let vault = Arc::clone(&server_vault);
        let withdrawn = Arc::clone(&withdrawn);
        let scope = grant.authority_scope.clone();
        move || {
            let key = SigningKey::from_bytes(blake3::hash(EntityId::now().as_bytes()).as_bytes());
            let mut claims = root.claims.clone();
            claims.slip_id = *blake3::hash(EntityId::now().as_bytes()).as_bytes();
            claims.parent_id = None;
            claims.holder_ref = other_actor.to_hex();
            claims.actor_class = Some("human".to_owned());
            claims.org_ref = None;
            claims.binding_key = key.verifying_key().to_bytes();
            claims.single_use = false;
            claims.records = BTreeSet::new();
            claims.channels.clear();
            claims.grant_ref = Some(grant_id.to_hex());
            claims.scope = scope.clone();
            vault.mint_capability_slip(&issuer, claims).unwrap();
            withdrawn.fetch_add(1, Ordering::SeqCst);
        }
    });
    let held = Arc::new(Mutex::new(Vec::new()));
    arm_withdrawals(&server_vault, grant_id, withdrawals, withdraw, &held);
    let fetched = client.fetch_item(&window, item).await;
    // An unrun arming holds the vault through its hook: drop them all here.
    let armed = std::mem::take(&mut *held.lock().unwrap());
    drop(armed);
    let kept = client
        .thin_item(item)
        .ok()
        .flatten()
        .is_some_and(|thin| thin.raw == server_vault.get_raw(&item).unwrap().unwrap());
    server_task.abort();
    let _ = server_task.await;
    Opened {
        fetched,
        withdrawn: withdrawn.load(Ordering::SeqCst),
        kept,
    }
}

#[tokio::test]
async fn a_touch_whose_answer_the_home_withdrew_once_is_asked_again() {
    let opened = open_after_withdrawals(1).await;
    assert_eq!(
        opened.withdrawn, 1,
        "the home withdrew the first touch answer"
    );
    assert!(
        opened.fetched.is_ok(),
        "a touch the home withdrew once is asked again: {:?}",
        opened.fetched
    );
    assert!(opened.kept, "the device keeps the home's bytes");
}

#[tokio::test]
async fn a_touch_the_home_withdrew_at_every_attempt_fails_as_a_home_offline() {
    // One withdrawal more than the device asks: it stops after three.
    let opened = open_after_withdrawals(4).await;
    assert!(
        matches!(
            &opened.fetched,
            Err(TransportError::WebSocket(reason)) if reason == "home node offline"
        ),
        "after its last attempt the device tells a home it cannot read from now, \
         not a refusal of its request: {:?}",
        opened.fetched
    );
    assert_eq!(
        opened.withdrawn, 3,
        "the device asks a touch at most three times"
    );
    assert!(!opened.kept, "no copy is kept");
}
