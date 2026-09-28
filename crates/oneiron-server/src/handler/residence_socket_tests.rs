//! A real enrol: root + thin index, one opened item, remote search and offline honesty.

use crate::config::SyncServerConfig;
use crate::server::SyncServer;
use futures_util::{SinkExt, StreamExt};
use oneiron::federation::{FederationGrant, FederationGrantPreset, FederationGrantRole};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::sync::client::NoteSyncSession;
use oneiron::sync::transport::{self, window_sub_tags};
use oneiron::sync::{
    ConnectionConfig, SearchSource, SyncClient, SyncClientConfig, SyncConnection, SyncEvent,
    SyncSelector, SyncSelectorWorld, SyncStatus, SyncTransportCredential, WindowKey, WindowManager,
    bridge::Materializer,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig,
};
use std::sync::Arc;
use std::time::Duration;
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

#[tokio::test]
async fn phone_enrols_with_index_then_opens_one_item_and_searches_home() {
    let server_dir = tempfile::tempdir().unwrap();
    let device_dir = tempfile::tempdir().unwrap();
    let server_vault = Arc::new(Vault::open(server_dir.path(), VaultConfig::device()).unwrap());
    let now = oneiron_vault_contract::now_ts();
    let actor = EntityId::now();
    let item = EntityId::now();
    let unopened = EntityId::now();
    let grant_id = EntityId::now();
    server_vault
        .put_entity(
            &actor,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            b"actor",
        )
        .unwrap();
    let title = rmp_serde::to_vec_named(&serde_json::json!({
        "title": "Current title", "content": "body-not-in-index"
    }))
    .unwrap();
    for id in [item, unopened] {
        server_vault
            .put_entity(
                &id,
                oneiron::registry::ENTITY_TYPE_PERSON,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &title,
            )
            .unwrap();
    }
    let server = Arc::new(
        SyncServer::new(
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
    server_vault
        .memory(actor, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: None,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".into(),
                content: "homeonlyresidencecanary".into(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
            occurred_at: now,
        })
        .unwrap();
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
        transport_credential: Some(transport_credential(&server, "residence-phone-transport")),
        note_session: Some(NoteSyncSession::new(slip.to_token().unwrap(), key)),
        residence_selector: Some(selector),
        ..Default::default()
    };
    let driver_config = config.clone();
    let (mut client, _events) = SyncClient::new(manager.clone(), config).unwrap();
    let mut socket = upgraded_socket(&server, &url, "residence-phone-socket").await;
    for frame in client.generate_initial_sync() {
        socket.send(Message::Binary(frame.into())).await.unwrap();
    }
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !client
            .server_windows()
            .contains(&window.as_str().to_owned())
        {
            if let Some(Ok(Message::Binary(frame))) = socket.next().await {
                for reply in client.handle_server_message(&frame).unwrap() {
                    socket.send(Message::Binary(reply.into())).await.unwrap();
                }
            }
        }
    })
    .await
    .unwrap();
    assert!(manager.loaded_keys().is_empty(), "no full window on enrol");
    let count = client.fetch_current_index(now).await.unwrap();
    assert!(count >= 2);
    let row = device
        .sync_state_get(&format!("ri:w:{}:{}", window, item.to_hex()))
        .unwrap()
        .unwrap();
    assert!(
        !row.windows(b"body-not-in-index".len())
            .any(|slice| slice == b"body-not-in-index")
    );
    assert!(device.get_raw(&item).unwrap().is_none());
    client.fetch_item(&window, item).await.unwrap();
    assert!(
        device.get_raw(&item).unwrap().is_none(),
        "thin read is not a writable CRDT row"
    );
    assert_eq!(
        client.thin_item(item).unwrap().unwrap().raw,
        server_vault.get_raw(&item).unwrap().unwrap()
    );
    assert!(client.thin_item(unopened).unwrap().is_none());
    assert!(
        manager.loaded_keys().is_empty(),
        "first touch must not promote the full window"
    );
    let remote = client
        .search_resident("homeonlyresidencecanary", 10)
        .await
        .unwrap();
    assert_eq!(remote.source, SearchSource::Home);
    assert!(remote.complete);
    assert!(!remote.hits.is_empty());

    // Exercise the real connection owner, not only SyncClient frame builders:
    // enrol reaches Synced with the bound actor session and selector and still
    // materializes no full month window.
    let driver_dir = tempfile::tempdir().unwrap();
    let driver_vault = Arc::new(Vault::open(driver_dir.path(), VaultConfig::device()).unwrap());
    let driver_manager = Arc::new(WindowManager::new(
        driver_vault.clone(),
        Arc::new(Materializer::new()),
        "enrolling-phone",
    ));
    let driver = SyncConnection::new(
        driver_manager.clone(),
        ConnectionConfig {
            client_config: driver_config,
            auto_reconnect: false,
        },
    )
    .unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move { driver.run(shutdown_rx).await.unwrap() });
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(25));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if driver_vault
                .sync_state_get(&format!("ri:w:{}:{}", window, item.to_hex()))
                .unwrap()
                .is_some()
            {
                break;
            }
            tick.tick().await;
        }
    })
    .await
    .unwrap();
    assert!(driver_manager.loaded_keys().is_empty());
    shutdown_tx.send(()).unwrap();
    let mut events = tokio::time::timeout(std::time::Duration::from_secs(15), task)
        .await
        .unwrap()
        .unwrap();
    let mut synced = false;
    while let Ok(event) = events.try_recv() {
        synced |= matches!(event, SyncEvent::StatusChanged(SyncStatus::Synced));
    }
    assert!(synced, "bound opened-item enrol must reach Synced");
    server_task.abort();
    let _ = server_task.await;
    let offline = client
        .search_resident("body-not-in-index", 10)
        .await
        .unwrap();
    assert_eq!(offline.source, SearchSource::LocalOnly);
    assert!(!offline.complete);
    assert!(
        offline
            .hits
            .iter()
            .any(|hit| hit.entity_id == item.to_hex())
    );
}

#[tokio::test]
async fn thin_first_edit_promotes_causally_and_concurrent_home_edit_converges() {
    let server_dir = tempfile::tempdir().unwrap();
    let device_dir = tempfile::tempdir().unwrap();
    let home = Arc::new(Vault::open(server_dir.path(), VaultConfig::device()).unwrap());
    let actor = EntityId::now();
    let item = EntityId::now();
    let second_item = EntityId::now();
    let grant_id = EntityId::now();
    let now = oneiron_vault_contract::now_ts();
    home.put_entity(
        &actor,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"actor",
    )
    .unwrap();
    let original = rmp_serde::to_vec_named(&serde_json::json!({"title":"base"})).unwrap();
    home.put_entity(
        &item,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        &original,
    )
    .unwrap();
    home.put_entity(
        &second_item,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        &original,
    )
    .unwrap();
    let server = Arc::new(
        SyncServer::new(
            home.clone(),
            SyncServerConfig {
                auth_secret: Some("residence-causal-root".into()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let grant = FederationGrant::new(
        crate::handler::selector_grant_scope(),
        actor,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    oneiron::sync::put_selector_test_federation_grant(&home, &grant_id, &grant, 1).unwrap();
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
        transport_credential: Some(transport_credential(&server, "residence-causal-transport")),
        note_session: Some(NoteSyncSession::new(slip.to_token().unwrap(), key)),
        residence_selector: Some(selector.clone()),
        ..Default::default()
    };
    let conn = SyncConnection::new(
        manager.clone(),
        ConnectionConfig {
            client_config: config.clone(),
            auto_reconnect: false,
        },
    )
    .unwrap();
    let (mut client, _events) = SyncClient::new(manager.clone(), config).unwrap();
    let mut socket = upgraded_socket(&server, &url, "residence-causal-socket").await;
    for frame in client.generate_initial_sync() {
        socket.send(Message::Binary(frame.into())).await.unwrap();
    }
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !client
            .server_windows()
            .contains(&window.as_str().to_owned())
        {
            if let Some(Ok(Message::Binary(frame))) = socket.next().await {
                for reply in client.handle_server_message(&frame).unwrap() {
                    socket.send(Message::Binary(reply.into())).await.unwrap();
                }
            }
        }
    })
    .await
    .unwrap();
    client.fetch_current_index(now).await.unwrap();
    client.fetch_item(&window, item).await.unwrap();
    assert!(device.get_raw(&item).unwrap().is_none());
    let edited = rmp_serde::to_vec_named(&serde_json::json!({"title":"device edit"})).unwrap();
    assert!(
        device
            .put_entity(
                &item,
                oneiron::registry::ENTITY_TYPE_PERSON,
                TimeRange {
                    start: now,
                    end: now
                },
                now,
                &edited
            )
            .is_err()
    );
    conn.edit_opened_item(
        &window,
        item,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        &edited,
    )
    .await
    .unwrap();
    assert!(
        device
            .sync_state_get(&format!("rp:w:{window}"))
            .unwrap()
            .is_some()
    );
    assert!(client.thin_item(item).unwrap().is_none());
    // Reopening A and first-touching B after the window is promoted must
    // use its canonical copy, never mint another ro:e: cache or re-promote.
    client.fetch_item(&window, item).await.unwrap();
    client.fetch_item(&window, second_item).await.unwrap();
    assert!(client.thin_item(item).unwrap().is_none());
    assert!(client.thin_item(second_item).unwrap().is_none());
    let second_edit =
        rmp_serde::to_vec_named(&serde_json::json!({"title":"second device edit"})).unwrap();
    conn.edit_opened_item(
        &window,
        second_item,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        &second_edit,
    )
    .await
    .unwrap();
    // The refetched A stays editable on the same canonical copy.
    let edited =
        rmp_serde::to_vec_named(&serde_json::json!({"title":"reopened device edit"})).unwrap();
    conn.edit_opened_item(
        &window,
        item,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        &edited,
    )
    .await
    .unwrap();
    assert!(client.thin_item(item).unwrap().is_none());
    let loaded = manager.open_window(&window).unwrap();
    let proof = transport::encode_window_sync(
        window.as_str(),
        window_sub_tags::PROMOTION_REQUEST,
        &oneiron::sync::encode_sync_selector(&selector).unwrap(),
    )
    .into_result()
    .unwrap();
    let vv = transport::encode_window_sync(
        window.as_str(),
        window_sub_tags::VV_REQUEST,
        &loaded.doc.oplog_vv().encode(),
    )
    .into_result()
    .unwrap();
    socket.send(Message::Binary(proof.into())).await.unwrap();
    socket.send(Message::Binary(vv.into())).await.unwrap();
    let server_before = server.get_or_create_window(&window).await.unwrap();
    let direct_delta = loaded
        .doc
        .export(loro::ExportMode::updates(&server_before.oplog_vv()))
        .unwrap();
    assert!(
        loro::LoroDoc::decode_import_blob_meta(&direct_delta, true)
            .unwrap()
            .change_num
            > 0,
        "first edit must carry a local Loro op"
    );
    let mut persisted_update = 1u64.to_be_bytes().to_vec();
    persisted_update.extend_from_slice(&direct_delta);
    socket
        .send(Message::Binary(
            transport::encode_window_sync(
                window.as_str(),
                window_sub_tags::RESIDENCE_UPDATE,
                &persisted_update,
            )
            .into_result()
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let mut seen = Vec::new();
    let exchange = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut check = tokio::time::interval(std::time::Duration::from_millis(100));
        check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if home
                .get_raw(&item)
                .unwrap()
                .is_some_and(|raw| raw.ends_with(&edited))
                && device
                    .get_raw(&item)
                    .unwrap()
                    .is_some_and(|raw| raw.ends_with(&edited))
                && server_before.oplog_vv() == loaded.doc.oplog_vv()
            {
                break;
            }
            let message = tokio::select! {
                _ = check.tick() => continue,
                message = socket.next() => message.unwrap().unwrap(),
            };
            if let Message::Binary(frame) = message {
                let sub = if frame.first() == Some(&transport::TAG_WINDOW_SYNC) {
                    transport::decode_window_sync(&frame[1..])
                        .ok()
                        .map(|(_, tag, _)| tag)
                } else {
                    None
                };
                seen.push(("in", frame[0], sub, frame.len()));
                for reply in client.handle_server_message(&frame).unwrap() {
                    let sub = if reply.first() == Some(&transport::TAG_WINDOW_SYNC) {
                        transport::decode_window_sync(&reply[1..])
                            .ok()
                            .map(|(_, tag, _)| tag)
                    } else {
                        None
                    };
                    seen.push(("out", reply[0], sub, reply.len()));
                    if sub == Some(window_sub_tags::UPDATE) {
                        let (_, _, payload) = transport::decode_window_sync(&reply[1..]).unwrap();
                        let home_doc = server.get_or_create_window(&window).await.unwrap();
                        oneiron::sync::window::validate_window_update_locality(&home_doc, payload)
                            .unwrap_or_else(|error| {
                                panic!("promoted delta rejected locally: {error}")
                            });
                        let candidate = home_doc.fork();
                        let status = candidate.import(payload).unwrap_or_else(|error| {
                            panic!("promoted delta import refused: {error}")
                        });
                        assert!(
                            status.pending.is_none(),
                            "promoted delta has unavailable dependencies"
                        );
                    }
                    socket.send(Message::Binary(reply.into())).await.unwrap();
                    socket.flush().await.unwrap();
                    socket.send(Message::Ping(Vec::new().into())).await.unwrap();
                }
            }
        }
    })
    .await;
    if exchange.is_err() {
        let home_vv = server
            .get_or_create_window(&window)
            .await
            .unwrap()
            .oplog_vv();
        panic!(
            "promotion exchange stalled: frames={seen:?}; home={:?}; device={:?}; edited={edited:?}; home_vv={home_vv:?}; device_vv={:?}",
            home.get_raw(&item).unwrap().map(|raw| raw[25..].to_vec()),
            device.get_raw(&item).unwrap().map(|raw| raw[25..].to_vec()),
            loaded.doc.oplog_vv()
        );
    }
    assert!(
        home.get_raw(&second_item)
            .unwrap()
            .is_some_and(|raw| raw.ends_with(&second_edit))
    );
    let home_doc = server.get_or_create_window(&window).await.unwrap();
    let device_doc = loaded.doc.clone();
    let before_home = home_doc.oplog_vv();
    let before_device = device_doc.oplog_vv();
    let mut home_raw = home.get_raw(&item).unwrap().unwrap();
    home_raw.truncate(25);
    let home_edit =
        rmp_serde::to_vec_named(&serde_json::json!({"title":"home concurrent"})).unwrap();
    home_raw.extend_from_slice(&home_edit);
    let mut device_raw = device.get_raw(&item).unwrap().unwrap();
    device_raw.truncate(25);
    let device_edit =
        rmp_serde::to_vec_named(&serde_json::json!({"title":"device concurrent"})).unwrap();
    device_raw.extend_from_slice(&device_edit);
    home_doc
        .get_map("entities")
        .insert(&item.to_hex(), home_raw.as_slice())
        .unwrap();
    home_doc.commit();
    device_doc
        .get_map("entities")
        .insert(&item.to_hex(), device_raw.as_slice())
        .unwrap();
    device_doc.commit();
    assert_ne!(before_home, home_doc.oplog_vv());
    assert_ne!(before_device, device_doc.oplog_vv());
    socket
        .send(Message::Binary(
            transport::encode_window_sync(
                window.as_str(),
                window_sub_tags::VV_REQUEST,
                &device_doc.oplog_vv().encode(),
            )
            .into_result()
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while home_doc.oplog_vv() != device_doc.oplog_vv() {
            let message = socket.next().await.unwrap().unwrap();
            if let Message::Binary(frame) = message {
                for reply in client.handle_server_message(&frame).unwrap() {
                    socket.send(Message::Binary(reply.into())).await.unwrap();
                }
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(home_doc.get_deep_value(), device_doc.get_deep_value(),);
    server_task.abort();
    let _ = server_task.await;
}

/// Home holds one world-scoped CLAIM, born in its world-month window. The
/// device is an opened-item replica that follows that world only if asked.
struct WorldResidence {
    _dirs: [tempfile::TempDir; 2],
    home: Arc<Vault>,
    server: Arc<SyncServer>,
    server_task: tokio::task::JoinHandle<()>,
    url: String,
    device: Arc<Vault>,
    manager: Arc<WindowManager>,
    config: SyncClientConfig,
    selector: SyncSelector,
    world: EntityId,
    claim: EntityId,
    window: WindowKey,
    base: WindowKey,
    now: u64,
}

impl WorldResidence {
    async fn start(follow_world: bool) -> Self {
        let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
        let home = Arc::new(Vault::open(dirs[0].path(), VaultConfig::device()).unwrap());
        let now = oneiron_vault_contract::now_ts();
        let at = TimeRange {
            start: now,
            end: now,
        };
        let actor = EntityId::now();
        let world = EntityId::now();
        let claim = EntityId::now();
        let grant_id = EntityId::now();
        home.put_entity(
            &actor,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"actor",
        )
        .unwrap();
        home.put_entity(
            &world,
            oneiron::registry::ENTITY_TYPE_WORLD,
            at,
            now,
            b"world",
        )
        .unwrap();
        // The CLAIM's subject edge names a shared base-month PERSON.
        let subject = EntityId::now();
        home.put_entity(
            &subject,
            oneiron::registry::ENTITY_TYPE_PERSON,
            at,
            now,
            b"subject",
        )
        .unwrap();
        let mut body = ClaimBody::new(
            "test.world_residence",
            ClaimSubject::Entity(subject),
            rmpv::Value::from("world fact"),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.world = Some(world);
        home.put_claim(&claim, &body, at, now).unwrap();
        let server = Arc::new(
            SyncServer::new(
                home.clone(),
                SyncServerConfig {
                    auth_secret: Some("residence-world-root".into()),
                    ..Default::default()
                },
            )
            .unwrap(),
        );
        let grant = FederationGrant::new(
            crate::handler::selector_grant_scope(),
            actor,
            FederationGrantRole::Member,
            FederationGrantPreset::Member,
        );
        oneiron::sync::put_selector_test_federation_grant(&home, &grant_id, &grant, 1).unwrap();
        let base = WindowKey::from_timestamp(now);
        let window = WindowKey::for_world(now, world);
        server.get_or_create_window(&base).await.unwrap();
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
        let device = Arc::new(Vault::open(dirs[1].path(), VaultConfig::device()).unwrap());
        let manager = Arc::new(WindowManager::new(
            device.clone(),
            Arc::new(Materializer::new()),
            "phone",
        ));
        let mut config = SyncClientConfig {
            server_url: url.clone(),
            transport_credential: Some(transport_credential(&server, "residence-world-transport")),
            note_session: Some(NoteSyncSession::new(slip.to_token().unwrap(), key)),
            residence_selector: Some(selector.clone()),
            ..Default::default()
        };
        if follow_world {
            config.followed_worlds = Some(vec![world]);
        }
        Self {
            _dirs: dirs,
            home,
            server,
            server_task,
            url,
            device,
            manager,
            config,
            selector,
            world,
            claim,
            window,
            base,
            now,
        }
    }

    fn at(&self) -> TimeRange {
        TimeRange {
            start: self.now,
            end: self.now,
        }
    }

    /// The device's v12 socket, bound and holding a root that lists the
    /// world-month window.
    async fn device_socket(&self, client: &mut SyncClient, jti: &str) -> Socket {
        let mut socket = upgraded_socket(&self.server, &self.url, jti).await;
        for frame in client.generate_initial_sync() {
            socket.send(Message::Binary(frame.into())).await.unwrap();
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            while !client
                .server_windows()
                .contains(&self.window.as_str().to_owned())
            {
                if let Some(Ok(Message::Binary(frame))) = socket.next().await {
                    for reply in client.handle_server_message(&frame).unwrap() {
                        socket.send(Message::Binary(reply.into())).await.unwrap();
                    }
                }
            }
        })
        .await
        .unwrap();
        socket
    }

    /// Fetch the thin CLAIM, then make the first edit through the opened-item
    /// door, which promotes the world-month window.
    async fn fetch_and_edit(&self, client: &mut SyncClient) {
        client.fetch_item(&self.window, self.claim).await.unwrap();
        let thin = client.thin_item(self.claim).unwrap().unwrap();
        assert_eq!(thin.window, self.window);
        assert!(
            self.device.get_raw(&self.claim).unwrap().is_none(),
            "a thin read is not a writable CRDT row"
        );
        let edited = with_confidence(&thin.raw[25..], EDITED_CONFIDENCE);
        let conn = SyncConnection::new(
            self.manager.clone(),
            ConnectionConfig {
                client_config: self.config.clone(),
                auto_reconnect: false,
            },
        )
        .unwrap();
        conn.edit_opened_item(
            &self.window,
            self.claim,
            oneiron::registry::ENTITY_TYPE_CLAIM,
            self.at(),
            self.now,
            &edited,
        )
        .await
        .unwrap();
        assert!(
            self.device
                .sync_state_get(&format!("rp:w:{}", self.window))
                .unwrap()
                .is_some()
        );
        assert!(client.thin_item(self.claim).unwrap().is_none());
    }

    /// Sends the promotion proof, the promoted VV and the first edit as a
    /// RESIDENCE_UPDATE, then relays both ways until home and device agree.
    /// Returns every window sub-tag the device received and the ACK payload.
    async fn promote_and_converge(
        &self,
        client: &mut SyncClient,
        socket: &mut Socket,
    ) -> (Vec<u8>, Vec<u8>) {
        let loaded = self.manager.open_window(&self.window).unwrap();
        let home_doc = self
            .server
            .get_or_create_window(&self.window)
            .await
            .unwrap();
        let delta = loaded
            .doc
            .export(loro::ExportMode::updates(&home_doc.oplog_vv()))
            .unwrap();
        let mut update = 1u64.to_be_bytes().to_vec();
        update.extend_from_slice(&delta);
        for (tag, payload) in [
            (
                window_sub_tags::PROMOTION_REQUEST,
                oneiron::sync::encode_sync_selector(&self.selector).unwrap(),
            ),
            (window_sub_tags::VV_REQUEST, loaded.doc.oplog_vv().encode()),
            (window_sub_tags::RESIDENCE_UPDATE, update),
        ] {
            let frame = transport::encode_window_sync(self.window.as_str(), tag, &payload)
                .into_result()
                .unwrap();
            socket.send(Message::Binary(frame.into())).await.unwrap();
        }
        let mut seen = Vec::new();
        let mut ack = None;
        let exchange = tokio::time::timeout(Duration::from_secs(10), async {
            let mut check = tokio::time::interval(Duration::from_millis(100));
            check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                if ack.is_some()
                    && carries_edit(&self.home, self.claim)
                    && carries_edit(&self.device, self.claim)
                    && home_doc.oplog_vv() == loaded.doc.oplog_vv()
                {
                    break;
                }
                let message = tokio::select! {
                    _ = check.tick() => continue,
                    message = socket.next() => match message {
                        Some(Ok(message)) => message,
                        other => {
                            panic!("home closed the device socket after {seen:?}: {other:?}")
                        }
                    },
                };
                let Message::Binary(frame) = message else {
                    continue;
                };
                if frame.first() == Some(&transport::TAG_WINDOW_SYNC) {
                    let (key, tag, payload) = transport::decode_window_sync(&frame[1..]).unwrap();
                    assert_eq!(key, self.window.as_str(), "only the promoted window syncs");
                    seen.push(tag);
                    if tag == window_sub_tags::RESIDENCE_ACK {
                        ack = Some(payload.to_vec());
                    }
                }
                for reply in client.handle_server_message(&frame).unwrap() {
                    socket.send(Message::Binary(reply.into())).await.unwrap();
                }
            }
        })
        .await;
        assert!(exchange.is_ok(), "promotion exchange stalled: {seen:?}");
        let ack = ack.unwrap();
        assert_eq!(&ack[..8], &1u64.to_be_bytes());
        assert_eq!(&ack[8..], blake3::hash(&delta).as_bytes());
        (seen, ack)
    }
}

const EDITED_CONFIDENCE: f32 = 0.25;

/// Re-encodes a CLAIM body with a new confidence: an edit of the record that
/// keeps its identity, predicate, value and world.
fn with_confidence(body: &[u8], confidence: f32) -> Vec<u8> {
    let rmpv::Value::Map(mut entries) = rmpv::decode::read_value(&mut &body[..]).unwrap() else {
        panic!("claim body is a map");
    };
    let slot = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("conf"))
        .unwrap();
    slot.1 = rmpv::Value::F32(confidence);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &rmpv::Value::Map(entries)).unwrap();
    out
}

/// Whether `vault`'s CLAIM row carries the device's edit.
fn carries_edit(vault: &Vault, claim: EntityId) -> bool {
    let Some(raw) = vault.get_raw(&claim).unwrap() else {
        return false;
    };
    let rmpv::Value::Map(entries) = rmpv::decode::read_value(&mut &raw[25..]).unwrap() else {
        return false;
    };
    entries.iter().any(|(key, value)| {
        key.as_str() == Some("conf") && value.as_f64() == Some(f64::from(EDITED_CONFIDENCE))
    })
}

fn window_map_has(doc: &loro::LoroDoc, id: EntityId) -> bool {
    doc.get_map("entities").get(&id.to_hex()).is_some()
}

async fn assert_socket_refused(socket: &mut Socket, frame: Vec<u8>, what: &str) {
    socket.send(Message::Binary(frame.into())).await.unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match socket.next().await {
                None | Some(Ok(Message::Close(_)) | Err(_)) => break,
                Some(Ok(Message::Binary(frame))) => {
                    if frame.first() == Some(&transport::TAG_WINDOW_SYNC) {
                        let (_, tag, _) = transport::decode_window_sync(&frame[1..]).unwrap();
                        assert!(
                            !RESIDENCE_SUB_TAGS.contains(&tag),
                            "{what}: v11 got residence sub-tag {tag}"
                        );
                    }
                }
                Some(Ok(_)) => {}
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "{what} must close the v11 socket");
}

const RESIDENCE_SUB_TAGS: [u8; 5] = [
    window_sub_tags::RESIDENCE_UPDATE,
    window_sub_tags::RESIDENCE_ACK,
    window_sub_tags::PROMOTION_REQUEST,
    window_sub_tags::PROMOTION_GRANTED,
    window_sub_tags::PROMOTED_INVALIDATE,
];

#[tokio::test]
async fn v12_residence_round_trips_world_month_key() {
    let fixture = WorldResidence::start(true).await;
    let key = fixture.window.as_str();
    assert_eq!(key.len(), 40, "YYYY-MM@<32hex>");
    assert_eq!(&key[..7], fixture.base.as_str());
    assert_eq!(&key[7..], format!("@{}", fixture.world.to_hex()));
    let (mut client, _events) =
        SyncClient::new(fixture.manager.clone(), fixture.config.clone()).unwrap();
    let mut socket = fixture
        .device_socket(&mut client, "residence-world-v12")
        .await;

    // Index: the followed world's current month is listed, and the CLAIM
    // is indexed under its world-month key, never under the base month.
    assert!(client.fetch_current_index(fixture.now).await.unwrap() >= 1);
    let indexed = |window: &WindowKey| {
        fixture
            .device
            .sync_state_get(&format!("ri:w:{window}:{}", fixture.claim.to_hex()))
            .unwrap()
            .is_some()
    };
    assert!(indexed(&fixture.window));
    assert!(!indexed(&fixture.base));

    // Fetch and edit, then the edit's RESIDENCE_ACK names its exact bytes.
    fixture.fetch_and_edit(&mut client).await;
    let (seen, _ack) = fixture.promote_and_converge(&mut client, &mut socket).await;
    assert!(seen.contains(&window_sub_tags::PROMOTION_GRANTED));
    assert!(seen.contains(&window_sub_tags::RESIDENCE_ACK));
    fixture.server_task.abort();
}

#[tokio::test]
async fn two_vault_thin_world_claim_edit_promotes_into_its_world_month() {
    let fixture = WorldResidence::start(false).await;
    assert_eq!(
        fixture.config.followed_worlds,
        SyncClientConfig::default().followed_worlds,
        "a default opened-item device"
    );
    let (mut client, _events) =
        SyncClient::new(fixture.manager.clone(), fixture.config.clone()).unwrap();
    let mut socket = fixture
        .device_socket(&mut client, "residence-world-default")
        .await;
    // An unfollowed world is not indexed, but its item still opens by id.
    client.fetch_current_index(fixture.now).await.unwrap();
    assert!(
        fixture
            .device
            .sync_state_get(&format!(
                "ri:w:{}:{}",
                fixture.window,
                fixture.claim.to_hex()
            ))
            .unwrap()
            .is_none()
    );
    fixture.fetch_and_edit(&mut client).await;
    fixture.promote_and_converge(&mut client, &mut socket).await;

    // The edit lands in the CLAIM's world-month window, not the base month,
    // on both vaults, and only the world-month window was promoted.
    let home_world = fixture
        .server
        .get_or_create_window(&fixture.window)
        .await
        .unwrap();
    let home_base = fixture
        .server
        .get_or_create_window(&fixture.base)
        .await
        .unwrap();
    let device_world = fixture.manager.open_window(&fixture.window).unwrap();
    assert!(window_map_has(&home_world, fixture.claim));
    assert!(!window_map_has(&home_base, fixture.claim));
    assert!(window_map_has(&device_world.doc, fixture.claim));
    assert!(
        fixture
            .manager
            .window(&fixture.base)
            .is_none_or(|base| !window_map_has(&base.doc, fixture.claim))
    );
    assert!(
        fixture
            .device
            .sync_state_get(&format!("rp:w:{}", fixture.base))
            .unwrap()
            .is_none()
    );
    // Home converges with the device's canonical copy.
    assert_eq!(home_world.oplog_vv(), device_world.doc.oplog_vv());
    assert_eq!(
        home_world.get_deep_value(),
        device_world.doc.get_deep_value()
    );
    // Both vaults materialize the edit. The home re-proposes it: a replicated
    // change cannot carry the old body's critical-confirm Auto status.
    assert!(carries_edit(&fixture.home, fixture.claim));
    assert!(carries_edit(&fixture.device, fixture.claim));
    fixture.server_task.abort();
}

#[tokio::test]
async fn v11_owner_client_gets_no_residence_sub_tags() {
    let fixture = WorldResidence::start(false).await;
    let key = fixture.window.as_str();
    // A v11 owner socket subscribes to the world-month window.
    let mut owner = upgraded_socket(&fixture.server, &fixture.url, "residence-v11-owner").await;
    owner
        .send(Message::Binary(
            transport::encode_chunk_full_window_protocol_hello().into(),
        ))
        .await
        .unwrap();
    let subscribe = transport::encode_window_sync(
        key,
        window_sub_tags::VV_REQUEST,
        &loro::VersionVector::new().encode(),
    )
    .into_result()
    .unwrap();
    owner.send(Message::Binary(subscribe.into())).await.unwrap();
    let mut owner_tags = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !owner_tags.contains(&window_sub_tags::VV_RESPONSE) {
            if let Some(Ok(Message::Binary(frame))) = owner.next().await
                && frame.first() == Some(&transport::TAG_WINDOW_SYNC)
            {
                owner_tags.push(transport::decode_window_sync(&frame[1..]).unwrap().1);
            }
        }
    })
    .await
    .unwrap();

    // A v12 device promotes and writes the same window.
    let (mut client, _events) =
        SyncClient::new(fixture.manager.clone(), fixture.config.clone()).unwrap();
    let mut device = fixture
        .device_socket(&mut client, "residence-v11-peer")
        .await;
    fixture.fetch_and_edit(&mut client).await;
    let (seen, _ack) = fixture.promote_and_converge(&mut client, &mut device).await;
    assert!(seen.contains(&window_sub_tags::RESIDENCE_ACK));

    // The v11 owner gets the ordinary UPDATE fan-out and no residence tags.
    let mut fanout = false;
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(Ok(message)) = owner.next().await {
            if let Message::Binary(frame) = message
                && frame.first() == Some(&transport::TAG_WINDOW_SYNC)
            {
                let (_, tag, _) = transport::decode_window_sync(&frame[1..]).unwrap();
                owner_tags.push(tag);
                fanout |= tag == window_sub_tags::UPDATE;
            }
        }
    })
    .await;
    assert!(
        fanout,
        "the v11 owner still receives the edit: {owner_tags:?}"
    );
    assert!(
        owner_tags
            .iter()
            .all(|tag| !RESIDENCE_SUB_TAGS.contains(tag)),
        "v11 got a residence sub-tag: {owner_tags:?}"
    );

    // Its own residence frames are refused.
    let selector = oneiron::sync::encode_sync_selector(&fixture.selector).unwrap();
    let promotion =
        transport::encode_window_sync(key, window_sub_tags::PROMOTION_REQUEST, &selector)
            .into_result()
            .unwrap();
    assert_socket_refused(&mut owner, promotion, "PROMOTION_REQUEST").await;
    let mut second = upgraded_socket(&fixture.server, &fixture.url, "residence-v11-writer").await;
    second
        .send(Message::Binary(
            transport::encode_chunk_full_window_protocol_hello().into(),
        ))
        .await
        .unwrap();
    let mut update = 1u64.to_be_bytes().to_vec();
    update.extend_from_slice(
        &fixture
            .manager
            .open_window(&fixture.window)
            .unwrap()
            .doc
            .export(loro::ExportMode::all_updates())
            .unwrap(),
    );
    let residence_update =
        transport::encode_window_sync(key, window_sub_tags::RESIDENCE_UPDATE, &update)
            .into_result()
            .unwrap();
    assert_socket_refused(&mut second, residence_update, "RESIDENCE_UPDATE").await;
    fixture.server_task.abort();
}
