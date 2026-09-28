#![expect(
    clippy::unwrap_used,
    reason = "test fixture failures should panic immediately"
)]
//! A real enrol: root + thin index, one opened item, remote search and offline honesty.

use crate::config::SyncServerConfig;
use crate::server::SyncServer;
use futures_util::{SinkExt, StreamExt};
use oneiron::federation::{FederationGrant, FederationGrantPreset, FederationGrantRole};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::sync::client::NoteSyncSession;
use oneiron::sync::{
    SearchSource, SyncClient, SyncClientConfig, SyncSelector, SyncSelectorWorld, WindowKey,
    WindowManager, bridge::Materializer,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use std::sync::Arc;
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

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
        auth_token: "residence-phone-root".into(),
        note_session: Some(NoteSyncSession::new(slip.to_token().unwrap(), key)),
        residence_selector: Some(selector),
        ..Default::default()
    };
    let driver_config = config.clone();
    let (mut client, _events) = SyncClient::new(manager.clone(), config).unwrap();
    let mut request = url.as_str().into_client_request().unwrap();
    request.headers_mut().insert(
        "authorization",
        "Bearer residence-phone-root".parse().unwrap(),
    );
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
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
    use oneiron::sync::{ConnectionConfig, SyncConnection, SyncEvent, SyncStatus};
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
    use oneiron::sync::transport::{self, window_sub_tags};
    use oneiron::sync::{ConnectionConfig, SyncConnection};
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
        auth_token: "residence-causal-root".into(),
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
    let mut request = url.as_str().into_client_request().unwrap();
    request.headers_mut().insert(
        "authorization",
        "Bearer residence-causal-root".parse().unwrap(),
    );
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
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
