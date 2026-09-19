//! Streaming text stays on the existing opaque, budgeted ephemeral hub lane.
use super::*;
use crate::config::SyncServerConfig;
use oneiron::sync::{EphemeralStore, LoroValue, decode_ephemeral_states, encode_ephemeral_states};

#[tokio::test]
async fn message_stream_presence_canonical_fanout_and_late_join_never_persist_text() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let server = SyncServer::new(Arc::clone(&vault), SyncServerConfig::default()).unwrap();
    let message = oneiron::EntityId::now();
    let key = format!("msg:{}", message.to_hex());
    let producer = EphemeralStore::new(30_000);
    producer.set(
        &key,
        LoroValue::Map(
            vec![
                ("schema_version".to_owned(), LoroValue::I64(1)),
                (
                    "message_id".to_owned(),
                    LoroValue::String(message.to_hex().into()),
                ),
                (
                    "generation".to_owned(),
                    LoroValue::String(oneiron::EntityId::now().to_hex().into()),
                ),
                ("seq".to_owned(), LoroValue::I64(2)),
                ("text".to_owned(), LoroValue::String("one two".into())),
            ]
            .into(),
        ),
    );
    let config = SyncServerConfig::default();
    let mut state = ConnState::new(
        config.max_messages_per_sec,
        protocol::PROTOCOL_VERSION,
        FederationQuotaConfig::new(
            config.max_federation_windows_per_connection,
            config.federation_flood_pause_secs,
        ),
    );
    let (direct_tx, mut direct_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut fanout = server.broadcast_tx.subscribe();
    handle_sync_message(
        &server,
        17,
        SyncMessage::Ephemeral(producer.encode(&key)),
        &direct_tx,
        &mut state,
    )
    .await
    .unwrap();
    assert!(direct_rx.try_recv().is_err());
    let (sender, frame) = fanout.try_recv().unwrap();
    assert_eq!(sender, 17);
    assert_eq!(frame[0], oneiron::sync::TAG_EPHEMERAL);
    let receiver = EphemeralStore::new(30_000);
    receiver.apply(&frame[1..]).unwrap();
    assert_eq!(receiver.get(&key), producer.get(&key));
    let late = encode_late_join_ephemeral_snapshot(&server, 18).unwrap();
    let late_receiver = EphemeralStore::new(30_000);
    late_receiver.apply(&late[1..]).unwrap();
    assert_eq!(late_receiver.get(&key), producer.get(&key));
    assert!(!vault.entity_exists(&message).unwrap());
    assert!(vault.search_text("one two", 10).unwrap().is_empty());
    // Loro uses millisecond LWW timestamps and ignores equal-timestamp updates.
    // Exercise a causally newer clear without depending on test execution speed.
    let mut cleared = decode_ephemeral_states(&frame[1..]).unwrap();
    for row in &mut cleared {
        row.value = None;
        row.timestamp += 1;
    }
    handle_sync_message(
        &server,
        17,
        SyncMessage::Ephemeral(encode_ephemeral_states(&cleared).unwrap()),
        &direct_tx,
        &mut state,
    )
    .await
    .unwrap();
    let (_, clear) = fanout.try_recv().unwrap();
    assert!(
        decode_ephemeral_states(&clear[1..])
            .unwrap()
            .iter()
            .all(|row| row.value.is_none())
    );
    receiver.apply(&clear[1..]).unwrap();
    assert!(receiver.get(&key).is_none());
}

#[tokio::test]
async fn message_stream_local_host_relay_is_live_without_a_sync_client() {
    use oneiron::memory::{
        MessageWriteMode, StreamCadence, StreamSyncVisibility, WitnessAuthor, WitnessMessage,
        WitnessTurn,
    };
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let actor = oneiron::EntityId::now();
    vault
        .put_entity(
            &actor,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .unwrap();
    let server = SyncServer::new(Arc::clone(&vault), SyncServerConfig::default()).unwrap();
    let mut fanout = server.broadcast_tx.subscribe();
    let message = oneiron::EntityId::now();
    let turn = WitnessTurn {
        conversation_ref: oneiron::EntityId::now().to_hex(),
        turn_ref: Some(oneiron::EntityId::now().to_hex()),
        occurred_at: 1,
        messages: vec![WitnessMessage {
            id: Some(message.to_hex()),
            author: WitnessAuthor::User,
            message_type: "dialogue".to_owned(),
            content: String::new(),
            metadata: None,
            is_visible: true,
            order: 0,
        }],
    };
    let memory = vault.memory(actor, oneiron::EdgeActorClass::Human);
    let handle = memory
        .begin_message_stream(
            &turn,
            Some(MessageWriteMode::Streamed {
                visibility: StreamSyncVisibility::AllDevices,
                cadence: StreamCadence::PerToken,
            }),
        )
        .unwrap();
    memory
        .append_to_stream(handle, "live native producer")
        .unwrap();
    let (sender, frame) = tokio::time::timeout(std::time::Duration::from_secs(5), fanout.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sender, 0);
    assert_eq!(frame[0], oneiron::sync::TAG_EPHEMERAL);
    assert!(
        server
            .ephemeral_store
            .get(&format!("msg:{}", message.to_hex()))
            .is_some()
    );
    assert!(!vault.entity_exists(&message).unwrap());
}
