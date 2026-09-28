//! Observable stream contracts: no partial persistence, cadence, finality and retry.
use super::*;
use crate::config::VaultConfig;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
#[cfg(feature = "sync")]
use crate::registry::ENTITY_TYPE_MESSAGE;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;

fn fixture() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let actor = EntityId::now();
    vault
        .put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .unwrap();
    (dir, vault, actor)
}
fn input() -> WitnessTurn {
    WitnessTurn {
        conversation_ref: EntityId::now().to_hex(),
        turn_ref: Some(EntityId::now().to_hex()),
        occurred_at: 10,
        messages: vec![WitnessMessage {
            id: Some(EntityId::now().to_hex()),
            author: WitnessAuthor::User,
            message_type: "dialogue".to_owned(),
            content: String::new(),
            metadata: None,
            is_visible: true,
            order: 0,
        }],
    }
}
fn streamed(cadence: StreamCadence) -> MessageWriteMode {
    MessageWriteMode::Streamed {
        visibility: StreamSyncVisibility::AllDevices,
        cadence,
    }
}
fn content(vault: &Vault, message: EntityId) -> String {
    let body = vault.get(&message).unwrap().unwrap();
    let value: serde_json::Value = rmp_serde::from_slice(&body).unwrap();
    value["content"].as_str().unwrap().to_owned()
}
fn assert_no_seed(vault: &Vault) {
    let txn = vault.store.env.read_txn().unwrap();
    assert!(
        vault
            .store
            .vault_meta
            .prefix_iter(&txn, storage::ACTIVE.decl().prefix)
            .unwrap()
            .next()
            .is_none()
    );
}
// Pin all durable op/index substrates, not a log line or private diagnostic.
fn durable_substrates(vault: &Vault) -> Vec<Vec<(Vec<u8>, Vec<u8>)>> {
    let txn = vault.store.env.read_txn().unwrap();
    let mut out = Vec::new();
    for db in [
        &vault.store.entities,
        &vault.store.type_index,
        &vault.store.edges_out,
        &vault.store.edges_in,
        &vault.store.text_postings,
        &vault.store.text_forward,
        &vault.store.text_meta,
        &vault.store.sync_queue,
    ] {
        out.push(
            db.iter(&txn)
                .unwrap()
                .map(|r| {
                    let (k, v) = r.unwrap();
                    (k.to_vec(), v.to_vec())
                })
                .collect(),
        );
    }
    out.push(
        vault
            .store
            .sync_state
            .iter(&txn)
            .unwrap()
            .map(|r| {
                let (k, v) = r.unwrap();
                (k.as_bytes().to_vec(), v.to_vec())
            })
            .collect(),
    );
    out.push(
        vault
            .store
            .vault_meta
            .iter(&txn)
            .unwrap()
            .filter_map(|r| {
                let (k, v) = r.unwrap();
                (!k.starts_with(storage::ACTIVE.decl().prefix)).then(|| (k.to_vec(), v.to_vec()))
            })
            .collect(),
    );
    out
}
#[test]
fn message_stream_partials_have_no_durable_ops_and_idle_commits_atomically() {
    let (_dir, vault, actor) = fixture();
    let memory = vault.memory(actor, EdgeActorClass::Human);
    let before = durable_substrates(&vault);
    let turn = input();
    let handle = memory
        .begin_message_stream_at(
            &turn,
            Some(streamed(StreamCadence::PerWindow { chars: 300 })),
            100,
        )
        .unwrap();
    memory
        .append_to_stream_at(handle, "ephemeraloneiron", 200)
        .unwrap();
    memory.flush_stream(handle).unwrap();
    assert_eq!(durable_substrates(&vault), before);
    assert!(!vault.entity_exists(&handle.message_id()).unwrap());
    assert!(vault.search_text("ephemeraloneiron", 5).unwrap().is_empty());
    assert!(
        vault
            .pump_message_streams_at(30_199)
            .unwrap()
            .finalized
            .is_empty()
    );
    let report = vault.pump_message_streams_at(30_200).unwrap();
    assert!(report.refused.is_empty());
    assert_eq!(report.finalized.len(), 1);
    let receipt = &report.finalized[0];
    assert_eq!(receipt.finality, StreamFinality::Partial);
    assert_eq!(
        receipt.finality_reason,
        StreamFinalityReason::IdleTimeout30s
    );
    assert_eq!(content(&vault, handle.message_id()), "ephemeraloneiron");
    assert_eq!(
        vault
            .message_stream_receipt(&handle.message_id())
            .unwrap()
            .as_ref(),
        Some(receipt)
    );
    assert_eq!(
        vault
            .message_stream_receipt_by_ref(&receipt.receipt_ref)
            .unwrap()
            .as_ref(),
        Some(receipt)
    );
    assert_eq!(vault.active_message_streams().unwrap(), 0);
    assert_no_seed(&vault);
    let turn_id = EntityId::from_hex(turn.turn_ref.as_ref().unwrap()).unwrap();
    assert!(
        vault
            .edge_exists(&handle.message_id(), EdgeKind::PartOf, &turn_id)
            .unwrap()
    );
    assert!(
        vault
            .search_text("ephemeraloneiron", 5)
            .unwrap()
            .iter()
            .any(|hit| hit.id == handle.message_id())
    );
}
#[test]
fn message_stream_crash_recovers_only_committed_base_with_explicit_loss_receipt() {
    let (dir, vault, actor) = fixture();
    let message = {
        let memory = vault.memory(actor, EdgeActorClass::Human);
        let handle = memory
            .begin_message_stream(&input(), Some(streamed(StreamCadence::Manual)))
            .unwrap();
        memory
            .append_to_stream(handle, "lost-only-in-memory")
            .unwrap();
        handle.message_id()
    };
    drop(vault);
    let reopened = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let receipt = reopened.message_stream_receipt(&message).unwrap().unwrap();
    assert_eq!(receipt.finality, StreamFinality::Partial);
    assert_eq!(
        receipt.finality_reason,
        StreamFinalityReason::ProcessCrashRecovery
    );
    assert!(receipt.recovered && receipt.ephemeral_text_lost);
    assert_eq!(content(&reopened, message), "");
    assert_no_seed(&reopened);
    drop(reopened);
    let reopened = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    assert_eq!(
        reopened.message_stream_receipt(&message).unwrap(),
        Some(receipt)
    );
}
#[test]
fn message_stream_finalize_failure_retains_output_and_retry_is_lossless() {
    let (_dir, vault, actor) = fixture();
    let memory = vault.memory(actor, EdgeActorClass::Human);
    let turn = input();
    let handle = memory
        .begin_message_stream(&turn, Some(streamed(StreamCadence::Manual)))
        .unwrap();
    memory
        .append_to_stream(handle, "must survive refusal")
        .unwrap();
    // Remove the actor row to force the transaction-authoritative binding check.
    let actor_row = vault
        .with_write_txn(|txn| {
            let row = vault
                .store
                .entities
                .get(txn, actor.as_bytes())?
                .map(std::borrow::Cow::into_owned);
            vault.store.entities.delete(txn, actor.as_bytes())?;
            Ok(row)
        })
        .unwrap()
        .unwrap();
    assert!(memory.finalize_stream(handle).is_err());
    assert_eq!(
        memory.message_stream_partial(handle).unwrap().text,
        "must survive refusal"
    );
    assert_eq!(vault.active_message_streams().unwrap(), 1);
    assert!(
        vault
            .message_stream_receipt(&handle.message_id())
            .unwrap()
            .is_none()
    );
    assert!(!vault.entity_exists(&handle.message_id()).unwrap());
    // Restore the exact actor fixture, not the buffered output.
    vault
        .with_write_txn(|txn| vault.store.entities.put(txn, actor.as_bytes(), &actor_row))
        .unwrap();
    let receipt = memory.finalize_stream(handle).unwrap();
    assert_eq!(receipt.finality, StreamFinality::Final);
    assert_eq!(content(&vault, handle.message_id()), "must survive refusal");
    assert_no_seed(&vault);
}
#[test]
fn message_stream_policy_precedence_bounds_and_actor_ownership() {
    let (_dir, vault, actor) = fixture();
    let memory = vault.memory(actor, EdgeActorClass::Human);
    assert_eq!(
        vault.message_stream_policy().unwrap(),
        MessageStreamPolicy::default()
    );
    let atomic = memory.begin_message_stream(&input(), None).unwrap();
    assert_eq!(
        memory.message_stream_partial(atomic).unwrap().mode,
        MessageWriteMode::Atomic
    );
    memory.finalize_stream(atomic).unwrap();
    let mut policy = MessageStreamPolicy {
        default_mode: streamed(StreamCadence::Manual),
        idle_timeout_ms: 10,
        ..Default::default()
    };
    memory.set_message_stream_policy(&policy).unwrap();
    let default = memory.begin_message_stream_at(&input(), None, 0).unwrap();
    assert_eq!(
        memory.message_stream_partial(default).unwrap().mode,
        policy.default_mode
    );
    policy
        .agent_overrides
        .insert(actor, streamed(StreamCadence::PerToken));
    memory.set_message_stream_policy(&policy).unwrap();
    let actor_override = memory.begin_message_stream_at(&input(), None, 0).unwrap();
    assert_eq!(
        memory.message_stream_partial(actor_override).unwrap().mode,
        streamed(StreamCadence::PerToken)
    );
    let explicit_turn = input();
    let explicit = memory
        .begin_message_stream_at(&explicit_turn, Some(MessageWriteMode::Atomic), 0)
        .unwrap();
    assert_eq!(
        memory.message_stream_partial(explicit).unwrap().mode,
        MessageWriteMode::Atomic
    );
    assert!(matches!(
        memory.begin_message_stream(&explicit_turn, None),
        Err(MessageStreamError::StreamAlreadyActive(_))
    ));
    let outsider = vault.memory(EntityId::now(), EdgeActorClass::Human);
    assert!(matches!(
        outsider.append_to_stream(explicit, "forged"),
        Err(MessageStreamError::WrongActor)
    ));
    let expired = vault.pump_message_streams_at(10).unwrap();
    assert_eq!(expired.finalized.len(), 3);
    for receipt in &expired.finalized {
        assert_eq!(
            receipt.finality_reason,
            StreamFinalityReason::IdleTimeout { timeout_ms: 10 }
        );
        assert_eq!(
            vault
                .message_stream_receipt(&receipt.message_id)
                .unwrap()
                .as_ref(),
            Some(receipt)
        );
    }
    assert!(matches!(
        memory.append_to_stream(explicit, "stale"),
        Err(MessageStreamError::StreamNotFound)
    ));
    let mut handles = Vec::new();
    for _ in 0..MAX_MESSAGE_STREAMS {
        handles.push(memory.begin_message_stream_at(&input(), None, 100).unwrap());
    }
    assert!(matches!(
        memory.begin_message_stream(&input(), None),
        Err(MessageStreamError::TooManyStreams)
    ));
    memory
        .cancel_stream(handles[0], StreamCancelReason::UserInterrupted)
        .unwrap();
    assert!(memory.begin_message_stream(&input(), None).is_ok());
}
#[test]
fn message_stream_buffer_overflow_does_not_accept_delta() {
    let (_dir, vault, actor) = fixture();
    let memory = vault.memory(actor, EdgeActorClass::Human);
    let handle = memory
        .begin_message_stream(&input(), Some(MessageWriteMode::Atomic))
        .unwrap();
    memory.append_to_stream(handle, "retained").unwrap();
    assert!(matches!(
        memory.append_to_stream(handle, &"x".repeat(MAX_MESSAGE_STREAM_BYTES)),
        Err(MessageStreamError::BufferOverflow)
    ));
    assert_eq!(
        memory.message_stream_partial(handle).unwrap().text,
        "retained"
    );
}
#[cfg(feature = "sync")]
fn frame_text(frame: &[u8]) -> Option<String> {
    assert_eq!(frame[0], crate::sync::TAG_EPHEMERAL);
    let states = crate::sync::decode_ephemeral_states(&frame[1..]).unwrap();
    assert_eq!(states.len(), 1);
    states[0].value.as_ref().map(|v| {
        let crate::sync::LoroValue::Map(fields) = v else {
            panic!("map")
        };
        let crate::sync::LoroValue::String(text) = &fields["text"] else {
            panic!("text")
        };
        text.to_string()
    })
}
#[cfg(feature = "sync")]
#[test]
fn message_stream_native_presence_cadence_flush_visibility_and_tombstone() {
    let (_dir, vault, actor) = fixture();
    let memory = vault.memory(actor, EdgeActorClass::Human);
    let mut frames = vault.message_streams.presence.subscribe_frames();
    let (_remote_dir, remote_vault, _) = fixture();
    let manager = Arc::new(crate::sync::WindowManager::new(
        Arc::new(remote_vault),
        Arc::new(crate::sync::bridge::Materializer::new()),
        "stream-test",
    ));
    let (mut remote, _events) = crate::sync::SyncClient::new(manager, Default::default()).unwrap();
    let handle = memory
        .begin_message_stream(&input(), Some(streamed(StreamCadence::PerToken)))
        .unwrap();
    for (token, full) in [("one", "one"), (" two", "one two")] {
        memory.append_to_stream(handle, token).unwrap();
        let frame = frames.try_recv().unwrap();
        assert_eq!(frame_text(&frame).as_deref(), Some(full));
        assert!(remote.handle_server_message(&frame).unwrap().is_empty());
        let key = format!("msg:{}", handle.message_id().to_hex());
        assert!(remote.ephemeral(&key).is_some());
    }
    memory.finalize_stream(handle).unwrap();
    assert_eq!(frame_text(&frames.try_recv().unwrap()), None);
    let window = memory
        .begin_message_stream(
            &input(),
            Some(streamed(StreamCadence::PerWindow { chars: 3 })),
        )
        .unwrap();
    memory.append_to_stream(window, "é界").unwrap();
    assert!(frames.try_recv().is_err());
    memory.append_to_stream(window, "🙂").unwrap();
    assert_eq!(
        frame_text(&frames.try_recv().unwrap()).as_deref(),
        Some("é界🙂")
    );
    memory.append_to_stream(window, "x").unwrap();
    assert!(frames.try_recv().is_err());
    memory.flush_stream(window).unwrap();
    assert_eq!(
        frame_text(&frames.try_recv().unwrap()).as_deref(),
        Some("é界🙂x")
    );
    memory.flush_stream(window).unwrap();
    assert!(frames.try_recv().is_err());
    let sentence = memory
        .begin_message_stream(&input(), Some(streamed(StreamCadence::PerSentence)))
        .unwrap();
    memory.append_to_stream(sentence, "hello").unwrap();
    assert!(frames.try_recv().is_err());
    memory.append_to_stream(sentence, "! ").unwrap();
    assert_eq!(
        frame_text(&frames.try_recv().unwrap()).as_deref(),
        Some("hello! ")
    );
    let local = memory
        .begin_message_stream(
            &input(),
            Some(MessageWriteMode::Streamed {
                visibility: StreamSyncVisibility::OriginatorOnly,
                cadence: StreamCadence::Manual,
            }),
        )
        .unwrap();
    memory.append_to_stream(local, "private live view").unwrap();
    memory.flush_stream(local).unwrap();
    assert!(frames.try_recv().is_err());
    assert!(
        vault
            .message_streams
            .presence
            .store
            .get(&format!("msg:{}", local.message_id().to_hex()))
            .is_some()
    );
    let large = memory
        .begin_message_stream(&input(), Some(streamed(StreamCadence::Manual)))
        .unwrap();
    memory
        .append_to_stream(large, &"x ".repeat(35_000))
        .unwrap();
    assert!(matches!(
        memory.flush_stream(large),
        Err(MessageStreamError::PresenceFrameTooLarge)
    ));
    assert_eq!(memory.finalize_stream(large).unwrap().bytes, 70_000);
}
#[cfg(feature = "sync")]
#[test]
fn message_stream_continuation_uses_same_document_and_crash_retains_committed_base() {
    let (dir, vault, actor) = fixture();
    let turn = input();
    let memory = vault.memory(actor, EdgeActorClass::Human);
    let first = memory
        .begin_message_stream(&turn, Some(MessageWriteMode::Atomic))
        .unwrap();
    memory.append_to_stream(first, "base").unwrap();
    let original = memory.finalize_stream(first).unwrap();
    let second = memory
        .begin_message_stream(&turn, Some(MessageWriteMode::Atomic))
        .unwrap();
    assert!(matches!(
        memory.append_to_stream(first, "stale generation"),
        Err(MessageStreamError::StreamNotFound)
    ));
    memory.append_to_stream(second, " + continuation").unwrap();
    let second_receipt = memory.finalize_stream(second).unwrap();
    assert_eq!(content(&vault, first.message_id()), "base + continuation");
    assert_ne!(original.generation, second_receipt.generation);
    assert_eq!(
        vault
            .message_stream_receipt_by_ref(&original.receipt_ref)
            .unwrap(),
        Some(original)
    );
    let third = memory
        .begin_message_stream(&turn, Some(MessageWriteMode::Atomic))
        .unwrap();
    memory.append_to_stream(third, " uncommitted tail").unwrap();
    let message = third.message_id();
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    assert_eq!(content(&vault, message), "base + continuation");
    let receipt = vault.message_stream_receipt(&message).unwrap().unwrap();
    assert!(receipt.ephemeral_text_lost);
    assert_eq!(receipt.bytes, "base + continuation".len() as u64);
    assert_eq!(
        vault.entities_by_type(ENTITY_TYPE_MESSAGE).unwrap(),
        vec![message]
    );
    let mut sibling = turn;
    sibling.messages[0].id = Some(EntityId::now().to_hex());
    sibling.messages[0].order = 1;
    sibling.messages[0].content = "next sibling".to_owned();
    vault
        .memory(actor, EdgeActorClass::Human)
        .commit_message(&sibling)
        .unwrap();
    assert_no_seed(&vault);
}

#[test]
fn message_stream_concurrent_begin_has_one_winner_and_idle_never_loses_accepted_output() {
    let (_dir, vault, actor) = fixture();
    let turn = input();
    let barrier = std::sync::Barrier::new(2);
    let outcomes = std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            barrier.wait();
            vault
                .memory(actor, EdgeActorClass::Human)
                .begin_message_stream_at(&turn, None, 0)
        });
        let b = scope.spawn(|| {
            barrier.wait();
            vault
                .memory(actor, EdgeActorClass::Human)
                .begin_message_stream_at(&turn, None, 0)
        });
        [a.join().unwrap(), b.join().unwrap()]
    });
    assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(
        outcomes
            .iter()
            .any(|r| matches!(r, Err(MessageStreamError::StreamAlreadyActive(_))))
    );
    let handle = outcomes.into_iter().find_map(Result::ok).unwrap();
    let barrier = std::sync::Barrier::new(2);
    let (append, report) = std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            barrier.wait();
            vault
                .memory(actor, EdgeActorClass::Human)
                .append_to_stream_at(handle, "accepted", 30_000)
        });
        let b = scope.spawn(|| {
            barrier.wait();
            vault.pump_message_streams_at(30_000)
        });
        (a.join().unwrap(), b.join().unwrap().unwrap())
    });
    if append.is_ok() {
        assert!(report.finalized.is_empty());
        let memory = vault.memory(actor, EdgeActorClass::Human);
        memory.finalize_stream(handle).unwrap();
        assert_eq!(content(&vault, handle.message_id()), "accepted");
    } else {
        assert!(matches!(append, Err(MessageStreamError::StreamNotFound)));
        assert_eq!(report.finalized.len(), 1);
        assert_eq!(content(&vault, handle.message_id()), "");
    }
}

#[cfg(feature = "sync")]
#[test]
fn message_stream_continuation_window_counts_only_new_unicode_scalars() {
    let (_dir, vault, actor) = fixture();
    let memory = vault.memory(actor, EdgeActorClass::Human);
    let turn = input();
    let first = memory
        .begin_message_stream(&turn, Some(MessageWriteMode::Atomic))
        .unwrap();
    memory.append_to_stream(first, "committed base").unwrap();
    memory.finalize_stream(first).unwrap();
    let mut frames = vault.message_streams.presence.subscribe_frames();
    let continuation = memory
        .begin_message_stream(&turn, Some(streamed(StreamCadence::PerWindow { chars: 3 })))
        .unwrap();
    memory.append_to_stream(continuation, "é界").unwrap();
    assert!(frames.try_recv().is_err());
    memory.append_to_stream(continuation, "🙂").unwrap();
    assert_eq!(
        frame_text(&frames.try_recv().unwrap()).as_deref(),
        Some("committed baseé界🙂")
    );
    memory.finalize_stream(continuation).unwrap();
    assert_eq!(
        content(&vault, continuation.message_id()),
        "committed baseé界🙂"
    );
}
