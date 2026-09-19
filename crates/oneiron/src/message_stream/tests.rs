//! Caller-visible streaming laws; partial text never reaches storage.
use super::*;
use crate::edge::EdgeActorClass;
use crate::memory::{WitnessAuthor, WitnessMessage};
fn fixture() -> (tempfile::TempDir, Vault, WriteActor) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let actor = WriteActor::new(
        vault.ensure_embedded_owner_actor().unwrap(),
        EdgeActorClass::Human,
    );
    (dir, vault, actor)
}
fn template() -> WitnessTurn {
    WitnessTurn {
        conversation_ref: EntityId::now().to_hex(),
        turn_ref: None,
        occurred_at: 1,
        messages: vec![WitnessMessage {
            id: None,
            author: WitnessAuthor::User,
            message_type: "text".into(),
            content: String::new(),
            metadata: None,
            is_visible: true,
            order: 0,
        }],
    }
}
fn streamed() -> MessageWriteMode {
    MessageWriteMode::Streamed {
        sync_visibility: StreamSyncVisibility::AllDevices,
        cadence: StreamCadence::PerToken,
    }
}
fn text(vault: &Vault, id: EntityId) -> String {
    let body = vault.get(&id).unwrap().unwrap();
    let value = rmpv::decode::read_value(&mut body.as_slice()).unwrap();
    let rmpv::Value::Map(fields) = value else {
        panic!("MESSAGE map");
    };
    fields
        .iter()
        .find_map(|(k, v)| (k.as_str() == Some("content")).then(|| v.as_str().unwrap().to_owned()))
        .unwrap()
}
#[test]
fn duplicate_begin_refuses_and_finalize_writes_full_text_with_one_receipt() {
    let (_dir, vault, actor) = fixture();
    let id = EntityId::now();
    let turn = template();
    let handle = vault
        .begin_message_stream(id, turn.clone(), actor, Some(streamed()))
        .unwrap();
    assert!(
        matches!(vault.begin_message_stream(id,turn,actor,None),Err(MessageStreamError::Engine(Error::Record(RecordError::StreamAlreadyActive {message}))) if message==id)
    );
    let frame = vault.append_to_stream(&handle, "first ").unwrap().unwrap();
    assert_eq!(frame.text, "first ");
    assert_eq!(frame.visibility, StreamSyncVisibility::AllDevices);
    vault.append_to_stream(&handle, "second").unwrap();
    assert!(vault.get(&id).unwrap().is_none());
    assert!(vault.message_finality_receipt(id).unwrap().is_none());
    assert_eq!(
        vault.flush_stream(&handle).unwrap().unwrap().text,
        "first second"
    );
    assert!(vault.get(&id).unwrap().is_none());
    let receipt = vault.finalize_stream(&handle).unwrap();
    assert_eq!(receipt.finality(), MessageFinality::Final);
    assert_eq!(text(&vault, id), "first second");
    assert_eq!(vault.message_finality_receipt(id).unwrap(), Some(receipt));
    assert!(matches!(
        vault.append_to_stream(&handle, "late"),
        Err(Error::Record(RecordError::StreamNotActive { .. }))
    ));
}
#[test]
fn cancel_keeps_partial_and_reason_after_reopen() {
    let (dir, vault, actor) = fixture();
    let id = EntityId::now();
    let h = vault
        .begin_message_stream(id, template(), actor, None)
        .unwrap();
    assert_eq!(h.mode(), MessageWriteMode::Atomic);
    assert!(vault.append_to_stream(&h, "partial").unwrap().is_none());
    let receipt = vault
        .cancel_stream(&h, StreamCancelReason::UserInterrupted)
        .unwrap();
    assert_eq!(receipt.finality(), MessageFinality::Cancelled);
    assert_eq!(receipt.reason(), Some(&StreamCancelReason::UserInterrupted));
    drop(vault);
    let reopened = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    assert_eq!(text(&reopened, id), "partial");
    assert_eq!(
        reopened.message_finality_receipt(id).unwrap(),
        Some(receipt)
    );
}
#[test]
fn mode_precedence_and_bound_chat_override_are_effective() {
    let (_dir, vault, actor) = fixture();
    let policy = MessageStreamPolicy {
        default_mode: streamed(),
        ..Default::default()
    };
    vault.set_message_stream_policy(&policy, actor).unwrap();
    let default = vault
        .begin_message_stream(EntityId::now(), template(), actor, None)
        .unwrap();
    assert_eq!(default.mode(), streamed());
    vault
        .memory(actor.entity_ref(), actor.actor_class())
        .set_message_stream_override(Some(MessageWriteMode::Atomic))
        .unwrap();
    let own = vault
        .begin_message_stream(EntityId::now(), template(), actor, None)
        .unwrap();
    assert_eq!(own.mode(), MessageWriteMode::Atomic);
    let explicit = vault
        .begin_message_stream(EntityId::now(), template(), actor, Some(streamed()))
        .unwrap();
    assert_eq!(explicit.mode(), streamed());
    for handle in [default, own, explicit] {
        vault
            .cancel_stream(&handle, StreamCancelReason::AgentAborted)
            .unwrap();
    }
}
#[test]
fn refused_finalization_keeps_buffer_and_mints_neither_message_nor_receipt() {
    let (_dir, vault, actor) = fixture();
    let id = EntityId::now();
    let mut turn = template();
    turn.messages[0].author = WitnessAuthor::System;
    let h = vault
        .begin_message_stream(id, turn, actor, Some(streamed()))
        .unwrap();
    vault.append_to_stream(&h, "not authorized").unwrap();
    assert!(vault.finalize_stream(&h).is_err());
    assert!(vault.get(&id).unwrap().is_none());
    assert!(vault.message_finality_receipt(id).unwrap().is_none());
    assert_eq!(
        vault.flush_stream(&h).unwrap().unwrap().text,
        "not authorized"
    );
}
