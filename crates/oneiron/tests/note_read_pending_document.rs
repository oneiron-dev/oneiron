//! A replica that holds a NOTE's row before its authority has sent the
//! NOTE's head document answers the typed NOTE read with no value, never a
//! corrupt-body refusal. Once the document lands, the same read answers the
//! NOTE's text from the local copy (FIX-LIST
//! [REPLICA-NOTE-READ-400-BEFORE-DOCUMENT]; E2E SYNC-01 and SYNC-05).
//!
//! The NOTE row and its head document travel on separate lanes: the row in
//! its window, the document on the owner lane, which the sync registry asks
//! for from an empty version once the row is held. The typed read refused
//! the state between the two as "invalid NOTE body: NOTE head document
//! missing", which the HTTP door answers 400, so a device that switched to
//! sync-all could not poll a NOTE until its text arrived.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test
//! note_read_pending_document`.
#![cfg(feature = "sync")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use loro::{LoroDoc, VersionVector};
use oneiron::note::{NoteReadRequest, NoteReadSource, NoteReadView};
use oneiron::sync::bridge::Materializer;
use oneiron::sync::client::NoteSyncSession;
use oneiron::sync::transport::TAG_RPC;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{
    export_window_updates_since, forward_rematerialize, reverse_rematerialize,
};
use oneiron::sync::{SyncClient, SyncClientConfig, SyncEvent, WindowManager};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
use oneiron_contracts::record_layout::EntityMetadataHeader;
use rmpv::Value;
use tokio::sync::mpsc::UnboundedReceiver;

const TEXT: &str = "The tide tables for the north harbour.";

/// The fixed request id of the client's `auth.bind` call.
const BIND_REQUEST_ID: u64 = 4_294_967_295;

/// An own device: its vault, its owner, its window manager and a NOTE
/// client whose session the home has bound.
struct Device {
    vault: Arc<Vault>,
    owner: EntityId,
    manager: Arc<WindowManager>,
    client: SyncClient,
    _events: UnboundedReceiver<SyncEvent>,
    _dir: tempfile::TempDir,
}

fn device() -> Device {
    let dir = tempfile::tempdir().expect("device dir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::default()).expect("device vault"));
    let owner = vault.ensure_embedded_owner_actor().expect("device owner");
    let manager = Arc::new(WindowManager::new(
        vault.clone(),
        Arc::new(Materializer::new()),
        "own-device",
    ));
    let (mut client, events) = SyncClient::new(
        manager.clone(),
        SyncClientConfig {
            server_url: "ws://127.0.0.1:9/ws".to_owned(),
            note_session: Some(NoteSyncSession::new(
                "note-session".to_owned(),
                SigningKey::from_bytes(&[1; 32]),
            )),
            ..Default::default()
        },
    )
    .expect("device client");
    client
        .handle_server_message(&bind_reply())
        .expect("the home binds the NOTE session");
    Device {
        vault,
        owner,
        manager,
        client,
        _events: events,
        _dir: dir,
    }
}

/// The home's `rpc.res` answer to the client's `auth.bind`.
fn bind_reply() -> Vec<u8> {
    let mut frame = vec![TAG_RPC];
    rmpv::encode::write_value(
        &mut frame,
        &Value::Map(vec![
            (Value::from("type"), Value::from("rpc.res")),
            (Value::from("id"), Value::from(BIND_REQUEST_ID)),
            (Value::from("seq"), Value::from(0_u64)),
            (Value::from("last"), Value::from(true)),
            (Value::from("payload"), Value::Binary(vec![0xc0])),
        ]),
    )
    .expect("encode the bind reply");
    frame
}

/// The window that holds `note`'s row on `source`.
fn window_of(source: &Vault, note: EntityId) -> WindowKey {
    let raw = source
        .get_raw(&note)
        .expect("read the NOTE row")
        .expect("the NOTE row exists");
    WindowKey::from_timestamp(
        EntityMetadataHeader::parse(&raw)
            .expect("the NOTE row header")
            .learned_at,
    )
}

/// Sends `source`'s window `key` to `peer` whole: the rows only, no NOTE
/// document.
fn send_window(source: &Vault, peer: &Vault, key: &WindowKey) {
    let window = LoroDoc::new();
    reverse_rematerialize(source, &window, key).expect("build the source window");
    let bytes =
        export_window_updates_since(source, key, &window, &VersionVector::default().encode())
            .expect("export the source window")
            .into_bytes();
    let received = LoroDoc::new();
    received.import(&bytes).expect("decode the window");
    forward_rematerialize(peer, &received, &Materializer::new(), key)
        .expect("the peer takes the window");
}

/// The device owner's typed NOTE read (`vault.notes.read`): its value, or
/// the refusal it answers.
fn read(device: &Device, note: EntityId) -> Result<Option<NoteReadView>, String> {
    device
        .vault
        .memory(device.owner, EdgeActorClass::Human)
        .read_note(&NoteReadRequest {
            note_ref: note.to_hex(),
            reason: None,
            version: None,
            spans: Vec::new(),
        })
        .map(|result| result.value)
        .map_err(|error| format!("{error:?}"))
}

#[test]
fn a_replica_holding_a_notes_row_before_its_document_reads_no_value_then_the_text() {
    let source_dir = tempfile::tempdir().expect("source dir");
    let source =
        Arc::new(Vault::open(source_dir.path(), VaultConfig::default()).expect("source vault"));
    let author = WriteActor::new(
        source.ensure_embedded_owner_actor().expect("source owner"),
        EdgeActorClass::Human,
    );
    let source_manager = Arc::new(WindowManager::new(
        source.clone(),
        Arc::new(Materializer::new()),
        "authority",
    ));
    let note = source
        .create_note("research", TEXT, author)
        .expect("the source writes a NOTE");
    let mut device = device();

    send_window(&source, &device.vault, &window_of(&source, note));

    // The premise, on main as well: the device holds the NOTE's row and no
    // part of its document.
    assert!(
        device
            .vault
            .get_raw(&note)
            .expect("read the device's NOTE row")
            .is_some(),
        "the device holds the NOTE's row"
    );
    assert!(
        device
            .vault
            .note_program_document(note)
            .expect("read the device's NOTE document")
            .is_none(),
        "the device holds no document of the NOTE yet"
    );

    match read(&device, note) {
        Ok(value) => assert_eq!(
            value, None,
            "the read before the document lands holds no body"
        ),
        Err(error) => {
            panic!("the read before the document lands answers, it does not refuse: {error}")
        }
    }

    device
        .manager
        .documents()
        .subscribe_owner(note)
        .expect("the device subscribes to the NOTE on the owner lane");
    let version = device
        .manager
        .documents()
        .open(note)
        .expect("the device's NOTE document")
        .version_vector()
        .expect("the device's document version");
    let frame = source_manager
        .export_owner_document(note, &version)
        .expect("the owner-lane export");
    device
        .client
        .handle_server_message(&frame)
        .expect("the device takes the NOTE document");

    let landed = read(&device, note)
        .expect("the read after the document lands")
        .expect("the device's owner reads the NOTE");
    assert_eq!(landed.markdown, TEXT);
    assert_eq!(landed.source, NoteReadSource::Local);
}
