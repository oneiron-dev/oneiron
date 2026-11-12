//! A sync client that carries a NOTE session accepts the home's `auth.bind`
//! reply with the call receipt stamp the home puts on it, keeps that stamp,
//! and refuses a reply whose stamp has another shape or that answers another
//! request (FIX-LIST [T0I-RESIDENCE-BIND-REPLY-STAMP-REFUSED]; E2E SYNC-01,
//! SYNC-04 and SYNC-05).
//!
//! The home records the bind as one call of its connection (FIX 811) and
//! stamps the reply with that receipt (OF-538): `receipt_ref: "call:<32hex>"`,
//! or `receipt_ref: null` beside `no_record: true`. The client refused every
//! key past the five it knew, so no device's NOTE session ever bound.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test note_bind_reply_stamp`.
#![cfg(feature = "sync")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::client::{BindReceipt, NoteSyncSession};
use oneiron::sync::transport::TAG_RPC;
use oneiron::sync::{SyncClient, SyncClientConfig, SyncEvent, WindowManager};
use oneiron::{Vault, VaultConfig};
use rmpv::Value;
use tokio::sync::mpsc::UnboundedReceiver;

/// The fixed request id of the client's `auth.bind` call.
const BIND_REQUEST_ID: u64 = 4_294_967_295;

/// A call receipt ref as the home mints it: `call:` and a lower-case id.
const RECEIPT_REF: &str = "call:0196f3a2b4c57d8e9f0a1b2c3d4e5f60";

/// A device's sync client with a NOTE session, before any reply.
struct Device {
    client: SyncClient,
    _events: UnboundedReceiver<SyncEvent>,
    _dir: tempfile::TempDir,
}

fn device() -> Device {
    let dir = tempfile::tempdir().expect("device dir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("device vault"));
    let manager = Arc::new(WindowManager::new(
        vault,
        Arc::new(Materializer::new()),
        "note-bind-device",
    ));
    let (client, events) = SyncClient::new(
        manager,
        SyncClientConfig {
            server_url: "ws://127.0.0.1:9/ws".to_owned(),
            note_session: Some(NoteSyncSession::new(
                "note-session-token".to_owned(),
                SigningKey::from_bytes(&[7; 32]),
            )),
            ..Default::default()
        },
    )
    .expect("sync client");
    Device {
        client,
        _events: events,
        _dir: dir,
    }
}

/// The home's `rpc.res` answer to request `id`: the five keys every reply
/// carries, then `stamp` as given.
fn bind_reply(id: u64, stamp: &[(&str, Value)]) -> Vec<u8> {
    let mut fields = vec![
        (Value::from("type"), Value::from("rpc.res")),
        (Value::from("id"), Value::from(id)),
        (Value::from("seq"), Value::from(0_u64)),
        (Value::from("last"), Value::from(true)),
        (Value::from("payload"), Value::Binary(vec![0xc0])),
    ];
    fields.extend(
        stamp
            .iter()
            .map(|(key, value)| (Value::from(*key), value.clone())),
    );
    let mut frame = vec![TAG_RPC];
    rmpv::encode::write_value(&mut frame, &Value::Map(fields)).expect("encode the reply");
    frame
}

#[test]
fn a_reply_stamped_with_the_binds_call_receipt_binds_the_note_session_and_keeps_the_stamp() {
    let mut device = device();
    assert_eq!(device.client.note_bind_receipt(), None);

    let reply = bind_reply(
        BIND_REQUEST_ID,
        &[("receipt_ref", Value::from(RECEIPT_REF))],
    );
    let answered = device.client.handle_server_message(&reply);

    assert!(
        answered.is_ok(),
        "the stamped reply is accepted: {answered:?}"
    );
    assert_eq!(
        device.client.note_bind_receipt(),
        Some(&BindReceipt::Recorded(RECEIPT_REF.to_owned()))
    );
}

#[test]
fn a_reply_stamped_no_record_binds_the_note_session_and_keeps_the_stamp() {
    let mut device = device();

    let reply = bind_reply(
        BIND_REQUEST_ID,
        &[
            ("receipt_ref", Value::Nil),
            ("no_record", Value::from(true)),
        ],
    );
    let answered = device.client.handle_server_message(&reply);

    assert!(
        answered.is_ok(),
        "the no-record reply is accepted: {answered:?}"
    );
    assert_eq!(
        device.client.note_bind_receipt(),
        Some(&BindReceipt::NoRecord)
    );
}

#[test]
fn an_unstamped_reply_still_binds_the_note_session() {
    let mut device = device();

    let answered = device
        .client
        .handle_server_message(&bind_reply(BIND_REQUEST_ID, &[]));

    assert!(
        answered.is_ok(),
        "the unstamped reply is accepted: {answered:?}"
    );
    assert_eq!(
        device.client.note_bind_receipt(),
        Some(&BindReceipt::Unrecorded)
    );
}

#[test]
fn a_stamped_reply_to_another_request_is_refused() {
    let mut device = device();

    let reply = bind_reply(7, &[("receipt_ref", Value::from(RECEIPT_REF))]);
    let answered = device.client.handle_server_message(&reply);

    assert!(
        format!("{answered:?}").contains("NOTE auth.bind refused"),
        "a reply to another request is refused: {answered:?}"
    );
    assert_eq!(device.client.note_bind_receipt(), None);
}

#[test]
fn a_stamp_of_any_other_shape_is_refused() {
    let upper = RECEIPT_REF.to_uppercase().replacen("CALL:", "call:", 1);
    let short = &RECEIPT_REF[..RECEIPT_REF.len() - 1];
    let shapes: Vec<(&str, Vec<(&str, Value)>)> = vec![
        (
            "a ref of another kind",
            vec![(
                "receipt_ref",
                Value::from("receipt:0196f3a2b4c57d8e9f0a1b2c3d4e5f60"),
            )],
        ),
        (
            "a call ref one digit short",
            vec![("receipt_ref", Value::from(short))],
        ),
        (
            "a call ref in upper case",
            vec![("receipt_ref", Value::from(upper.as_str()))],
        ),
        (
            "a ref that is a number",
            vec![("receipt_ref", Value::from(7_u64))],
        ),
        ("a null ref alone", vec![("receipt_ref", Value::Nil)]),
        ("no_record alone", vec![("no_record", Value::from(true))]),
        (
            "no_record beside a ref",
            vec![
                ("receipt_ref", Value::from(RECEIPT_REF)),
                ("no_record", Value::from(true)),
            ],
        ),
        (
            "no_record false",
            vec![
                ("receipt_ref", Value::from(RECEIPT_REF)),
                ("no_record", Value::from(false)),
            ],
        ),
        (
            "the ref twice",
            vec![
                ("receipt_ref", Value::from(RECEIPT_REF)),
                ("receipt_ref", Value::from(RECEIPT_REF)),
            ],
        ),
        (
            "a key the home never writes",
            vec![
                ("receipt_ref", Value::from(RECEIPT_REF)),
                ("attempt", Value::from("a")),
            ],
        ),
    ];
    for (shape, stamp) in shapes {
        let mut device = device();
        let answered = device
            .client
            .handle_server_message(&bind_reply(BIND_REQUEST_ID, &stamp));
        assert!(
            format!("{answered:?}").contains("NOTE auth.bind refused"),
            "{shape} is refused: {answered:?}"
        );
        assert_eq!(device.client.note_bind_receipt(), None, "{shape}");
    }
}
