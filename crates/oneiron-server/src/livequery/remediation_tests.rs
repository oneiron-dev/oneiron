#![allow(clippy::unwrap_used)]
use super::subscriptions::{DerivedView, LiveQueries, LiveQuerySource};
use super::*;
use oneiron::sync::bridge::{MaterializedDiffSummary, OriginMark};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[test]
fn messagepack_envelope_rejects_json_trailing_bytes_and_wrong_sequences() {
    let value = json!({"requestId":7,"method":"hydrate","params":{"refs":[]}});
    let bytes = test_wire::request(TAG_RPC, value.clone());
    assert_eq!(decode_rpc(&bytes[1..]).unwrap().request_id, 7);
    assert!(decode_rpc(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(decode_rpc(&trailing[1..]).is_err());
    for (seq, last) in [(1, true), (0, false)] {
        let bad = wire::frame(
            TAG_RPC,
            "rpc.req",
            7,
            seq,
            last,
            json!({"method":"hydrate","params":{"refs":[]}}),
        )
        .unwrap();
        assert!(decode_rpc(&bad[1..]).is_err());
    }
    let ping = wire::frame(TAG_RPC, "ping", 7, 0, true, json!({"nonce":42})).unwrap();
    assert_eq!(decode_rpc(&ping[1..]).unwrap().method, "ping");
}

#[test]
fn cursor_vectors_and_result_chunks_are_messagepack_binary() {
    let cursor = Cursor {
        document: "fixture".into(),
        version_vector: vec![0, 255, 1],
        batch: 1,
    };
    let encoded = wire::packed(&cursor).unwrap();
    let decoded = rmpv::decode::read_value(&mut encoded.as_slice()).unwrap();
    let vv = decoded
        .as_map()
        .unwrap()
        .iter()
        .find(|(k, _)| k.as_str() == Some("versionVector"))
        .unwrap();
    assert!(matches!(&vv.1, rmpv::Value::Binary(bytes) if bytes == &[0,255,1]));
    let request = test_wire::request(
        TAG_SUB,
        json!({"method":"sub.ack","subscriptionId":7,"cursor":cursor}),
    );
    assert!(
        matches!(decode_sub(&request[1..]).unwrap(), SubRequest::Ack { cursor: c, .. } if c == cursor)
    );
    let frames = rpc_result(7, json!([])).unwrap();
    let envelope: wire::Envelope<serde_bytes::ByteBuf> = wire::decode(&frames[0][1..]).unwrap();
    assert_eq!(envelope.kind, "rpc.res");
    assert_eq!(envelope.seq, 0);
    assert!(envelope.last);
}

#[test]
fn rpc_larger_than_one_protocol_frame_streams_in_order_and_terminates() {
    let value = json!("x".repeat(oneiron::sync::transport::MAX_DECODED_PAYLOAD_BYTES + 1));
    let frames = rpc_result(9, value.clone()).unwrap();
    assert!(frames.len() > 1);
    assert!(
        frames
            .iter()
            .all(|frame| frame.len() < wire::CHUNK_BYTES + 1024)
    );
    assert_eq!(test_wire::reply(&frames)["result"], value);
    for value in [Value::Null, json!([])] {
        let frames = rpc_result(9, value).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(test_wire::reply(&frames)["last"], true);
    }
}

struct Source {
    doc: loro::LoroDoc,
    value: Mutex<Value>,
    ready: AtomicBool,
}
impl Source {
    fn new(value: Value) -> Self {
        Self {
            doc: loro::LoroDoc::new(),
            value: Mutex::new(value),
            ready: AtomicBool::new(true),
        }
    }
}
impl LiveQuerySource for Source {
    fn derive(&self, _: &ScopedView, _: Channel) -> Result<DerivedView, AppError> {
        Ok(DerivedView {
            value: self.value.lock().unwrap().clone(),
            cursor: Cursor {
                document: "fixture".into(),
                version_vector: self.doc.oplog_vv().encode(),
                batch: 0,
            },
            dependencies: BTreeSet::from(["e:11111111111111111111111111111111".to_owned()]),
        })
    }
    fn can_resume(&self, _: &Cursor) -> Result<bool, AppError> {
        Ok(true)
    }
    fn ready(&self, _: &MaterializedDiffSummary, _: &OriginMark) -> Result<bool, AppError> {
        Ok(self.ready.load(Ordering::Acquire))
    }
}

#[test]
fn all_snapshot_channels_are_chunked_then_eose_before_live_data() {
    for channel in [Channel::View, Channel::Receipts, Channel::PendingConsent] {
        let value = json!("x".repeat(wire::CHUNK_BYTES * 2));
        let source = Arc::new(Source::new(value.clone()));
        let tier = LiveQueries::new(1, source);
        let pushes = tier
            .open(1, ScopedView::default(), channel, None, None)
            .unwrap();
        assert_eq!(pushes.last().unwrap().kind, "eose");
        let frames: Vec<_> = pushes.iter().flat_map(|p| p.encode().unwrap()).collect();
        assert!(frames.len() >= 4);
        assert_eq!(test_wire::reply(&frames)["result"], value);
    }
}

#[tokio::test]
async fn socket_delivery_is_disabled_until_an_open_and_after_close() {
    let (_dir, server) = production_tests::server();
    let hub = connection::Hub::for_server(&server);
    let mut connection = connection::Connection::new(hub, 9);
    assert!(!connection.has_active_subscriptions());
    let auth = crate::test_credentials::authenticate(&server, &production_tests::token("human"));
    connection
        .control(
            &auth,
            SubRequest::Open {
                subscription_id: 1,
                scoped_view: ScopedView::default(),
                channel: Channel::Receipts,
                cursor: None,
                origin: None,
            },
        )
        .unwrap();
    assert!(connection.has_active_subscriptions());
    let private = routing::wrap(9, 1, vec![TAG_SUB, 0x80]);
    assert!(connection.receive_broadcast(&private).is_some());
    assert!(
        connection
            .receive_broadcast(&routing::wrap(10, 1, vec![TAG_SUB, 0x80]))
            .is_none()
    );
    assert!(
        connection
            .receive_broadcast(&routing::wrap(9, 2, vec![TAG_SUB, 0x80]))
            .is_none()
    );
    connection
        .control(&auth, SubRequest::Close { subscription_id: 1 })
        .unwrap();
    assert!(!connection.has_active_subscriptions());
    assert!(connection.receive_broadcast(&private).is_none());
}
