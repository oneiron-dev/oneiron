#![allow(clippy::unwrap_used)]
use super::subscriptions::{DerivedView, LiveQueries, LiveQuerySource};
use super::*;
use oneiron::sync::bridge::{LiveQueryTee, MaterializedDiffSummary, OriginMark};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[test]
fn app_payload_limits_are_checked_before_copying_or_decoding() {
    let max = oneiron::sync::transport::MAX_DECODED_PAYLOAD_BYTES;
    for tag in [TAG_RPC, TAG_SUB] {
        let mut bytes = vec![0; max + 2];
        bytes[0] = tag;
        assert!(matches!(crate::protocol::parse_message(&bytes),
            Err(ProtocolError::FrameTooLarge { size, max: cap }) if size == max + 1 && cap == max));
        bytes.pop();
        assert!(crate::protocol::parse_message(&bytes).is_ok());
    }
}

#[test]
fn all_caller_controlled_list_sizes_are_validated_before_engine_reads() {
    for limit in [0, crate::api::CORE_MAX_LIST_LIMIT + 1, usize::MAX] {
        for (method, params) in [
            ("queryBm25", json!({"query":"x","limit":limit})),
            (
                "neighbors",
                json!({"entityRef":"invalid","opts":{"limit":limit}}),
            ),
            ("pendingWrites", json!({"limit":limit})),
            ("claimList", json!({"limit":limit})),
        ] {
            assert!(Read::parse(method, params).is_err(), "{method}: {limit}");
        }
    }
    assert!(Read::parse("hydrate", json!({"refs":vec!["x";1001]})).is_err());
    assert!(Read::parse("hydrate", json!({"refs":[]})).is_ok());
    assert!(Read::parse("hydrate", json!({"refs":vec!["x";1000]})).is_ok());
    assert!(Read::parse("queryBm25", json!({"query":"x","limit":1000})).is_ok());
}

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
            dependencies: BTreeSet::from(["w:".to_owned()]),
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
fn aggregate_retention_rejects_open_and_reclaims_on_close() {
    let hub = budget::Budget::new(100 * 1024);
    let source = Arc::new(Source::new(json!("x".repeat(60 * 1024))));
    let a = LiveQueries::with_budget(1, source.clone(), hub.clone());
    let b = LiveQueries::with_budget(2, source, hub);
    a.open(1, ScopedView::default(), Channel::View, None, None)
        .unwrap();
    assert!(
        b.open(1, ScopedView::default(), Channel::View, None, None)
            .is_err()
    );
    a.close(1).unwrap();
    b.open(1, ScopedView::default(), Channel::View, None, None)
        .unwrap();
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

#[test]
fn a_refresh_between_publication_and_purge_does_not_consume_the_invalidation() {
    let source = Arc::new(Source::new(json!(1)));
    let tier = LiveQueries::new(1, source.clone());
    let opened = tier
        .open(1, ScopedView::default(), Channel::View, None, None)
        .unwrap();
    tier.ack(1, &opened[0].cursor).unwrap();
    source.ready.store(false, Ordering::Release);
    tier.on_materialized(
        "w:2026-03/tombstones",
        &MaterializedDiffSummary {
            containers: vec!["w:2026-03/entities/11111111111111111111111111111111".into()],
            bytes: 0,
        },
        &OriginMark {
            conn_id: None,
            origin: Some("deletion_tombstone".into()),
        },
    );
    tier.refresh().unwrap();
    assert!(tier.buffered().unwrap().is_empty());
    *source.value.lock().unwrap() = json!(0);
    source.ready.store(true, Ordering::Release);
    tier.refresh().unwrap();
    assert_eq!(tier.buffered().unwrap()[0].result, Some(json!(0)));
}

#[tokio::test]
async fn socket_delivery_is_disabled_until_an_open_and_after_close() {
    let (_dir, server) = production_tests::server();
    let hub = connection::Hub::for_server(&server);
    let mut connection = connection::Connection::new(hub, 9);
    assert!(!connection.has_active_subscriptions());
    let auth = CoreAuth::from_bind_token(
        &production_tests::token("human"),
        &server.config,
        server.vault().as_ref(),
    )
    .unwrap();
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
