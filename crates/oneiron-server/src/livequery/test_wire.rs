#![allow(clippy::unwrap_used)]
//! Socket fixture codec. Old assertion shapes are produced only after checking
//! the actual MessagePack envelope, binary chunks, sequencing and snapshot EOSE.
use super::*;

pub(crate) fn request(tag: u8, mut value: Value) -> Vec<u8> {
    let object = value.as_object_mut().unwrap();
    let id = object
        .remove(if tag == TAG_RPC {
            "requestId"
        } else {
            "subscriptionId"
        })
        .unwrap();
    let kind = if tag == TAG_RPC {
        "rpc.req".to_owned()
    } else {
        object
            .remove("method")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned()
    };
    let envelope = json!({"type":kind,"id":id,"seq":0,"last":true,"payload":value});
    let mut bytes = vec![tag];
    rmpv::encode::write_value(&mut bytes, &messagepack(envelope)).unwrap();
    bytes
}

fn messagepack(value: Value) -> rmpv::Value {
    match value {
        Value::Null => rmpv::Value::Nil,
        Value::Bool(b) => b.into(),
        Value::Number(n) => {
            if let Some(n) = n.as_u64() {
                n.into()
            } else if let Some(n) = n.as_i64() {
                n.into()
            } else {
                rmpv::Value::F64(n.as_f64().unwrap())
            }
        }
        Value::String(s) => s.into(),
        Value::Array(a) => rmpv::Value::Array(a.into_iter().map(messagepack).collect()),
        Value::Object(o) => rmpv::Value::Map(
            o.into_iter()
                .map(|(k, v)| {
                    let value = if k == "versionVector" {
                        rmpv::Value::Binary(serde_json::from_value::<Vec<u8>>(v).unwrap())
                    } else {
                        messagepack(v)
                    };
                    (k.into(), value)
                })
                .collect(),
        ),
    }
}

#[derive(Deserialize)]
struct SubPayload {
    cursor: Cursor,
    data: Option<serde_bytes::ByteBuf>,
}

#[derive(Default)]
pub(crate) struct Collector {
    data: Vec<u8>,
    identity: Option<(String, u64)>,
    next_seq: Option<u64>,
    snapshot: Option<Value>,
}
impl Collector {
    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Option<Value> {
        let tag = bytes[0];
        let e: wire::Envelope<serde::de::IgnoredAny> = wire::decode(&bytes[1..]).unwrap();
        if e.kind == "sub.eose" {
            let snapshot = self.snapshot.take().expect("EOSE must follow a snapshot");
            assert_eq!(snapshot["subscriptionId"], e.id);
            let end: wire::Envelope<SubPayload> = wire::decode(&bytes[1..]).unwrap();
            assert_eq!(
                snapshot["cursor"],
                serde_json::to_value(end.payload.cursor).unwrap()
            );
            assert!(e.last);
            return Some(snapshot);
        }
        if e.kind.ends_with(".err") {
            let e: wire::Envelope<Value> = wire::decode(&bytes[1..]).unwrap();
            assert!(e.last);
            return Some(if tag == TAG_RPC {
                json!({"requestId":e.id,"last":true,"error":e.payload})
            } else {
                json!({"subscriptionId":e.id,"last":true,"error":e.payload})
            });
        }
        let cursor;
        let data = if tag == TAG_RPC {
            let body: wire::Envelope<serde_bytes::ByteBuf> = wire::decode(&bytes[1..]).unwrap();
            cursor = None;
            body.payload.into_vec()
        } else {
            let body: wire::Envelope<SubPayload> = wire::decode(&bytes[1..]).unwrap();
            cursor = Some(body.payload.cursor);
            if e.kind == "sub.gap" {
                return Some(json!({"subscriptionId":e.id,"kind":"gap","cursor":cursor.unwrap()}));
            }
            body.payload.data.unwrap().into_vec()
        };
        if let Some(identity) = &self.identity {
            assert_eq!(identity, &(e.kind.clone(), e.id));
            assert_eq!(self.next_seq, Some(e.seq));
        } else if tag == TAG_RPC {
            assert_eq!(e.seq, 0);
        }
        self.identity = Some((e.kind.clone(), e.id));
        self.next_seq = Some(e.seq + 1);
        assert!(data.len() <= wire::CHUNK_BYTES);
        self.data.extend(data);
        if !e.last {
            return None;
        }
        let value: Value = rmp_serde::from_slice(&std::mem::take(&mut self.data)).unwrap();
        self.identity = None;
        self.next_seq = None;
        if tag == TAG_RPC {
            return Some(json!({"requestId":e.id,"result":value,"last":true}));
        }
        let result = json!({"subscriptionId":e.id,"kind":e.kind.strip_prefix("sub.").unwrap(),
            "cursor":cursor.unwrap(),"result":value});
        if e.kind == "sub.snapshot" {
            self.snapshot = Some(result);
            None
        } else {
            Some(result)
        }
    }
}

pub(crate) fn reply(frames: &[Vec<u8>]) -> Value {
    let mut collector = Collector::default();
    let values: Vec<_> = frames
        .iter()
        .filter_map(|frame| collector.feed(frame))
        .collect();
    assert_eq!(values.len(), 1);
    values.into_iter().next().unwrap()
}
