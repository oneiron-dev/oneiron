//! Version-8 app envelopes. Result chunks are MessagePack binary fragments of
//! one MessagePack value. Concatenate by seq before decoding or acknowledging.
use super::*;
use std::io::Write;

pub(super) const CHUNK_BYTES: usize = 64 * 1024;
const MAX_RESULT_BYTES: usize = 32 * 1024 * 1024;
pub(super) const SEQUENCES_PER_BATCH: u64 = 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Envelope<T> {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: u64,
    pub seq: u64,
    pub last: bool,
    pub payload: T,
}

struct BoundedWriter(Vec<u8>);
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > MAX_RESULT_BYTES {
            return Err(std::io::Error::other("app result too large"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) fn packed(value: &impl Serialize) -> Result<Vec<u8>, ProtocolError> {
    let mut writer = BoundedWriter(Vec::new());
    value
        .serialize(&mut rmp_serde::Serializer::new(&mut writer).with_struct_map())
        .map_err(|_| ProtocolError::FrameTooLarge {
            size: MAX_RESULT_BYTES + 1,
            max: MAX_RESULT_BYTES,
        })?;
    Ok(writer.0)
}

pub(super) fn decode<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<Envelope<T>, ProtocolError> {
    let max = oneiron::sync::transport::MAX_DECODED_PAYLOAD_BYTES;
    if bytes.len() > max {
        return Err(ProtocolError::FrameTooLarge {
            size: bytes.len(),
            max,
        });
    }
    let mut decoder = rmp_serde::Deserializer::new(std::io::Cursor::new(bytes));
    let envelope = Envelope::deserialize(&mut decoder)
        .map_err(|_| ProtocolError::InvalidPayload("invalid app envelope"))?;
    if decoder.position() as usize != bytes.len() {
        return Err(ProtocolError::InvalidPayload("trailing app envelope bytes"));
    }
    Ok(envelope)
}

pub(super) fn frame<T: Serialize>(
    tag: u8,
    kind: &str,
    id: u64,
    seq: u64,
    last: bool,
    payload: T,
) -> Result<Vec<u8>, ProtocolError> {
    let mut bytes = vec![tag];
    bytes.extend(packed(&Envelope {
        kind: kind.to_owned(),
        id,
        seq,
        last,
        payload,
    })?);
    let max = oneiron::sync::transport::MAX_DECODED_PAYLOAD_BYTES;
    if bytes.len() - 1 > max {
        return Err(ProtocolError::FrameTooLarge {
            size: bytes.len() - 1,
            max,
        });
    }
    Ok(bytes)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcBody {
    method: String,
    #[serde(default)]
    params: Value,
}

pub(super) fn rpc(bytes: &[u8]) -> Result<RpcRequest, ProtocolError> {
    let envelope: Envelope<Value> = decode(bytes)?;
    if envelope.seq != 0 || !envelope.last {
        return Err(ProtocolError::InvalidPayload(
            "requests must be terminal seq zero",
        ));
    }
    if envelope.kind == "ping" {
        return Ok(RpcRequest {
            request_id: envelope.id,
            method: "ping".to_owned(),
            params: envelope.payload,
        });
    }
    if envelope.kind != "rpc.req" {
        return Err(ProtocolError::InvalidPayload("expected rpc.req"));
    }
    let body: RpcBody = serde_json::from_value(envelope.payload)
        .map_err(|_| ProtocolError::InvalidPayload("invalid RPC request"))?;
    Ok(RpcRequest {
        request_id: envelope.id,
        method: body.method,
        params: body.params,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Open {
    scoped_view: ScopedView,
    #[serde(default)]
    channel: Channel,
    #[serde(default)]
    cursor: Option<Cursor>,
    #[serde(default)]
    origin: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ack {
    cursor: Cursor,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Close {}

pub(crate) fn sub(bytes: &[u8]) -> Result<SubRequest, ProtocolError> {
    // Ignore the body while selecting a typed decoder; binary fields stay binary.
    let envelope: Envelope<serde::de::IgnoredAny> = decode(bytes)?;
    if envelope.seq != 0 || !envelope.last {
        return Err(ProtocolError::InvalidPayload(
            "controls must be terminal seq zero",
        ));
    }
    Ok(match envelope.kind.as_str() {
        "sub.open" => {
            let e: Envelope<Open> = decode(bytes)?;
            SubRequest::Open {
                subscription_id: e.id,
                scoped_view: e.payload.scoped_view,
                channel: e.payload.channel,
                cursor: e.payload.cursor,
                origin: e.payload.origin,
            }
        }
        "sub.ack" => {
            let e: Envelope<Ack> = decode(bytes)?;
            SubRequest::Ack {
                subscription_id: e.id,
                cursor: e.payload.cursor,
            }
        }
        "sub.close" => {
            let _: Envelope<Close> = decode(bytes)?;
            SubRequest::Close {
                subscription_id: envelope.id,
            }
        }
        _ => {
            return Err(ProtocolError::InvalidPayload(
                "unknown subscription control",
            ));
        }
    })
}

pub(super) fn result(id: u64, value: &Value) -> Result<Vec<Vec<u8>>, ProtocolError> {
    let bytes = packed(value)?;
    bytes
        .chunks(CHUNK_BYTES)
        .enumerate()
        .map(|(seq, chunk)| {
            frame(
                TAG_RPC,
                "rpc.res",
                id,
                seq as u64,
                (seq + 1) * CHUNK_BYTES >= bytes.len(),
                serde_bytes::Bytes::new(chunk),
            )
        })
        .collect()
}

#[derive(Serialize)]
pub(super) struct SubData<'a> {
    pub cursor: &'a Cursor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<&'a serde_bytes::Bytes>,
}

pub(super) fn push(push: &subscriptions::Push) -> Result<Vec<Vec<u8>>, ProtocolError> {
    let seq =
        push.cursor
            .batch
            .checked_mul(SEQUENCES_PER_BATCH)
            .ok_or(ProtocolError::InvalidPayload(
                "subscription sequence exhausted",
            ))?;
    let kind = match push.kind {
        "snapshot" => "sub.snapshot",
        "data" => "sub.data",
        "eose" => "sub.eose",
        _ => "sub.gap",
    };
    if let Some(value) = &push.result {
        // A resync gap precedes its snapshot at the same logical cursor.
        let seq = if push.kind == "snapshot" {
            seq + 1
        } else {
            seq
        };
        let bytes = packed(value)?;
        return bytes
            .chunks(CHUNK_BYTES)
            .enumerate()
            .map(|(part, chunk)| {
                frame(
                    TAG_SUB,
                    kind,
                    push.subscription_id,
                    seq + part as u64,
                    (part + 1) * CHUNK_BYTES >= bytes.len(),
                    SubData {
                        cursor: &push.cursor,
                        data: Some(serde_bytes::Bytes::new(chunk)),
                    },
                )
            })
            .collect();
    }
    let seq = if push.kind == "eose" {
        seq + SEQUENCES_PER_BATCH - 1
    } else {
        seq
    };
    Ok(vec![frame(
        TAG_SUB,
        kind,
        push.subscription_id,
        seq,
        true,
        SubData {
            cursor: &push.cursor,
            data: None,
        },
    )?])
}
