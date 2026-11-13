//! The existing app-tier MessagePack auth.bind handshake on the sync socket.
use crate::sync::transport::{TAG_RPC, TransportError};
use serde::{Deserialize, Serialize};
const REQUEST_ID: u64 = 4294967295;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    #[serde(rename = "type")]
    kind: String,
    id: u64,
    seq: u64,
    last: bool,
    payload: T,
}

/// A fresh holder proof on every bind: the proof is not a replacement bearer
/// token.
pub(super) fn bind_frame(session: &super::NoteSyncSession) -> Result<Vec<u8>, TransportError> {
    let slip =
        crate::authority::CapabilitySlip::from_token(session.token()).map_err(|_| refused())?;
    let binding = crate::authority::holder_proof(&slip, session.key(), crate::unix_seconds_now())
        .map_err(|_| refused())?;
    let envelope = Envelope {
        kind: "rpc.req".into(),
        id: REQUEST_ID,
        seq: 0,
        last: true,
        payload: serde_json::json!({"method":"auth.bind","params":{
            "token": session.token(),
            "binding": binding,
        }}),
    };
    let payload = rmp_serde::to_vec_named(&envelope).map_err(|_| refused())?;
    if payload.len() > crate::sync::transport::MAX_DECODED_PAYLOAD_BYTES {
        return Err(refused());
    }
    let mut frame = vec![TAG_RPC];
    frame.extend(payload);
    Ok(frame)
}

/// What the home's `auth.bind` reply states of the bind's call receipt. The
/// home records the bind as one call of the connection (FIX 811) and stamps
/// its reply as it stamps every RPC reply (OF-538).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindReceipt {
    /// `receipt_ref: "call:<32hex>"`: the home's lasting receipt of the bind.
    Recorded(String),
    /// `receipt_ref: null` beside `no_record: true`: the home keeps no row
    /// of the call and says so.
    NoRecord,
    /// No stamp: the home could not write the receipt (it logs that), or
    /// predates the stamp.
    Unrecorded,
}

/// The keys every `auth.bind` reply carries.
const REPLY_KEYS: [&str; 5] = ["type", "id", "seq", "last", "payload"];

/// Accepts the home's answer to this session's bind and returns its stamp.
/// The answer is the one `rpc.res` chunk of the bind's own request id with a
/// nil payload; the stamp rides that envelope, so it is the receipt of this
/// bind. A reply to another request id, any other key, a key twice, or a
/// stamp of any other shape is refused.
pub(super) fn accept_bind_reply(bytes: &[u8]) -> Result<BindReceipt, TransportError> {
    if bytes.len() > 4096 {
        return Err(refused());
    }
    let mut cursor = bytes;
    let reply = rmpv::decode::read_value(&mut cursor).map_err(|_| refused())?;
    let rmpv::Value::Map(fields) = reply else {
        return Err(refused());
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut receipt_ref = None;
    let mut no_record = false;
    for (key, value) in &fields {
        let key = key.as_str().ok_or_else(refused)?;
        if !seen.insert(key) {
            return Err(refused());
        }
        let valid = match key {
            "type" => value.as_str() == Some("rpc.res"),
            "id" => value.as_u64() == Some(REQUEST_ID),
            "seq" => value.as_u64() == Some(0),
            "last" => value.as_bool() == Some(true),
            "payload" => matches!(value, rmpv::Value::Binary(data) if data == &[0xc0]),
            "receipt_ref" => {
                receipt_ref = Some(value);
                true
            }
            // The home writes the key only when it is true.
            "no_record" => {
                no_record = value.as_bool() == Some(true);
                no_record
            }
            _ => false,
        };
        if !valid {
            return Err(refused());
        }
    }
    if !cursor.is_empty() || !REPLY_KEYS.iter().all(|key| seen.contains(key)) {
        return Err(refused());
    }
    bind_receipt(receipt_ref, no_record).ok_or_else(refused)
}

/// The stamp a reply's `receipt_ref` and `no_record` state together, as the
/// home writes them; `None` for any other pair.
fn bind_receipt(receipt_ref: Option<&rmpv::Value>, no_record: bool) -> Option<BindReceipt> {
    match (receipt_ref, no_record) {
        (None, false) => Some(BindReceipt::Unrecorded),
        (Some(rmpv::Value::Nil), true) => Some(BindReceipt::NoRecord),
        (Some(rmpv::Value::String(text)), false) => text
            .as_str()
            .filter(|text| is_call_receipt_ref(text))
            .map(|text| BindReceipt::Recorded(text.to_owned())),
        _ => None,
    }
}

/// Whether `text` is a call receipt ref as the home mints it: `call:` and
/// the 32 lower-case hex digits of the receipt's id.
fn is_call_receipt_ref(text: &str) -> bool {
    text.strip_prefix(crate::receipt::CALL_RECEIPT_REF_PREFIX)
        .is_some_and(|hex| {
            hex.len() == 32
                && hex
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        })
}
fn refused() -> TransportError {
    TransportError::InvalidPayload("NOTE auth.bind refused")
}
