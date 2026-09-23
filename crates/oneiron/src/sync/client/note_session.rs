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
    use ed25519_dalek::Signer;
    let timestamp = crate::unix_seconds_now();
    let nonce = crate::EntityId::now().to_hex();
    let slip =
        crate::authority::CapabilitySlip::from_token(session.token()).map_err(|_| refused())?;
    let transcript = slip
        .binding_transcript(&crate::authority::holder_proof_challenge(timestamp, &nonce))
        .map_err(|_| refused())?;
    let signature: String = session
        .key()
        .sign(&transcript)
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let envelope = Envelope {
        kind: "rpc.req".into(),
        id: REQUEST_ID,
        seq: 0,
        last: true,
        payload: serde_json::json!({"method":"auth.bind","params":{
            "token": session.token(),
            "binding": {"timestamp": timestamp, "nonce": nonce, "signature": signature},
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

pub(super) fn accept_bind_reply(bytes: &[u8]) -> Result<(), TransportError> {
    if bytes.len() > 4096 {
        return Err(refused());
    }
    let mut cursor = bytes;
    let reply = rmpv::decode::read_value(&mut cursor).map_err(|_| refused())?;
    let rmpv::Value::Map(fields) = reply else {
        return Err(refused());
    };
    let expected = ["type", "id", "seq", "last", "payload"];
    let mut seen = std::collections::BTreeSet::new();
    for (key, value) in &fields {
        let key = key.as_str().ok_or_else(refused)?;
        if !expected.contains(&key) || !seen.insert(key) {
            return Err(refused());
        }
        let valid = match key {
            "type" => value.as_str() == Some("rpc.res"),
            "id" => value.as_u64() == Some(REQUEST_ID),
            "seq" => value.as_u64() == Some(0),
            "last" => value.as_bool() == Some(true),
            "payload" => matches!(value, rmpv::Value::Binary(data) if data == &[0xc0]),
            _ => false,
        };
        if !valid {
            return Err(refused());
        }
    }
    if !cursor.is_empty() || seen.len() != expected.len() {
        return Err(refused());
    }
    Ok(())
}
fn refused() -> TransportError {
    TransportError::InvalidPayload("NOTE auth.bind refused")
}
