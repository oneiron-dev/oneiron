//! Moved from `crates/oneiron/src/sync/home_handoff/envelope.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::sync::home_handoff::refused;
use ed25519_dalek::Signature;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use ed25519_dalek::VerifyingKey;
use getrandom::SysRng;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

pub const HEADER_DOMAIN: &[u8] = b"oneiron/home-handoff/header/v1\0";

pub fn signature(bytes: &[u8]) -> Result<Signature> {
    <[u8; 64]>::try_from(bytes)
        .map(|bytes| Signature::from_bytes(&bytes))
        .map_err(|_| refused("a signature is malformed"))
}

pub fn transcript(domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut out = domain.to_vec();
    out.extend_from_slice(bytes);
    out
}

pub fn encode<V: Serialize + ?Sized>(value: &V) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|_| refused("a handoff value does not encode"))
}

pub fn decode<V: Serialize + DeserializeOwned>(bytes: &[u8]) -> Result<V> {
    <Named as SideCodec<V>>::decode(bytes).map_err(|_| refused("a handoff value does not decode"))
}
