//! The `terms_key` key of the FEDERATION_GRANT body (pass 28 R2): the per-grant 32-byte key the
//! row's giving act commits to its terms under (`GrantAct`, `grant_terms_commitment`). Canon
//! asks a keyed hash under a per-grant nonce, because scope values are low-entropy and "a
//! host-readable cloud log line yields nothing either" (ARCH-0043:181); the key lives in the row
//! alone, so it goes when the row is erased.
//!
//! The key is not a term: [`FederationGrant`] does not hold it, every reader of the terms
//! decodes the row as before, and the canonical body the commitment covers is the body without
//! it ([`super::encode_federation_grant_body`]). Only a giving writer puts it
//! ([`encode_federation_grant_body_keyed`]) and only the standing read takes it back
//! ([`decode_federation_grant_body_keyed`]). A row rewritten without its key keeps its terms
//! and loses its standing: its act no longer opens.

use std::io::Cursor;

use rmpv::Value;

use super::{FederationGrant, decode_federation_grant_value, federation_grant_body_entries};
use crate::authority::grant_terms_commitment;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::codec::{encode_msgpack_value, invalid_grant, optional_value};

pub(super) const KEY_TERMS_KEY: &str = "terms_key";

/// A Grant row's terms key.
pub type GrantTermsKey = [u8; 32];

/// `grant`'s body with the terms key `key` as its last entry.
///
/// # Errors
/// An invalid grant, or an encode failure.
pub fn encode_federation_grant_body_keyed(
    grant: &FederationGrant,
    key: &GrantTermsKey,
) -> Result<Vec<u8>> {
    let mut entries = federation_grant_body_entries(grant)?;
    entries.push((Value::from(KEY_TERMS_KEY), Value::Binary(key.to_vec())));
    encode_msgpack_value(
        &Value::Map(entries),
        "federation grant body MessagePack encode failed",
    )
}

/// A body's Grant and its terms key; `None` for a body with no key. A malformed key refuses
/// the body.
///
/// # Errors
/// A body [`super::decode_federation_grant_body`] refuses, or a key that is not 32 bytes.
pub fn decode_federation_grant_body_keyed(
    bytes: &[u8],
) -> Result<(FederationGrant, Option<GrantTermsKey>)> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_grant())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_grant());
    }
    let grant = decode_federation_grant_value(&value)?;
    let Value::Map(entries) = &value else {
        return Err(invalid_grant());
    };
    let key = optional_value(entries, KEY_TERMS_KEY)?
        .map(|value| match value {
            Value::Binary(bytes) => GrantTermsKey::try_from(bytes.as_slice()).ok(),
            _ => None,
        })
        .map(|key| key.ok_or_else(invalid_grant))
        .transpose()?;
    Ok((grant, key))
}

/// The body `bytes` re-encoded in canonical form, its terms key kept: a schema upgrade of a
/// stored row never drops the key its act opens with.
///
/// # Errors
/// A body [`decode_federation_grant_body_keyed`] refuses.
pub fn reencode_federation_grant_body(bytes: &[u8]) -> Result<Vec<u8>> {
    match decode_federation_grant_body_keyed(bytes)? {
        (grant, Some(key)) => encode_federation_grant_body_keyed(&grant, &key),
        (grant, None) => super::encode_federation_grant_body(&grant),
    }
}

/// The commitment a giving act of row `id` carries to `grant`'s terms under `key`: over the
/// canonical body without the key.
///
/// # Errors
/// An invalid grant.
pub fn federation_grant_terms(
    id: EntityId,
    grant: &FederationGrant,
    key: &GrantTermsKey,
) -> Result<[u8; 32]> {
    let body = super::encode_federation_grant_body(grant)?;
    Ok(grant_terms_commitment(key, id, &body))
}
