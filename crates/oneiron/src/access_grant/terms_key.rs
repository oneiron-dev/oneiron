//! The `terms_key` key of the ACCESS_GRANT body (pass 28 R2e; Engine RULING SR-5
//! ACCESS-GRANT-KIND = A): the per-row 32-byte key a grant act commits to the row's terms under
//! (`GrantAct`, `grant_terms_commitment`), as a Grant row's own `terms_key` does
//! (`crate::federation::encode_federation_grant_body_keyed`). Scope values are low-entropy, and
//! "a host-readable cloud log line yields nothing either" (ARCH-0043:181); the key lives in the
//! row alone, so it goes when the row is erased.
//!
//! The key is not a term: [`AccessGrant`] does not hold it, every reader of the terms decodes
//! the row as before (a body without it decodes too), no field profile shows it, and the
//! canonical body the commitment covers is the body without it
//! ([`super::encode_access_grant_body`]: no key, no witness history). Only the body writer puts
//! it ([`encode_access_grant_body_keyed`]) and only a standing read takes it back
//! ([`decode_access_grant_body_keyed`]).

use std::io::Cursor;

use rmpv::Value;

use super::AccessGrant;
use super::codec::{access_grant_body_entries, invalid_grant, write_body};
use crate::authority::grant_terms_commitment;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::GrantTermsKey;

pub(super) const KEY_TERMS_KEY: &str = "terms_key";

/// Whether `key` may key a row's terms: never all zero, a key anyone can guess.
fn usable_key(key: &GrantTermsKey) -> bool {
    key.iter().any(|byte| *byte != 0)
}

/// `grant`'s live body with the terms key `key` as its last entry.
///
/// # Errors
/// An invalid grant, an all-zero key, or an encode failure.
pub(crate) fn encode_access_grant_body_keyed(
    grant: &AccessGrant,
    key: &GrantTermsKey,
) -> Result<Vec<u8>> {
    if !usable_key(key) {
        return Err(invalid_grant());
    }
    let mut entries = access_grant_body_entries(grant)?;
    entries.push((Value::from(KEY_TERMS_KEY), Value::Binary(key.to_vec())));
    write_body(entries)
}

/// A live body's grant and its terms key; `None` for a body with no key, which an engine
/// write by standing policy or an older writer puts. A malformed or all-zero key refuses the
/// body.
///
/// # Errors
/// A body [`super::decode_access_grant_body`] refuses, or a malformed key.
pub(crate) fn decode_access_grant_body_keyed(
    bytes: &[u8],
) -> Result<(AccessGrant, Option<GrantTermsKey>)> {
    let grant = super::decode_access_grant_body(bytes)?;
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_grant())?;
    let Value::Map(entries) = &value else {
        return Err(invalid_grant());
    };
    let key = entries
        .iter()
        .find(|(name, _)| name.as_str() == Some(KEY_TERMS_KEY))
        .map(|(_, value)| match value {
            Value::Binary(bytes) => GrantTermsKey::try_from(bytes.as_slice())
                .ok()
                .filter(usable_key)
                .ok_or_else(invalid_grant),
            _ => Err(invalid_grant()),
        })
        .transpose()?;
    Ok((grant, key))
}

/// The commitment a giving act of row `id` carries to `grant`'s terms under `key`: over the
/// canonical body, with no key and no witness history.
///
/// # Errors
/// An invalid grant, or an all-zero key.
pub(crate) fn access_grant_terms(
    id: EntityId,
    grant: &AccessGrant,
    key: &GrantTermsKey,
) -> Result<[u8; 32]> {
    if !usable_key(key) {
        return Err(invalid_grant());
    }
    let body = super::encode_access_grant_body(grant)?;
    Ok(grant_terms_commitment(key, id, &body))
}
