//! Seeds the resolution policy's single-valued predicates for extraction tests.
//!
//! The typed owner manifest door preserves unrelated policy tables and names no
//! single-valued field, and the raw manifest header length is crate-private, so
//! integration tests cannot seed this table themselves. This door rewrites the
//! default manifest's `single_valued_predicates` array in place and leaves every
//! other manifest entry unchanged.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;

/// Replaces the default manifest's single-valued predicates with `predicates`.
///
/// Each entry names one predicate the native resolution policy treats as
/// single-valued. An entry already present is replaced, never duplicated.
///
/// # Errors
///
/// The vault's, a missing default manifest, or a manifest body that does not
/// decode as a MessagePack map.
pub fn seed_extraction_single_valued_predicates(vault: &Vault, predicates: &[&str]) -> Result<()> {
    let id: EntityId = crate::gate::default_policy_manifest_id()?;
    let raw = vault
        .get_raw(&id)?
        .ok_or_else(|| Error::InvalidConfig("the default policy manifest is missing".into()))?;
    let mut cursor = std::io::Cursor::new(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]);
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor).map_err(|error| {
        Error::InvalidConfig(format!("the policy manifest did not decode: {error}"))
    })?
    else {
        return Err(Error::InvalidConfig(
            "the policy manifest is not a map".into(),
        ));
    };
    entries.retain(|(key, _)| key.as_str() != Some("single_valued_predicates"));
    entries.push((
        Value::from("single_valued_predicates"),
        Value::Array(predicates.iter().map(|name| Value::from(*name)).collect()),
    ));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries)).map_err(|error| {
        Error::InvalidConfig(format!("the policy manifest did not encode: {error}"))
    })?;
    crate::test_fixtures::put_policy_manifest_bytes(vault, id, &bytes)
}
