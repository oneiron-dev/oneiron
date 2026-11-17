//! Doors to a derivation's Person item (untangle 6.9h): the minted PERSON's
//! body as stored, and whether the cleanup lists it as an empty extraction
//! mint.

use crate::error::Result;
use crate::{EntityId, Vault};

/// What a minted PERSON's stored body says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonBody {
    /// Its `name`.
    pub name: Option<String>,
    /// Whether it carries a source audience: the words that named it are
    /// read only in relationships or privately.
    pub source_audience: bool,
}

/// The stored body of the PERSON `id`; `None` when no row stands there.
///
/// # Errors
///
/// The vault's.
pub fn person_body(vault: &Vault, id: EntityId) -> Result<Option<PersonBody>> {
    let Some(body) = vault.get(&id)? else {
        return Ok(None);
    };
    let Ok(rmpv::Value::Map(fields)) = rmpv::decode::read_value(&mut body.as_slice()) else {
        return Ok(Some(PersonBody {
            name: None,
            source_audience: false,
        }));
    };
    let field = |key: &str| {
        fields
            .iter()
            .find(|(name, _)| name.as_str() == Some(key))
            .map(|(_, value)| value)
    };
    Ok(Some(PersonBody {
        name: field("name")
            .and_then(rmpv::Value::as_str)
            .map(str::to_owned),
        source_audience: field("source_audience").is_some(),
    }))
}

/// Whether the vault cleanup lists `id` as an empty row to archive: for a
/// PERSON, an extraction mint at its stored revision with no live claim.
///
/// # Errors
///
/// The vault's.
pub fn cleanup_lists(vault: &Vault, id: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(crate::vault_cleanup::zero_live_members_in_txn(vault, &txn, &id)?.is_some())
}
