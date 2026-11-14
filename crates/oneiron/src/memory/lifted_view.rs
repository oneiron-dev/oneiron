//! A lifted carrier's view as the bound actor reads it (OF-067, Engine ruling
//! G2 = b). The vault owner reads each lifted key as stored. Every other
//! reader reads it as its handle (`[secret sc12]`, owner ruling G04 = A),
//! and a granted agent reads a value through that handle's reveal.

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::{Memory, MemoryResult};
use crate::batch::secret_scan::LiftedKeys;
use crate::error::Error;
use crate::secret_custody::SecretSight;

impl Memory<'_> {
    /// Whether the bound actor reads a lifted key as its handle.
    pub(crate) fn reads_lifted_keys_masked(&self) -> MemoryResult<bool> {
        Ok(self.secret_sight()? == SecretSight::Masked)
    }

    /// [`Self::reads_lifted_keys_masked`] in `txn`, a snapshot its caller
    /// holds (FIX 6992): a projection never opens a second reader.
    pub(crate) fn reads_lifted_keys_masked_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> MemoryResult<bool> {
        Ok(self.secret_sight_in_txn(txn)? == SecretSight::Masked)
    }

    /// `view` as the bound actor reads it: for a reader other than the
    /// owner, each value the lifted texts `keys` reads hold as its handle,
    /// wherever the view holds it.
    pub(crate) fn lifted_view<T: Serialize + DeserializeOwned>(
        &self,
        view: T,
        keys: impl FnOnce() -> crate::Result<LiftedKeys>,
    ) -> MemoryResult<T> {
        masked_view(self.reads_lifted_keys_masked()?, view, keys)
    }

    /// [`Self::lifted_view`] inside a projection that holds `txn` (FIX 6992).
    pub(crate) fn lifted_view_in_txn<T: Serialize + DeserializeOwned>(
        &self,
        txn: &heed::RoTxn<'_>,
        view: T,
        keys: impl FnOnce() -> crate::Result<LiftedKeys>,
    ) -> MemoryResult<T> {
        masked_view(self.reads_lifted_keys_masked_in_txn(txn)?, view, keys)
    }
}

impl Memory<'_> {
    /// The lifted keys the bound reader reads as handles in a text projected
    /// from the stored record `bodies`: those the marks of each string of
    /// those bodies name. `None` for a reader who reads each key as stored
    /// (the owner, a granted agent).
    pub(crate) fn lifted_keys_of_bodies_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        bodies: &[Vec<u8>],
    ) -> MemoryResult<Option<LiftedKeys>> {
        if !self.reads_lifted_keys_masked_in_txn(txn)? {
            return Ok(None);
        }
        Ok(Some(lifted_keys_of_bodies_in_txn(
            &self.vault.store,
            txn,
            bodies,
        )?))
    }
}

/// The lifted keys a text projected from the stored record `bodies` holds,
/// whoever reads it: those the marks of each string of those bodies name.
/// An engine check of what a text says reads it with each of these as its
/// handle, so a key no reader but the owner is served never counts.
///
/// # Errors
///
/// Storage errors, and a mark whose key span does not cut its text.
pub(crate) fn lifted_keys_of_bodies_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    bodies: &[Vec<u8>],
) -> crate::Result<LiftedKeys> {
    let values = bodies
        .iter()
        .filter_map(|body| super::support::decode_body_json(body))
        .collect();
    LiftedKeys::of_json_in_txn(store, txn, &serde_json::Value::Array(values))
}

impl Memory<'_> {
    /// A claim's served `value` and `scope` as the bound reader reads them
    /// (FIX 13735): for every reader but the owner, each lifted key a string
    /// or an object key of either holds becomes its handle, as in a recall
    /// hit's body. A view masks them before it makes its label from them.
    pub(crate) fn mask_lifted_claim_parts(
        &self,
        value: &mut serde_json::Value,
        scope: Option<&mut serde_json::Value>,
    ) -> MemoryResult<()> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        if !self.reads_lifted_keys_masked_in_txn(&txn)? {
            return Ok(());
        }
        let mut texts = Vec::new();
        claim_texts(value, &mut texts);
        if let Some(scope) = scope.as_deref() {
            claim_texts(scope, &mut texts);
        }
        let keys = LiftedKeys::of_in_txn(&self.vault.store, &txn, texts)?;
        if !keys.is_empty() {
            mask_claim_json(&keys, value);
            if let Some(scope) = scope {
                mask_claim_json(&keys, scope);
            }
        }
        Ok(())
    }
}

/// Every string `value` holds, its object keys included: the texts a lifted
/// key of a claim's value or scope is found by.
fn claim_texts<'a>(value: &'a serde_json::Value, out: &mut Vec<&'a str>) {
    match value {
        serde_json::Value::String(text) => out.push(text),
        serde_json::Value::Array(items) => items.iter().for_each(|item| claim_texts(item, out)),
        serde_json::Value::Object(fields) => {
            for (key, item) in fields {
                out.push(key);
                claim_texts(item, out);
            }
        }
        _ => {}
    }
}

/// `value` with each lifted key `keys` names as its handle, in its strings
/// and its object keys alike. An object two of whose member names would read
/// as one handle is redacted whole, so no member silently replaces another.
fn mask_claim_json(keys: &LiftedKeys, value: &mut serde_json::Value) {
    let collided = match value {
        serde_json::Value::String(text) => {
            if let Some(masked) = keys.masked(text) {
                *text = masked;
            }
            false
        }
        serde_json::Value::Array(items) => {
            items
                .iter_mut()
                .for_each(|item| mask_claim_json(keys, item));
            false
        }
        serde_json::Value::Object(fields) => {
            let mut masked = serde_json::Map::new();
            let mut collided = false;
            for (key, mut item) in std::mem::take(fields) {
                mask_claim_json(keys, &mut item);
                collided |= masked
                    .insert(keys.masked(&key).unwrap_or(key), item)
                    .is_some();
            }
            *fields = masked;
            collided
        }
        _ => false,
    };
    if collided {
        *value = serde_json::Value::String("[redacted]".to_owned());
    }
}

/// `view` with each value `keys` reads held as its handle when `masked`.
fn masked_view<T: Serialize + DeserializeOwned>(
    masked: bool,
    view: T,
    keys: impl FnOnce() -> crate::Result<LiftedKeys>,
) -> MemoryResult<T> {
    if !masked {
        return Ok(view);
    }
    let keys = keys()?;
    if keys.is_empty() {
        return Ok(view);
    }
    let mut value = serde_json::to_value(&view)
        .map_err(|_| Error::InvariantViolation("a lifted carrier's view did not encode"))?;
    if !keys.mask_json(&mut value) {
        return Ok(view);
    }
    Ok(serde_json::from_value(value)
        .map_err(|_| Error::InvariantViolation("a lifted carrier's masked view did not decode"))?)
}
