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

    /// `view` as the bound actor reads it: for a reader other than the
    /// owner, each value the lifted texts `keys` reads hold as its handle,
    /// wherever the view holds it.
    pub(crate) fn lifted_view<T: Serialize + DeserializeOwned>(
        &self,
        view: T,
        keys: impl FnOnce() -> crate::Result<LiftedKeys>,
    ) -> MemoryResult<T> {
        if !self.reads_lifted_keys_masked()? {
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
        Ok(serde_json::from_value(value).map_err(|_| {
            Error::InvariantViolation("a lifted carrier's masked view did not decode")
        })?)
    }
}
