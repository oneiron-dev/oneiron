//! A policy manifest as a seed writes it (DEC-0005): its entity id and its
//! exact MessagePack body, as hex. Apply installs it through the owner's
//! manifest door and retires it by quarantining those exact bytes. No
//! comparator yet proves that a manifest change narrows the vault, so every
//! change waits for the owner's word.
use super::invalid;
use super::seed::hex;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::gate::manifest_authenticity::manifest_is_quarantined;
use crate::{EntityId, Vault};

/// A manifest body's bytes, from hex.
fn manifest_bytes(body: &str) -> Option<Vec<u8>> {
    if body.len() % 2 != 0 {
        return None;
    }
    (0..body.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(body.get(at..at + 2)?, 16).ok())
        .collect()
}

/// A manifest body as the owner's install door stores it, as hex. A row
/// reads as landed once the vault holds exactly this.
pub(super) fn manifest_as_stored(body: &str) -> Option<String> {
    let stored = crate::gate::owner_policy_manifest_as_stored(manifest_bytes(body)?).ok()?;
    Some(hex(&stored))
}

impl Vault {
    /// Installs the manifest a row declares, as `owner`. Bytes the owner
    /// once quarantined under that id refuse: the install would store them
    /// and they would still not count.
    pub(super) fn install_shape_manifest(
        &self,
        owner: &AuthenticatedOwner,
        manifest_ref: &str,
        body: &str,
        now: u64,
    ) -> Result<String> {
        let id = EntityId::from_hex(manifest_ref)
            .map_err(|_| invalid("a manifest is named by entity id hex"))?;
        let bytes =
            manifest_bytes(body).ok_or_else(|| invalid("a manifest body is MessagePack as hex"))?;
        let stored = crate::gate::owner_policy_manifest_as_stored(bytes.clone())?;
        {
            let txn = self.store.env.read_txn()?;
            if manifest_is_quarantined(&self.store, &txn, &id, &stored)? {
                return Err(invalid(
                    "the owner quarantined these exact bytes; installing them again would not count",
                ));
            }
        }
        self.install_owner_policy_manifest(owner, id, bytes, now)?;
        Ok(id.to_hex())
    }
}
