//! A policy manifest as a seed writes it (DEC-0005): its entity id and its
//! exact MessagePack body, as hex. Apply installs it through the owner's
//! manifest door and retires it by quarantining those exact bytes. A create
//! or update that narrows the resolved policy on every axis
//! (`crate::gate::manifest_resolution_narrows`) lands with a receipt, checked
//! again in the writer that lands it. Every other change waits for the
//! owner's word.
use super::seed::hex;
use super::{ShapeChange, ShapeItemClass, ShapePlanItem, ShapeRow, ShapeTarget, invalid};
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
    /// Marks each manifest create or update in `items` Receipted when,
    /// written in plan order on the vault as it stands, it narrows the
    /// resolved policy on every axis. The rest stay Widening.
    pub(super) fn classify_shape_manifests(&self, items: &mut [ShapePlanItem]) -> Result<()> {
        let mut at = Vec::new();
        let mut installs = Vec::new();
        for (index, item) in items.iter().enumerate() {
            if let (
                ShapeChange::Create | ShapeChange::Update,
                ShapeTarget::Manifest { manifest_ref },
                Some(ShapeRow::Manifest { body, .. }),
            ) = (&item.change, &item.target, &item.after)
                && let (Ok(id), Some(bytes)) =
                    (EntityId::from_hex(manifest_ref), manifest_bytes(body))
            {
                at.push(index);
                installs.push((id, bytes));
            }
        }
        if installs.is_empty() {
            return Ok(());
        }
        let steps = self.manifest_installs_narrow(&installs, crate::unix_seconds_now())?;
        for (index, narrows) in at.into_iter().zip(steps) {
            if narrows {
                items[index].class = ShapeItemClass::Receipted;
            }
        }
        Ok(())
    }

    /// Installs the manifest a row declares, as `owner`. Bytes the owner
    /// once quarantined under that id refuse: the install would store them
    /// and they would still not count. A row planned as a `narrowing` lands
    /// only if it still narrows the policy the vault holds just before it.
    pub(super) fn install_shape_manifest(
        &self,
        owner: &AuthenticatedOwner,
        manifest_ref: &str,
        body: &str,
        narrowing: bool,
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
        if !narrowing {
            self.install_owner_policy_manifest(owner, id, bytes, now)?;
        } else if !self.install_owner_policy_manifest_narrowing(owner, id, bytes, now)? {
            return Err(invalid(
                "this manifest no longer narrows the vault's policy as it stands; plan again, and it waits for the owner's word",
            ));
        }
        Ok(id.to_hex())
    }
}
