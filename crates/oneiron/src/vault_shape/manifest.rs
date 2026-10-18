//! A policy manifest as a seed writes it (DEC-0005): its entity id and its
//! exact MessagePack body, as hex. Apply installs it through the owner's
//! manifest door and retires it by quarantining those exact bytes. A create
//! or update that narrows the resolved policy on every axis
//! (`crate::gate::manifest_resolution_narrows`) lands with a receipt, checked
//! again in the writer that lands it. Every other change waits for the
//! owner's word.
use super::seed::hex;
use super::{ShapeChange, ShapeItemClass, ShapePlanItem, ShapeRow, ShapeTarget, invalid};
use crate::channel_identity::channel_identity_send_holder_in_txn;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::gate::manifest_authenticity::manifest_is_quarantined;
use crate::{EntityId, Vault};
use std::collections::BTreeMap;

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
    /// resolved policy on every axis. The rest stay Widening. Returns
    /// whether each of `senders` may send once every manifest change is in
    /// place (ARCH-0070 reach); None when the plan changes no manifest, or
    /// one of its changes would not land.
    pub(super) fn classify_shape_manifests(
        &self,
        items: &mut [ShapePlanItem],
        senders: &[EntityId],
    ) -> Result<Option<BTreeMap<EntityId, bool>>> {
        let mut at = Vec::new();
        let mut installs = Vec::new();
        let mut retires = Vec::new();
        let mut whole = true;
        for (index, item) in items.iter().enumerate() {
            let ShapeTarget::Manifest { manifest_ref } = &item.target else {
                continue;
            };
            let id = EntityId::from_hex(manifest_ref).ok();
            let bytes = match &item.after {
                Some(ShapeRow::Manifest { body, .. }) => manifest_bytes(body),
                _ => None,
            };
            match (&item.change, id, bytes) {
                (ShapeChange::Retire, Some(id), _) => retires.push(id),
                (ShapeChange::Create | ShapeChange::Update, Some(id), Some(bytes)) => {
                    at.push(index);
                    installs.push((id, bytes));
                }
                _ => whole = false,
            }
        }
        if installs.is_empty() && retires.is_empty() {
            return Ok(None);
        }
        let read = |txn: &heed::RoTxn<'_>| -> Result<BTreeMap<EntityId, bool>> {
            let mut sends = BTreeMap::new();
            for id in senders {
                if let Some((_, may_send)) =
                    channel_identity_send_holder_in_txn(&self.store, txn, id)?
                {
                    sends.insert(*id, may_send);
                }
            }
            Ok(sends)
        };
        let (steps, sends) =
            self.project_manifest_changes(&installs, &retires, crate::unix_seconds_now(), read)?;
        for (index, narrows) in at.into_iter().zip(steps) {
            if narrows {
                items[index].class = ShapeItemClass::Receipted;
            }
        }
        Ok(sends.filter(|_| whole))
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
