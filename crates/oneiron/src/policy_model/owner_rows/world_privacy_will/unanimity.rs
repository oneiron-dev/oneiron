//! "Widen needs every owner" (FIX 4480, the several-holders ruling): one
//! per-vault policy row with a per-world override, default off. The owner's
//! words: "too much consensus can be bad. an admin should be able to just
//! do". When the row is on for a world, any widen of it (a holder's own, or an
//! agent's ask) lands only once every live Owner of the vault said yes; the
//! author's own act counts as his yes, and Admins alone cannot satisfy it.
//! Tightening stays any one holder (CALLS "FIX 4480 unanimity scope").

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::super::ledger::{PolicyChangedEvent, put_event_in_txn};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::gate::PolicyRowScope;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// Event kind on the shared owner-policy stream for a change of the row.
const UNANIMITY_CHANGED: &str = "policy.world_privacy.unanimity.changed";

/// The row: the vault's setting, and each world's override of it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WidenUnanimity {
    /// The vault's setting, for every world without an override.
    pub vault: bool,
    /// Per-world overrides, keyed by the WORLD row as hex.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub worlds: BTreeMap<String, bool>,
}

impl WidenUnanimity {
    /// Whether a widen of `world` needs every owner's yes.
    #[must_use]
    pub fn applies_to(&self, world: EntityId) -> bool {
        self.worlds
            .get(&world.to_hex())
            .copied()
            .unwrap_or(self.vault)
    }
}

const UNANIMITY: SideTable<(), WidenUnanimity, Named> =
    SideTable::new(&side_table::OWNER_POLICY_WORLD_PRIVACY_UNANIMITY);

/// The live Owners every one of whose yes a widen of `world` needs; empty
/// while the row is off for it, so any one holder's yes applies a widen.
pub(super) fn widen_needs_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    world: EntityId,
) -> Result<Vec<EntityId>> {
    let row = UNANIMITY.get(&vault.store, txn, &())?.unwrap_or_default();
    if !row.applies_to(world) {
        return Ok(Vec::new());
    }
    super::super::authority::owners_in_txn(vault, txn)
}

impl Vault {
    /// The "widen needs every owner" row as it stands.
    pub fn widen_needs_every_owner(&self) -> Result<WidenUnanimity> {
        let txn = self.store.env.read_txn()?;
        Ok(UNANIMITY.get(&self.store, &txn, &())?.unwrap_or_default())
    }

    /// A live Owner sets the row: the vault's setting when `world` is
    /// `None`, else that world's override, which `on: None` clears. It lands
    /// at once with an event on the owner-policy stream (policy hook: who sets
    /// it is any one live Owner, CALLS "FIX 4480 unanimity setter").
    ///
    /// # Errors
    /// [`crate::error::GateError::ConsentOwnerNotAuthenticated`] unless
    /// `owner` is a live Owner of this vault; [`crate::Error::InvalidConfig`]
    /// for a vault setting of `None`.
    pub fn set_widen_needs_every_owner(
        &self,
        owner: &AuthenticatedOwner,
        world: Option<EntityId>,
        on: Option<bool>,
    ) -> Result<WidenUnanimity> {
        self.with_write_txn(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let mut row = UNANIMITY.get(&self.store, txn, &())?.unwrap_or_default();
            match (world, on) {
                (None, Some(on)) => row.vault = on,
                (None, None) => {
                    return Err(crate::Error::InvalidConfig(
                        "the vault's \"widen needs every owner\" setting is on or off".to_owned(),
                    ));
                }
                (Some(world), Some(on)) => {
                    row.worlds.insert(world.to_hex(), on);
                }
                (Some(world), None) => {
                    row.worlds.remove(&world.to_hex());
                }
            }
            UNANIMITY.put(&self.store, txn, &(), &row)?;
            put_event_in_txn(
                self,
                txn,
                &PolicyChangedEvent {
                    kind: UNANIMITY_CHANGED.to_owned(),
                    receipt_id: self.store.clock.entity_id()?.to_hex(),
                    author: actor.to_hex(),
                    scope: Some(world.map_or(PolicyRowScope::Vault, |world| {
                        PolicyRowScope::World(world.to_hex())
                    })),
                    target: None,
                    at: self.instant_in_txn(txn)?.secs(),
                },
            )?;
            Ok(row)
        })
    }
}
