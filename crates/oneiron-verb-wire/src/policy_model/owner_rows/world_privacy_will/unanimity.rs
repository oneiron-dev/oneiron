//! Moved from `crates/oneiron/src/policy_model/owner_rows/world_privacy_will/unanimity.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::policy_model::owner_rows::world_privacy_will::record::WorldPrivacyRequestStatus;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// The row: the vault's setting, and each world's override of it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
        self.applies_to_hex(&world.to_hex())
    }

    fn applies_to_hex(&self, world: &str) -> bool {
        self.worlds.get(world).copied().unwrap_or(self.vault)
    }

    /// The row after one change: the vault's setting when `world` is `None`,
    /// else that world's override, which `on: None` clears.
    fn changed(&self, world: Option<EntityId>, on: Option<bool>) -> Result<Self> {
        let mut row = self.clone();
        match (world, on) {
            (None, Some(on)) => row.vault = on,
            (None, None) => {
                return Err(Error::InvalidConfig(
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
        Ok(row)
    }

    /// Whether going to `after` turns any effective scope from on to off: the
    /// vault's setting, which every world without an override follows, or a
    /// world's own effective setting.
    fn turns_off(&self, after: &Self) -> bool {
        (self.vault && !after.vault)
            || self
                .worlds
                .keys()
                .chain(after.worlds.keys())
                .any(|world| self.applies_to_hex(world) && !after.applies_to_hex(world))
    }
}

/// What a change of the row came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WidenUnanimityOutcome {
    /// The change landed: the row as it now stands.
    Set(WidenUnanimity),
    /// It turns the setting off for some world while it is on, so it waits
    /// for every live Owner's yes: the request, with the yeses so far.
    Pending(WidenUnanimityOffRequest),
    /// A live Owner declined the pending turn-off; the row is unchanged.
    Declined(WidenUnanimityOffRequest),
}

/// A change of the row that turns it off for some world while it is on,
/// frozen when an owner asked for it. It lands once every live Owner said
/// yes, the asking owner's own yes counted; any one live Owner's no declines
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WidenUnanimityOffRequest {
    /// Its id, as hex.
    pub request_id: String,
    /// The world whose override it changes, as hex; `None` for the vault's
    /// setting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub world: Option<String>,
    /// The value it sets: off, or `None` to clear a world's override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    /// The live Owner who asked for it, as hex.
    pub author: String,
    /// Every live Owner whose yes it needs, as hex, as of its last answer.
    pub needs: Vec<String>,
    /// The yeses collected so far, as hex.
    pub yes: Vec<String>,
    /// Pending; applied (`receipt_id` names the row's change event on the
    /// owner-policy stream, `holder` the owner whose yes landed it); or
    /// declined.
    pub status: WorldPrivacyRequestStatus,
    pub at: u64,
}

impl WidenUnanimityOffRequest {
    fn id(&self) -> Result<EntityId> {
        EntityId::from_hex(&self.request_id)
            .map_err(|_| Error::CorruptedIndex("widen unanimity turn-off id"))
    }

    fn world_id(&self) -> Result<Option<EntityId>> {
        self.world
            .as_deref()
            .map(|world| {
                EntityId::from_hex(world)
                    .map_err(|_| Error::CorruptedIndex("widen unanimity turn-off world"))
            })
            .transpose()
    }
}
