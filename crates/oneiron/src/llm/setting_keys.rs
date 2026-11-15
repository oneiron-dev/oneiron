//! The catalogue keys `llm` declares (DESIGN 15-setting-primitive, stage 1): the owner's model
//! choices that each had a table and a setter of their own. The owner sets each through
//! `vault.settings.set`; every change is one `SETTING_CHANGE` row.

use serde::{Deserialize, Serialize};

use super::ModelLocality;
use super::manifest::{self, ModelSlot};
use super::routing::DescriptionPolicy;
use crate::Vault;
use crate::error::{Error, Result};
use crate::setting::{ItemDomain, Kind, SettingChange, SettingValue};

fn no_description_policy() -> Option<DescriptionPolicy> {
    None
}

fn no_resident_route() -> Option<ResidentRoute> {
    None
}

/// One slot's resident narrowing: the route its calls take, no wider than the manifest's pin
/// for the slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub(crate) struct ResidentRoute(pub(crate) ModelLocality);

impl SettingValue for ResidentRoute {}

/// The item a slot's row sits at, as the manifest's slot names spell it.
pub(crate) const fn slot_item(slot: ModelSlot) -> &'static str {
    match slot {
        ModelSlot::Llm => "llm",
        ModelSlot::Embedder => "embedder",
        ModelSlot::Oneironer => "oneironer",
    }
}

const SLOTS: [ModelSlot; 3] = [ModelSlot::Llm, ModelSlot::Embedder, ModelSlot::Oneironer];

fn slot_named(item: &str) -> Option<ModelSlot> {
    SLOTS.into_iter().find(|slot| slot_item(*slot) == item)
}

fn admits_slot(item: &str) -> bool {
    slot_named(item).is_some()
}

/// A resident narrowing is stored only while the manifest in force admits it: no wider than the
/// slot's pin, and every served role on the slot has a model at that route. A row with no item
/// narrows every slot, so each one must admit it. A clear always lands.
fn check_resident_route_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    change: &SettingChange,
) -> Result<()> {
    let Some(stored) = change.value.as_ref() else {
        return Ok(());
    };
    let Some(ResidentRoute(route)) = stored.decode::<Option<ResidentRoute>>().flatten() else {
        return Ok(());
    };
    let manifest = vault
        .model_manifest_in_txn(txn)?
        .ok_or_else(|| Error::InvalidConfig("manifest not configured".into()))?;
    let slots = match change.item.as_deref() {
        Some(item) => vec![
            slot_named(item)
                .ok_or_else(|| Error::InvalidConfig(format!("`{item}` is not a model slot")))?,
        ],
        None => manifest.routes.keys().copied().collect(),
    };
    slots
        .into_iter()
        .try_for_each(|slot| manifest::route_admits(&manifest, slot, route))
}

crate::setting::setting_keys! {
    /// The vault's model description policy: the models a routed seat may take, the owner's line
    /// about each, and the effort defaults. Null is no policy: a routed seat or verdict is then
    /// refused, and effort composes from the seat policy alone. A stored policy passes
    /// `DescriptionPolicy::validate`.
    pub(crate) DESCRIPTION_POLICY: Option<DescriptionPolicy> = "models.description_policy" {
        kind: Kind::new(no_description_policy),
    };
    /// The owner's resident narrowing of one model slot (item: llm, embedder or oneironer): the
    /// route its calls take, narrower than the manifest's pin. Null is none: the slot takes its
    /// pin. A set lands only while the manifest in force admits the route; a stored route a later
    /// manifest no longer admits reads as the pin until one admits it again.
    pub(crate) RESIDENT_ROUTE: Option<ResidentRoute> = "models.resident_route" {
        kind: Kind::new(no_resident_route),
        item: Some(ItemDomain { name: "model slot", admits: admits_slot }),
        on_change: Some(check_resident_route_in_txn),
    };
}
