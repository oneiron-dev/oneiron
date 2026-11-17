//! The catalogue keys `llm` declares (DESIGN 15-setting-primitive, stage 1): the owner's model
//! choices that each had a table and a setter of their own. The owner sets each through
//! `vault.settings.set`; every change is one `SETTING_CHANGE` row.
//!
//! The quota key lets an agent answer a spent-quota question (restriction wave 11, census C17).

use serde::{Deserialize, Serialize};

use super::ModelLocality;
use super::manifest::{self, ModelSlot};
use super::model_pack::{MODEL_PACK_REVERT_VERB, ModelPackChangeCause, revert_before};
use super::routing::DescriptionPolicy;
use crate::Vault;
use crate::agent_dispatch::AgentDispatcher;
use crate::check_in::ActClass;
use crate::error::{Error, Result};
use crate::setting::{
    EncodedValue, ItemDomain, Kind, ScopeKind, Setter, SettingChange, SettingMode, SettingScope,
    SettingValue, lower_is_tighter,
};
use crate::settings::model_pack::ModelPackPreference;

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

/// The owner's model pack preference as a setting value: follow the latest pack (the default),
/// pin a season or pin one pack.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub(crate) struct ModelPackPreferenceValue(pub(crate) ModelPackPreference);

impl SettingValue for ModelPackPreferenceValue {}

/// What moved the pack in effect. The engine writes this key only on a retirement's move; the
/// owner's one-tap revert gives its verb as the change's reason; any other change is the owner's
/// setting.
fn model_pack_change_cause(change: &SettingChange) -> ModelPackChangeCause {
    match change.setter {
        Setter::Engine { .. } => ModelPackChangeCause::Retirement,
        Setter::Owner
            if change
                .why
                .as_deref()
                .is_some_and(|why| why.starts_with(MODEL_PACK_REVERT_VERB)) =>
        {
            ModelPackChangeCause::Revert
        }
        _ => ModelPackChangeCause::Preference,
    }
}

/// The model pack preference is one value row at the vault, so the revert and a retirement's
/// move, which write that row, always decide: a pin of it is refused. A season or pack pin names
/// one the vault can follow now. The change records the move of the pack in effect, with its
/// notice and revert (FIX 5369), from the pack the row's prior value selects; a revert's, from
/// the pack in effect before it ([`revert_before`]): a version the revert installed again changed
/// what that prior value selects.
fn note_model_pack_preference_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    change: &SettingChange,
) -> Result<()> {
    if change.mode == SettingMode::Pin {
        return Err(Error::InvalidConfig(
            "the model pack preference is one value row: a pin of it would hold back the \
             one-tap revert and a retirement's move"
                .into(),
        ));
    }
    let preference = |value: Option<&EncodedValue>| {
        value
            .and_then(EncodedValue::decode::<ModelPackPreferenceValue>)
            .unwrap_or_default()
            .0
    };
    vault.check_model_pack_preference_in_txn(txn, &preference(change.value.as_ref()))?;
    let before = match revert_before() {
        Some(before) => before,
        None => vault.model_pack_selected_in_txn(txn, &preference(change.prior.as_ref()))?,
    };
    vault.note_active_model_pack_in_txn(txn, before, model_pack_change_cause(change))
}

/// Off: only the owner answers a quota question.
fn owner_answers() -> bool {
    false
}

/// The answers a quota question offers, by their wire names (`POST /v1/ai/quota/{id}`).
fn quota_choice(item: &str) -> bool {
    matches!(
        item,
        "wait" | "add_account" | "use_fallback" | "top_up" | "pay_as_you_go"
    )
}

/// The confirm sheet's line for letting an agent answer `top_up` or `pay_as_you_go` (or every
/// answer, on a row that names none): the spend cap in force over the row's scope, every open
/// root for the vault row and the roots over that agent's open attempts for an agent's row
/// (RESTRICTION-WAVE-11-CAP-NOTE; CAP-SCOPE = B). The other answers spend nothing and state no
/// line.
fn quota_answer_loosening_note(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: &SettingScope,
    item: Option<&str>,
) -> Result<Option<String>> {
    match item {
        None | Some("top_up" | "pay_as_you_go") => {
            let agent = match scope {
                SettingScope::Agent(agent) => Some(*agent),
                _ => None,
            };
            AgentDispatcher::new(vault)
                .spend_cap_in_force_line_in_txn(txn, agent)
                .map(Some)
        }
        Some(_) => Ok(None),
    }
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
    /// The owner's model pack preference (FIX 5367, 5369): follow the latest pack (the default),
    /// pin a season while an installed pack of it is served, or pin one installed, served pack,
    /// as the one-tap revert does. A change that moves the pack in effect sends its notice. One
    /// value row: a pin of it is refused. A retirement moves a pin whose pack retired to its
    /// successor as the engine's own change.
    pub(crate) MODEL_PACK_PREFERENCE: ModelPackPreferenceValue = "models.pack_preference" {
        kind: Kind::new(ModelPackPreferenceValue::default),
        on_change: Some(note_model_pack_preference_in_txn),
    };
    /// Let this agent give this answer to a spent-quota question. Off by default for every
    /// answer: only the owner answers at `POST /v1/ai/quota/{id}`, as before. One item per
    /// answer (`wait`, `add_account`, `use_fallback`, `top_up`, `pay_as_you_go`), so the owner
    /// lets an agent wait out a window without letting it put a paid offer back. `top_up` and
    /// `pay_as_you_go` put the offer back at once and its calls spend on the provider's account,
    /// so the key is declared with the billing act class: turning any answer on is a payment
    /// loosening (RESTRICTION-WAVE-11-OWNER-ROWS Q1 = A; ARCH-0082 #payment). The engine never
    /// pays; the provider's own payment authentication stays where it is. An agent's row names
    /// one agent; the vault row opens every agent, and an agent's own row wins over it. A member
    /// is never let in by this key. Only the owner turns it on; an agent's change waits on the
    /// owner's answer (restriction wave 11, census C17). The confirm sheet for turning on
    /// `top_up` or `pay_as_you_go` states the spend cap in force, or "no cap", first.
    pub(crate) MODELS_QUOTA_AGENT_MAY_ANSWER: bool = "models.quota.agent_may_answer" {
        kind: Kind::new(owner_answers)
            .strictest(owner_answers)
            .tighter(lower_is_tighter::<bool>),
        scopes: &[ScopeKind::Vault, ScopeKind::Agent],
        item: Some(ItemDomain { name: "quota answers", admits: quota_choice }),
        act: ActClass::Billing,
        loosening_note: Some(quota_answer_loosening_note),
    };
}
