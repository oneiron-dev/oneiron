//! The catalogue keys `llm` declares (DESIGN 15-setting-primitive, stages 1 and 2): the model
//! choices that each had a table and a setter of their own. Each is set through
//! `vault.settings.set`; every change is one `SETTING_CHANGE` row.

use serde::{Deserialize, Serialize};

use oneiron_model::llm::locality_rank;

use super::manifest::{self, ModelSlot};
use super::model_pack::{MODEL_PACK_REVERT_VERB, ModelPackChangeCause};
use super::routing::DescriptionPolicy;
use super::{ModelLocality, PurposeDefaultTable, VoicePrecedence};
use crate::Vault;
use crate::error::{Error, Result};
use crate::setting::{
    EncodedValue, ItemDomain, Kind, SetBy, Setter, SettingChange, SettingMode, SettingValue,
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
/// notice and revert (FIX 5369); the pack before it is the one the row's prior value selects.
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
    let before = vault.model_pack_selected_in_txn(txn, &preference(change.prior.as_ref()))?;
    vault.note_active_model_pack_in_txn(txn, before, model_pack_change_cause(change))
}

/// The vault's purpose-default table as a setting value: per call purpose and voice lane, the
/// tier and the widest locality its calls take, the widest extraction destination, the voice
/// precedence and the self-compaction row. A stored table passes `PurposeDefaultTable::validate`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub(crate) struct PurposeDefaults(pub(crate) PurposeDefaultTable);

impl SettingValue for PurposeDefaults {
    fn check(self) -> Result<Self> {
        self.0.validate()?;
        Ok(self)
    }
}

/// The policy setting whose vault-scope `policy.change` grant makes a person a holder of the
/// purpose defaults: `PolicySetting::InferenceDefaults`'s name, the target
/// [`super::purpose_default_grant_target`] spells.
const INFERENCE_DEFAULTS_POLICY_TARGET: &str = "settings.inference_defaults";

/// Whether `next` sends no call wider than `prior` (the resident door's narrowing check, now the
/// key's order): no purpose row, voice row, extraction bound or self-compaction row at a wider
/// locality, and a vault-only voice precedence kept. A row `prior` lacks cannot be judged, so it
/// counts as wider.
fn purpose_defaults_no_wider(next: &PurposeDefaults, prior: &PurposeDefaults) -> bool {
    let (next, prior) = (&next.0, &prior.0);
    let within =
        |next: ModelLocality, prior: ModelLocality| locality_rank(next) <= locality_rank(prior);
    next.purposes.iter().all(|(purpose, row)| {
        prior
            .purposes
            .get(purpose)
            .is_some_and(|was| within(row.locality, was.locality))
    }) && next.voice.iter().all(|(lane, row)| {
        prior
            .voice
            .get(lane)
            .is_some_and(|was| within(row.locality, was.locality))
    }) && within(next.extraction_max_locality, prior.extraction_max_locality)
        && within(
            next.self_compaction.locality,
            prior.self_compaction.locality,
        )
        && (prior.voice_precedence != VoicePrecedence::VaultOnly
            || next.voice_precedence == VoicePrecedence::VaultOnly)
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
    /// The vault's inference defaults (FIX 8211): per call purpose and voice lane the tier and
    /// the widest locality its calls take, the widest extraction destination, the voice
    /// precedence and the self-compaction row. The owner and a person holding the policy power
    /// over `settings.inference_defaults` move it both ways; an agent holding the key's line
    /// narrows it, and anyone else's change asks. A narrowing sends no purpose, voice lane, bound
    /// or self-compaction row wider and keeps a vault-only voice precedence.
    pub(crate) PURPOSE_DEFAULTS: PurposeDefaults = "models.purpose_defaults" {
        kind: Kind::new(PurposeDefaults::default).custom(purpose_defaults_no_wider),
        set_by: SetBy::Policy,
        policy_target: Some(INFERENCE_DEFAULTS_POLICY_TARGET),
    };
}
