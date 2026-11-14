//! Persisted customization settings and client-visible change events.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, Raw, RawValue, SideTable};
use crate::store::Store;

pub mod backup;
pub(crate) mod board_layout;
pub mod default_facet;
mod destination;
mod device_local;
mod device_only;
pub use oneiron_store::settings::model_pack;
pub use oneiron_store::settings::model_versioning;
mod models;
pub mod non_base_world_claim_fraction;
pub(crate) mod room_threads;
pub mod snapshot_read;
pub mod undo_send;
pub use oneiron_store::settings::web_connector;

pub use destination::{
    CallerLocality, ReadDestination, RecipientChoice, RecipientLimit, RecipientWhy, ReleaseHold,
    read_destination_at, read_destination_locality,
};
pub(crate) use destination::{
    machine_recipient_hold_in, recipient_limits_in, withheld_row_hold_in, withheld_worlds_in,
    worlds_hold_in,
};
pub(crate) use device_local::{
    device_local_keeps_among, device_local_worlds_at, device_local_worlds_for,
    device_local_worlds_for_machine, off_device_readable_in, off_device_readable_in_txn,
};
pub(crate) use device_only::{
    CarriedWorlds, carried_worlds_in, device_only_recipient_worlds,
    device_only_recipient_worlds_raw, device_only_withholds, device_only_withholds_raw,
    device_only_withholds_run, minted_worlds_in,
};

pub use board_layout::{
    AgentBoardLayoutOverride, BOARD_LAYOUT_AGENT_OVERRIDES_MAX, BoardLayoutSettings,
};
pub use model_versioning::{
    DEFAULT_MODEL_STACK_CURRENT_ID, DEFAULT_MODEL_STACK_V1_ID, ModelStack, ModelStackDeprecation,
    ModelStackDeprecationStage, ModelStackDeprecationStatus, ModelStackDisclosure, ModelStackId,
    ModelStackIdError, ModelStackModel, ModelStackPreference, ModelStackRegistry,
    ModelStackRegistryError, ModelStackResolution, default_model_stack_registry,
    try_default_model_stack_registry,
};
pub use room_threads::RoomThreadAdminSettings;

#[doc(hidden)]
pub use oneiron_records::settings::{
    AccentLayer, CUSTOMIZATION_SETTINGS_CHANGED_EVENT_KIND, CUSTOMIZATION_SETTINGS_LAYER_COUNT,
    CUSTOMIZATION_SETTINGS_SCHEMA_VERSION, CustomizationLayer, CustomizationLayerValue,
    CustomizationSettings, CustomizationSettingsChangeEvent, CustomizationSettingsUpdate,
    ModeLayer, TypeLayer, WorldLayer,
};
#[doc(hidden)]
use oneiron_records::settings::{
    TOKEN_MAX_BYTES, WORLD_LABEL_MAX_BYTES, validate_label, validate_token,
};

/// ONE-1707: the one additive knob over Dreamer plugin suggestions.
///
/// ABSENCE MEANS ON. The ticket's contract is "disableable, default ON", so
/// an untouched vault — which has never written this key — must read `true`
/// without any seeding step. A default that had to be written at open time
/// would make "fresh config" mean "config we already touched", and a
/// migration that missed a vault would silently disable the feature.
const PLUGIN_SUGGESTIONS_ENABLED: SideTable<(), PluginSuggestionsFlag, Raw> =
    SideTable::new(&side_table::PLUGIN_SUGGESTIONS_ENABLED);

/// Pinned on-disk encoding of the boolean knob above.
const SETTINGS_BOOL_TRUE: [u8; 1] = [1];
const SETTINGS_BOOL_FALSE: [u8; 1] = [0];

/// The plugin-suggestions knob: one byte, `1` for on and `0` for off. Any
/// other byte is a corrupted knob rather than a silently-defaulted one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PluginSuggestionsFlag(bool);

impl RawValue for PluginSuggestionsFlag {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::CodecError> {
        Ok(if self.0 {
            SETTINGS_BOOL_TRUE.to_vec()
        } else {
            SETTINGS_BOOL_FALSE.to_vec()
        })
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::CodecError> {
        match bytes {
            b if b == SETTINGS_BOOL_TRUE => Ok(Self(true)),
            b if b == SETTINGS_BOOL_FALSE => Ok(Self(false)),
            _ => Err(Error::CorruptedIndex("plugin suggestions knob").into()),
        }
    }
}

/// Persisted customization profile. Key: ().
const CUSTOMIZATION_SETTINGS: SideTable<(), CustomizationSettings, Named> =
    SideTable::new(&side_table::CUSTOMIZATION_SETTINGS);
/// Whether a masked copy of a `CUSTOMIZATION_SETTINGS` row still decodes as its typed value,
/// for the historical lift sweep (FIX 2680).
pub(crate) fn customization_settings_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<CustomizationSettings, Named>(bytes)
}

/// Monotonic sequence counter for customization change-notification events. Key: ().
const CUSTOMIZATION_EVENT_SEQUENCE: SideTable<(), u64, Raw> =
    SideTable::new(&side_table::CUSTOMIZATION_EVENT_SEQUENCE);
/// One client-readable customization-settings change-notification event. Key: u64be (sequence).
const CUSTOMIZATION_EVENT: SideTable<u64, CustomizationSettingsChangeEvent, Named> =
    SideTable::new(&side_table::CUSTOMIZATION_EVENT);
/// Whether a masked copy of a `CUSTOMIZATION_EVENT` row still decodes as its typed value,
/// for the historical lift sweep (FIX 2680).
pub(crate) fn customization_event_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<CustomizationSettingsChangeEvent, Named>(bytes)
}

impl Vault {
    /// Reads the Dreamer plugin-suggestion knob. **Absent means enabled.**
    ///
    /// There is no environment override and no second cadence key: this one
    /// boolean is the entire dial. A corrupt value fails closed as a typed
    /// error rather than silently reverting to the default, because a
    /// disabled knob that reads back as enabled would resume proactive
    /// suggestions an owner switched off.
    ///
    /// # Errors
    ///
    /// Storage errors, and [`Error::CorruptedIndex`] when the stored byte is
    /// not the pinned boolean encoding.
    pub fn plugin_suggestions_enabled(&self) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        Ok(PLUGIN_SUGGESTIONS_ENABLED
            .get(&self.store, &rtxn, &())?
            .is_none_or(|flag| flag.0))
    }

    /// Persists the Dreamer plugin-suggestion knob.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn set_plugin_suggestions_enabled(&self, enabled: bool) -> Result<()> {
        self.with_write_txn_grouped(|wtxn| {
            PLUGIN_SUGGESTIONS_ENABLED.put(
                &self.store,
                wtxn,
                &(),
                &PluginSuggestionsFlag(enabled),
            )?;
            Ok(())
        })
    }

    /// Held by a release verdict from its first flag read to its acceptance.
    /// A flag commit holds the other side, so a flag committed before a
    /// verdict accepts is always one it read. Hold it over reads only: never
    /// across a write or an async send.
    #[cfg(feature = "sync")]
    pub(crate) fn device_only_acceptance(&self) -> std::sync::RwLockReadGuard<'_, ()> {
        self.store
            .device_only_flag_lock
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Reads the persisted customization settings, or the default four-layer model.
    pub fn customization_settings(&self) -> Result<CustomizationSettings> {
        let rtxn = self.store.env.read_txn()?;
        customization_settings_in_read_txn(&self.store, &rtxn)
    }

    /// Persists one customization layer and emits a client-readable event when it changed.
    pub fn set_customization_layer(
        &self,
        value: CustomizationLayerValue,
    ) -> Result<CustomizationSettingsUpdate> {
        value.validate()?;
        self.with_write_txn_grouped(|wtxn| {
            let mut settings = customization_settings_in_write_txn(&self.store, wtxn)?;
            let previous = settings.layer_value(value.layer());
            if previous == value {
                return Ok(CustomizationSettingsUpdate {
                    settings,
                    event: None,
                });
            }

            settings.apply_layer_value(value.clone());
            // The side-row wall reads the profile before it is checked and kept (OF-067): a
            // secret in a label keeps its handle there, and a token field, which cannot hold
            // one, fails the check. The event carries the value as kept.
            CUSTOMIZATION_SETTINGS.admit(self, wtxn, &(), &mut settings)?;
            settings.validate()?;
            let value = settings.layer_value(value.layer());
            let sequence = next_customization_event_sequence(&self.store, wtxn)?;
            let event = CustomizationSettingsChangeEvent::new(
                sequence,
                self.store.clock.now_recorded_at(),
                previous,
                value,
            );
            event.validate()?;
            CUSTOMIZATION_SETTINGS.put(self, wtxn, &(), &settings)?;
            CUSTOMIZATION_EVENT.put(self, wtxn, &sequence, &event)?;
            Ok(CustomizationSettingsUpdate {
                settings,
                event: Some(event),
            })
        })
    }

    /// Reads customization change events after `after_sequence`, capped by `limit`.
    pub fn customization_events_after(
        &self,
        after_sequence: u64,
        limit: usize,
    ) -> Result<Vec<CustomizationSettingsChangeEvent>> {
        let rtxn = self.store.env.read_txn()?;
        customization_events_after_in_txn(&self.store, &rtxn, after_sequence, limit)
    }
}

fn customization_settings_in_read_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
) -> Result<CustomizationSettings> {
    let Some(settings) = CUSTOMIZATION_SETTINGS.get(store, rtxn, &())? else {
        return Ok(CustomizationSettings::default());
    };
    settings.validate()?;
    Ok(settings)
}

fn customization_settings_in_write_txn(
    store: &Store,
    wtxn: &RwTxn<'_>,
) -> Result<CustomizationSettings> {
    let Some(settings) = CUSTOMIZATION_SETTINGS.get(store, wtxn, &())? else {
        return Ok(CustomizationSettings::default());
    };
    settings.validate()?;
    Ok(settings)
}

fn next_customization_event_sequence(store: &Store, wtxn: &mut RwTxn<'_>) -> Result<u64> {
    let next = match CUSTOMIZATION_EVENT_SEQUENCE.get(store, wtxn, &())? {
        Some(current) => current
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("customization event sequence"))?,
        None => 1,
    };
    CUSTOMIZATION_EVENT_SEQUENCE.put(store, wtxn, &(), &next)?;
    Ok(next)
}

fn customization_events_after_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    after_sequence: u64,
    limit: usize,
) -> Result<Vec<CustomizationSettingsChangeEvent>> {
    let mut events = Vec::new();
    for row in CUSTOMIZATION_EVENT.iter_from(store, rtxn, &[])? {
        let (sequence, event) = row?;
        if sequence <= after_sequence {
            continue;
        }
        if events.len() >= limit {
            break;
        }
        event.validate()?;
        if event.sequence != sequence {
            return Err(Error::CorruptedIndex("customization settings event"));
        }
        events.push(event);
    }
    Ok(events)
}

pub(crate) mod tables;
#[cfg(test)]
mod tests;

/// Every world whose settings keep it off the machines `destination` names:
/// the world settings' one judge, asked for each machine a read's rows go to,
/// its proof revalidated in `txn` (mesh PR2b). Only a destination no live
/// machine proof names is unknown. Read through [`device_local_worlds_for`],
/// and through `device_local_worlds_for_machine` (FIX 5588 S4), which judges
/// the same settings via `WorldPrivacyView::withheld_for`: every door asks
/// one of those two functions which worlds a caller's rows are withheld from.
fn device_only_worlds_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    destination: &ReadDestination,
) -> Result<std::collections::BTreeSet<EntityId>> {
    withheld_worlds_in(vault, txn, destination)
}

// The lift sweep's typed acceptance for this module's authored side
// tables (FIX 2680), named by their declarations.
pub(crate) use self::models::model_owner_fallback_accepts_masked;
