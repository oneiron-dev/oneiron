//! This machine's residence choice: sync every window it may read, or sync
//! what it opened, and the worlds the owner picked for it to follow. Both
//! are node-local, never synced and never an authority entry: they decide
//! which copies the machine wants, not what its actor may read or where a
//! world's readable copies may live.

use std::collections::BTreeSet;

use oneiron_verb_wire::verbs::residence::ResidenceModeName;

use crate::Vault;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::setting::{EngineSetting, SetSetting, SettingCaller};
use crate::store::setting_keys::RESIDENCE_MODE;
use crate::sync::client::SyncResidenceMode;

/// The one local row of the owner's world pick (`rs:worlds`): each picked
/// world's 16 id bytes, ascending. Key: ().
const WORLD_PICK_KEY: &str = "rs:worlds";

/// The owner's last explicit choice for this machine: the `sync.residence.mode` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceSyncPreference {
    pub mode: SyncResidenceMode,
}

/// The persisted choice, or `None` when the owner never chose on this machine.
pub fn load_device_sync_preference(vault: &Vault) -> Result<Option<DeviceSyncPreference>> {
    let txn = vault.store.env.read_txn()?;
    Ok(RESIDENCE_MODE
        .read_in_txn(vault, &txn, &[], None)?
        .value
        .map(|mode| DeviceSyncPreference { mode: mode.into() }))
}

/// Record the owner's choice for this machine. The live connection applies
/// it by reconnecting; see `SyncConnection::set_residence_mode`.
pub fn set_device_sync_preference(
    vault: &Vault,
    mode: SyncResidenceMode,
) -> Result<DeviceSyncPreference> {
    vault.with_write_txn_grouped(|txn| set_device_sync_preference_in_txn(vault, txn, mode))
}

/// [`set_device_sync_preference`] in the caller's transaction, for a door
/// that records more in the same commit. The engine writes the row: every
/// caller is a path that switches the live connection with it, and the key
/// refuses any other change. The key runs nothing after the commit.
pub(crate) fn set_device_sync_preference_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    mode: SyncResidenceMode,
) -> Result<DeviceSyncPreference> {
    let mut request = SetSetting::vault_value(
        RESIDENCE_MODE.spec.name,
        serde_json::json!(ResidenceModeName::from(mode)),
    );
    request.why = Some("the residence switch".to_owned());
    vault.set_setting_in_txn(txn, SettingCaller::Engine(EngineSetting::own()), &request)?;
    Ok(DeviceSyncPreference { mode })
}

/// The worlds the owner picked for this machine to follow (ARCH-0023b
/// #partial-sync), read in `txn`; none until the owner picks. Under sync all the
/// machine follows every world it may read, whatever it picked.
pub(crate) fn device_world_pick_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<BTreeSet<EntityId>> {
    let Some(bytes) = vault.store.sync_state.get(txn, WORLD_PICK_KEY)? else {
        return Ok(BTreeSet::new());
    };
    if bytes.len() % 16 != 0 {
        return Err(Error::CorruptedIndex("device world pick"));
    }
    bytes
        .chunks_exact(16)
        .map(|chunk| {
            let mut id = [0; 16];
            id.copy_from_slice(chunk);
            EntityId::from_bytes(id).map_err(|_| Error::CorruptedIndex("device world pick"))
        })
        .collect()
}

/// [`device_world_pick_in`] in its own read.
pub fn load_device_world_pick(vault: &Vault) -> Result<BTreeSet<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    device_world_pick_in(vault, &rtxn)
}

/// Record the owner's pick of the worlds this machine follows, replacing
/// the one before, in the caller's transaction. The live connection applies
/// it by renegotiating; see `SyncConnection::set_followed_worlds`.
pub(crate) fn set_device_world_pick_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    worlds: &BTreeSet<EntityId>,
) -> Result<()> {
    let bytes: Vec<u8> = worlds
        .iter()
        .flat_map(|world| world.as_bytes().iter().copied())
        .collect();
    vault.store.sync_state.put(txn, WORLD_PICK_KEY, &bytes)?;
    Ok(())
}

/// Whether this vault is a replica of a vault another machine started: its
/// own-device sync lane reached the home at least once (`m:last_sync`). Its
/// setup then comes from the home's rows, even none, never from its own
/// file config (OF-370). A replica that never reached its home yet reads as
/// a vault of its own.
pub fn synced_as_replica(vault: &Vault) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(crate::sync::window_rows::LAST_SYNC
        .get(&vault.store, &rtxn, &())?
        .is_some())
}

/// Whether this machine is the elected MACRO home. The election names the
/// candidate by the same stable sync device id this install mints.
pub fn local_is_elected_home(vault: &Vault) -> Result<bool> {
    let Some(home) = DreamerRunnerStore::new(vault).home_node_designation()? else {
        return Ok(false);
    };
    Ok(home.node_id == crate::identity::load_or_mint_client_id(vault)?)
}

/// The mode a machine runs: the elected home holds every window it may
/// read; any other machine runs its owner's choice, or the host's configured
/// mode (Opened by default) when the owner never chose. Neither widens a
/// grant or a world's residence setting.
#[must_use]
pub fn effective_residence_mode(
    preference: Option<DeviceSyncPreference>,
    configured: SyncResidenceMode,
    is_home: bool,
) -> SyncResidenceMode {
    if is_home {
        return SyncResidenceMode::All;
    }
    preference.map_or(configured, |preference| preference.mode)
}

/// Resolve the mode for one own-device connection from durable state.
pub fn resolve_residence_mode(
    vault: &Vault,
    configured: SyncResidenceMode,
) -> Result<SyncResidenceMode> {
    Ok(effective_residence_mode(
        load_device_sync_preference(vault)?,
        configured,
        local_is_elected_home(vault)?,
    ))
}
