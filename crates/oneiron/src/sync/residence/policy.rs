//! This machine's residence choice: sync every window it may read, or sync
//! what it opened. The choice is node-local, never synced and never an
//! authority entry: it decides which copies the machine wants, not what its
//! actor may read or where a world's readable copies may live.

use crate::Vault;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::error::{Error, Result};
use crate::sync::client::SyncResidenceMode;

/// The one local preference row (`rs:mode`). Key: ().
const PREFERENCE_KEY: &str = "rs:mode";
const PREFERENCE_LEN: usize = 9;

/// The owner's last explicit choice for this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceSyncPreference {
    pub mode: SyncResidenceMode,
    /// Recorded-clock seconds when the choice was made.
    pub chosen_at: u64,
}

impl DeviceSyncPreference {
    fn encode(self) -> [u8; PREFERENCE_LEN] {
        let mut bytes = [0; PREFERENCE_LEN];
        bytes[0] = match self.mode {
            SyncResidenceMode::Opened => 0,
            SyncResidenceMode::All => 1,
        };
        bytes[1..].copy_from_slice(&self.chosen_at.to_be_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let bytes: &[u8; PREFERENCE_LEN] = bytes
            .try_into()
            .map_err(|_| Error::CorruptedIndex("device sync preference"))?;
        let mode = match bytes[0] {
            0 => SyncResidenceMode::Opened,
            1 => SyncResidenceMode::All,
            _ => return Err(Error::CorruptedIndex("device sync preference")),
        };
        let mut at = [0; 8];
        at.copy_from_slice(&bytes[1..]);
        Ok(Self {
            mode,
            chosen_at: u64::from_be_bytes(at),
        })
    }
}

/// The persisted choice, or `None` when the owner never chose on this machine.
pub fn load_device_sync_preference(vault: &Vault) -> Result<Option<DeviceSyncPreference>> {
    vault
        .sync_state_get(PREFERENCE_KEY)?
        .map(|bytes| DeviceSyncPreference::decode(&bytes))
        .transpose()
}

/// Record the owner's choice for this machine. The live connection applies
/// it by reconnecting; see `SyncConnection::set_residence_mode`.
pub fn set_device_sync_preference(
    vault: &Vault,
    mode: SyncResidenceMode,
) -> Result<DeviceSyncPreference> {
    let preference = DeviceSyncPreference {
        mode,
        chosen_at: vault.store.clock.wall_now(),
    };
    vault.with_write_txn_grouped(|txn| {
        vault
            .store
            .sync_state
            .put(txn, PREFERENCE_KEY, &preference.encode())?;
        Ok(())
    })?;
    Ok(preference)
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
