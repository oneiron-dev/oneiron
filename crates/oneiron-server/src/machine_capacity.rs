//! The host's capacity probe (CROSS-ARCH-0024 #my-network 05): serving
//! measures this machine as it starts and then every hour, and records what
//! it found on this install's MACHINE entity
//! ([`oneiron::Vault::record_machine_capacity`]). A reading in which no
//! total, power source or agent count moved writes nothing.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use oneiron::Vault;
use oneiron::machine_capacity::{
    MachineCapacity, MachineCapacityWrite, MachineMeasurement, MachinePower,
};

use crate::server::SyncServer;

/// How often serving measures the machine again.
const PROBE_EVERY: Duration = Duration::from_secs(60 * 60);

/// Where this machine draws its power from now.
fn power_source() -> MachinePower {
    #[cfg(unix)]
    {
        if oneiron_vault_contract::host_adapters::on_mains_power() {
            MachinePower::Mains
        } else {
            MachinePower::Battery
        }
    }
    #[cfg(not(unix))]
    {
        MachinePower::Unknown
    }
}

/// Measures this machine now: its cores, memory, GPU memory, power, and the
/// disk holding `data_dir`. A figure the platform does not give reads 0
/// (no GPU known reads empty).
#[must_use]
pub fn measure_this_machine(data_dir: &Path, measured_at: u64) -> MachineCapacity {
    MachineCapacity::from_measurement(
        MachineMeasurement {
            cores: u64::try_from(crate::machine::cores()).unwrap_or(u64::MAX),
            memory_total_bytes: crate::machine::memory_bytes().unwrap_or(0),
            memory_available_bytes: oneiron_contracts::limit_ask::available_memory_bytes()
                .unwrap_or(0),
            gpu_memory_mib: crate::machine::gpu_memory_mib(),
            disk_total_bytes: crate::machine::disk_total_bytes(data_dir).unwrap_or(0),
            disk_free_bytes: crate::machine::free_disk_bytes(data_dir).unwrap_or(0),
            power: power_source(),
        },
        measured_at,
    )
}

/// Measures this machine and records it on this install's MACHINE entity:
/// one probe, as serving runs it. It blocks on the vault's writer and on the
/// GPU and power queries, so async callers run it on a blocking thread.
///
/// # Errors
///
/// What the vault's record write returns.
pub fn record_measured_capacity(vault: &Vault) -> oneiron::Result<MachineCapacityWrite> {
    let capacity = measure_this_machine(vault.path(), oneiron_base::unix_seconds_now());
    vault.record_machine_capacity(&capacity)
}

/// Serving's probe: once now, then every [`PROBE_EVERY`], each under the
/// host's housekeeping admission. A failed probe is logged and the next one
/// tries again; it ends when the server does.
pub(crate) fn spawn(
    server: &Arc<SyncServer>,
    admit: crate::server::HousekeepingAdmission,
) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(server);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(PROBE_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let Some(server) = weak.upgrade() else {
                break;
            };
            let Some(pass) = admit() else {
                continue;
            };
            let vault = Arc::clone(server.vault());
            drop(server);
            match tokio::task::spawn_blocking(move || {
                let _pass = pass;
                record_measured_capacity(&vault)
            })
            .await
            {
                Ok(Ok(MachineCapacityWrite::Recorded(claim))) => {
                    tracing::debug!(claim = %claim.to_hex(), "machine capacity recorded");
                }
                Ok(Ok(MachineCapacityWrite::Unchanged(_))) => {}
                Ok(Ok(MachineCapacityWrite::NoMachine)) => tracing::debug!(
                    "this install has no MACHINE row yet, so its capacity is not recorded; \
                     its first enrolled start records it"
                ),
                Ok(Err(error)) => tracing::warn!(
                    kind = ?error.kind(),
                    reason = %error,
                    "the machine capacity probe failed; it runs again next hour"
                ),
                Err(error) => tracing::warn!(%error, "the machine capacity probe stopped"),
            }
        }
    })
}
