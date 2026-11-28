//! The two layers of a node's controls (pass 34, `34-compute-general/DESIGN.md` section 2.4;
//! EM-17 = A, row P0): the box's `[execution_node]` file, the most this box will ever do, and the
//! owner's machine policy rows, the switches of his panel. The node applies the stricter of the
//! two for every value.
//!
//! The owner's rows are read from this node's own vault, as the setting projection writes them
//! from the signed acts this node's fold counts ([`oneiron::machine_policy`]). A row another
//! machine's engine, agent or person wrote stays on that machine (RULING SETTING-7A-2-DECIDERS =
//! A), and an act carried without the owner's proof changes nothing, so the issuer cannot write
//! the policy a node obeys. A box whose file sets `owner_policy = false` obeys its file only, as
//! every node did before this row.
//!
//! Where a box figure and an owner figure bound one thing, the smaller room wins: the memory work
//! may hold is the lesser of the box's `job_memory_gib` and the machine's total less
//! `keep_headroom.memory_mib`, the same for threads, and the disk kept free is the larger of the
//! box's `disk_reserve_gib` and `keep_headroom.disk_gib`. With neither figure set the memory and
//! the threads have no room of their own here, as before this row: the memory floor's lease still
//! bounds the memory, and each template's `cpu_threads` the threads.
//!
//! The readiness check (row Q4) runs at the shorter of the box's `readiness_every_secs` and the
//! owner's `jobs.readiness.every_secs`, and a passed check clears the node's drain only when the
//! box's `drain_clear_by` and the owner's `machines.drain.clear_by` both leave it to the check.

use std::path::Path;

use oneiron::EntityId;
use oneiron::Vault;
use oneiron::job_workload::{DevicePlacement, NetworkMode};
use oneiron::machine_policy::{ExecutionState, MachineAccepts, MachinePolicy};

use super::availability::GpuDeviceAvailability;
use super::node_settings::{DrainClearBy, ExecutionNodeSettings};
use super::wire::{TemplateOffer, WorkloadPin};

/// Where Linux lists the machine's power supplies.
const POWER_SUPPLY_DIR: &str = "/sys/class/power_supply";

/// The owner's policy for this node now: `Ok(None)` when the box does not accept it
/// (`owner_policy = false`) or the machine has no MACHINE id yet, so its file alone rules.
/// `devices` are the ids of the devices the box offers, and every template the file holds is
/// read.
///
/// # Errors
///
/// Why the rows could not be read; the node then takes no new work.
pub fn owner_policy(
    vault: &Vault,
    machine: Option<EntityId>,
    settings: &ExecutionNodeSettings,
    devices: &[String],
) -> Result<Option<MachinePolicy>, String> {
    let Some(machine) = machine.filter(|_| settings.owner_policy) else {
        return Ok(None);
    };
    let devices: Vec<&str> = devices.iter().map(String::as_str).collect();
    let templates: Vec<&str> = settings.templates.keys().map(String::as_str).collect();
    vault
        .machine_policy(machine, &devices, &templates)
        .map(Some)
        .map_err(|error| error.to_string())
}

/// Why the owner's policy takes no new work on this machine at `now_ms`, or `None`: the machine
/// is paused or draining, outside its hours, or on battery where only mains power is allowed
/// (`on_mains`: `None` when the machine cannot tell, which an owner's `mains_only` reads as not
/// on mains).
#[must_use]
pub fn work_refusal(policy: &MachinePolicy, now_ms: u64, on_mains: Option<bool>) -> Option<String> {
    match policy.execution.state {
        ExecutionState::On => {}
        ExecutionState::Paused => return Some("owner: paused".to_owned()),
        ExecutionState::Draining => return Some("owner: draining".to_owned()),
    }
    if !policy.windows.covers(now_ms) {
        return Some("owner: outside the machine's hours".to_owned());
    }
    if policy.windows.mains_only && on_mains != Some(true) {
        return Some("owner: not on mains power".to_owned());
    }
    None
}

/// The owner's part of reserve step 5 for `pin`: the machine accepts the work, and the network
/// mode it asks for is one the owner opened to its template. The box's part passed first.
///
/// # Errors
///
/// The refusal reason, for the key's end.
pub fn admit_pin(policy: &MachinePolicy, pin: &WorkloadPin) -> Result<(), String> {
    if policy.accepts == MachineAccepts::ResumableOnly {
        // No pin can say it is resumable before row P3 gives a template `resumable`.
        return Err("not_resumable: the owner accepts resumable work only".to_owned());
    }
    admit_network(policy, pin)
}

/// The network part of [`admit_pin`]: the mode `pin` asks for is one the
/// owner opened to its template. The launch commit asks it again, so a mode
/// the owner closed since the reserve does not start.
///
/// # Errors
///
/// `network_not_permitted`, for the key's end.
pub fn admit_network(policy: &MachinePolicy, pin: &WorkloadPin) -> Result<(), String> {
    let opened = policy
        .template_network
        .get(&pin.template)
        .is_some_and(|opened| opened.0.contains(&pin.network));
    if !opened {
        return Err("network_not_permitted: not opened by the owner".to_owned());
    }
    Ok(())
}

/// The template's network modes as the node offers them: the box's list less every mode the
/// owner has not opened. With no owner policy, the box's list.
#[must_use]
pub fn offered_network(
    policy: Option<&MachinePolicy>,
    template: &str,
    box_modes: &[NetworkMode],
) -> Vec<NetworkMode> {
    let Some(policy) = policy else {
        return box_modes.to_vec();
    };
    let opened = policy.template_network.get(template);
    box_modes
        .iter()
        .copied()
        .filter(|mode| opened.is_some_and(|opened| opened.0.contains(mode)))
        .collect()
}

/// The file's templates as the node offers them: each with the network modes the owner opened
/// among the box's.
#[must_use]
pub fn offered_templates(
    policy: Option<&MachinePolicy>,
    settings: &ExecutionNodeSettings,
) -> Vec<TemplateOffer> {
    let offers = settings.template_offers().unwrap_or_else(|why| {
        tracing::warn!(%why, "a template of the execution node does not encode");
        Vec::new()
    });
    offers
        .into_iter()
        .map(|mut offer| {
            offer.network = offered_network(policy, &offer.name, &offer.network);
            offer
        })
        .collect()
}

/// `devices` less every device the owner withholds: an `Availability` sample offers no withheld
/// device, so the issuer's start gate places nothing on it.
pub fn retain_offered(policy: Option<&MachinePolicy>, devices: &mut Vec<GpuDeviceAvailability>) {
    devices.retain(|device| device_offered(policy, &device.device.device_id));
}

/// Whether the owner offers the device `device_id` to work. A device the policy was not read for
/// is offered: the box's own list decides it.
#[must_use]
pub fn device_offered(policy: Option<&MachinePolicy>, device_id: &str) -> bool {
    policy
        .and_then(|policy| policy.devices.get(device_id))
        .is_none_or(|offer| offer.offered)
}

/// The memory work may hold on this machine, in MiB: the lesser of the box's `job_memory_gib`
/// (the machine's total `total_mib` when the file names none) and the total less the owner's
/// `keep_headroom.memory_mib`. `None` when neither is set.
#[must_use]
pub fn work_memory_mib(
    settings: &ExecutionNodeSettings,
    policy: Option<&MachinePolicy>,
    total_mib: u64,
) -> Option<u64> {
    let kept = policy.map_or(0, |policy| policy.keep_headroom.memory_mib);
    if settings.job_memory_gib.is_none() && kept == 0 {
        return None;
    }
    let boxed = settings
        .job_memory_gib
        .map_or(total_mib, |gib| gib.saturating_mul(1024));
    Some(boxed.min(total_mib.saturating_sub(kept)))
}

/// The threads one run may use on this machine: the lesser of the box's `job_threads` (the
/// machine's `cores` when the file names none) and the cores less the owner's
/// `keep_headroom.threads`. `None` when neither is set.
#[must_use]
pub fn work_threads(
    settings: &ExecutionNodeSettings,
    policy: Option<&MachinePolicy>,
    cores: u32,
) -> Option<u32> {
    let kept = policy.map_or(0, |policy| policy.keep_headroom.threads);
    if settings.job_threads.is_none() && kept == 0 {
        return None;
    }
    let boxed = settings.job_threads.unwrap_or(cores);
    Some(boxed.min(cores.saturating_sub(kept)))
}

/// The disk every booking leaves free, in bytes: the larger of the box's `disk_reserve_gib` and
/// the owner's `keep_headroom.disk_gib`.
#[must_use]
pub fn disk_reserve_bytes(settings: &ExecutionNodeSettings, policy: Option<&MachinePolicy>) -> u64 {
    let kept = policy.map_or(0, |policy| policy.keep_headroom.disk_gib);
    settings.disk_reserve_gib.max(kept).saturating_mul(1 << 30)
}

/// How often the node checks itself while no attempt runs, in seconds: the shorter of the box's
/// `readiness_every_secs` and the owner's `jobs.readiness.every_secs`.
#[must_use]
pub fn readiness_every_secs(
    settings: &ExecutionNodeSettings,
    policy: Option<&MachinePolicy>,
) -> u64 {
    policy.map_or(settings.readiness_every_secs, |policy| {
        settings
            .readiness_every_secs
            .min(policy.readiness_every_secs)
    })
}

/// Who clears the node's drain: the box's `drain_clear_by`, unless the owner's
/// `machines.drain.clear_by` is stricter. A passed readiness check clears the drain only when both
/// leave it to the check. An owner row of `owner`, `grants` or `person_at_box` keeps the drain for
/// the person at the box, because no act of the owner's or of a Grant reaches the node's own drain
/// yet (the issuer's `vault.machines.execution.clear_drain` clears the issuer's guard only).
#[must_use]
pub fn drain_clear_by(
    settings: &ExecutionNodeSettings,
    policy: Option<&MachinePolicy>,
) -> DrainClearBy {
    let owner_leaves_it_to_the_check = policy.is_none_or(|policy| {
        matches!(
            policy.drain_clear_by,
            oneiron::machine_policy::DrainClearBy::AfterReadinessCheck
        )
    });
    if owner_leaves_it_to_the_check {
        settings.drain_clear_by
    } else {
        DrainClearBy::PersonAtBox
    }
}

/// The launch commit's check of a placement against both layers: every placed device is one the
/// owner offers; the host memory the placement leases, with `held_mib` that the node's launched
/// keys hold, fits the memory work may hold; and the threads the run asks fit the threads one run
/// may use. `total_mib` and `cores` are the machine's own.
///
/// # Errors
///
/// The refusal reason, for the key's end.
pub fn admit_placement(
    settings: &ExecutionNodeSettings,
    policy: Option<&MachinePolicy>,
    pin: &WorkloadPin,
    placement: &DevicePlacement,
    held_mib: u64,
    (total_mib, cores): (u64, u32),
) -> Result<(), String> {
    if let Some(device) = placement
        .devices
        .iter()
        .find(|device| !device_offered(policy, &device.device_id))
    {
        return Err(format!("device_withheld: {}", device.device_id));
    }
    if let Some(room) = work_memory_mib(settings, policy, total_mib)
        && held_mib.saturating_add(placement.host_memory_mib) > room
    {
        return Err("memory_room: the machine's work memory is held".to_owned());
    }
    let threads = settings.templates.get(&pin.template).map_or(0, |template| {
        if pin.request.cpu_threads == 0 {
            template.cpu_threads
        } else {
            pin.request.cpu_threads
        }
    });
    if let Some(room) = work_threads(settings, policy, cores)
        && threads > room
    {
        return Err("thread_room: the run asks more threads than work may use here".to_owned());
    }
    Ok(())
}

/// Whether this machine runs on mains power now: `Some(true)` on mains or with no battery (a
/// desktop or a server), `Some(false)` on battery, `None` where it cannot tell.
#[must_use]
pub fn on_mains_power() -> Option<bool> {
    if cfg!(target_os = "linux") {
        on_mains_power_in(Path::new(POWER_SUPPLY_DIR))
    } else {
        None
    }
}

/// [`on_mains_power`] over the power supplies listed in `dir`, each a directory with `type` and
/// `online` files: on mains when a `Mains` supply is online or no `Battery` supply is listed.
#[must_use]
pub fn on_mains_power_in(dir: &Path) -> Option<bool> {
    let read = |path: &Path| std::fs::read_to_string(path).ok();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Some(true),
        Err(_) => return None,
    };
    let (mut battery, mut mains_online) = (false, false);
    for entry in entries {
        let supply = entry.ok()?.path();
        match read(&supply.join("type")).as_deref().map(str::trim) {
            Some("Battery") => battery = true,
            Some("Mains") => {
                mains_online |= read(&supply.join("online")).as_deref().map(str::trim) == Some("1");
            }
            _ => {}
        }
    }
    Some(mains_online || !battery)
}
