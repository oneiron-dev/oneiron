//! Devices in a resource request (pass 34, `34-compute-general/DESIGN.md`
//! section 2.1): what a run claims ([`DeviceClaim`]), what a machine reports
//! about each device it has ([`DeviceFacts`]), and the one placement rule both
//! the issuer and the node apply ([`ResourceRequest::place_devices`]).
//!
//! A device is matched by its kind, its features and its memory, never by a
//! vendor or a model name. A run with no device claim takes no device lease:
//! the same attempt, on threads and memory alone.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::pin::ResourceRequest;

/// The most device claims one resource request makes.
pub const REQUEST_DEVICE_CLAIMS_MAX: usize = 8;

/// What kind of device a claim asks for and a machine reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DeviceKind {
    Gpu,
    Npu,
    Fpga,
    /// Another kind, by the name its probe gives it.
    Other(String),
}

/// Whether a claim takes a device alone or beside other claims.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Sharing {
    /// The device holds this claim and no other.
    #[default]
    Exclusive,
    /// Admitted beside other shared claims, up to the device's
    /// [`DeviceFacts::max_claimants`]. Time slicing gives no memory or
    /// fault isolation, and the receipt says so.
    Shared,
}

/// One kind of device a run needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceClaim {
    pub kind: DeviceKind,
    /// Whole devices of this kind. A count of 0 takes no lease; R2's pin
    /// shape check refuses it before placement.
    pub count: u32,
    /// The least device memory, in MiB; 0 takes any. On a device that
    /// shares the machine's memory it is leased from that pool with the
    /// request's own `memory_mib` ([`DevicePlacement::host_memory_mib`]).
    pub memory_mib: u64,
    /// Each must be among the device's features, e.g. `cuda`, `metal`,
    /// `rocm`, `oneapi`, `vulkan`, `directml`.
    pub features: Vec<String>,
    pub sharing: Sharing,
}

/// How a device's memory is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceMemory {
    /// The device's own memory.
    Dedicated { mib: u64 },
    /// The machine's own memory, which the device shares with the host (as
    /// on Apple silicon): one pool.
    Unified { mib: u64 },
}

impl DeviceMemory {
    /// The memory the device can use, in MiB.
    #[must_use]
    pub fn mib(self) -> u64 {
        match self {
            Self::Dedicated { mib } | Self::Unified { mib } => mib,
        }
    }

    /// Whether the device draws on the host's memory.
    #[must_use]
    pub fn is_unified(self) -> bool {
        matches!(self, Self::Unified { .. })
    }
}

/// Where a device's id comes from: an id that survives a reboot and a
/// reorder. A device with none is not offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceIdSource {
    /// The vendor's UUID.
    VendorUuid,
    /// The device's serial number.
    Serial,
    /// The platform's fixed registry id, for a built-in device.
    PlatformRegistry,
}

/// What the scope can promise about who else uses a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceClosure {
    /// The scope opens this device and no other, and other accounts cannot
    /// open it.
    Closed,
    /// The node counts the claimants it let in and cannot stop another
    /// local process from using the device.
    Admitted,
}

/// What a device is doing now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceState {
    /// Free for a claim.
    Offered,
    /// Kept out of jobs by the machine's owner or another booker.
    Withheld,
    /// Out until a clean probe, with why.
    Quarantined { why: String },
    /// Held by these keys.
    Leased { keys: Vec<String> },
}

/// What a machine reports about one device: one row per device. A report
/// that repeats an id offers no row of that id
/// ([`ResourceRequest::place_devices`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceFacts {
    pub id: String,
    pub id_source: DeviceIdSource,
    pub kind: DeviceKind,
    /// Shown to people; never matched.
    pub vendor: String,
    /// Shown to people; never matched.
    pub model: String,
    pub memory: DeviceMemory,
    pub features: Vec<String>,
    pub closure: DeviceClosure,
    pub state: DeviceState,
    /// How many claims may hold the device at once: 1 unless its owner lets
    /// it share.
    pub max_claimants: u32,
}

impl DeviceClaim {
    /// Whether `device` can ever serve this claim: the same kind, every
    /// feature the claim names, and at least the claim's memory. Its vendor
    /// and model are not read.
    #[must_use]
    pub fn is_met_by(&self, device: &DeviceFacts) -> bool {
        device.kind == self.kind
            && self
                .features
                .iter()
                .all(|feature| device.features.contains(feature))
            && device.memory.mib() >= self.memory_mib
    }
}

/// A device as placement reads it: its facts and the sharing of every claim
/// that holds it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldDevice {
    pub facts: DeviceFacts,
    pub holders: Vec<Sharing>,
}

impl HeldDevice {
    /// Whether this device takes `claim` now, beside its holders. Every
    /// holder counts: an exclusive claim only on a device with no holder, a
    /// shared one only where no holder is exclusive and fewer than
    /// `max_claimants` hold it. A withheld or quarantined device takes none.
    #[must_use]
    pub fn admits(&self, claim: &DeviceClaim) -> bool {
        let available = matches!(
            self.facts.state,
            DeviceState::Offered | DeviceState::Leased { .. }
        );
        let beside_holders = match claim.sharing {
            Sharing::Exclusive => self.holders.is_empty(),
            Sharing::Shared => {
                !self.holders.contains(&Sharing::Exclusive)
                    && self.holders.len()
                        < usize::try_from(self.facts.max_claimants).unwrap_or(usize::MAX)
            }
        };
        available && beside_holders && claim.is_met_by(&self.facts)
    }
}

/// One device a run leases, for one claim of its request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceLease {
    /// The claim's place in the request's `devices`.
    pub claim: usize,
    pub device_id: String,
    pub sharing: Sharing,
}

/// The leases a request takes on one machine: all of them or none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePlacement {
    /// Empty for a request with no device claim.
    pub devices: Vec<DeviceLease>,
    /// The host memory the run leases from the machine's memory floor, in
    /// MiB, which is also the scope's memory limit: the request's own
    /// `memory_mib`, plus the claim's `memory_mib` for each leased device
    /// that shares the host's memory.
    pub host_memory_mib: u64,
}

/// Why a request's devices cannot be placed on one machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevicePlacementError {
    /// No set of this machine's devices meets the claim at this place in
    /// the request, whoever holds them: waiting never clears it.
    NoDevice {
        claim: usize,
        kind: DeviceKind,
        features: Vec<String>,
    },
    /// Devices meet every claim, but too few take this one now.
    DeviceBusy { claim: usize },
    /// The request's own memory plus the memory of its claims on devices
    /// that share the host's memory has no value in MiB, from the claim at
    /// this place on: no machine holds it, and waiting never clears it.
    HostMemoryOverflow { claim: usize },
}

impl ResourceRequest {
    /// Places this request's device claims on a machine whose devices are
    /// `devices`: `count` distinct devices for each claim, each device
    /// leased once. The placement is complete or it is an error; a request
    /// with no device claim is placed on any machine with no device lease.
    /// A device is its id: a row whose id another row of `devices` repeats
    /// is never placed.
    ///
    /// # Errors
    /// [`DevicePlacementError::NoDevice`] when the machine's devices cannot
    /// serve the claims even with nothing else holding them, else
    /// [`DevicePlacementError::DeviceBusy`] when the holders and states now
    /// leave too few. [`DevicePlacementError::HostMemoryOverflow`] when the
    /// host memory the placement leases has no value in MiB.
    pub fn place_devices(
        &self,
        devices: &[HeldDevice],
    ) -> Result<DevicePlacement, DevicePlacementError> {
        let no_device = |claim: usize| {
            let claim_at = &self.devices[claim];
            DevicePlacementError::NoDevice {
                claim,
                kind: claim_at.kind.clone(),
                features: claim_at.features.clone(),
            }
        };
        let devices = leasable(devices);
        // More devices asked than the machine has: counted before any
        // claim is expanded, so a large count allocates nothing.
        let mut needed = 0_u64;
        for (claim, claim_at) in self.devices.iter().enumerate() {
            needed = needed.saturating_add(u64::from(claim_at.count));
            if needed > u64::try_from(devices.len()).unwrap_or(u64::MAX) {
                return Err(no_device(claim));
            }
        }
        let units: Vec<(usize, &DeviceClaim)> = self
            .devices
            .iter()
            .enumerate()
            .flat_map(|(claim, claim_at)| {
                std::iter::repeat_n((claim, claim_at), claim_at.count as usize)
            })
            .collect();
        if let Err(claim) = match_units(&units, &devices, |claim_at, device| {
            claim_at.is_met_by(&device.facts)
        }) {
            return Err(no_device(claim));
        }
        let owners = match_units(&units, &devices, |claim_at, device| device.admits(claim_at))
            .map_err(|claim| DevicePlacementError::DeviceBusy { claim })?;
        let mut leases = Vec::with_capacity(units.len());
        let mut host_memory_mib = self.memory_mib;
        for (device, unit) in devices.iter().zip(&owners) {
            let Some(unit) = unit else { continue };
            let (claim, claim_at) = units[*unit];
            if device.facts.memory.is_unified() {
                host_memory_mib = host_memory_mib
                    .checked_add(claim_at.memory_mib)
                    .ok_or(DevicePlacementError::HostMemoryOverflow { claim })?;
            }
            leases.push(DeviceLease {
                claim,
                device_id: device.facts.id.clone(),
                sharing: claim_at.sharing,
            });
        }
        leases.sort_by_key(|lease| lease.claim);
        Ok(DevicePlacement {
            devices: leases,
            host_memory_mib,
        })
    }
}

/// The rows of `devices` that placement may lease: each row whose id no
/// other row repeats. A lease names its device by id, so an id on two rows
/// could be leased twice in one placement, or on a free row while a key
/// holds it on the other. Which row is true is unknown: a repeated id offers
/// none of its rows, as a device with no id is not offered.
fn leasable(devices: &[HeldDevice]) -> Vec<&HeldDevice> {
    let mut rows_of: BTreeMap<&str, usize> = BTreeMap::new();
    for device in devices {
        *rows_of.entry(device.facts.id.as_str()).or_default() += 1;
    }
    devices
        .iter()
        .filter(|device| rows_of.get(device.facts.id.as_str()) == Some(&1))
        .collect()
}

/// Gives each device need (a claim's place and the claim, one entry per
/// device) its own device that `fits` it: a maximum bipartite matching, so a
/// claim that could take either of two devices leaves the one another claim
/// needs. Returns, per device, the need it serves; or the claim of the first
/// need left without a device. Iterative: no recursion over the machine's
/// reported devices.
fn match_units(
    units: &[(usize, &DeviceClaim)],
    devices: &[&HeldDevice],
    fits: impl Fn(&DeviceClaim, &HeldDevice) -> bool,
) -> Result<Vec<Option<usize>>, usize> {
    let mut owners: Vec<Option<usize>> = vec![None; devices.len()];
    for (root, (claim, _)) in units.iter().enumerate() {
        if !augment(root, units, devices, &fits, &mut owners) {
            return Err(*claim);
        }
    }
    Ok(owners)
}

/// Gives the need `root`, which holds no device yet, a device: a breadth
/// first search for a free device that `fits` it, through devices whose
/// holders can move to another, then the moves along that path.
fn augment(
    root: usize,
    units: &[(usize, &DeviceClaim)],
    devices: &[&HeldDevice],
    fits: &impl Fn(&DeviceClaim, &HeldDevice) -> bool,
    owners: &mut [Option<usize>],
) -> bool {
    let mut seen = vec![false; devices.len()];
    // The need that reached each device, which takes it if its holder moves.
    let mut wanted_by = vec![0_usize; devices.len()];
    // The device each need holds and gives up when it moves.
    let mut gives_up: Vec<Option<usize>> = vec![None; units.len()];
    let mut queue = std::collections::VecDeque::from([root]);
    while let Some(unit) = queue.pop_front() {
        for (device, held) in devices.iter().copied().enumerate() {
            if seen[device] || !fits(units[unit].1, held) {
                continue;
            }
            seen[device] = true;
            wanted_by[device] = unit;
            if let Some(holder) = owners[device] {
                gives_up[holder] = Some(device);
                queue.push_back(holder);
                continue;
            }
            let (mut free, mut taker) = (device, unit);
            loop {
                owners[free] = Some(taker);
                let Some(held) = gives_up[taker] else {
                    return true;
                };
                free = held;
                taker = wanted_by[held];
            }
        }
    }
    false
}
