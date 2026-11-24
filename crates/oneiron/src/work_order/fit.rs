//! `fit` (pass 34, 1.3 and 4.2): whether an order can run on a machine now, from the facts the
//! machine reported, or every reason it cannot. The issuer computes it to place and to explain;
//! the node computes it again from its own state at reserve and inside the launch commit, and
//! the node's answer is the one that counts (pass 33, 7.3, 7.5). A stale fact can cost a wasted
//! attempt of zero seconds, never a wrong start.
//!
//! A fact a machine does not report yet is absent here and limits nothing: the room, device and
//! role facts arrive with R1's `Node` and `Availability` facts (Q1's read half) and rows P0 and
//! P2. The order's own request (row G1's [`ResourceRequest`]) is read through [`Needs::of`]
//! alone.
use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::job_workload::{DeviceKind, ResourceRequest, Sharing};

use super::blocker::Blocker;
use super::record::WorkOrder;

/// What a machine reported, as the issuer last read it. Every room fact is optional: absent
/// means not reported, and an absent fact blocks nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MachineFacts {
    pub machine: EntityId,
    pub reach: MachineReach,
    /// Whether the machine runs jobs at all.
    pub enabled: bool,
    /// The node's own refusal of this issuer's requests (its peer, grant or issuer check), by
    /// the node's code.
    #[serde(default)]
    pub refusal: Option<Blocker>,
    #[serde(default)]
    pub paused: Option<String>,
    #[serde(default)]
    pub drained: Option<String>,
    #[serde(default)]
    pub templates: Vec<TemplateFact>,
    #[serde(default)]
    pub room: Room,
    /// The devices the machine offers jobs, when it reports them.
    #[serde(default)]
    pub devices: Option<Vec<DeviceFact>>,
    /// The owner's window for new work on this machine, when one is set.
    #[serde(default)]
    pub window: Option<WindowFact>,
    /// The share of the tighter of threads and memory the owner keeps free on this machine,
    /// in percent, when he set one.
    #[serde(default)]
    pub keep_headroom_pct: Option<u8>,
    /// The machine's work roles; none means every role matches.
    #[serde(default)]
    pub roles: Vec<String>,
    /// The warm keys present on the machine.
    #[serde(default)]
    pub warm: Vec<String>,
}

/// Whether the issuer reached the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MachineReach {
    Answered { at_ms: u64 },
    Unreachable { since_ms: Option<u64> },
}

/// One template a machine holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TemplateFact {
    pub name: String,
    pub digest: String,
}

/// A machine's room for jobs: totals and what is free, each when reported.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Room {
    #[serde(default)]
    pub threads_total: Option<u32>,
    #[serde(default)]
    pub threads_free: Option<u32>,
    #[serde(default)]
    pub memory_total_mib: Option<u64>,
    #[serde(default)]
    pub memory_free_mib: Option<u64>,
    #[serde(default)]
    pub disk_free_mib: Option<u64>,
    /// When the earliest running attempt's cutoff falls, when known: the latest time any held
    /// room frees.
    #[serde(default)]
    pub frees_at_ms: Option<u64>,
}

/// One device a machine offers jobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeviceFact {
    pub id: String,
    /// The device's kind, matched by name (`gpu`, `npu`, ...); no vendor is named.
    pub kind: String,
    pub memory_mib: u64,
    #[serde(default)]
    pub features: Vec<String>,
    /// When the attempt holding it reaches its cutoff; `None` while it is free.
    #[serde(default)]
    pub busy_until_ms: Option<u64>,
}

/// The owner's window for new work on one machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WindowFact {
    pub open: bool,
    /// When it next opens, while closed.
    #[serde(default)]
    pub opens_ms: Option<u64>,
}

/// What one attempt of an order needs of a machine, read from the order's request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Needs {
    /// 0 when the request takes its template's default, which the issuer does not know: it
    /// limits nothing here, and the node's own fit counts.
    pub threads: u32,
    pub memory_mib: u64,
    pub disk_mib: u64,
    pub devices: Vec<DeviceNeed>,
}

/// Devices of one kind an attempt claims: one of the request's device claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceNeed {
    /// The claim's kind by name, as [`DeviceFact::kind`] reports it.
    pub kind: String,
    pub count: u32,
    /// The least device memory; 0 takes any.
    pub memory_mib: u64,
    /// Each must be among the device's features.
    pub features: Vec<String>,
    /// The issuer's device facts carry no holders yet (R1's node facts bring them), so a
    /// shared claim waits for a free device here as an exclusive one does; the node, which
    /// knows its holders, admits it beside them (pass 34, 2.1).
    pub sharing: Sharing,
}

/// A device kind by the name a machine reports it under (`gpu`, `npu`, `fpga`, or the
/// probe's own name for another kind).
#[must_use]
pub fn device_kind_name(kind: &DeviceKind) -> &str {
    match kind {
        DeviceKind::Gpu => "gpu",
        DeviceKind::Npu => "npu",
        DeviceKind::Fpga => "fpga",
        DeviceKind::Other(name) => name,
    }
}

impl Needs {
    /// What `request` asks of one machine. The one reader of the request's shape. A claim of
    /// count 0 takes no device (R2's pin shape check refuses it before an order is made).
    #[must_use]
    pub fn of(request: &ResourceRequest) -> Self {
        let devices = request
            .devices
            .iter()
            .filter(|claim| claim.count > 0)
            .map(|claim| DeviceNeed {
                kind: device_kind_name(&claim.kind).to_owned(),
                count: claim.count,
                memory_mib: claim.memory_mib,
                features: claim.features.clone(),
                sharing: claim.sharing,
            })
            .collect();
        Self {
            threads: request.cpu_threads,
            memory_mib: request.memory_mib,
            disk_mib: request.disk_mib,
            devices,
        }
    }

    /// Whether the attempt claims any device.
    #[must_use]
    pub fn claims_devices(&self) -> bool {
        !self.devices.is_empty()
    }
}

impl MachineFacts {
    /// The devices that could serve `need` and `allowed` ids (empty: any), whether free or not.
    fn matching_devices<'a>(
        &'a self,
        need: &'a DeviceNeed,
        allowed: &'a [String],
    ) -> impl Iterator<Item = &'a DeviceFact> + 'a {
        self.devices
            .iter()
            .flatten()
            .filter(move |device| {
                device.kind == need.kind
                    && device.memory_mib >= need.memory_mib
                    && need
                        .features
                        .iter()
                        .all(|feature| device.features.contains(feature))
                    && (allowed.is_empty() || allowed.contains(&device.id))
            })
    }

    /// The free devices this machine would give `needs`, smallest memory first, so the least
    /// device memory goes unclaimed. `None` while devices are not reported.
    #[must_use]
    pub fn devices_for(&self, needs: &Needs, allowed: &[String]) -> Option<Vec<String>> {
        self.devices.as_ref()?;
        let mut picked = Vec::new();
        for need in &needs.devices {
            let mut free: Vec<&DeviceFact> = self
                .matching_devices(need, allowed)
                .filter(|device| device.busy_until_ms.is_none() && !picked.contains(&device.id))
                .collect();
            free.sort_by(|a, b| a.memory_mib.cmp(&b.memory_mib).then(a.id.cmp(&b.id)));
            let count = usize::try_from(need.count).unwrap_or(usize::MAX);
            if free.len() < count {
                return Some(Vec::new());
            }
            picked.extend(free.into_iter().take(count).map(|device| device.id.clone()));
        }
        Some(picked)
    }

    /// Takes `needs` out of this machine's free room, as an attempt made on it in this pass
    /// holds it, so the next order of the pass is fitted against what is left.
    pub fn hold(&mut self, needs: &Needs, devices: &[String], until_ms: u64) {
        let room = &mut self.room;
        room.threads_free = room.threads_free.map(|free| free.saturating_sub(needs.threads));
        room.memory_free_mib = room
            .memory_free_mib
            .map(|free| free.saturating_sub(needs.memory_mib));
        room.disk_free_mib = room.disk_free_mib.map(|free| free.saturating_sub(needs.disk_mib));
        for device in self.devices.iter_mut().flatten() {
            if devices.contains(&device.id) {
                device.busy_until_ms = Some(until_ms);
            }
        }
    }

    /// The headroom left after `needs` is placed here, in whole tens of percent of the tighter
    /// of threads and memory; `None` when neither total is reported.
    #[must_use]
    pub fn headroom_after_tenths(&self, needs: &Needs) -> Option<u64> {
        let share = |total: Option<u64>, free: Option<u64>, need: u64| -> Option<u64> {
            let total = total.filter(|total| *total > 0)?;
            let left = free?.saturating_sub(need);
            Some(left.saturating_mul(10) / total)
        };
        let threads = share(
            self.room.threads_total.map(u64::from),
            self.room.threads_free.map(u64::from),
            u64::from(needs.threads),
        );
        let memory = share(
            self.room.memory_total_mib,
            self.room.memory_free_mib,
            needs.memory_mib,
        );
        match (threads, memory) {
            (Some(threads), Some(memory)) => Some(threads.min(memory)),
            (one, None) | (None, one) => one,
        }
    }
}

/// Every reason `order` cannot run on `machine` now; empty when it fits. `template` is the
/// pin's template name and digest. The order-level reasons (its authority, its approval, a
/// retry's time, an unconfirmed attempt) are the loop's, not this function's.
#[must_use]
pub fn fit(order: &WorkOrder, template: (&str, &str), machine: &MachineFacts) -> Vec<Blocker> {
    let mut blocked = Vec::new();
    if let MachineReach::Unreachable { since_ms } = machine.reach {
        blocked.push(Blocker::MachineUnreachable { since_ms });
        return blocked;
    }
    if let Some(refusal) = &machine.refusal {
        blocked.push(refusal.clone());
    }
    if !machine.enabled && machine.refusal != Some(Blocker::NotEnabled) {
        blocked.push(Blocker::NotEnabled);
    }
    if let Some(why) = &machine.paused {
        blocked.push(Blocker::Paused { why: why.clone() });
    }
    if let Some(why) = &machine.drained {
        blocked.push(Blocker::Drained { why: why.clone() });
    }
    if let Some(window) = machine.window
        && !window.open
    {
        blocked.push(Blocker::OutsideWindow {
            opens_ms: window.opens_ms,
        });
    }
    let (name, digest) = template;
    match machine.templates.iter().find(|held| held.name == name) {
        None => blocked.push(Blocker::TemplateNotOffered),
        Some(held) if held.digest != digest => blocked.push(Blocker::TemplateChanged),
        Some(_) => {}
    }
    let needs = Needs::of(&order.request);
    fit_devices(order, machine, &needs, &mut blocked);
    fit_room(machine, &needs, &mut blocked);
    blocked
}

fn fit_devices(order: &WorkOrder, machine: &MachineFacts, needs: &Needs, blocked: &mut Vec<Blocker>) {
    if machine.devices.is_none() {
        return;
    }
    let allowed = &order.limits.device_ids;
    for need in &needs.devices {
        let count = usize::try_from(need.count).unwrap_or(usize::MAX);
        let matching: Vec<&DeviceFact> = machine.matching_devices(need, allowed).collect();
        if matching.len() < count {
            blocked.push(Blocker::NoDevice {
                kind: need.kind.clone(),
                features: need.features.clone(),
            });
            continue;
        }
        let free = matching
            .iter()
            .filter(|device| device.busy_until_ms.is_none())
            .count();
        if free < count {
            let soonest = matching
                .iter()
                .filter_map(|device| device.busy_until_ms.map(|until| (until, &device.id)))
                .min();
            if let Some((until, device)) = soonest {
                blocked.push(Blocker::DeviceBusy {
                    device: device.clone(),
                    free_at_ms: Some(until),
                });
            }
        }
    }
}

fn fit_room(machine: &MachineFacts, needs: &Needs, blocked: &mut Vec<Blocker>) {
    let room = &machine.room;
    if room.threads_total.is_some_and(|total| total < needs.threads) {
        blocked.push(Blocker::AboveCeiling {
            resource: "threads".to_owned(),
        });
    } else if room.threads_free.is_some_and(|free| free < needs.threads) {
        blocked.push(Blocker::ThreadsBusy {
            free_at_ms: room.frees_at_ms,
        });
    }
    if room.memory_total_mib.is_some_and(|total| total < needs.memory_mib) {
        blocked.push(Blocker::AboveCeiling {
            resource: "memory".to_owned(),
        });
    } else if room.memory_free_mib.is_some_and(|free| free < needs.memory_mib) {
        blocked.push(Blocker::MemoryBusy {
            free_at_ms: room.frees_at_ms,
        });
    }
    if let Some(free) = room.disk_free_mib
        && free < needs.disk_mib
    {
        blocked.push(Blocker::DiskShort {
            short_mib: needs.disk_mib - free,
        });
    }
    if let Some(keep) = machine.keep_headroom_pct
        && blocked.is_empty()
        && machine
            .headroom_after_tenths(needs)
            .is_some_and(|tenths| tenths.saturating_mul(10) < u64::from(keep))
    {
        blocked.push(Blocker::KeepHeadroom);
    }
}
