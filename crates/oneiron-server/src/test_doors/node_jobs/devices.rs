//! The scripted GPU slot table: its devices, their leases, quarantines and
//! drains, and a device probe a test can fail.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use oneiron::machine_capacity::GpuDevice;
use oneiron_organ_host::GpuSlotGrant;

use super::locked;
use crate::gpu_execution_node::jobs::NodeDevices;
use crate::gpu_execution_node::jobs::node_parts::{
    GpuDeviceLease, GpuDeviceProcesses, GpuLeaseEnd, GpuSlotRefusal, GpuSlotRequest,
};

#[derive(Debug, Clone)]
struct ScriptedDevice {
    device: GpuDevice,
    offered: bool,
    /// Compute processes of another account on the device.
    foreign_pids: Vec<u32>,
    taken_by: Option<String>,
}

#[derive(Debug, Default)]
struct DevicesState {
    devices: Vec<ScriptedDevice>,
    /// Quarantined devices, by id, with why: the slot table's in-memory
    /// set.
    quarantined: BTreeMap<String, String>,
    leases: u32,
    probe_fails: bool,
    finished: Vec<(String, GpuLeaseEnd)>,
    drains: Vec<String>,
}

/// The machine's GPUs, scripted: each taken by at most one key.
#[derive(Debug, Clone, Default)]
pub struct ScriptedDevices {
    state: Arc<Mutex<DevicesState>>,
}

impl ScriptedDevices {
    /// One offered device of `memory_total_mib`, free.
    #[must_use]
    pub fn one(device_id: &str, memory_total_mib: u64) -> Arc<Self> {
        let devices = Self::default();
        locked(&devices.state).devices.push(ScriptedDevice {
            device: GpuDevice {
                device_id: device_id.to_owned(),
                model: "scripted".to_owned(),
                memory_total_mib,
            },
            offered: true,
            foreign_pids: Vec::new(),
            taken_by: None,
        });
        Arc::new(devices)
    }

    /// Puts compute processes of another account on the device.
    pub fn set_foreign_pids(&self, device_id: &str, pids: Vec<u32>) {
        let mut state = locked(&self.state);
        if let Some(device) = state
            .devices
            .iter_mut()
            .find(|device| device.device.device_id == device_id)
        {
            device.foreign_pids = pids;
        }
    }

    /// Offers or withholds the device.
    pub fn set_offered(&self, device_id: &str, offered: bool) {
        let mut state = locked(&self.state);
        if let Some(device) = state
            .devices
            .iter_mut()
            .find(|device| device.device.device_id == device_id)
        {
            device.offered = offered;
        }
    }

    /// Whether the device probe fails.
    pub fn set_probe_fails(&self, fails: bool) {
        locked(&self.state).probe_fails = fails;
    }

    /// The key the device is taken by.
    #[must_use]
    pub fn taken_by(&self, device_id: &str) -> Option<String> {
        locked(&self.state)
            .devices
            .iter()
            .find(|device| device.device.device_id == device_id)
            .and_then(|device| device.taken_by.clone())
    }

    /// Empties the scripted slot table's quarantines, as a slot table that
    /// restarted with the engine holds none.
    pub fn forget_quarantines(&self) {
        locked(&self.state).quarantined.clear();
    }

    /// Why the device is quarantined in the scripted slot table, if it is.
    #[must_use]
    pub fn quarantined(&self, device_id: &str) -> Option<String> {
        locked(&self.state).quarantined.get(device_id).cloned()
    }

    /// How many leases were given in all.
    #[must_use]
    pub fn leases_given(&self) -> u32 {
        locked(&self.state).leases
    }

    /// Every drain the job service asked the slot table for.
    #[must_use]
    pub fn drains(&self) -> Vec<String> {
        locked(&self.state).drains.clone()
    }

    /// The drain that stands, as the slot table answers it.
    #[must_use]
    pub fn drained(&self) -> Option<String> {
        locked(&self.state).drains.last().cloned()
    }

    /// Every finish the job service recorded, by key.
    #[must_use]
    pub fn finished(&self) -> Vec<(String, GpuLeaseEnd)> {
        locked(&self.state).finished.clone()
    }

    fn free(&self, key: &str) {
        for device in &mut locked(&self.state).devices {
            if device.taken_by.as_deref() == Some(key) {
                device.taken_by = None;
            }
        }
    }
}

struct ScriptedLease {
    devices: ScriptedDevices,
    grant: GpuSlotGrant,
    open: bool,
}

impl GpuDeviceLease for ScriptedLease {
    fn grant(&self) -> &GpuSlotGrant {
        &self.grant
    }

    fn confirm_launch(&mut self) -> Result<(), GpuSlotRefusal> {
        Ok(())
    }

    fn end_check(&self) -> Result<GpuDeviceProcesses, GpuSlotRefusal> {
        self.devices.end_check(&self.grant.key)
    }

    fn finish(mut self: Box<Self>, end: GpuLeaseEnd) {
        self.open = false;
        NodeDevices::finish(&self.devices, &self.grant.key, &end);
    }

    fn keep(mut self: Box<Self>) -> GpuSlotGrant {
        self.open = false;
        self.grant.clone()
    }
}

impl Drop for ScriptedLease {
    fn drop(&mut self) {
        if self.open {
            self.devices.free(&self.grant.key);
        }
    }
}

impl NodeDevices for ScriptedDevices {
    fn could_take(&self, request: &GpuSlotRequest) -> Result<(), String> {
        let state = locked(&self.state);
        state
            .devices
            .iter()
            .any(|device| {
                device.offered
                    && !state.quarantined.contains_key(&device.device.device_id)
                    && request.admits(&device.device)
            })
            .then_some(())
            .ok_or_else(|| "no_device".to_owned())
    }

    fn lease_for_launch(
        &self,
        request: &GpuSlotRequest,
    ) -> Result<Box<dyn GpuDeviceLease>, GpuSlotRefusal> {
        let mut guard = locked(&self.state);
        let state = &mut *guard;
        let Some(device) = state
            .devices
            .iter_mut()
            .find(|device| request.admits(&device.device))
        else {
            return Err(GpuSlotRefusal::NoMatch);
        };
        let device_id = device.device.device_id.clone();
        if !device.offered {
            return Err(GpuSlotRefusal::Withheld { device_id });
        }
        if let Some(why) = state.quarantined.get(&device_id) {
            return Err(GpuSlotRefusal::Quarantined {
                device_id,
                why: why.clone(),
            });
        }
        if device.taken_by.is_some() {
            return Err(GpuSlotRefusal::Taken { device_id });
        }
        if !device.foreign_pids.is_empty() {
            return Err(GpuSlotRefusal::Busy {
                device_id,
                pids: device.foreign_pids.clone(),
            });
        }
        device.taken_by = Some(request.key.clone());
        let grant = GpuSlotGrant {
            key: request.key.clone(),
            device: device.device.clone(),
            granted_at_ms: 0,
        };
        state.leases += 1;
        Ok(Box::new(ScriptedLease {
            devices: self.clone(),
            grant,
            open: true,
        }))
    }

    fn reattach(&self, key: &str, device_id: &str) -> Result<(), GpuSlotRefusal> {
        let mut state = locked(&self.state);
        let Some(device) = state
            .devices
            .iter_mut()
            .find(|device| device.device.device_id == device_id)
        else {
            return Err(GpuSlotRefusal::UnknownDevice {
                device_id: device_id.to_owned(),
            });
        };
        match &device.taken_by {
            Some(other) if other != key => Err(GpuSlotRefusal::Taken {
                device_id: device_id.to_owned(),
            }),
            _ => {
                device.taken_by = Some(key.to_owned());
                Ok(())
            }
        }
    }

    fn end_check(&self, key: &str) -> Result<GpuDeviceProcesses, GpuSlotRefusal> {
        let state = locked(&self.state);
        if state.probe_fails {
            return Err(GpuSlotRefusal::Unmeasured {
                reason: "scripted probe failure".to_owned(),
            });
        }
        state
            .devices
            .iter()
            .find(|device| device.taken_by.as_deref() == Some(key))
            .map(|device| GpuDeviceProcesses {
                pids: device.foreign_pids.clone(),
                hidden: 0,
            })
            .ok_or(GpuSlotRefusal::NotHeld)
    }

    fn finish(&self, key: &str, end: &GpuLeaseEnd) {
        self.free(key);
        locked(&self.state)
            .finished
            .push((key.to_owned(), end.clone()));
    }

    fn drain(&self, why: &str) {
        locked(&self.state).drains.push(why.to_owned());
    }

    fn quarantine(&self, device_id: &str, why: &str) {
        locked(&self.state)
            .quarantined
            .insert(device_id.to_owned(), why.to_owned());
    }

    fn clear_quarantine(&self, device_id: &str) {
        locked(&self.state).quarantined.remove(device_id);
    }
}
