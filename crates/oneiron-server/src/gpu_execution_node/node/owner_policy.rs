//! The node's reads of the owner's machine policy rows (row P0; pass 34 DESIGN 2.4), and the
//! admissions that apply the stricter of them and the box's file: every read of the owner's rows
//! goes through [`ExecutionNode::owner_policy`], which `snapshot`, the template check and the
//! launch commit's placement fit each take fresh.

use oneiron::job_workload::DevicePlacement;
use oneiron::machine_policy::MachinePolicy;

use super::super::machine_policy;
use super::super::node_settings::{DrainClearBy, ExecutionNodeSettings};
use super::super::wire::WorkloadPin;
use super::ExecutionNode;

impl ExecutionNode {
    /// The owner's machine policy for this node now, read from the node's own vault for the
    /// devices the box offers and every template the file holds: `None` when the file does not
    /// accept it or the machine has no MACHINE id yet.
    ///
    /// # Errors
    ///
    /// `owner_policy_unreadable` and why the rows do not read: the node then takes no new work.
    pub(super) fn owner_policy(
        &self,
        settings: &ExecutionNodeSettings,
    ) -> Result<Option<MachinePolicy>, String> {
        let devices: Vec<String> = self.shared.slots.offer().offered.iter().cloned().collect();
        machine_policy::owner_policy(&self.shared.vault, self.own_machine(), settings, &devices)
            .map_err(|why| format!("owner_policy_unreadable: {why}"))
    }

    /// The owner's policy beside the file `settings` as a snapshot reads it, and why it takes no
    /// new work now (paused, draining, outside the hours, not on mains power, or rows that do not
    /// read), which the node's pause shows.
    pub(super) fn owner_controls(
        &self,
        settings: &Result<Option<ExecutionNodeSettings>, String>,
    ) -> (Option<MachinePolicy>, Option<String>) {
        let Ok(Some(settings)) = settings else {
            return (None, None);
        };
        match self.owner_policy(settings) {
            Ok(policy) => {
                let why = policy.as_ref().and_then(|policy| {
                    machine_policy::work_refusal(
                        policy,
                        wall_ms(),
                        machine_policy::on_mains_power(),
                    )
                });
                (policy, why)
            }
            Err(why) => (None, Some(why)),
        }
    }

    /// The disk every booking leaves free now, in bytes: the larger of the box's reserve and the
    /// owner's kept disk.
    ///
    /// # Errors
    ///
    /// The owner's rows do not read.
    pub(super) fn disk_reserve_bytes(
        &self,
        settings: &ExecutionNodeSettings,
    ) -> Result<u64, String> {
        let policy = self.owner_policy(settings)?;
        Ok(machine_policy::disk_reserve_bytes(
            settings,
            policy.as_ref(),
        ))
    }

    /// The readiness check's period and who clears the node's drain, from the box's file
    /// `settings` and the owner's rows in one read: the shorter period, and the stricter clear.
    /// Rows that do not read keep the box's period and leave the drain to the person at the box.
    pub(crate) fn readiness_settings(
        &self,
        settings: &ExecutionNodeSettings,
    ) -> (u64, DrainClearBy) {
        match self.owner_policy(settings) {
            Ok(policy) => (
                machine_policy::readiness_every_secs(settings, policy.as_ref()),
                machine_policy::drain_clear_by(settings, policy.as_ref()),
            ),
            Err(_) => (settings.readiness_every_secs, DrainClearBy::PersonAtBox),
        }
    }

    /// Design 7.3 reserve step 5: the pin fits a template this node holds
    /// now, by digest, entry, scope, network, outputs, ceilings and
    /// parameters; and the owner's policy (row P0) accepts the work and has
    /// opened the network mode it asks.
    ///
    /// # Errors
    ///
    /// The refusal reason, for the key's end.
    pub fn admit_pin(&self, pin: &WorkloadPin) -> Result<(), String> {
        match self.settings() {
            Ok(Some(settings)) => {
                settings.admit_pin(pin)?;
                match self.owner_policy(&settings)? {
                    Some(policy) => machine_policy::admit_pin(&policy, pin),
                    None => Ok(()),
                }
            }
            Ok(None) => Err("node_disabled".to_owned()),
            Err(why) => Err(format!("node_settings_unreadable: {why}")),
        }
    }

    /// The launch commit's fit of a pin's placement on this node's devices
    /// (pass 34, section 2.1, the sum rule): the host memory the placement
    /// leases, the request's own and each leased unified device's claim
    /// together, is within the template's memory ceiling. The owner's network
    /// row is read again: a mode closed since the reserve does not launch
    /// (row NODE-NETWORK-HOST-UNIT). Then both layers
    /// (row P0): every placed device is one the owner offers, the memory with
    /// `held_mib` that the node's launched keys hold fits the memory work may
    /// hold, and the run's threads fit the threads one run may use.
    ///
    /// # Errors
    ///
    /// The refusal reason, for the key's end.
    pub fn admit_placement(
        &self,
        pin: &WorkloadPin,
        placement: &DevicePlacement,
        held_mib: u64,
    ) -> Result<(), String> {
        match self.settings() {
            Ok(Some(settings)) => {
                settings.admit_placement(pin, placement)?;
                let policy = self.owner_policy(&settings)?;
                let total_mib =
                    oneiron::host_memory::memory_bytes().map_or(u64::MAX, |bytes| bytes >> 20);
                let cores = u32::try_from(crate::machine::cores()).unwrap_or(u32::MAX);
                machine_policy::admit_placement(
                    &settings,
                    policy.as_ref(),
                    pin,
                    placement,
                    held_mib,
                    (total_mib, cores),
                )
            }
            Ok(None) => Err("node_disabled".to_owned()),
            Err(why) => Err(format!("node_settings_unreadable: {why}")),
        }
    }
}

/// The wall clock, in Unix milliseconds: the owner's hours are hours of the week.
fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}
