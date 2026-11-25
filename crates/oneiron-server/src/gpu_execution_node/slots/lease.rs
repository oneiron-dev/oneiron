//! The node takes a device lease inside its launch commit and immediately
//! confirms launch. There is no hold during staging. A pause or quarantine
//! refuses both steps without releasing existing slots.
//!
//! A lease lives for the workload's life. Dropping or finishing it gives
//! back the slot. Keeping it hands the slot to the journaled key, which the
//! node reattaches after a restart.

use std::sync::Arc;

use super::{
    GpuDeviceLease, GpuDeviceProcesses, GpuDeviceState, GpuLeaseEnd, GpuSlotGrant, GpuSlotRefusal,
    GpuSlotRequest, GpuSlotTable, MachineGpus, Shared, Stage, processes_on, refusal, unmeasured,
};

impl MachineGpus for GpuSlotTable {
    fn try_lease(
        &self,
        request: &GpuSlotRequest,
    ) -> Result<Box<dyn GpuDeviceLease>, GpuSlotRefusal> {
        Ok(Box::new(
            self.lease(request, oneiron_base::unix_millis_now())?,
        ))
    }
}

/// One GPU leased to the workload that runs its job. Dropping it gives the
/// GPU back; [`Self::finish`] also records how the job ended; [`Self::keep`]
/// hands it to the running job.
#[derive(Debug)]
pub struct GpuSlotLease {
    pub(super) shared: Arc<Shared>,
    pub(super) grant: GpuSlotGrant,
    pub(super) ended: bool,
}

impl GpuSlotLease {
    /// The GPU it holds, under which key, and since when.
    #[must_use]
    pub fn grant(&self) -> &GpuSlotGrant {
        &self.grant
    }

    /// The launch recheck, just before each start of the job's process: a
    /// fresh reading shows its GPU still offered, not withheld, and running
    /// no compute process, and the machine is neither paused nor drained.
    /// A retry is checked afresh, as the first attempt is, whatever an
    /// earlier confirmation answered. A confirmation writes the GPU's kept
    /// record, so the GPU stays the job's past this server's life.
    ///
    /// # Errors
    ///
    /// [`GpuSlotRefusal`]: why the job must not start. The lease still
    /// holds its GPU.
    pub fn confirm_launch(&mut self) -> Result<(), GpuSlotRefusal> {
        let shared = &self.shared;
        let mut state = shared.lock();
        if let Some(reason) = &state.paused {
            return Err(GpuSlotRefusal::Paused {
                reason: reason.clone(),
            });
        }
        let at = state.at(&self.grant.key).ok_or(GpuSlotRefusal::NotHeld)?;
        state.check_quarantine(&self.grant.device.device_id)?;
        // The driver first, then the withheld list and the drain, so a
        // withhold or a drain written while the driver answered still counts.
        let reading = shared.read(&mut state).map_err(unmeasured)?;
        if let Some(reason) = shared.drained(&state).map_err(unmeasured)? {
            return Err(GpuSlotRefusal::Drained { reason });
        }
        let device = reading
            .devices
            .iter()
            .find(|device| device.device_id == self.grant.device.device_id)
            .ok_or_else(|| GpuSlotRefusal::UnknownDevice {
                device_id: self.grant.device.device_id.clone(),
            })?;
        // The slot is this lease's own, so the GPU is judged as if untaken.
        match shared.state_of(&reading, &state, None, device) {
            GpuDeviceState::Free => {
                shared
                    .keep_record(&self.grant.device.device_id, &self.grant.key)
                    .map_err(|error| GpuSlotRefusal::Unmeasured {
                        reason: format!("the GPU's kept record could not be written: {error}"),
                    })?;
                state.slots[at].stage = Stage::Launched;
                Ok(())
            }
            other => Err(refusal(device, other)),
        }
    }

    /// The compute processes on its GPU now, from a fresh reading.
    ///
    /// # Errors
    ///
    /// [`GpuSlotRefusal::Unmeasured`] when the driver cannot be read.
    pub fn end_check(&self) -> Result<GpuDeviceProcesses, GpuSlotRefusal> {
        let processes = self.shared.probe.compute_processes().map_err(unmeasured)?;
        Ok(processes_on(&processes, &self.grant.device.device_id))
    }

    /// Gives the GPU back and records how its job ended: a success starts
    /// the count of failed jobs over, a failure adds to it (and drains the
    /// machine at `drain_after_failures`), a cancel leaves it as it was.
    pub fn finish(mut self, end: GpuLeaseEnd) {
        self.ended = true;
        let mut state = self.shared.lock();
        self.shared.end(&mut state, &self.grant.key, Some(&end));
    }

    /// Hands the slot to the journaled key until [`GpuSlotTable::finish`] or
    /// [`GpuSlotTable::release`] ends it.
    pub fn keep(mut self) -> GpuSlotGrant {
        self.ended = true;
        let mut state = self.shared.lock();
        if let Some(at) = state.at(&self.grant.key) {
            state.slots[at].guarded = false;
        }
        self.grant.clone()
    }
}

impl Drop for GpuSlotLease {
    fn drop(&mut self) {
        if !self.ended {
            let mut state = self.shared.lock();
            self.shared.end(&mut state, &self.grant.key, None);
        }
    }
}

impl GpuDeviceLease for GpuSlotLease {
    fn grant(&self) -> &GpuSlotGrant {
        Self::grant(self)
    }

    fn confirm_launch(&mut self) -> Result<(), GpuSlotRefusal> {
        Self::confirm_launch(self)
    }

    fn end_check(&self) -> Result<GpuDeviceProcesses, GpuSlotRefusal> {
        Self::end_check(self)
    }

    fn finish(self: Box<Self>, end: GpuLeaseEnd) {
        Self::finish(*self, end);
    }

    fn keep(self: Box<Self>) -> GpuSlotGrant {
        Self::keep(*self)
    }
}
