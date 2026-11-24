//! The lease a workload holds on one GPU slot (beside the memory floor's
//! leases): it ends the slot when it drops or finishes, unless it was kept.

use std::sync::Arc;

use super::{
    GpuDeviceLease, GpuDeviceProcesses, GpuDeviceState, GpuJobEnd, GpuSlotHold, GpuSlotRefusal,
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
    pub(super) hold: GpuSlotHold,
    pub(super) ended: bool,
}

impl GpuSlotLease {
    /// The GPU it holds, under which key, and since when.
    #[must_use]
    pub fn hold(&self) -> &GpuSlotHold {
        &self.hold
    }

    /// The launch recheck, just before the job's process starts: a fresh
    /// reading shows its GPU still offered, not withheld, and running no
    /// compute process, and the machine is not drained. Once confirmed it
    /// stays confirmed.
    ///
    /// # Errors
    ///
    /// [`GpuSlotRefusal`]: why the job must not start. The lease still
    /// holds its GPU.
    pub fn confirm_launch(&mut self) -> Result<(), GpuSlotRefusal> {
        let shared = &self.shared;
        let mut state = shared.lock();
        let at = state.at(&self.hold.key).ok_or(GpuSlotRefusal::NotHeld)?;
        if state.slots[at].stage == Stage::Launched {
            return Ok(());
        }
        // The driver first, then the withheld list and the drain, so a
        // withhold or a drain written while the driver answered still counts.
        let reading = shared.read(&mut state).map_err(unmeasured)?;
        if let Some(reason) = shared.drained(&state).map_err(unmeasured)? {
            return Err(GpuSlotRefusal::Drained { reason });
        }
        let device = reading
            .devices
            .iter()
            .find(|device| device.device_id == self.hold.device.device_id)
            .ok_or_else(|| GpuSlotRefusal::UnknownDevice {
                device_id: self.hold.device.device_id.clone(),
            })?;
        // The slot is this lease's own, so the GPU is judged as if untaken.
        match shared.state_of(&reading, None, device) {
            GpuDeviceState::Free => {
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
        Ok(processes_on(&processes, &self.hold.device.device_id))
    }

    /// Gives the GPU back and records how its job ended: a success starts
    /// the count of failed jobs over, a failure adds to it (and drains the
    /// machine at `drain_after_failures`), a cancel leaves it as it was.
    pub fn finish(mut self, end: GpuJobEnd) {
        self.ended = true;
        let mut state = self.shared.lock();
        self.shared.end(&mut state, &self.hold.key, Some(&end));
    }

    /// Hands the GPU to the running job: the slot stays under its key, past
    /// this lease, until [`GpuSlotTable::finish`] or
    /// [`GpuSlotTable::release`] ends it.
    pub fn keep(mut self) -> GpuSlotHold {
        self.ended = true;
        let mut state = self.shared.lock();
        if let Some(at) = state.at(&self.hold.key) {
            state.slots[at].guarded = false;
        }
        self.hold.clone()
    }
}

impl Drop for GpuSlotLease {
    fn drop(&mut self) {
        if !self.ended {
            let mut state = self.shared.lock();
            self.shared.end(&mut state, &self.hold.key, None);
        }
    }
}

impl GpuDeviceLease for GpuSlotLease {
    fn hold(&self) -> &GpuSlotHold {
        Self::hold(self)
    }

    fn confirm_launch(&mut self) -> Result<(), GpuSlotRefusal> {
        Self::confirm_launch(self)
    }

    fn end_check(&self) -> Result<GpuDeviceProcesses, GpuSlotRefusal> {
        Self::end_check(self)
    }

    fn finish(self: Box<Self>, end: GpuJobEnd) {
        Self::finish(*self, end);
    }

    fn keep(self: Box<Self>) -> GpuSlotHold {
        Self::keep(*self)
    }
}
