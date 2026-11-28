//! The drain guard: once `drain_after_failures` jobs in a row finish failed,
//! or at its node's word, the machine takes no new GPU work until the drain
//! is cleared: by `resume` at the box, or by a passed readiness check when
//! `machines.drain.clear_by` is `after_readiness_check`, the default
//! (`jobs::readiness`). With a `drain_file`, the drain outlasts a restart.

use super::{GpuProbeError, GpuSlotTable, Shared, State};

impl GpuSlotTable {
    /// Why this machine is drained, while it is.
    ///
    /// # Errors
    ///
    /// [`GpuProbeError::DrainUnreadable`] when the drain file cannot be
    /// read.
    pub fn drained(&self) -> Result<Option<String>, GpuProbeError> {
        let state = self.shared.lock();
        self.shared.drained(&state)
    }

    /// Drains the machine at its node's word (a job unit ran that no key of
    /// the node's journal started): it takes no new GPU job until the drain
    /// is cleared, as after repeated failures.
    pub fn drain(&self, why: String) {
        let mut state = self.shared.lock();
        self.shared.drain(&mut state, why);
    }

    /// A person's clear of the drain: the machine takes GPU work again, and
    /// its count of failed jobs starts over.
    ///
    /// # Errors
    ///
    /// The drain file's removal error; the drain then stands.
    pub fn clear_drain(&self) -> std::io::Result<()> {
        let mut state = self.shared.lock();
        if let Some(file) = &self.shared.offer.drain_file {
            match std::fs::remove_file(file) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        state.failures_in_a_row = 0;
        state.drain_in_memory = None;
        Ok(())
    }
}

impl Shared {
    /// Why the machine is drained, while it is: the drain file's first line,
    /// or a drain kept in memory.
    pub(super) fn drained(&self, state: &State) -> Result<Option<String>, GpuProbeError> {
        if let Some(reason) = &state.drain_in_memory {
            return Ok(Some(reason.clone()));
        }
        let Some(path) = &self.offer.drain_file else {
            return Ok(None);
        };
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(Some(
                text.lines()
                    .map(str::trim)
                    .find(|line| !line.is_empty())
                    .unwrap_or("drained")
                    .to_owned(),
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(GpuProbeError::DrainUnreadable {
                reason: format!("{}: {error}", path.display()),
            }),
        }
    }

    /// Drains the machine: into the drain file when one is named, else (or
    /// when the write fails) in memory.
    pub(super) fn drain(&self, state: &mut State, drain: String) {
        tracing::warn!(%drain, "this machine takes no new GPU job until a person clears the drain");
        if let Some(path) = &self.offer.drain_file {
            let text = format!(
                "{drain}\nDelete this file to clear the drain; the machine then takes GPU jobs again.\n"
            );
            match std::fs::write(path, text) {
                // The file now holds the drain, so deleting it clears it.
                Ok(()) => {
                    state.drain_in_memory = None;
                    return;
                }
                Err(error) => tracing::warn!(
                    %error,
                    path = %path.display(),
                    "the GPU drain file could not be written; the drain is kept in memory"
                ),
            }
        }
        state.drain_in_memory = Some(drain);
    }
}
