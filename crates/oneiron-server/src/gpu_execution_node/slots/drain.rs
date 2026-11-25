//! The drain guard: once `drain_after_failures` jobs in a row finish failed,
//! or at its node's word, the machine takes no new GPU work until a person
//! clears it. With a `drain_file`, the drain outlasts a restart.

use std::time::{SystemTime, UNIX_EPOCH};

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
    /// the node's journal started): it takes no new GPU job until a person
    /// clears the drain, as after repeated failures.
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
        self.shared.clear_drain(&mut state)
    }

    /// The clear from the owner's panel (pass 34, 2.4): clears the drain only
    /// when it began before `before_ms`, the owner's clear time in Unix
    /// milliseconds as the vault stamped it, and answers whether it did. The
    /// drain's start is by this machine's clock, so a vault clock ahead of it
    /// moves the line later (FIX row NODE-DRAIN-PANEL-CLEAR-CLOCK-SKEW). A
    /// drain begins at the drain file's last write (a time on a whole second
    /// counts as the end of that second), or when the drain kept in memory was
    /// set; with both, at the later. The look and the removal hold the table's
    /// lock, so a drain the table writes meanwhile stands.
    ///
    /// # Errors
    ///
    /// The drain file's metadata or removal error; the drain then stands.
    pub fn clear_drain_begun_before(&self, before_ms: u64) -> std::io::Result<bool> {
        let mut state = self.shared.lock();
        match self.shared.drain_began_ms(&state)? {
            Some(began_ms) if began_ms < before_ms => {
                self.shared.clear_drain(&mut state)?;
                Ok(true)
            }
            Some(_) | None => Ok(false),
        }
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
        state.drain_in_memory_began_ms = oneiron_base::unix_millis_now();
    }

    /// When the standing drain began, in Unix milliseconds, or `None` with no
    /// drain: the later of the drain file's last write and the time the drain
    /// in memory was set.
    fn drain_began_ms(&self, state: &State) -> std::io::Result<Option<u64>> {
        let in_memory = state
            .drain_in_memory
            .as_ref()
            .map(|_| state.drain_in_memory_began_ms);
        let in_file = match &self.offer.drain_file {
            None => None,
            Some(path) => match std::fs::metadata(path) {
                Ok(metadata) => Some(file_began_ms(metadata.modified()?)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error),
            },
        };
        Ok(in_memory.max(in_file))
    }

    /// Clears the drain: removes the drain file, forgets the drain in memory,
    /// and starts the count of failed jobs over.
    fn clear_drain(&self, state: &mut State) -> std::io::Result<()> {
        if let Some(file) = &self.offer.drain_file {
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

/// When a drain file's drain began, in Unix milliseconds, from the file's last
/// write. A time on a whole second may come from a filesystem that keeps whole
/// seconds only, so it counts as the last millisecond of that second: a clear
/// given within that second leaves the drain standing. A time before the epoch
/// never counts as before a clear.
fn file_began_ms(modified: SystemTime) -> u64 {
    let Ok(since) = modified.duration_since(UNIX_EPOCH) else {
        return u64::MAX;
    };
    let began_ms = u64::try_from(since.as_millis()).unwrap_or(u64::MAX);
    if since.subsec_nanos() == 0 {
        began_ms.saturating_add(999)
    } else {
        began_ms
    }
}
