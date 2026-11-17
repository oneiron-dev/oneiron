//! What the app shell reports about fetching predictions on this machine (ARCH-0023b
//! #predicted-residence: "Phones fetch only on Wi-Fi and power").
//!
//! The report is a fact of the open install, not of one connection: it is held on the open
//! vault's session, and every sync connection this vault runs reads the same report. A
//! connection rebuilt after a credential renewal or an embedded engine's wake therefore
//! starts from the shell's last report instead of closed again. In memory only: a new open
//! starts closed until the shell reports.

use crate::Vault;

/// What the app shell reports about fetching predictions on this machine. A computer fetches
/// whatever the shell reports; a phone fetches only when both hold, closed by default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FetchConditions {
    /// Whether the machine is on an unmetered network.
    pub unmetered: bool,
    /// Whether the machine is on power.
    pub powered: bool,
}

impl Vault {
    /// Records what the app shell reports about fetching predictions on this machine, for every
    /// sync connection this open vault runs now or later. A change wakes each running predicted
    /// upkeep, so a newly opened gate fetches now rather than at the next upkeep.
    pub fn report_fetch_conditions(&self, conditions: FetchConditions) {
        self.world_keys
            .fetch_conditions
            .send_if_modified(|current| {
                let changed = *current != conditions;
                *current = conditions;
                changed
            });
    }

    /// The app shell's last report on this open vault, closed until it reports.
    pub fn reported_fetch_conditions(&self) -> FetchConditions {
        *self.world_keys.fetch_conditions.borrow()
    }

    /// A receiver that sees each change of the app shell's report.
    pub(crate) fn watch_fetch_conditions(&self) -> tokio::sync::watch::Receiver<FetchConditions> {
        self.world_keys.fetch_conditions.subscribe()
    }
}
