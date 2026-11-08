//! Served forms a host commits itself, after the work it must finish first
//! (FIX 26).

use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::receipt::ServedForm;

/// The served forms an adapter's hydrates produced, held for the host to
/// commit ([`crate::claim::ScopedRead::commit_served_forms`]) instead of
/// committed before the adapter answers. A host whose answer has a fallible
/// step after the read (an MCP session observation) stages that step first,
/// then commits these, so a failed answer leaves no served-form receipt.
#[derive(Debug, Default)]
pub struct DeferredServedForms(Mutex<Vec<ServedForm>>);

impl DeferredServedForms {
    /// The forms held so far; the set is left empty.
    #[must_use]
    pub fn take(&self) -> Vec<ServedForm> {
        std::mem::take(&mut *self.forms())
    }

    /// Holds `served` for the host's commit.
    pub(super) fn defer(&self, served: &[ServedForm]) {
        self.forms().extend_from_slice(served);
    }

    fn forms(&self) -> MutexGuard<'_, Vec<ServedForm>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
