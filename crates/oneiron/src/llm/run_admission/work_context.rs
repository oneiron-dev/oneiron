//! Host scheduling and physical-custody context for one run-admission handle.
//! It is metadata, never prompt text, conditioning, or a budget widening.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::llm::{WorkClass, WorkPriority};

/// A dependency or host ticket identity shared across the admission layers.
pub type WorkId = u64;

/// Cooperative cancellation shared by one work tree. Device tickets snapshot
/// its flag when dependency links change, so cancelling a child never cancels
/// its parent or siblings through a retained Arc.
#[derive(Debug, Clone, Default)]
pub struct WorkCancel(Arc<AtomicBool>);

impl WorkCancel {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    /// The flag a host places on a device work request.
    #[must_use]
    pub fn shared(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.0)
    }
}

/// Whether the physical call spends money or is keyless own-server work.
/// This is host-attested locality/custody evidence, never caller JSON.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum WorkPhysical {
    #[default]
    Paid,
    KeylessOwnServer,
}

/// What a host preserves through sourced/initiated handles and dependency
/// gates. Unlabeled work is Foreground; memory work maps to Background at the
/// RunAdmission boundary rather than gaining a parallel mark.
#[derive(Debug, Clone)]
pub struct WorkContext {
    pub class: WorkClass,
    pub priority: WorkPriority,
    pub deadline: Option<Instant>,
    pub parent: Option<WorkId>,
    pub cancel: WorkCancel,
    pub physical: WorkPhysical,
}

impl Default for WorkContext {
    fn default() -> Self {
        Self {
            class: WorkClass::Foreground,
            priority: WorkPriority::Normal,
            deadline: None,
            parent: None,
            cancel: WorkCancel::new(),
            physical: WorkPhysical::Paid,
        }
    }
}
