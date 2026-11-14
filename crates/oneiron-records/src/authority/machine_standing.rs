//! Moved from `crates/oneiron/src/authority/machine_standing.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::*;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::rc::Rc;
use std::sync::Arc;

/// Whose trust a machine is judged under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StandingView {
    /// `T(X)`, pin-free and install-free: validity, and `read_X`, which is
    /// diagnostics and holder execution, never who may edit.
    Under(MachineAdmitter),
    /// `T(pin)` with this install's floors and counting: the settings this
    /// install reads, and the machines it counts.
    Install,
}
