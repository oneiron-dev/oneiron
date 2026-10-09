//! Sync server state and maintenance jobs, split by concern.
mod core;
mod embedding;
mod leases;
mod lifecycle;
mod message_stream;
mod recall;
mod tagging;
mod windows;

pub(crate) use self::core::BroadcastPayload;
pub use self::core::SyncServer;
pub(crate) use self::recall::blocking;

#[cfg(test)]
mod slip_transport_tests;
#[cfg(test)]
mod tests;

// The flat server.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header, and
// every server-internal item the tests name bare. After the directory split
// the seam re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::{leases::*, lifecycle::*, windows::*};
#[cfg(test)]
use crate::config::SyncServerConfig;
#[cfg(test)]
use loro::{ExportMode, LoroDoc, LoroValue, ValueOrContainer};
#[cfg(test)]
use oneiron::sync::WindowKey;
#[cfg(test)]
use oneiron::sync::lease::{self, LeaseRecord, LeaseStatus, ROOT_LEASES_MAP};
#[cfg(test)]
use oneiron::sync::schema::read_window_list;
#[cfg(test)]
use std::sync::Arc;
