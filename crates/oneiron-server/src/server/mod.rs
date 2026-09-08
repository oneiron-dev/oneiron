//! Sync server state and maintenance jobs, split by concern.
mod core;
mod leases;
mod lifecycle;
mod windows;

pub(crate) use self::core::BroadcastPayload;
pub use self::core::SyncServer;

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
use oneiron::sync::lease::{self, LEASE_DURATION_SECS, LeaseRecord, LeaseStatus, ROOT_LEASES_MAP};
#[cfg(test)]
use oneiron::sync::schema::{read_window_list, schema_version_bytes};
#[cfg(test)]
use std::sync::Arc;
