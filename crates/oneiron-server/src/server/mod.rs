//! Sync server state and maintenance jobs, split by concern.
mod board_publisher;
mod connector_events;
mod connector_sends;
mod cooperative_deletion;
mod core;
mod embedding;
mod housekeeping;
mod leases;
mod lifecycle;
mod media_embedding;
mod message_stream;
mod oversight;
mod presence;
mod read_shape;
mod reader_runner;
mod recall;
mod recall_rerank;
mod resident_pump;
mod run_host_door;
mod space_move;
mod tagging;
mod wave_door;
mod windows;

pub(crate) use self::core::BroadcastPayload;
pub use self::core::{SyncServer, TaskWorkTurn};
pub(crate) use self::housekeeping::{HousekeepingAdmission, admit_every_pass};
pub(crate) use self::media_embedding::MediaEmbedRefusal;
pub(crate) use self::oversight::HEALER_OVERSIGHT_EVERY;
pub use self::oversight::OversightStartError;
pub use self::read_shape::RetrievalQueryCheck;
pub(crate) use self::read_shape::{QueryDoor, query_caller};
pub(crate) use self::reader_runner::{
    READER_CHILD_READ_ONLY, ReaderRunner, ReaderSeats, run_launch_scope,
};
pub(crate) use self::recall::blocking;
pub(crate) use self::run_host_door::answer_as_agent;
pub(crate) use self::wave_door::{wave_plan, wave_receipt};

#[cfg(test)]
mod housekeeping_tests;
#[cfg(test)]
pub(crate) mod live_rows_tests;
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
