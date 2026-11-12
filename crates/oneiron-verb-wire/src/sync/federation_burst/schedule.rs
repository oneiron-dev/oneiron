//! Moved from `crates/oneiron/src/sync/federation_burst/schedule.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::VecDeque;

pub const DAY: u64 = 24 * 60 * 60;

/// How long retained federation work waits for its turn unless the owner
/// sets another wait: a week.
pub const FEDERATION_BURST_WAIT_SECS: u64 = 7 * DAY;

/// How long a retained maintenance operation waits for its turn unless the
/// owner sets another wait: a week.
pub const MAINTENANCE_INGEST_WAIT_SECS: u64 = 7 * DAY;

/// How long a held facet stamp waits for its row unless the owner sets
/// another wait: 30 days, the hold the stamps always had.
pub const FACET_STAMP_WAIT_SECS: u64 = 30 * DAY;

/// A queue of retained peer work the one schedule serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetainedWorkQueue {
    /// Deferred and isolated federation updates and deferred selector reads.
    /// A caller is one peer under one selector.
    FederationBurst,
    /// Signed maintenance operations past their signer's share of a quota
    /// window. A caller is one signer.
    MaintenanceIngest,
    /// Facet stamps held ahead of their rows. A caller is one sender's lane.
    FacetStamp,
}

impl RetainedWorkQueue {
    /// The queue's stable code: its key in the wait and cursor tables.
    pub const fn code(self) -> &'static str {
        match self {
            Self::FederationBurst => "federation_burst",
            Self::MaintenanceIngest => "maintenance_ingest",
            Self::FacetStamp => "facet_stamp",
        }
    }

    /// The wait the queue's work has when the owner sets none.
    pub const fn default_wait_secs(self) -> u64 {
        match self {
            Self::FederationBurst => FEDERATION_BURST_WAIT_SECS,
            Self::MaintenanceIngest => MAINTENANCE_INGEST_WAIT_SECS,
            Self::FacetStamp => FACET_STAMP_WAIT_SECS,
        }
    }
}
