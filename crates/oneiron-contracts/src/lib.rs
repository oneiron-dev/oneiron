//! Shared value vocabulary of the oneiron engine: the lowest engine crate, with no
//! dependency on any implementation crate. `oneiron` re-exports every module here at
//! its old `oneiron::<module>` path; applications depend on `oneiron`, not on this crate.

pub mod affect;
pub mod claim;
pub mod code_run;
pub mod companion;
pub mod entity_id;
pub mod error;
pub mod gate;
pub mod identity_topology;
pub mod limits;
pub mod memory;
pub mod record_layout;
pub mod registry;
pub mod retrieval_telemetry;
pub mod secret_custody;
pub mod secret_lease;
pub mod temporal;

// The same root aliases `oneiron` has, so moved code keeps its `crate::` paths.
pub use crate::entity_id::EntityId;
pub use crate::error::{Error, ErrorKind, Result};
