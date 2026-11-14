//! Moved from `crates/oneiron/src/receipt/task_type_ref.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The root node of the task-type tree. An outcome with no task (a chat turn,
/// a channel actor's health) and every unsure placement carries it.
pub const ROOT_TYPE_NODE: &str = "root";
