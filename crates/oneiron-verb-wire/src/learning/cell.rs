//! Moved from `crates/oneiron/src/learning/cell.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::claim::learning_predicate::LearningPredicate;
pub use crate::receipt::task_type_ref::ROOT_TYPE_NODE;
pub use crate::receipt::task_type_ref::TypeRef;
use serde::Deserialize;
use serde::Serialize;

/// Longest qualifier text a cell keeps, in bytes.
pub const MAX_QUALIFIER_BYTES: usize = 256;
