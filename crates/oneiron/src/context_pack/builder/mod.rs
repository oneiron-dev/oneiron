//! The fluent [`ContextPackBuilder`] query API and its assembly pipeline.
//!
//! Directory hub: `pack_run` carries what a run produces and how its
//! telemetry row is finalized or discarded, `query` owns the fluent search,
//! filter, boost, hydration, budget and format surface, and `assembly`
//! executes a configured builder through retrieval, hydration and validation.
//! `selection` keeps critical rows first under a pack's budgets and counts
//! them, and `instruction_files` resolves a pack's instruction-file handles.

mod assembly;
mod instruction_files;
mod pack_run;
mod query;
mod replay;
mod scoped;
mod selection;

pub(super) use self::pack_run::{ContextPackRun, ContextPackTelemetry, HydrateOptions};
pub use self::pack_run::{SerializedContextPack, UnfinalizedContextPack};
pub use self::query::ContextPackBuilder;
pub use self::selection::select_critical_pack_rows;
