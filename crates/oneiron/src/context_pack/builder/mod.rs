//! The fluent [`ContextPackBuilder`] query API and its assembly pipeline.
//!
//! Directory hub: `pack_run` carries what a run produces and how its
//! telemetry row is finalized or discarded, `query` owns the fluent search,
//! filter, boost, hydration, budget and format surface, and `assembly`
//! executes a configured builder through retrieval, hydration and validation.

mod assembly;
mod pack_run;
mod query;
mod scoped;

pub(super) use self::pack_run::{ContextPackRun, ContextPackTelemetry, HydrateOptions};
pub use self::pack_run::{SerializedContextPack, UnfinalizedContextPack};
pub use self::query::ContextPackBuilder;
