//! Run tree projection and control adapter over generic AttemptQueue rows.
//!
//! Lifecycle transitions stay in [`AttemptQueue`]. This module renders queue rows
//! and their lifecycle/operator events into a deterministic tree surface.

mod a2a;
mod adapter;
mod consent;
mod render;
mod types;

pub use self::a2a::project_attempt_to_a2a;
pub use self::adapter::{RunTreeAdapter, mark_run_tree_failure};
pub use self::consent::{
    GATE_CONSENT_BUNDLE_DOMAIN, GATE_CONSENT_BUNDLE_FALLBACK_LABEL,
    GATE_CONSENT_BUNDLE_SCHEMA_VERSION, GateConsentBundle, GateConsentBundleAction,
    GateConsentBundleMember, GateConsentBundleReceipt,
};
pub use self::render::render_run_tree;
pub use self::types::{
    RunTree, RunTreeEvent, RunTreeEventKind, RunTreeFailure, RunTreeFailureDiagram, RunTreeNode,
    RunTreeNodeMarker, RunTreeNodeMarkerKind, RunTreeRepair, RunTreeStatus, RunTreeTimestamps,
};

#[cfg(test)]
mod tests;

// The flat run_tree.rs module used to provide this private helper to the
// sibling test module through `use super::run_tree_events`. After the
// directory split the seam re-imports it so `tests.rs` resolves exactly as
// it did before.
#[cfg(test)]
use self::render::run_tree_events;
