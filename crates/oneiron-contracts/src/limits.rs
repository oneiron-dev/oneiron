//! Traversal safety caps for the engine's graph walks.
//!
//! These were `pub(crate)` inside `oneiron` and are `pub` here only so the engine
//! crates above can keep sharing one value. Callers: the ancestor and ChildOf walks in
//! `oneiron` (conversation DAG, code revisions, lenses, batch overlay, vault edges).
//! They are bounds, not authority; nothing outside the engine crates should depend on them.

/// Cap for ancestor walks to prevent pathological `ancestors()` result growth.
pub const MAX_ANCESTOR_DEPTH: usize = 10_000;

/// Cap for ChildOf cycle-check traversals to prevent pathological walks.
pub const MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS: usize = 10_000;

/// Error label for ChildOf cycle checks that exceed the traversal safety cap.
pub const ERR_CHILD_OF_CYCLE_CHECK: &str = "child_of_cycle_check";
