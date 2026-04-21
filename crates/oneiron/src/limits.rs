/// Cap for ChildOf cycle-check traversals to prevent pathological walks.
pub(crate) const MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS: usize = 10_000;

/// Error label for ChildOf cycle checks that exceed the traversal safety cap.
pub(crate) const ERR_CHILD_OF_CYCLE_CHECK: &str = "child_of_cycle_check";
