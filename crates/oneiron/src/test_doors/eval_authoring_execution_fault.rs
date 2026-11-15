//! Arms the requested-eval-authoring execution-record write fault (FIX
//! EVAL-AUTHORING-EXECUTE-UNRECORDED-END): while armed, record ends and
//! recoveries fail as a storage-write fault would, so a test shows what a
//! host does when its record write fails and the queue's settle write
//! succeeds. The fault is process-global: tests that arm it must not
//! overlap.

/// Arms the fault: the next `count` execution-record writes fail. `0`
/// disarms.
pub fn fail_execution_writes(count: usize) {
    crate::skill_optimize::fail_execution_writes(count);
}
