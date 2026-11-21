//! Arms the requested-eval-authoring execution-record write fault (FIX
//! EVAL-AUTHORING-EXECUTE-UNRECORDED-END): while armed, record ends and
//! recoveries fail as a storage-write fault would, so a test shows what a
//! host does when its record write fails and the queue's settle write
//! succeeds. The fault is armed on one vault: tests on other vaults run
//! beside it untouched.

use crate::Vault;

/// Arms the fault on `vault`: its next `count` execution-record writes
/// fail. `0` disarms.
pub fn fail_execution_writes(vault: &Vault, count: usize) {
    crate::skill_optimize::fail_execution_writes(vault, count);
}
