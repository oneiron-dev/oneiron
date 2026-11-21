//! What the integration tests arm and read through the doors, held by each open vault
//! ([`crate::Vault`]'s `test_door_state`), never by the process: tests that run in parallel in
//! one process each see only their own vault's state. In memory only.

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;

use crate::EntityId;

/// The doors' state on one open vault.
#[derive(Default)]
pub(crate) struct VaultTestDoorState {
    /// The subjects whose first `test.fail_once` run failed on this vault
    /// (`schedule::TEST_FAIL_ONCE`): every later run about them is done, on any thread.
    pub(crate) fail_once_failed: Mutex<BTreeSet<Option<EntityId>>>,
    /// Each set the `dreamer.excluded_conversations` hook asked the follower to forget on this
    /// vault, oldest first (`dreamer_exclusion_forgets`).
    pub(crate) dreamer_exclusion_forgets: Mutex<Vec<BTreeSet<EntityId>>>,
    /// How many more eval-authoring execution-record writes fail on this vault
    /// (`eval_authoring_execution_fault`); `0` is disarmed.
    pub(crate) failing_execution_writes: AtomicUsize,
}
