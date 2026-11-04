//! The engine hooks every store opens with.

use crate::store::{StoreDeleteGuards, StoreProjectWrites, StoreRecordHooks, StoreScopeStamps};

/// The engine hooks a store is assembled with. Every open door takes one as a
/// required input; the type has no default, so no store exists without each
/// hook.
#[derive(Clone, Copy)]
pub struct StoreHooks {
    /// The delete guards the store layer's delete paths run.
    pub delete_guards: &'static dyn StoreDeleteGuards,
    /// The record-scope stamp hooks the store layer's write and erase paths
    /// run.
    pub scope_stamps: &'static dyn StoreScopeStamps,
    /// The project write hooks the store layer's batch put and import paths
    /// run.
    pub project_writes: &'static dyn StoreProjectWrites,
    /// The identity-topology, federation and room hooks the store layer's
    /// write, erase and read paths run.
    pub record_hooks: &'static dyn StoreRecordHooks,
}
