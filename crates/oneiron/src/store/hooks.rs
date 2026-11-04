//! The engine hooks every store opens with.

#[cfg(feature = "sync")]
use crate::store::StoreSyncHooks;
use crate::store::{
    StoreActorScrubs, StoreDeleteGuards, StoreProjectWrites, StoreRecordHooks, StoreScopeStamps,
};

/// The engine hooks a store is assembled with. Every open door takes one as a
/// required input; the type has no default, so no store exists without each
/// hook.
#[derive(Clone, Copy)]
pub struct StoreHooks {
    /// The delete guards the store layer's delete paths run.
    pub(crate) delete_guards: &'static dyn StoreDeleteGuards,
    /// The record-scope stamp hooks the store layer's write and erase paths
    /// run.
    pub(crate) scope_stamps: &'static dyn StoreScopeStamps,
    /// The project write hooks the store layer's batch put and import paths
    /// run.
    pub(crate) project_writes: &'static dyn StoreProjectWrites,
    /// The identity-topology, federation and room hooks the store layer's
    /// write, erase and read paths run.
    pub(crate) record_hooks: &'static dyn StoreRecordHooks,
    /// The actor scrubs of store-declared side tables whose eraser lives in
    /// the engine.
    pub(crate) actor_scrubs: &'static dyn StoreActorScrubs,
    /// The sync hooks the store layer's write, erase and maintenance paths
    /// run in a build with sync.
    #[cfg(feature = "sync")]
    pub(crate) sync_hooks: &'static dyn StoreSyncHooks,
}
