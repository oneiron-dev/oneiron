//! What the integration tests arm and read through the doors, held by each open vault
//! ([`crate::Vault`]'s `test_door_state`), never by the process: tests that run in parallel in
//! one process each see only their own vault's state. In memory only.

use std::any::{Any, TypeId};
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex, PoisonError};

use crate::{EntityId, Vault};

/// The doors' state on one open vault.
#[derive(Default)]
pub(crate) struct VaultTestDoorState {
    /// Each set the `dreamer.excluded_conversations` hook asked the follower to forget on this
    /// vault, oldest first (`dreamer_exclusion_forgets`).
    pub(crate) dreamer_exclusion_forgets: Mutex<Vec<BTreeSet<EntityId>>>,
    /// How many more eval-authoring execution-record writes fail on this vault
    /// (`eval_authoring_execution_fault`); `0` is disarmed.
    pub(crate) failing_execution_writes: AtomicUsize,
    /// What other crates' test doors keep on this vault ([`vault_extension`]). Shared, so a
    /// selector answer made in the vault can carry it to where its hook runs
    /// (`SelectorReleaseBasis::test_door_extensions`).
    pub(crate) extensions: Arc<VaultTestDoorExtensions>,
}

/// What other crates' test doors keep on one open vault: one value per type.
#[derive(Default)]
pub struct VaultTestDoorExtensions(Mutex<HashMap<TypeId, Arc<dyn Any + Send + Sync>>>);

impl VaultTestDoorExtensions {
    /// The `T` kept here, made with `T::default()` at its first use. The default is made, and a
    /// default that lost a race is dropped, with the map unlocked, so a `T::default()` or a
    /// `T::drop` that reads another value of this map does not deadlock; when two first uses
    /// race, the value inserted first is kept.
    #[must_use]
    pub fn get<T: Any + Default + Send + Sync>(&self) -> Arc<T> {
        let key = TypeId::of::<T>();
        let kept = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
            .cloned();
        let value = kept.unwrap_or_else(|| {
            let made: Arc<dyn Any + Send + Sync> = Arc::new(T::default());
            let inserted = Arc::clone(
                self.0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .entry(key)
                    .or_insert_with(|| Arc::clone(&made)),
            );
            // The map is unlocked here: a `made` that lost the race drops its last handle now.
            drop(made);
            inserted
        });
        value
            .downcast::<T>()
            .unwrap_or_else(|_| unreachable!("each value is keyed by its own type"))
    }
}

/// The `T` another crate's test doors keep on `vault`, made with `T::default()` at its first use:
/// one per type and open vault, so tests that run side by side never share it.
#[must_use]
pub fn vault_extension<T: Any + Default + Send + Sync>(vault: &Vault) -> Arc<T> {
    vault.test_door_state.extensions.get()
}
