//! A test commits a change in the gap between a selector answer's queue and
//! its release (SELECTOR-RELEASE-POINT = B): the hook armed for a grant runs
//! once, as the next answer made under that grant is queued, after the
//! answer is made and before it can leave. Kept on the vault the answer is
//! made in, by grant, so tests that run side by side in one binary never
//! take each other's hooks.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use oneiron::sync::SelectorReleaseBasis;
use oneiron::test_doors::vault_state::vault_extension;
use oneiron::{EntityId, Vault};

type Hook = Box<dyn FnOnce() + Send>;

/// The hooks armed on one vault, by grant.
#[derive(Default)]
struct ArmedHooks(Mutex<HashMap<EntityId, Hook>>);

impl ArmedHooks {
    fn by_grant(&self) -> MutexGuard<'_, HashMap<EntityId, Hook>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Runs `hook` as the next answer made in `vault` under `grant` is queued.
pub fn arm(vault: &Vault, grant: EntityId, hook: impl FnOnce() + Send + 'static) {
    vault_extension::<ArmedHooks>(vault)
        .by_grant()
        .insert(grant, Box::new(hook));
}

/// Whether a hook armed in `vault` for `grant` has not run yet.
pub fn armed(vault: &Vault, grant: &EntityId) -> bool {
    vault_extension::<ArmedHooks>(vault)
        .by_grant()
        .contains_key(grant)
}

/// Runs the hook armed for the grant of `basis` in the vault its answer was
/// made in, if one is armed.
pub(crate) fn run(basis: &SelectorReleaseBasis) {
    let hook = basis
        .test_door_extensions()
        .get::<ArmedHooks>()
        .by_grant()
        .remove(basis.grant_id());
    if let Some(hook) = hook {
        hook();
    }
}
