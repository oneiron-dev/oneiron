//! A test commits a change in the gap between a selector answer's queue and
//! its release (SELECTOR-RELEASE-POINT = B): the hook armed for a grant runs
//! once, as the next answer made under that grant is queued, after the
//! answer is made and before it can leave. Kept on the vault the answer is
//! made in, by grant, so tests that run side by side in one binary never
//! take each other's hooks. A hook stays armed only while the [`ArmedHook`]
//! that armed it is held, so an unrun hook that holds its vault never keeps
//! that vault open.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use oneiron::sync::SelectorReleaseBasis;
use oneiron::test_doors::vault_state::vault_extension;
use oneiron::{EntityId, Vault};

type Hook = Box<dyn FnOnce() + Send>;

/// The hooks armed on one vault.
#[derive(Default)]
struct ArmedHooks(Mutex<ArmedByGrant>);

/// The hooks armed on one vault, by grant, each with the number of the arming
/// that armed it.
#[derive(Default)]
struct ArmedByGrant {
    /// The number the next arming on this vault takes.
    next_arming: u64,
    by_grant: HashMap<EntityId, (u64, Hook)>,
}

impl ArmedHooks {
    fn lock(&self) -> MutexGuard<'_, ArmedByGrant> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One arming by [`arm`]. Dropping it disarms its hook if the hook has not
/// run and no later arming of the grant replaced it.
#[must_use = "dropping it disarms the hook"]
pub struct ArmedHook {
    hooks: Arc<ArmedHooks>,
    grant: EntityId,
    arming: u64,
}

impl Drop for ArmedHook {
    fn drop(&mut self) {
        let unrun = {
            let mut armed = self.hooks.lock();
            let own = armed
                .by_grant
                .get(&self.grant)
                .is_some_and(|(arming, _)| *arming == self.arming);
            own.then(|| armed.by_grant.remove(&self.grant)).flatten()
        };
        // Dropped with the map unlocked: the hook may hold the last handle to
        // its vault.
        drop(unrun);
    }
}

/// Runs `hook` as the next answer made in `vault` under `grant` is queued,
/// while the returned [`ArmedHook`] is held. Arming a grant again replaces
/// its unrun hook.
pub fn arm(vault: &Vault, grant: EntityId, hook: impl FnOnce() + Send + 'static) -> ArmedHook {
    let hooks = vault_extension::<ArmedHooks>(vault);
    let (arming, replaced) = {
        let mut armed = hooks.lock();
        let arming = armed.next_arming;
        armed.next_arming = arming.wrapping_add(1);
        let replaced = armed.by_grant.insert(grant, (arming, Box::new(hook)));
        (arming, replaced)
    };
    // Dropped with the map unlocked, as in `ArmedHook::drop`.
    drop(replaced);
    ArmedHook {
        hooks,
        grant,
        arming,
    }
}

/// Whether a hook armed in `vault` for `grant` has not run yet.
pub fn armed(vault: &Vault, grant: &EntityId) -> bool {
    vault_extension::<ArmedHooks>(vault)
        .lock()
        .by_grant
        .contains_key(grant)
}

/// Runs the hook armed for the grant of `basis` in the vault its answer was
/// made in, if one is armed.
pub(crate) fn run(basis: &SelectorReleaseBasis) {
    let hook = basis
        .test_door_extensions()
        .get::<ArmedHooks>()
        .lock()
        .by_grant
        .remove(basis.grant_id());
    if let Some((_, hook)) = hook {
        hook();
    }
}
