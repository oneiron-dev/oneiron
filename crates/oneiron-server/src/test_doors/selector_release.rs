//! A test commits a change in the gap between a selector answer's queue and
//! its release (SELECTOR-RELEASE-POINT = B): the hook armed for a grant runs
//! once, at the next release judgement of an answer made under that grant,
//! before the judgement reads the grant. Keyed by grant, so tests that run
//! side by side in one binary never take each other's hooks.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use oneiron::EntityId;

type Hook = Box<dyn FnOnce() + Send>;

static ARMED: Mutex<Option<HashMap<EntityId, Hook>>> = Mutex::new(None);

/// Runs `hook` at the next release judgement of an answer made under `grant`.
pub fn arm(grant: EntityId, hook: impl FnOnce() + Send + 'static) {
    ARMED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get_or_insert_with(HashMap::new)
        .insert(grant, Box::new(hook));
}

/// Whether a hook armed for `grant` has not run yet.
pub fn armed(grant: &EntityId) -> bool {
    ARMED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .is_some_and(|hooks| hooks.contains_key(grant))
}

pub(crate) fn run(grant: &EntityId) {
    let hook = ARMED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_mut()
        .and_then(|hooks| hooks.remove(grant));
    if let Some(hook) = hook {
        hook();
    }
}
