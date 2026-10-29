//! The vaults this process serves, each by its canonical root (FIX 11157).
//!
//! The read-only door refuses a root this process holds open, so a read one
//! vault's pass makes of another vault this process also serves (a pending
//! credential restore's source) goes through the served handle instead.
//! Only a [`Weak`] is kept: a handle no holder keeps is never revived here.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, PoisonError, Weak};

use crate::Vault;

static SERVED: LazyLock<Mutex<HashMap<PathBuf, Weak<Vault>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

impl Vault {
    /// Records this handle as the one this process serves at its root, for
    /// as long as any holder keeps it, so a pass over another vault of this
    /// process reads it through this handle.
    pub fn register_served(self: &Arc<Self>) {
        let mut served = SERVED.lock().unwrap_or_else(PoisonError::into_inner);
        served.retain(|_, vault| vault.strong_count() > 0);
        served.insert(self.store.owner._registered_path.path.clone(), Arc::downgrade(self));
    }
}

/// The handle this process serves at canonical `root`, while a holder keeps
/// it.
pub(crate) fn served_vault_at(root: &Path) -> Option<Arc<Vault>> {
    let mut served = SERVED.lock().unwrap_or_else(PoisonError::into_inner);
    served.retain(|_, vault| vault.strong_count() > 0);
    served.get(root).and_then(Weak::upgrade)
}
