//! A host hands the verb hooks its own sandbox.

use std::sync::Arc;

use crate::Vault;
use crate::runtime_hooks::HookBodyRuntime;

impl Vault {
    /// Verb hooks run on `runtime` instead of building their own sandbox.
    pub fn install_hook_runtime(&self, runtime: Arc<dyn HookBodyRuntime>) {
        // placeholder: IMPL-E's state.rs version replaces this
        let _ = runtime;
    }
}
