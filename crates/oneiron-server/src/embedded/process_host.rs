//! The app host of a binding whose app is a plain process (OF-237): the
//! Python and Node served clients, which have no app keychain or app timer
//! of their own to hand the engine.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use oneiron_vault_contract::host_adapters::AppHost;
use zeroize::Zeroizing;

/// An [`AppHost`] over the secrets a process starts its engine with.
///
/// Its keychain answers exactly those secrets, by name. It arms no timer: a
/// serving engine's own wait wakes the Dreamer when its next wake is due,
/// and a stopped one serves again on the process's `wake`. It holds no
/// state but the secrets, so every clone answers alike.
#[derive(Clone)]
pub struct ProcessHost {
    secrets: Arc<BTreeMap<String, Zeroizing<Vec<u8>>>>,
}

impl ProcessHost {
    /// A host whose keychain holds `secrets`, by exact name.
    pub fn new(secrets: impl IntoIterator<Item = (String, Vec<u8>)>) -> Self {
        Self {
            secrets: Arc::new(
                secrets
                    .into_iter()
                    .map(|(name, secret)| (name, Zeroizing::new(secret)))
                    .collect(),
            ),
        }
    }
}

impl AppHost for ProcessHost {
    fn keychain(&mut self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        self.secrets
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no such secret in the process host: {name}"))
    }

    fn schedule_wake(&mut self, _at: Option<SystemTime>) -> anyhow::Result<()> {
        Ok(())
    }
}
