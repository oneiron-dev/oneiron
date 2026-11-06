//! The registry's singular native open and insertion result.

use std::sync::Arc;

use oneiron::Vault;

use super::{ActiveLane, SharedEnvEntry, SharedEnvRegistry, SharedEnvSpec, open_one, run_lane};

impl SharedEnvRegistry {
    /// Opens one configured entry, runs its lane unless it has left, and
    /// inserts it, returning that actual strongly held native vault. Invalid
    /// entries and failures still log, but a join caller also receives the
    /// error instead of inferring success from a void return. A refused first
    /// admission still defers only the lane run, not registry membership.
    pub(crate) async fn insert(
        &self,
        entry: &crate::config::SharedEnvConfig,
        config: &crate::config::ServeConfig,
        lease_vault_id: u64,
        admission: crate::server::HousekeepingAdmission,
        freeze: Option<crate::device_sync::ReapFreeze>,
    ) -> Result<Arc<Vault>, String> {
        let spec = match SharedEnvSpec::from_config(entry) {
            Ok(spec) => spec,
            Err(error) => {
                tracing::warn!("shared env skipped: {error:#}");
                return Err(error.to_string());
            }
        };
        let present = self
            .lock()
            .contains_key(&(spec.vault_id, spec.member.clone()));
        if present {
            tracing::warn!(
                vault_id = spec.vault_id,
                path = %spec.path.display(),
                "shared env skipped: its membership is already open"
            );
            return Err("shared env membership is already open".into());
        }
        let config = config.clone();
        let opened =
            tokio::task::spawn_blocking(move || open_one(&spec, &config, lease_vault_id)).await;
        match opened {
            Ok(Ok(env)) => {
                let lane = if env.left {
                    // Already left: no run needs an admission.
                    None
                } else {
                    let first = admission();
                    let (stop, stop_rx) = tokio::sync::oneshot::channel();
                    let task = tokio::spawn(run_lane(
                        Arc::clone(&env.connection),
                        stop_rx,
                        freeze,
                        first,
                        env.key.0,
                    ));
                    Some(ActiveLane {
                        connection: Arc::clone(&env.connection),
                        stop,
                        task,
                        vault_id: env.key.0,
                    })
                };
                // A completed purge stays complete across restarts: the
                // receipt persists it, so reconfirming never re-owes the
                // orphan-body collection. An unreadable receipt reads as
                // incomplete: the idempotent confirmation resumes it.
                let purge_complete =
                    match oneiron::sync::shared_leave::leave_purge_complete(&env.vault) {
                        Ok(complete) => complete,
                        Err(error) => {
                            tracing::warn!(
                                vault_id = env.key.0,
                                kind = ?error.kind(),
                                "shared env purge state unreadable; its leave reconfirms"
                            );
                            false
                        }
                    };
                let vault = Arc::clone(&env.vault);
                self.lock().insert(
                    env.key,
                    SharedEnvEntry {
                        path: env.path,
                        home_url: env.home_url,
                        vault: env.vault,
                        connection: env.connection,
                        lane,
                        purge_complete,
                        last_leave_check: 0,
                    },
                );
                Ok(vault)
            }
            Ok(Err(reason)) => {
                tracing::warn!("shared env skipped: {reason}");
                Err(reason)
            }
            Err(error) => {
                tracing::warn!("shared env skipped: its open task failed: {error}");
                Err(error.to_string())
            }
        }
    }

    /// The native handle currently held for this exact membership.
    pub(crate) fn get(&self, vault_id: u64, member: &str) -> Option<Arc<Vault>> {
        self.lock()
            .get(&(vault_id, member.to_owned()))
            .map(|entry| Arc::clone(&entry.vault))
    }
}
