//! The served hook regen pass (ARCH-0080 §8, FIX 4689). Each lifecycle tick
//! asks the engine for the hooks of the vault's own packs whose verb table
//! or sandbox contract moved under them; when any is due, it runs the
//! engine's regen pass ([`oneiron::Vault::run_hook_regen_pass`]) on a
//! blocking thread, off the request path, with the Coach's regenerator and
//! the vault's hook sandbox. An identical fingerprint adopts: an agent's
//! hook through its own put, any other through the owner's put when this
//! host is the owner's own (self-hosted); elsewhere the AutoAdopt waits on
//! the record for the owner (CALLS HOOK-REGEN-AUTO-ADOPT). Plain and managed
//! serve run the same scheduler, so both run it.
//!
//! Log lines carry counts and an error's kind, never a body or an intent.

use std::sync::Arc;

use oneiron::runtime_hooks::HookRegenPassReport;

use super::core::SyncServer;
use super::housekeeping::HousekeepingAdmission;
use super::lifecycle::LifecycleJobKind;
use crate::ai_host::hook_regen::ServedHookRegenerator;

impl SyncServer {
    /// Starts the hook regen pass on a task of its own, held for the host's
    /// stop, unless the last one is still running, the host is stopping, or
    /// the host's gate refused it. A stopping host lets the regen in hand
    /// finish and starts no other.
    pub(super) async fn start_hook_regen_pass(self: &Arc<Self>, admit: &HousekeepingAdmission) {
        if self.housekeeping_passes.stopping()
            || !self.begin_lifecycle_job(LifecycleJobKind::HookRegen).await
        {
            return;
        }
        let Some(admission) = admit() else {
            self.end_lifecycle_job(LifecycleJobKind::HookRegen).await;
            return;
        };
        let server = Arc::clone(self);
        let handle = tokio::runtime::Handle::current();
        let run = tokio::spawn(async move {
            let _admission = admission;
            let pass = Arc::clone(&server);
            match tokio::task::spawn_blocking(move || regen_due_hooks(&pass, &handle)).await {
                Ok(Ok(Some(report))) => {
                    if report.regenerated + report.failed > 0 {
                        tracing::info!(
                            regenerated = report.regenerated,
                            adopted = report.adopted,
                            waiting = report.waiting,
                            failed = report.failed,
                            "hook regen pass ran"
                        );
                    }
                }
                Ok(Ok(None)) => {}
                Ok(Err(error)) => {
                    tracing::warn!(kind = ?error.kind(), "hook regen pass failed");
                }
                Err(error) => {
                    tracing::warn!(panicked = error.is_panic(), "hook regen task failed");
                }
            }
            server.end_lifecycle_job(LifecycleJobKind::HookRegen).await;
        });
        self.housekeeping_passes.hold(run);
    }
}

/// The engine's regen pass over the due hooks, or `None` when none is due.
/// The hook sandbox is taken only then, so a vault with no due hook builds
/// none.
fn regen_due_hooks(
    server: &Arc<SyncServer>,
    handle: &tokio::runtime::Handle,
) -> oneiron::Result<Option<HookRegenPassReport>> {
    let vault = server.vault();
    if vault.hooks_due_for_regen()?.is_empty() {
        return Ok(None);
    }
    let runtime = crate::commands::hook_sandbox(server)
        .map_err(|reason| oneiron::Error::InvalidConfig(format!("no hook sandbox: {reason}")))?;
    // The owner's proof only where this host is the owner's own.
    let owner = crate::owner::host_owner(vault).ok();
    let seat: &SyncServer = server;
    vault
        .run_hook_regen_pass(
            runtime.as_ref(),
            move |binding| ServedHookRegenerator::open(seat, binding, handle.clone()),
            owner.as_ref(),
            || !server.housekeeping_passes.stopping(),
        )
        .map(Some)
}
