//! The host's half of the origin mirror pushes (ARCH-0068 RA8; FIX 6866).
//!
//! The lifecycle tick starts a pass over every mirror target: each due
//! `schedule` mirror, each `full_auto` mirror and each open plan. The
//! vault-owned wake ([`oneiron::Vault::origin_mirror_wake`]) starts a pass
//! of its own at once when a published ref moves or the merge queue lands
//! green: every `full_auto` mirror and every open plan, and no other
//! lifecycle job. Passes never overlap; a wake that comes while one runs is
//! kept and starts the next pass when it ends. Each push waits for a git
//! exchange permit, then takes the host's write gate, both held until it
//! ends, and a stopping host starts no further push.

use std::sync::Arc;

use super::core::SyncServer;
use super::housekeeping::HousekeepingAdmission;
use super::lifecycle::LifecycleJobKind;

impl SyncServer {
    /// Starts a pass over the served repositories' mirror targets on a task
    /// of its own, held for the host's stop, unless a pass is still going or
    /// the host is stopping. `woken`: the vault's wake started it, so it
    /// reads no cadence; a pass already going answers that wake when it
    /// ends.
    pub(super) async fn start_mirror_pushes(
        self: &Arc<Self>,
        admit: &HousekeepingAdmission,
        woken: bool,
    ) {
        if woken {
            // Kept before the pass is asked for, so a pass ending meanwhile
            // still hands it on.
            self.vault().defer_origin_mirror_wake();
        }
        if self.housekeeping_passes.stopping()
            || !self.begin_lifecycle_job(LifecycleJobKind::MirrorPush).await
        {
            return;
        }
        // This pass reads every full-auto mirror as it stands: it answers
        // the kept wake.
        self.vault().take_origin_mirror_wake();
        let server = Arc::clone(self);
        let admit = Arc::clone(admit);
        let run = tokio::spawn(async move {
            server.push_mirrors(admit, woken).await;
            server.end_lifecycle_job(LifecycleJobKind::MirrorPush).await;
            // A wake that came while this pass ran starts the next one.
            if server.vault().take_origin_mirror_wake() {
                server.vault().wake_origin_mirrors();
            }
        });
        self.housekeeping_passes.hold(run);
    }

    /// One pass. Each push waits for a git exchange permit, then takes the
    /// host's write gate, both held until it ends.
    async fn push_mirrors(self: &Arc<Self>, admit: HousekeepingAdmission, woken: bool) {
        let server = Arc::clone(self);
        let run = tokio::task::spawn_blocking(move || {
            let admit = || {
                let permit = server.wait_for_git_permit()?;
                let admission = admit()?;
                Some(Box::new((permit, admission)) as Box<dyn Send>)
            };
            let stop = || server.housekeeping_passes.stopping();
            if woken {
                server.vault().push_woken_origin_mirrors(admit, stop)
            } else {
                server.vault().push_due_origin_mirrors(admit, stop)
            }
        })
        .await;
        match run {
            Ok(Ok(run)) if run.pushed + run.failed > 0 => {
                tracing::info!(
                    targets = run.targets,
                    pushed = run.pushed,
                    skipped = run.skipped,
                    failed = run.failed,
                    woken,
                    "origin mirror pushes ran"
                );
            }
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                tracing::warn!(kind = ?error.kind(), "origin mirror pushes failed");
            }
            Err(error) => {
                tracing::warn!(
                    panicked = error.is_panic(),
                    "origin mirror push task failed"
                );
            }
        }
    }
}
