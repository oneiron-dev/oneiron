//! The GPU line doors (design pass 32, section 5): `vault.gpu.lines.set`,
//! `.get` and `.families.admit`. The engine decides (`oneiron::gpu_line`):
//! the door admits the caller through the lane economy's door kit
//! (`verb_grant_caller`), calls the engine act, and after each write installs
//! the allocation the period record names on this server's host account
//! (section 4.1). Lines and period records live in side tables, which hold no
//! entity row: the doors list none.

use std::sync::Arc;

use oneiron::gpu_line::{
    GPU_SECONDS, GpuLineFamilyAdmitRequest, GpuLinePeriod, GpuLineRef, GpuLineSetRequest,
    GpuLineView, VAULT_GPU_LINES_FAMILIES_ADMIT, VAULT_GPU_LINES_GET, VAULT_GPU_LINES_SET,
    gpu_seconds,
};
use oneiron::llm::run_admission::AllocationGrantError;
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MemoryError, MemoryResult};

use super::support::Listed;
use super::verb_grant::verb_grant_door;
use crate::auth::CoreAuth;
use crate::gpu_host::now_ms;
use crate::server::SyncServer;

/// Installs the allocation `period` names on this server's host account:
/// one generation per period, so holds made in an older generation still
/// settle there and its unused room lapses. A generation the account already
/// holds, or an older one than it holds, is left as it is. The account
/// lives in memory, so a reserve door calls this before its job's admission.
pub(crate) fn install_line_allocation(server: &SyncServer, period: &GpuLinePeriod) {
    match server
        .host_account()
        .grant(period.allocation.allocation(gpu_seconds()))
    {
        Ok(()) | Err(AllocationGrantError::StaleGeneration) => {}
    }
}

/// Installs the allocation of `view`'s period when the door minted it.
fn install_view_allocation(server: &SyncServer, view: &GpuLineView) {
    if let Some(period) = view.period.as_ref().filter(|_| !view.preview) {
        install_line_allocation(server, period);
    }
}

/// Refuses an offer this host does not post, or one whose terms a line
/// cannot manage: a line counts one GPU-second as one unit, so the offer's
/// rate is 1 `gpu_seconds` and it adds no startup, teardown or rounding.
fn check_managed_offers(server: &SyncServer, offers: &[String]) -> MemoryResult<()> {
    for name in offers {
        let managed = server.config.gpu_jobs.offer(name).is_some_and(|posted| {
            let offer = &posted.offer;
            offer.connector.unit_cost == 1
                && offer.connector.cost_unit.as_str() == GPU_SECONDS
                && offer.startup_secs == 0
                && offer.teardown_secs == 0
                && offer.rounding_secs == 0
        });
        if !managed {
            return Err(MemoryError::new(
                MEMORY_CODE_BAD_REQUEST,
                format!(
                    "{VAULT_GPU_LINES_SET}: offer_not_managed: this host posts no offer {name} \
                     at rate 1 gpu_seconds with no overhead"
                ),
                &[],
            ));
        }
    }
    Ok(())
}

/// `vault.gpu.lines.set`: the owner sets one lane project's GPU line.
pub(crate) async fn vault_gpu_lines_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GpuLineSetRequest,
) -> Listed<GpuLineView> {
    verb_grant_door(
        server,
        auth,
        VAULT_GPU_LINES_SET,
        move |server, memory, owner| {
            if owner.is_some() {
                check_managed_offers(server, &input.policy.offers)?;
            }
            let view = memory.set_gpu_line(owner, &input, now_ms())?;
            install_view_allocation(server, &view);
            Ok(view)
        },
    )
    .await
}

/// `vault.gpu.lines.get`: one lane project's GPU line and the record of the
/// period that holds now.
pub(crate) async fn vault_gpu_lines_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GpuLineRef,
) -> Listed<GpuLineView> {
    verb_grant_door(
        server,
        auth,
        VAULT_GPU_LINES_GET,
        move |_, memory, owner| Ok(memory.gpu_line_view(owner, &input.project, now_ms())?),
    )
    .await
}

/// `vault.gpu.lines.families.admit`: seats one child project of the lane as
/// a family on its GPU line.
pub(crate) async fn vault_gpu_lines_families_admit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GpuLineFamilyAdmitRequest,
) -> Listed<GpuLineView> {
    verb_grant_door(
        server,
        auth,
        VAULT_GPU_LINES_FAMILIES_ADMIT,
        move |server, memory, owner| {
            let view = memory.admit_gpu_line_family(owner, &input, now_ms())?;
            install_view_allocation(server, &view);
            Ok(view)
        },
    )
    .await
}
