//! The GPU line doors (design pass 32, section 5): `vault.gpu.lines.set`,
//! `.get` and `.families.admit`. The engine decides (`oneiron::gpu_line`):
//! the door admits the caller through the lane economy's door kit
//! (`verb_grant_caller`), calls the engine act, and after each write installs
//! the period's allocation on this server's host account (LM-1). Lines and
//! period records live in side tables, which hold no entity row: the doors
//! list none.

use std::sync::Arc;

use oneiron::gpu_line::{
    GpuLine, GpuLineFamilyAdmitRequest, GpuLineRef, GpuLineSetRequest, GpuLineView,
    VAULT_GPU_LINES_FAMILIES_ADMIT, VAULT_GPU_LINES_GET, VAULT_GPU_LINES_SET,
};
use oneiron::llm::run_admission::AllocationGrantError;

use super::support::Listed;
use super::verb_grant::verb_grant_door;
use crate::auth::CoreAuth;
use crate::gpu_host::now_ms;
use crate::server::SyncServer;

/// Installs the allocation that funds `line`'s period holding `now_ms` on
/// this server's host account (LM-1): one generation per period, so holds
/// made in an older generation still settle there and its unused room
/// lapses. A generation the account already holds, or an older one than it
/// holds, is left as it is. The account lives in memory, so a reserve door
/// calls this before its job's admission.
pub(crate) fn install_line_allocation(server: &SyncServer, line: &GpuLine, now_ms: u64) {
    let Some(index) = line.period_index(now_ms) else {
        return;
    };
    match server.host_account().grant(line.period_allocation(index)) {
        Ok(()) | Err(AllocationGrantError::StaleGeneration) => {}
    }
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
            let now = now_ms();
            let view = memory.set_gpu_line(owner, &input, now)?;
            install_line_allocation(server, &view.line, now);
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
            let now = now_ms();
            let view = memory.admit_gpu_line_family(owner, &input, now)?;
            install_line_allocation(server, &view.line, now);
            Ok(view)
        },
    )
    .await
}
