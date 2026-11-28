//! The GPU line doors (design pass 32, section 5): `vault.gpu.lines.set`,
//! `.get` and `.families.admit`. The engine decides (`oneiron::gpu_line`):
//! the door admits the caller through the lane economy's door kit
//! (`verb_grant_caller`) and calls the engine act. The period record names
//! its allocation; its standing is a fold over the line's claims in the
//! vault, never a grant into this server's in-memory host account (Engine
//! ruling HOLD-IS-CLAIM-FOLD = A). Lines and period records live in side
//! tables, which hold no entity row: the doors list none.

use std::sync::Arc;

use oneiron::gpu_line::{
    GpuLineError, GpuLineFamilyAdmitRequest, GpuLinePolicy, GpuLineRef, GpuLineSetWire,
    GpuLineView, VAULT_GPU_LINES_FAMILIES_ADMIT, VAULT_GPU_LINES_GET, VAULT_GPU_LINES_SET,
};

use super::support::Listed;
use super::verb_grant::verb_grant_door;
use crate::auth::CoreAuth;
use crate::gpu_host::now_ms;
use crate::server::SyncServer;

/// Refuses an offer this host does not post, or one whose terms a line
/// cannot manage: a line counts one second as one unit, so the offer's cost
/// unit is the line's unit (pass 34, 3.1), its rate is 1 and it adds no
/// startup, teardown or rounding.
fn check_managed_offers(server: &SyncServer, policy: &GpuLinePolicy) -> Result<(), GpuLineError> {
    for name in &policy.offers {
        let managed = server.config.gpu_jobs.offer(name).is_some_and(|posted| {
            let offer = &posted.offer;
            offer.connector.unit_cost == 1
                && offer.connector.cost_unit == policy.unit
                && offer.startup_secs == 0
                && offer.teardown_secs == 0
                && offer.rounding_secs == 0
        });
        if !managed {
            return Err(GpuLineError::OfferNotManaged {
                offer: name.clone(),
                unit: policy.unit.as_str().to_owned(),
            });
        }
    }
    Ok(())
}

/// `vault.gpu.lines.set`: the owner sets one lane project's GPU line.
pub(crate) async fn vault_gpu_lines_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GpuLineSetWire,
) -> Listed<GpuLineView> {
    verb_grant_door(
        server,
        auth,
        VAULT_GPU_LINES_SET,
        move |server, memory, owner| {
            // The engine act checks the offers and unit in force (the stated
            // fields over the preset's document where one is named, pass 34,
            // 3.2) against this host's offers inside its write, after its
            // intent replay: a pack installed meanwhile cannot skip the check.
            let offers_managed = |policy: &GpuLinePolicy| check_managed_offers(server, policy);
            Ok(memory.set_gpu_line_from_wire(owner, &input, &offers_managed, now_ms())?)
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
        move |_, memory, owner| Ok(memory.admit_gpu_line_family(owner, &input, now_ms())?),
    )
    .await
}
