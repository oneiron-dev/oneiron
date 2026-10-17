//! `vault.shape.apply` (ARCH-0070) as a host door: the gated landing of a
//! shape plan. The vault owner's credential, as `/v1/owner` takes it, lands
//! the plan through the owner's doors, widenings only for the items it
//! approves. Any other credential applies as its principal: the seed is
//! stored and every item waits for the owner's word. The generated facade
//! handler and the MCP dispatcher both call this through `host_doors`.
use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::vault_shape::{ShapeApplier, ShapeApplyReceipt, ShapeApplyRequest};

use super::host_doors::internal;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.shape.apply`: lands a plan, or resumes the apply of one.
pub(crate) async fn vault_shape_apply(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ShapeApplyRequest,
) -> MemoryResult<ShapeApplyReceipt> {
    const VERB: &str = "vault.shape.apply";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let server = Arc::clone(server);
    if let Ok(owner) = crate::api::owner_routes::owner(auth, &server) {
        return tokio::task::spawn_blocking(move || -> MemoryResult<ShapeApplyReceipt> {
            let apply = |slips: Option<&HostSlipIssuer>| -> MemoryResult<ShapeApplyReceipt> {
                Ok(server.vault().apply_shape(
                    ShapeApplier::Owner {
                        owner: &owner,
                        slips,
                    },
                    &input,
                    now,
                    &mut |_| Ok(true),
                )?)
            };
            // With the host's slip issuer, a member the shape lowers or
            // removes loses their slips; a host with none still applies.
            crate::api::pairing::with_issuer(&server, |issuer| Ok(apply(Some(issuer))))
                .unwrap_or_else(|_| apply(None))
        })
        .await
        .map_err(|_| internal(VERB))?;
    }
    let (actor, class) = super::facade_actor(auth).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{VERB} applies as the vault owner or an authenticated principal"),
            &["Present the owner's credential, or a slip that names a principal."],
        )
    })?;
    let auth = auth.clone();
    tokio::task::spawn_blocking(move || {
        crate::api::credential_memory(&server.vault, Some(&auth), actor, class)
            .at(auth.locality())
            .shape_apply_as_principal(&input)
    })
    .await
    .map_err(|_| internal(VERB))?
}
