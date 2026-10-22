//! `vault.shape.apply` (ARCH-0070) as a host door: the gated landing of a
//! shape plan. The vault owner's credential, as `/v1/owner` takes it, lands
//! the plan through the owner's doors, widenings only for the items it
//! approves. Any other credential applies as its principal: the seed is
//! stored and every item waits for the owner's word. The generated facade
//! handler and the MCP dispatcher both call this through `host_doors`, with
//! where the owner's request reached this install (`surface`, the host's own
//! reading of it, never a field of the input): the audit record of his
//! conversation-learning answer, when a creation carries one (FIX 5603).
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::authority::{ActSurface, HostSlipIssuer};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::vault_shape::{ShapeApplier, ShapeApplyReceipt, ShapeApplyRequest};

use super::host_doors::support::{MaybeListed, internal};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// A receipt beside the rows it stands on, `None` when they are unknown.
type ShapeApplyListing = (ShapeApplyReceipt, Option<Vec<EntityId>>);

/// `vault.shape.apply`: lands a plan, or resumes the apply of one. Beside
/// it, the rows its receipt stands on ([`oneiron::Vault::apply_shape_listing`]):
/// what the re-plan read, the seed revision, each landing's live reads and
/// writes. `None` for a resumed apply, and once an item lands through a
/// door whose reads it does not follow. A refusal lists no row.
pub(crate) async fn vault_shape_apply(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: ShapeApplyRequest,
) -> MaybeListed<ShapeApplyReceipt> {
    match vault_shape_apply_answer(server, auth, surface, input).await {
        Ok((receipt, rows)) => (Ok(receipt), rows),
        Err(refusal) => (Err(refusal), Some(Vec::new())),
    }
}

/// [`vault_shape_apply`]'s answer, beside its listing.
async fn vault_shape_apply_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: ShapeApplyRequest,
) -> MemoryResult<ShapeApplyListing> {
    const VERB: &str = "vault.shape.apply";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let server = Arc::clone(server);
    // A hosted operator's root gets the typed refusal, never a fallback
    // caller (FIX 4371).
    super::owner_binding::host_preflight(&server, auth)?;
    if let Ok(owner) = crate::api::owner_routes::owner(auth, &server) {
        return tokio::task::spawn_blocking(move || -> MemoryResult<ShapeApplyListing> {
            // Each attempt lists into a set of its own.
            let apply = |slips: Option<&HostSlipIssuer>| -> MemoryResult<ShapeApplyListing> {
                Ok(server.vault().apply_shape_listing(
                    ShapeApplier::Owner {
                        owner: &owner,
                        slips,
                        surface,
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
    let (actor, class) = super::facade_actor(&server, auth).map_err(|_| {
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
            .shape_apply_as_principal_listing(&input)
    })
    .await
    .map_err(|_| internal(VERB))?
}
