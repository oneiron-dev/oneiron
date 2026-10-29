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

use oneiron::authority::{ActSurface, HostSlipIssuer};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError};
use oneiron::vault_shape::{ShapeApplier, ShapeApplyReceipt, ShapeApplyRequest};

use super::host_doors::support::{MaybeListed, internal};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.shape.apply`: lands a plan, or resumes the apply of one. Beside
/// it, the rows its receipt stands on ([`oneiron::Vault::apply_shape_listing`]):
/// what the first apply's re-plan read, the seed revision, each landing's
/// live reads and writes, kept by the apply's journal so a resumed apply
/// lists them too (FIX 3411, 3513). A refusal lists the rows read before
/// it; a refusal before any read lists none. `None` once a read ran whose
/// rows the apply does not follow, and for a blocking task that did not
/// finish.
pub(crate) async fn vault_shape_apply(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: ShapeApplyRequest,
) -> MaybeListed<ShapeApplyReceipt> {
    const VERB: &str = "vault.shape.apply";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let server = Arc::clone(server);
    // A hosted operator's root gets the typed refusal, never a fallback
    // caller (FIX 4371).
    if let Err(refusal) = super::owner_binding::host_preflight(&server, auth) {
        return (Err(refusal), Some(Vec::new()));
    }
    if let Ok(owner) = crate::api::owner_routes::owner(auth, &server) {
        return tokio::task::spawn_blocking(move || -> MaybeListed<ShapeApplyReceipt> {
            // Each attempt lists into a set of its own.
            let apply = |slips: Option<&HostSlipIssuer>| -> MaybeListed<ShapeApplyReceipt> {
                let (receipt, rows) = server.vault().apply_shape_listing(
                    ShapeApplier::Owner {
                        owner: &owner,
                        slips,
                        surface,
                    },
                    &input,
                    now,
                    &mut |_| Ok(true),
                );
                (receipt.map_err(MemoryError::from), rows)
            };
            // With the host's slip issuer, a member the shape lowers or
            // removes loses their slips; a host with none still applies.
            crate::api::pairing::with_issuer(&server, |issuer| Ok(apply(Some(issuer))))
                .unwrap_or_else(|_| apply(None))
        })
        .await
        .unwrap_or_else(|_| (Err(internal(VERB)), None));
    }
    let Ok((actor, class)) = super::facade_actor(&server, auth) else {
        let refusal = MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{VERB} applies as the vault owner or an authenticated principal"),
            &["Present the owner's credential, or a slip that names a principal."],
        );
        return (Err(refusal), Some(Vec::new()));
    };
    let auth = auth.clone();
    tokio::task::spawn_blocking(move || {
        crate::api::credential_memory(&server.vault, Some(&auth), actor, class)
            .at(auth.locality())
            .shape_apply_as_principal_listing(&input)
    })
    .await
    .unwrap_or_else(|_| (Err(internal(VERB)), None))
}
