//! The host door of the owner's project-card tap (OF-501):
//! `vault.projects.confirm`. `host_doors` re-exports it, so the generated
//! HTTP facade handler and the MCP dispatcher call it by the name every host
//! door has, and a tool call, a code-mode call and an SDK call meet one
//! admission: the vault owner's proof, as `/v1/owner` takes it
//! (`owner_routes::owner`). The tap names only the card, its action and when
//! it was made; the door binds the authenticated owner as its actor, the
//! surface it was made on, and the owner's project signer under the host's
//! slip issuer (the one `api/pairing.rs` builds), as `sign_root_project`
//! signs the root. The engine's `Vault::confirm_project_card` reads the
//! host-held card, mints or converts, and answers an exact retry with the
//! receipt it saved. The embedded handle's `projects_confirm` keeps refusing.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::genui::{
    ConsentActionKind, ConsentActionRequest, ConsentActorIdentity, ConsentSurface,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::workspace_roster::{ProjectCardConfirmRequest, ProjectMintReceipt};

use super::host_doors::internal;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The surface a project-card tap reaching this door was made on. The tap
/// carries no surface of its own and every caller of this door is the
/// owner's own app or tool, so the host names the owner's dashboard, as the
/// owner's feedback approval does.
const PROJECT_CARD_TAP_SURFACE: ConsentSurface = ConsentSurface::Dashboard;

/// `vault.projects.confirm`: the owner's tap mints the project a host-held
/// card proposes. Beside the answer, the records it derives from: the card's
/// source message, room and thread, and the project it minted.
pub(crate) async fn vault_projects_confirm(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ProjectCardConfirmRequest,
) -> (MemoryResult<ProjectMintReceipt>, Vec<EntityId>) {
    const VERB: &str = "vault.projects.confirm";
    let refused = || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{VERB} is the vault owner's"),
            &["Present the owner's own verified, unattenuated credential."],
        )
    };
    let Ok(owner) = crate::api::owner_routes::owner(auth, server) else {
        return (Err(refused()), Vec::new());
    };
    let Some(principal_ref) = auth.principal_ref().map(str::to_owned) else {
        return (Err(refused()), Vec::new());
    };
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        let vault = server.vault();
        let mut listed = Vec::new();
        match vault.project_card(&input.card_id) {
            Ok(Some(record)) => {
                let card = &record.card;
                listed.extend(
                    std::iter::once(&card.source_message_ref)
                        .chain(card.source_room_ref.as_ref())
                        .chain(card.source_thread_ref.as_ref())
                        .filter_map(|id| EntityId::from_hex(id).ok()),
                );
            }
            Ok(None) => {}
            Err(error) => return (Err(MemoryError::from(error)), listed),
        }
        let tap = match ConsentActionRequest::new(
            input.card_id.clone(),
            input.action_id,
            ConsentActionKind::ProjectMint,
            ConsentActorIdentity::SurfaceActor {
                actor_ref: principal_ref,
            },
            PROJECT_CARD_TAP_SURFACE,
            input.occurred_at,
        ) {
            Ok(tap) => tap,
            Err(error) => return (Err(MemoryError::from(error)), listed),
        };
        let minted = crate::api::pairing::with_issuer(&server, |issuer| {
            Ok(vault
                .owner_project_signer(issuer)
                .and_then(|signer| {
                    vault.confirm_project_card(&input.card_id, &tap, &owner, &signer)
                })
                .map_err(MemoryError::from))
        })
        .map_err(|_| internal(VERB))
        .and_then(|minted| minted);
        if let Ok(receipt) = &minted {
            listed.extend(EntityId::from_hex(&receipt.project_id).ok());
        }
        listed.dedup();
        (minted, listed)
    })
    .await
    .unwrap_or_else(|_| (Err(internal(VERB)), Vec::new()))
}
