//! The host door of `vault.messages.react` (OF-181). `host_doors`
//! re-exports it, so the generated HTTP facade handler, the MCP dispatcher
//! and `POST /v1/core/messages/{m}/reactions` all run one reaction write.
//! A local change writes as the credential's principal, who must be the
//! reacting person. A provider's reaction is connector ingress: only an
//! owner-grade credential brings it, and the mirror MACHINE writes it.
//! Beside the receipt, the door lists the rows it names (`host_door_lists`).
use std::sync::Arc;

use oneiron::WriteActor;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::reaction::{MessageReactionReceipt, MessageReactionRequest};

use super::FacadeApiError;
use super::host_doors::support::{Listed, hex_rows, internal, naming};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.messages.react`: one reaction change as the credential's
/// principal, or a provider's reaction on an owner-grade credential.
/// Beside it, the rows its receipt names: the reaction claim, the message
/// or turn it is on, the reacting person and, for a provider's echo, the
/// first-party claim it answers. The room the change lands in admits the
/// reactor; it is no source of the receipt.
pub(crate) async fn vault_messages_react(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MessageReactionRequest,
) -> Listed<MessageReactionReceipt> {
    let named = [
        Some(input.message.clone()),
        Some(input.by.clone()),
        input
            .external
            .as_ref()
            .and_then(|external| external.origin.clone()),
    ];
    naming(
        vault_messages_react_answer(server, auth, input).await,
        |receipt| {
            hex_rows(
                std::iter::once(receipt.id.as_str())
                    .chain(named.iter().flatten().map(String::as_str)),
            )
        },
    )
}

async fn vault_messages_react_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MessageReactionRequest,
) -> MemoryResult<MessageReactionReceipt> {
    let actor = match input.external {
        Some(_) => None,
        None => {
            // The one resolver names the actor (FIX 2222): a self-hosted root
            // or the dev mode reacts as the owner, by that owner alone, and a
            // hosted operator's root is refused.
            let (actor, class) =
                super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
            if oneiron::EntityId::from_hex(&input.by).ok() != Some(actor) {
                return Err(MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    "a reaction is by the credential's own principal",
                    &["Name the credential's own principal as `by`."],
                ));
            }
            Some(WriteActor::new(actor, class))
        }
    };
    react_message(server, auth, actor, input).await
}

/// One reaction change: a provider's reaction when `input` names its
/// external side and `auth` is owner-grade, else a local change as `actor`.
/// The REST route passes the actor its body bound, which an owner-grade
/// credential with no principal may name; every other caller passes the
/// credential's own.
pub(crate) async fn react_message(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    actor: Option<WriteActor>,
    input: MessageReactionRequest,
) -> MemoryResult<MessageReactionReceipt> {
    let vault = Arc::clone(&server.vault);
    if input.external.is_some() {
        if !auth.is_owner_grade() {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a provider reaction needs an owner-grade credential",
                &[],
            ));
        }
        let ingress = input.ingress()?;
        return tokio::task::spawn_blocking(move || vault.ingest_reaction(ingress))
            .await
            .map_err(|_| internal("vault.messages.react"))?
            .map(MessageReactionReceipt::from)
            .map_err(MemoryError::from);
    }
    let actor = actor.ok_or_else(|| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "a reaction is written by a bound actor",
            &[],
        )
    })?;
    tokio::task::spawn_blocking(move || {
        input
            .apply_as(&vault, actor)
            .map(MessageReactionReceipt::from)
    })
    .await
    .map_err(|_| internal("vault.messages.react"))?
}
