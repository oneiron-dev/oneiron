//! Owner registry and reveal-settlement doors, shared by HTTP and MCP.
use super::host_doors::support::{Listed, internal, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron::disclosure::{DisclosureCeilingRequest, DisclosureCeilingSet, DisclosureCeilingView};
use oneiron::memory::MemoryResult;
use oneiron::task_verb::sdk::{
    RevealAnswerRequest, RevealAnsweredView, RevealAskView, RevealAsksRequest,
};
use std::sync::Arc;

pub(crate) async fn vault_disclosure_ceiling_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DisclosureCeilingRequest,
) -> Listed<DisclosureCeilingView> {
    let answer = async {
        let owner = owner_proof(auth, server, "vault.disclosure.ceiling.get")?;
        let server = Arc::clone(server);
        tokio::task::spawn_blocking(move || {
            server
                .vault()
                .model_disclosure_ceiling(&owner, input)
                .map_err(Into::into)
        })
        .await
        .map_err(|_| internal("vault.disclosure.ceiling.get"))?
    }
    .await;
    (answer, Vec::new())
}

pub(crate) async fn vault_disclosure_ceiling_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DisclosureCeilingSet,
) -> Listed<DisclosureCeilingView> {
    let answer = async {
        let owner = owner_proof(auth, server, "vault.disclosure.ceiling.set")?;
        let server = Arc::clone(server);
        tokio::task::spawn_blocking(move || {
            server
                .vault()
                .set_model_disclosure_ceiling(&owner, input)
                .map_err(Into::into)
        })
        .await
        .map_err(|_| internal("vault.disclosure.ceiling.set"))?
    }
    .await;
    (answer, Vec::new())
}

pub(crate) async fn vault_disclosure_ceiling_clear(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DisclosureCeilingRequest,
) -> Listed<DisclosureCeilingView> {
    let answer = async {
        let owner = owner_proof(auth, server, "vault.disclosure.ceiling.clear")?;
        let server = Arc::clone(server);
        tokio::task::spawn_blocking(move || {
            server
                .vault()
                .clear_model_disclosure_ceiling(&owner, input)
                .map_err(Into::into)
        })
        .await
        .map_err(|_| internal("vault.disclosure.ceiling.clear"))?
    }
    .await;
    (answer, Vec::new())
}

pub(crate) async fn vault_disclosure_reveals(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RevealAsksRequest,
) -> Listed<Vec<RevealAskView>> {
    let answer: MemoryResult<Vec<RevealAskView>> = async {
        let owner = owner_proof(auth, server, "vault.disclosure.reveals")?;
        let server = Arc::clone(server);
        tokio::task::spawn_blocking(move || {
            oneiron::task_verb::sdk::disclosure_reveals_as_owner(server.vault(), &owner, input)
        })
        .await
        .map_err(|_| internal("vault.disclosure.reveals"))?
    }
    .await;
    (answer, Vec::new())
}

pub(crate) async fn vault_disclosure_reveals_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RevealAnswerRequest,
) -> Listed<RevealAnsweredView> {
    let answer: MemoryResult<RevealAnsweredView> = async {
        let owner = owner_proof(auth, server, "vault.disclosure.reveals.answer")?;
        let server = Arc::clone(server);
        tokio::task::spawn_blocking(move || {
            oneiron::task_verb::sdk::answer_disclosure_reveal_as_owner(
                server.vault(),
                &owner,
                input,
            )
        })
        .await
        .map_err(|_| internal("vault.disclosure.reveals.answer"))?
    }
    .await;
    (answer, Vec::new())
}
