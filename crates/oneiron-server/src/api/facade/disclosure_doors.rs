//! Owner reveal-settlement doors, shared by HTTP and MCP.
use super::host_doors::support::{Listed, internal, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron::memory::MemoryResult;
use oneiron::task_verb::sdk::{
    RevealAnswerRequest, RevealAnsweredView, RevealAskView, RevealAsksRequest,
};
use std::sync::Arc;

pub(crate) async fn vault_disclosure_reveals(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RevealAsksRequest,
) -> Listed<Vec<RevealAskView>> {
    let answer: MemoryResult<Vec<RevealAskView>> = async {
        let owner = owner_proof(auth, server, "vault.disclosure.reveals")?;
        let server = Arc::clone(server);
        super::clock_ingress::run_blocking(move || {
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
        super::clock_ingress::run_blocking(move || {
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
