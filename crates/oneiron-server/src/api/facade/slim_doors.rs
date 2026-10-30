//! Owner-bound lifecycle doors; each transport reaches the same engine transaction.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::slim::public::{
    SavedResumeStep, SlimDropReceipt, SlimDropRequest, SlimIdlePolicy, SlimResumeReceipt,
    SlimResumeStepRequest, SlimStateSnapshot,
};
use oneiron::task_verb::sdk::EmptyRequest;

use super::host_doors::support::{Listed, internal, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

async fn owned<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &AuthenticatedOwner) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let owner = match owner_proof(auth, server, verb) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    let answer = super::clock_ingress::run_blocking(move || {
        owner.revalidate(server.vault())?;
        act(&server, &owner)
    })
    .await
    .unwrap_or_else(|_| Err(internal(verb)));
    (answer, Vec::new())
}

pub(crate) async fn vault_slim_policy(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _: EmptyRequest,
) -> Listed<SlimIdlePolicy> {
    owned(server, auth, "vault.slim.policy", |_, _| {
        Ok(crate::models::outbound_wait::policy())
    })
    .await
}

pub(crate) async fn vault_slim_state(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _: EmptyRequest,
) -> Listed<SlimStateSnapshot> {
    owned(server, auth, "vault.slim.state", |server, _| {
        Ok(server.vault().slim_state_snapshot())
    })
    .await
}

/// The owner's shed waits its turn, and for a moment it can be decided,
/// rather than being refused while more than one outbound step is pending
/// (FIX 10157). Each look runs on the blocking pool and revalidates the
/// owner first; the wait between looks holds no thread.
pub(crate) async fn vault_slim_drop_heavy(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SlimDropRequest,
) -> Listed<SlimDropReceipt> {
    const VERB: &str = "vault.slim.drop_heavy";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let answer = server
        .vault()
        .shed_rebuildable_heap_as_owner(owner, input, |attempt| async move {
            super::clock_ingress::run_blocking(move || attempt.run())
                .await
                .map_err(|_| internal(VERB))
        })
        .await;
    (answer, Vec::new())
}

pub(crate) async fn vault_slim_resume(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _: EmptyRequest,
) -> Listed<SlimResumeReceipt> {
    owned(server, auth, "vault.slim.resume", |server, _| {
        server
            .vault()
            .resume_from_slim_on_inbound()
            .map(SlimResumeReceipt::from)
            .map_err(MemoryError::from)
    })
    .await
}

pub(crate) async fn vault_slim_resume_step(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SlimResumeStepRequest,
) -> Listed<SavedResumeStep> {
    let (answer, mut rows) = owned(
        server,
        auth,
        "vault.slim.resume_step",
        move |server, owner| {
            oneiron::slim::public::saved_resume_step_as_owner(server.vault(), owner, input)
        },
    )
    .await;
    if let Ok(SavedResumeStep::Model { checkpoint, .. }) = &answer {
        rows.extend(
            checkpoint
                .claim_ref
                .as_deref()
                .and_then(|id| oneiron::EntityId::from_hex(id).ok()),
        );
    }
    (answer, rows)
}
