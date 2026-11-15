//! The helper every generated host door runs (UC-01 PR 1; fable/19 DESIGN section 1.6): the row's engine call off
//! the runtime under its proof rule, on the bare server or on the credential's own handle, beside the rows its reads
//! listed. The generator writes each door as one call of these (`generated/doors.rs`), and adds the rows its row's
//! `rows` names to a success; a hand door may call them too.

use std::sync::Arc;

use oneiron::memory::{Memory, MemoryError, MemoryResult};

use super::proofs::{HandleRule, ProofRule};
use super::support::{Listed, credential_listing, internal, refused};
use crate::api::facade::clock_ingress;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `call` off the runtime under `R`'s proof. It reads through no handle, so it lists no row; a refusal of the proof
/// runs no call.
pub(in crate::api::facade) async fn door<R: ProofRule, T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    call: impl FnOnce(&SyncServer, &R::Proof) -> MemoryResult<T> + Send + 'static,
) -> Listed<T>
where
    R::Proof: Send + 'static,
{
    let proof = match R::prove(server, auth, verb) {
        Ok(proof) => proof,
        Err(refusal) => return refused(refusal),
    };
    let server = Arc::clone(server);
    clock_ingress::run_blocking(move || (call(&server, &proof), Vec::new()))
        .await
        .unwrap_or_else(|_| refused(internal(verb)))
}

/// [`door`] on the credential's own handle, reading as `R`'s actor: beside the answer, the rows the handle's reads
/// listed. The rule's proof comes first, then its actor; a refusal of either runs no call and lists no row.
pub(in crate::api::facade) async fn door_on_handle<R: HandleRule, T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    call: impl FnOnce(&SyncServer, &Memory<'_>, &R::Proof) -> MemoryResult<T> + Send + 'static,
) -> Listed<T>
where
    R::Proof: Send + 'static,
{
    let admitted = || {
        let proof = R::prove(server, auth, verb)?;
        let actor = R::actor(server, auth, &proof)?;
        Ok::<_, MemoryError>((proof, actor))
    };
    let (proof, actor) = match admitted() {
        Ok(admitted) => admitted,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, actor, verb, move |server, _, memory| {
        call(server, &memory, &proof)
    })
    .await
}
