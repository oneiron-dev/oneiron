//! Who reads engine substrate rows through a host door (untangle 6.6c): the
//! vault owner under its proof, or a person or agent on a verified slip of
//! its own, whose Steward grant (`read`, or `engine.controls` for the dials)
//! the engine checks at the read. Anyone else keeps the owner refusal.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::MemoryResult;
use oneiron::{EdgeActorClass, WriteActor};

use super::FacadeApiError;
use super::host_doors::support::{internal, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The owner under its proof (`Some`), or a person or agent on its own
/// verified slip (`None`), whose grant the engine reader checks.
pub(super) fn substrate_reader(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<Option<AuthenticatedOwner>> {
    match owner_proof(auth, server, verb) {
        Ok(owner) => Ok(Some(owner)),
        Err(refusal) => match (auth.verified_slip(), super::facade_actor(server, auth)) {
            (Some(_), Ok((_, EdgeActorClass::Human | EdgeActorClass::Agent))) => Ok(None),
            _ => Err(refusal),
        },
    }
}

/// `act` off the runtime, as the caller `auth` binds: every substrate read
/// reads LMDB, and the engine checks the caller's grant inside `act`.
pub(super) async fn as_reader<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, WriteActor) -> MemoryResult<T> + Send + 'static,
) -> MemoryResult<T> {
    let (actor, class) =
        super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
    let reader = WriteActor::new(actor, class);
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || act(&server, reader))
        .await
        .map_err(|_| internal(verb))?
}
