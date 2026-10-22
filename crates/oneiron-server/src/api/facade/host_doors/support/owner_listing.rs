//! The owner-listing `as_owner` shared by the artifact, commitment, code wait and hook regen doors.
//! `as_owner` is its call surface: the owner's proof, then the caller; a refusal is `refused`.
//! The support root defines `owner_proof`, `refused` and the listing this wrapper runs.

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{Memory, MemoryError, MemoryResult};

use super::{Listed, credential_listing, owner_proof, refused};
use crate::api::facade::FacadeApiError;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(in crate::api::facade) async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&Memory<'_>, &AuthenticatedOwner) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let admitted = || {
        let owner = owner_proof(auth, server, verb)?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok::<_, MemoryError>((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, verb, move |_, _, memory| {
        act(&memory, &owner)
    })
    .await
}
