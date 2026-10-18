//! Full-row vector uploads under the caller's own owner proof and write gate.
use std::sync::Arc;

use oneiron::memory::{MemoryResult, VectorPutReceipt, VectorPutRequest};

use super::FacadeApiError;
use super::host_doors::{Listed, credential_listing, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_vectors_put(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: VectorPutRequest,
) -> Listed<VectorPutReceipt> {
    let verb = "vault.vectors.put";
    let admitted = || -> MemoryResult<_> {
        let owner = owner_proof(auth, server, verb)?;
        let caller = super::facade_actor(server, auth)
            .map_err(FacadeApiError::into_memory_error)?;
        Ok((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return (Err(error), Vec::new()),
    };
    credential_listing(server, auth, caller, verb, move |_, _, memory| {
        memory.put_vector_as_owner(&owner, &input)
    })
    .await
}
