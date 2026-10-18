//! Owner-only extraction doors over the caller's own credential read lane.
use std::sync::Arc;

use oneiron::memory::{
    MemoryError, SignalExtractionRequest, SignalExtractionResult, SignalExtractionResultRequest,
    SignalExtractionTicket,
};
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::{Listed, credential_listing, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_memory_signal_extraction(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: SignalExtractionRequest,
) -> Listed<SignalExtractionTicket> {
    const VERB: &str = "vault.memory.signal_extraction";
    if session.is_some() {
        return refused(off_record());
    }
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.signal_extraction_as_owner(&owner, &input)
    })
    .await
}

pub(crate) async fn vault_memory_signal_extraction_result(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: SignalExtractionResultRequest,
) -> Listed<Option<SignalExtractionResult>> {
    const VERB: &str = "vault.memory.signal_extraction.result";
    if session.is_some() {
        return refused(off_record());
    }
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.signal_extraction_result_as_owner(&owner, &input)
    })
    .await
}

fn off_record() -> MemoryError {
    MemoryError::new(
        oneiron::memory::MEMORY_CODE_OFF_RECORD_SESSION_DOOR,
        "durable signal extraction requires canonical witnessed turns",
        &[],
    )
}
