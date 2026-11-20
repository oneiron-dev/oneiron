//! Fixture doors for the run TASK writer proof test (FIX
//! AGENT-RUN-HANDOVER-TRUSTS-REPLICATED-PAYLOAD): the run TASK a peer
//! machine syncs for a run it holds, with or without a writer proof; a
//! dispatch payload with fields forged; and the machine whose writer proof
//! counts on a run TASK here.

use ed25519_dalek::SigningKey;

use crate::agent_dispatch::{
    AgentDispatchInput, decode_agent_dispatch_input, encode_agent_dispatch_input,
    proven_agent_run_task_writer_in, put_peer_agent_run_task_in_txn,
};
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::dreamer_runner::{decode_dreamer_attempt_payload, encode_dreamer_attempt_payload};
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

/// The writer proof a peer's run TASK carries.
pub struct PeerWriter<'a> {
    /// The machine whose proof it is.
    pub machine: EntityId,
    /// The install key that signs as that machine.
    pub key: &'a SigningKey,
    /// The frozen payload the machine signed, when it is not the one the
    /// TASK carries: a TASK changed after its proof was made. `None`: the
    /// payload the TASK carries.
    pub signed_payload: Option<&'a [u8]>,
}

/// Puts the run TASK a peer machine of client id `node_id` syncs for a root
/// run it holds, with `payload` frozen and its lease long expired, under a
/// fresh attempt id this queue holds no row of, carrying `writer`'s proof
/// when given. Answers that attempt id.
///
/// # Errors
///
/// A payload that is no agent dispatch, a vault with no genesis-bound id for
/// a signed TASK, and storage errors.
pub fn put_peer_agent_run_task(
    vault: &Vault,
    payload: &[u8],
    node_id: u64,
    writer: Option<PeerWriter<'_>>,
) -> Result<AttemptId> {
    let attempt = AttemptId::now();
    let mut wtxn = vault.store.env.write_txn()?;
    put_peer_agent_run_task_in_txn(
        vault,
        &mut wtxn,
        attempt,
        payload,
        node_id,
        writer.map(|writer| {
            (
                writer.machine,
                writer.key,
                writer.signed_payload.unwrap_or(payload),
            )
        }),
    )?;
    wtxn.commit()?;
    Ok(attempt)
}

/// The queue payload of the try `attempt` this queue holds: the bytes its
/// dispatch froze.
///
/// # Errors
///
/// A try this queue holds no row of, and storage errors.
pub fn queue_payload(vault: &Vault, attempt: AttemptId) -> Result<Vec<u8>> {
    AttemptQueue::new(vault)
        .get(attempt)?
        .map(|record| record.payload)
        .ok_or(Error::EntityNotFound)
}

/// `payload` with its agent dispatch input changed by `edit`.
///
/// # Errors
///
/// A payload that is no agent dispatch.
pub fn with_dispatch_input(
    payload: &[u8],
    edit: impl FnOnce(&mut AgentDispatchInput),
) -> Result<Vec<u8>> {
    let mut decoded = decode_dreamer_attempt_payload(payload)?;
    let mut input = decode_agent_dispatch_input(&decoded.input)?;
    edit(&mut input);
    decoded.input = encode_agent_dispatch_input(&input)?;
    encode_dreamer_attempt_payload(&decoded)
}

/// The machine whose writer proof counts here on the run TASK of the try
/// `attempt`; `None` with no such TASK or no proof that counts.
///
/// # Errors
///
/// A run TASK that does not read, and storage errors.
pub fn agent_run_task_writer(vault: &Vault, attempt: AttemptId) -> Result<Option<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    proven_agent_run_task_writer_in(vault, &txn, attempt)
}
