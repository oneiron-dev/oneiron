//! Fixture doors for the run TASK writer proof tests (FIX
//! AGENT-RUN-HANDOVER-TRUSTS-REPLICATED-PAYLOAD, FIX
//! AGENT-RUN-OUTLIVED-ROOT-BOUND-FROM-REPLICATED-TASK): the run TASK a peer
//! machine syncs for a run it holds, a root or a child that outlived its
//! root, with or without a writer proof; that TASK's frozen parent bound
//! rewritten by a peer that holds no proof; its executor lease as a peer's
//! sync lands it (REVIEW-9863); a dispatch payload with fields forged or its
//! spawning parent set; and the machine whose writer proof counts on a run
//! TASK here.

use ed25519_dalek::SigningKey;

use crate::agent_dispatch::{
    AgentDispatchInput, decode_agent_dispatch_input, encode_agent_dispatch_input,
    proven_agent_run_task_writer_in, put_peer_agent_run_task_in_txn,
    rewrite_peer_agent_run_task_lease_in_txn, rewrite_peer_agent_run_task_parent_context_in_txn,
};
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::context_projection::ResolvedContextProjection;
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
    put_peer_run_task(vault, payload, node_id, None, writer)
}

/// Puts the run TASK a peer machine of client id `node_id` syncs for a
/// child it promoted to a root of its own when the child's parent settled
/// there (REVIEW-6638), as [`put_peer_agent_run_task`] puts a root's: the
/// TASK is flagged `outlived_root` and freezes the context bound
/// `parent_context` that parent handed the child (`None`: the parent
/// resolved no projection), and `writer`'s proof, when given, covers both.
/// Answers the fresh attempt id.
///
/// # Errors
///
/// As [`put_peer_agent_run_task`].
pub fn put_peer_outlived_root_run_task(
    vault: &Vault,
    payload: &[u8],
    node_id: u64,
    parent_context: Option<&ResolvedContextProjection>,
    writer: Option<PeerWriter<'_>>,
) -> Result<AttemptId> {
    put_peer_run_task(
        vault,
        payload,
        node_id,
        Some(parent_context.cloned()),
        writer,
    )
}

fn put_peer_run_task(
    vault: &Vault,
    payload: &[u8],
    node_id: u64,
    outlived: Option<Option<ResolvedContextProjection>>,
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
        outlived,
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

/// Rewrites the run TASK of the try `attempt` as a peer that holds no
/// proof would, in one whole-row write: its frozen parent bound becomes
/// `parent_context` (`None`: none frozen), its writer proof is dropped, and
/// every other field stays as stored.
///
/// # Errors
///
/// A try with no run TASK under its own id, a TASK that does not decode,
/// and storage errors.
pub fn rewrite_peer_frozen_parent_bound(
    vault: &Vault,
    attempt: AttemptId,
    parent_context: Option<&ResolvedContextProjection>,
) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    rewrite_peer_agent_run_task_parent_context_in_txn(
        vault,
        &mut wtxn,
        attempt,
        parent_context.cloned(),
    )?;
    wtxn.commit()?;
    Ok(())
}

/// Rewrites the executor lease on the run TASK of the try `attempt` in one
/// whole-row write, as the sync of a peer's lease write lands it: the hold
/// ends at `held_until`, held by the machine of client id `node_id` (`None`:
/// the holder stays). Every other field, the writer proof included, stays as
/// stored.
///
/// # Errors
///
/// As [`rewrite_peer_frozen_parent_bound`].
pub fn rewrite_peer_agent_run_lease(
    vault: &Vault,
    attempt: AttemptId,
    node_id: Option<u64>,
    held_until: u64,
) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    rewrite_peer_agent_run_task_lease_in_txn(vault, &mut wtxn, attempt, node_id, held_until)?;
    wtxn.commit()?;
    Ok(())
}

/// `payload` with its spawning parent set to `parent`: the dispatch of a
/// child of that attempt.
///
/// # Errors
///
/// A payload that is no dreamer attempt.
pub fn with_parent_attempt(payload: &[u8], parent: Option<AttemptId>) -> Result<Vec<u8>> {
    let mut decoded = decode_dreamer_attempt_payload(payload)?;
    decoded.parent_attempt = parent;
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
