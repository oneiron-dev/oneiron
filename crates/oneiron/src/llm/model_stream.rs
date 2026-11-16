//! Owner-submitted shared model streams over the engine's one-producer
//! [`LlmEventBus`](super::LlmEventBus): many subscribers attach to one
//! generation, deltas stay transient, and only the terminal
//! [`LlmResponse`] (its ordered `ContentPart`s) is durable, read back by
//! the caller's stable `stream_key` after any restart.
use std::sync::Arc;

use super::{FatalLlmError, LlmResponse, LlmResult, TerminalSink};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::memory::{MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::store::model_stream_row::StreamRow;

const STREAMS: SideTable<AttemptId, StreamRow, Named> = SideTable::new(&side_table::MODEL_STREAM);

#[doc(hidden)]
pub use oneiron_verb_wire::llm::model_stream::{
    ModelStreamAbort, ModelStreamDetach, ModelStreamDetached, ModelStreamEvents,
    ModelStreamEventsRequest, ModelStreamOpen, ModelStreamOpened, ModelStreamRelease,
    ModelStreamReleased, ModelStreamStatus, ModelStreamSubscribe, ModelStreamSubscribed,
    ModelStreamTerminal, ModelStreamTerminalRequest,
};

fn status(row: &StreamRow) -> ModelStreamStatus {
    if row.response.is_some() {
        ModelStreamStatus::Finished
    } else if row.failure.is_some() {
        ModelStreamStatus::Failed
    } else {
        ModelStreamStatus::Live
    }
}

fn opened(id: AttemptId, row: &StreamRow) -> ModelStreamOpened {
    ModelStreamOpened {
        stream_ref: bytes_to_hex_lower(id.as_bytes()),
        stream_key: row.stream_key.clone(),
        model: row.request.model.clone(),
        status: status(row),
    }
}

fn terminal_view(id: AttemptId, row: &StreamRow) -> ModelStreamTerminal {
    ModelStreamTerminal {
        stream_ref: bytes_to_hex_lower(id.as_bytes()),
        stream_key: row.stream_key.clone(),
        model: row.request.model.clone(),
        status: status(row),
        response: row.response.clone(),
        failure: row.failure.clone(),
    }
}

fn validate_key(stream_key: &str) -> MemoryResult<()> {
    if stream_key.trim().is_empty() {
        return Err(MemoryError::bad_request("stream_key must not be empty"));
    }
    Ok(())
}

fn identity(actor: EntityId, key: &str) -> Result<AttemptId> {
    let mut hash = blake3::Hasher::new_derive_key("oneiron public model stream v1");
    hash.update(actor.as_bytes());
    hash.update(key.as_bytes());
    let mut id = [0; 16];
    id.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    id[0] &= 0x7f;
    AttemptId::from_bytes(&id)
}

/// Open (or re-read) the caller's durable stream row. The same key with
/// the same request returns the standing row — live, finished or failed —
/// so a replay never starts a second producer; another request under the
/// key is refused inside the write transaction. The boolean is true only
/// for the transaction that created the row and may start its producer.
pub fn open_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &ModelStreamOpen,
) -> MemoryResult<(ModelStreamOpened, bool)> {
    validate_key(&input.stream_key)?;
    let actor = owner.revalidate(vault)?;
    let id = identity(actor, &input.stream_key)?;
    let (row, created) = vault.with_write_txn(|txn| {
        let actor = owner.revalidate_in_txn(vault, txn)?;
        match STREAMS.get(&vault.store, txn, &id)? {
            Some(row) => {
                if row.actor != actor || row.request != input.request {
                    return Err(Error::InvalidConfig(
                        "model-stream key already names another request".into(),
                    ));
                }
                Ok((row, false))
            }
            None => {
                let row = StreamRow {
                    actor,
                    stream_key: input.stream_key.clone(),
                    request: input.request.clone(),
                    response: None,
                    failure: None,
                };
                STREAMS.put(vault, txn, &id, &row)?;
                Ok((row, true))
            }
        }
    })?;
    Ok((opened(id, &row), created))
}

/// The current durable terminal state for a newly attached transient bus.
/// A live row says nothing about whether this process still has its producer.
pub fn retained_terminal_status_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    stream_key: &str,
) -> MemoryResult<Option<ModelStreamStatus>> {
    validate_key(stream_key)?;
    let actor = owner.revalidate(vault)?;
    let id = identity(actor, stream_key)?;
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    Ok(STREAMS
        .get(&vault.store, &txn, &id)?
        .filter(|row| row.actor == actor)
        .map(|row| status(&row))
        .filter(|status| {
            matches!(
                status,
                ModelStreamStatus::Finished | ModelStreamStatus::Failed
            )
        }))
}

/// Read this owner's durable terminal without touching a live producer.
pub fn terminal_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &ModelStreamTerminalRequest,
) -> MemoryResult<ModelStreamTerminal> {
    validate_key(&input.stream_key)?;
    let actor = owner.revalidate(vault)?;
    let id = identity(actor, &input.stream_key)?;
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let row = STREAMS
        .get(&vault.store, &txn, &id)?
        .filter(|row| row.actor == actor)
        .ok_or(Error::EntityNotFound)?;
    Ok(terminal_view(id, &row))
}

/// Stamp a producer that ended without a terminal (source failure, a
/// stream that closed with no `Done`, or a restart that lost it). A row
/// that already holds a terminal or a failure keeps it.
pub fn fail_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    stream_key: &str,
    failure: &str,
) -> MemoryResult<ModelStreamTerminal> {
    validate_key(stream_key)?;
    let actor = owner.revalidate(vault)?;
    let id = identity(actor, stream_key)?;
    let row = vault.with_write_txn(|txn| {
        let actor = owner.revalidate_in_txn(vault, txn)?;
        let mut row = STREAMS
            .get(&vault.store, txn, &id)?
            .filter(|row| row.actor == actor)
            .ok_or(Error::EntityNotFound)?;
        if row.response.is_none() && row.failure.is_none() {
            row.failure = Some(failure.to_owned());
            STREAMS.put(vault, txn, &id, &row)?;
        }
        Ok(row)
    })?;
    Ok(terminal_view(id, &row))
}

/// The durable sink a host gives its [`LlmEventBus`](super::LlmEventBus):
/// the one terminal lands under the owner's proof, revalidated inside
/// the write transaction, and a second terminal is refused.
pub struct ModelStreamSink {
    vault: Arc<Vault>,
    owner: AuthenticatedOwner,
    id: AttemptId,
}

/// Build a sink before or after open. No row is written until the producer
/// publishes its terminal; open must create the row before that can happen.
pub fn sink(
    vault: Arc<Vault>,
    owner: AuthenticatedOwner,
    stream_key: &str,
) -> MemoryResult<ModelStreamSink> {
    validate_key(stream_key)?;
    let actor = owner.revalidate(&vault)?;
    let id = identity(actor, stream_key)?;
    Ok(ModelStreamSink { vault, owner, id })
}

impl ModelStreamSink {
    /// The same stable identity open and terminal derive from the owner and key.
    pub fn stream_ref(&self) -> String {
        bytes_to_hex_lower(self.id.as_bytes())
    }
}

impl TerminalSink for ModelStreamSink {
    fn record(&mut self, terminal: &LlmResponse) -> LlmResult<()> {
        let vault: &Vault = &self.vault;
        let owner = &self.owner;
        let id = self.id;
        vault
            .with_write_txn(|txn| {
                let actor = owner.revalidate_in_txn(vault, txn)?;
                let mut row = STREAMS
                    .get(&vault.store, txn, &id)?
                    .filter(|row| row.actor == actor)
                    .ok_or(Error::EntityNotFound)?;
                if row.response.is_some() || row.failure.is_some() {
                    return Err(Error::InvalidConfig(
                        "model stream already has a terminal".into(),
                    ));
                }
                row.response = Some(terminal.clone());
                STREAMS.put(vault, txn, &id, &row)?;
                Ok(())
            })
            .map_err(|_| FatalLlmError::InvalidRequest.into())
    }
}
