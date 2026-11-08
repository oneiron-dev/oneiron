//! Resolves a pack's reader, room and contacts on one admitted worker.

use super::controls::CoreContextPackRequest;
use super::interlocutor::RoomAudience;
use super::{reader_optional_memory, resolve_core_interlocutor_set, resolve_core_room};
use crate::admission::Permit;
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::server::SyncServer;
use oneiron::claim::{OwnedScopedRead, ScopedRead};
use std::convert::Infallible;
use std::ops::ControlFlow;
use std::sync::Arc;
use tokio::sync::oneshot;

pub(super) struct ResolvedContextInputs {
    pub(super) read: OwnedScopedRead,
    pub(super) req: CoreContextPackRequest,
    pub(super) optional_memory: Option<oneiron::agent_def::OptionalMemory>,
    pub(super) room_id: Option<oneiron::EntityId>,
    pub(super) room_members: Option<Vec<oneiron::EntityId>>,
    pub(super) room: Option<RoomAudience>,
    pub(super) interlocutors: Option<oneiron::InterlocutorSet>,
}

// The turn drops after the inputs if a thread cannot start or its caller leaves.
struct ContextInputWork {
    read: OwnedScopedRead,
    req: CoreContextPackRequest,
    auth: CoreAuth,
    turn: Permit,
}

type InputReply = (Result<ResolvedContextInputs, ApiError>, Permit);

/// What one request's reader, room and contacts resolve to under the
/// caller's own read.
struct ContextInputParts {
    optional_memory: Option<oneiron::agent_def::OptionalMemory>,
    room_id: Option<oneiron::EntityId>,
    room_members: Option<Vec<oneiron::EntityId>>,
    room: Option<RoomAudience>,
    interlocutors: Option<oneiron::InterlocutorSet>,
}

impl ContextInputParts {
    /// The reader profile, room and contacts `req` names, in that order,
    /// under `read`. `checkpoint` runs before each stage after the first:
    /// a break there ends the stages with nothing resolved.
    fn resolve<B>(
        read: &ScopedRead<'_>,
        auth: &CoreAuth,
        req: &CoreContextPackRequest,
        checkpoint: impl Fn() -> ControlFlow<B>,
    ) -> Result<ControlFlow<B, Self>, ApiError> {
        let optional_memory = reader_optional_memory(read, req.reader.as_ref())?;
        if let ControlFlow::Break(stop) = checkpoint() {
            return Ok(ControlFlow::Break(stop));
        }
        let room_id = req
            .conversation_id
            .as_deref()
            .map(|room| super::super::parse_entity_id_param(room, "conversation_id"))
            .transpose()?;
        let (room_members, room) = resolve_core_room(read.vault(), auth, read, room_id)?;
        if let ControlFlow::Break(stop) = checkpoint() {
            return Ok(ControlFlow::Break(stop));
        }
        let interlocutors = resolve_core_interlocutor_set(
            read.vault(),
            auth,
            read,
            req.interlocutors.as_ref(),
            room.as_ref(),
        )?;
        Ok(ControlFlow::Continue(Self {
            optional_memory,
            room_id,
            room_members,
            room,
            interlocutors,
        }))
    }

    fn into_inputs(
        self,
        read: OwnedScopedRead,
        req: CoreContextPackRequest,
    ) -> ResolvedContextInputs {
        let Self {
            optional_memory,
            room_id,
            room_members,
            room,
            interlocutors,
        } = self;
        ResolvedContextInputs {
            read,
            req,
            optional_memory,
            room_id,
            room_members,
            room,
            interlocutors,
        }
    }
}

impl ContextInputWork {
    fn run(self, answer: oneshot::Sender<InputReply>) {
        if answer.is_closed() {
            return;
        }
        let closed = || {
            if answer.is_closed() {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        };
        let (read, inputs) = self
            .read
            .with_read(|read| ContextInputParts::resolve(read, &self.auth, &self.req, closed));
        let result = match inputs {
            Ok(ControlFlow::Continue(parts)) => Ok(parts.into_inputs(read, self.req)),
            Ok(ControlFlow::Break(())) => return,
            Err(error) => {
                drop(read);
                drop(self.req);
                Err(error)
            }
        };
        drop(self.auth);
        // Failed delivery drops the payload before returning its worker turn.
        let _ = answer.send((result, self.turn));
    }
}

/// `read`, the caller's own base reader, with its exact state moved into an
/// owner of the server's vault, as a worker or a validated pack holds it.
pub(super) fn transferred(
    server: &SyncServer,
    read: ScopedRead<'_>,
) -> Result<OwnedScopedRead, ApiError> {
    read.into_owned_base(Arc::clone(&server.vault))
        .map_err(|_| ApiError::internal_server_error("context-pack reader transfer failed"))
}

pub(super) async fn resolve_context_inputs(
    server: &SyncServer,
    auth: &CoreAuth,
    read: ScopedRead<'_>,
    req: CoreContextPackRequest,
) -> Result<ResolvedContextInputs, ApiError> {
    let read = transferred(server, read)?;
    let caller = auth
        .principal_ref()
        .unwrap_or(auth.principal())
        .trim()
        .to_owned();
    let turn = server.context_reads.admit_untimed(caller).await;
    let work = ContextInputWork {
        read,
        req,
        auth: auth.clone(),
        turn,
    };
    let (answer, returned) = oneshot::channel();
    std::thread::Builder::new()
        .name("context-pack-inputs".into())
        .spawn(move || work.run(answer))
        .map_err(|_| {
            ApiError::internal_server_error("context-pack input worker could not start")
        })?;
    let (result, _turn) = returned
        .await
        .map_err(|_| ApiError::internal_server_error("context-pack input worker failed"))?;
    result
}

/// [`resolve_context_inputs`] on the calling thread, for a verb hook's
/// rewritten request: the hook chain's own blocking thread resolves it
/// (FIX 1435). It takes no worker turn: the original request's turn stays
/// with the request it admitted.
pub(super) fn resolve_context_inputs_here(
    server: &SyncServer,
    auth: &CoreAuth,
    read: ScopedRead<'_>,
    req: CoreContextPackRequest,
) -> Result<ResolvedContextInputs, ApiError> {
    let read = transferred(server, read)?;
    let (read, parts) = read.with_read(|read| {
        ContextInputParts::resolve(read, auth, &req, || ControlFlow::<Infallible>::Continue(()))
    });
    let ControlFlow::Continue(parts) = parts?;
    Ok(parts.into_inputs(read, req))
}
