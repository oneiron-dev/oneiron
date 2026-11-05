//! Resolves a pack's reader, room and contacts on one admitted worker.

use super::controls::CoreContextPackRequest;
use super::interlocutor::RoomAudience;
use super::{reader_optional_memory, resolve_core_interlocutor_set, resolve_core_room};
use crate::admission::Permit;
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::server::SyncServer;
use oneiron::claim::{OwnedScopedRead, ScopedRead};
use std::sync::Arc;
use tokio::sync::oneshot;

/// Keeps the already-allocated interlocutor controls charged with their request.
pub(super) struct RetainedContextRequest {
    pub(super) request: CoreContextPackRequest,
    _storage: oneiron_contracts::host_memory::MemoryLease,
}

impl RetainedContextRequest {
    fn new(request: CoreContextPackRequest, memory: &crate::machine::MachineMemory) -> Self {
        let bytes = request
            .interlocutors
            .as_ref()
            .map_or(0, |controls| controls.retained_storage_bytes());
        let mut storage = memory.empty_lease();
        storage.materialized(0, bytes);
        Self {
            request,
            _storage: storage,
        }
    }
}

pub(super) struct ResolvedContextInputs {
    pub(super) read: OwnedScopedRead,
    pub(super) req: RetainedContextRequest,
    pub(super) optional_memory: Option<oneiron::agent_def::OptionalMemory>,
    pub(super) room_id: Option<oneiron::EntityId>,
    pub(super) room_members: Option<Vec<oneiron::EntityId>>,
    pub(super) room: Option<RoomAudience>,
    pub(super) interlocutors: Option<oneiron::InterlocutorSet>,
}

// The turn drops after the inputs if a thread cannot start or its caller leaves.
struct ContextInputWork {
    read: OwnedScopedRead,
    req: RetainedContextRequest,
    auth: CoreAuth,
    turn: Permit,
}

type InputReply = (Result<ResolvedContextInputs, ApiError>, Permit);

impl ContextInputWork {
    fn run(self, answer: oneshot::Sender<InputReply>) {
        if answer.is_closed() {
            return;
        }
        let (read, inputs) = self.read.with_read(|read| {
            let optional_memory = reader_optional_memory(read, self.req.request.reader.as_ref())?;
            if answer.is_closed() {
                return Ok(None);
            }
            let room_id = self
                .req
                .request
                .conversation_id
                .as_deref()
                .map(|room| super::super::parse_entity_id_param(room, "conversation_id"))
                .transpose()?;
            let (room_members, room) = resolve_core_room(read.vault(), &self.auth, read, room_id)?;
            if answer.is_closed() {
                return Ok(None);
            }
            let interlocutors = resolve_core_interlocutor_set(
                read.vault(),
                &self.auth,
                read,
                self.req.request.interlocutors.as_ref(),
                room.as_ref(),
            )?;
            Ok::<_, ApiError>(Some((
                optional_memory,
                room_id,
                room_members,
                room,
                interlocutors,
            )))
        });
        let result = match inputs {
            Ok(Some((optional_memory, room_id, room_members, room, interlocutors))) => {
                Ok(ResolvedContextInputs {
                    read,
                    req: self.req,
                    optional_memory,
                    room_id,
                    room_members,
                    room,
                    interlocutors,
                })
            }
            Ok(None) => return,
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

pub(super) async fn resolve_context_inputs(
    server: &SyncServer,
    auth: &CoreAuth,
    read: ScopedRead<'_>,
    req: CoreContextPackRequest,
) -> Result<ResolvedContextInputs, ApiError> {
    let read = read
        .into_owned_base(Arc::clone(&server.vault))
        .map_err(|_| ApiError::internal_server_error("context-pack reader transfer failed"))?;
    let req = RetainedContextRequest::new(req, &server.memory);
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
