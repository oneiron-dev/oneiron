//! Actor-bound session observations shared by core reads and board rendering.

use super::{is_shared_session_scope_id, validate_session_id};
use crate::{error::ApiError, server::SyncServer};
use oneiron::context_board::SessionReadSet;
use tokio::sync::{MappedMutexGuard, MutexGuard};

pub(crate) async fn session_read_set<'a>(
    server: &'a SyncServer,
    scope: &str,
    session: Option<&str>,
) -> Result<Option<MappedMutexGuard<'a, SessionReadSet>>, ApiError> {
    if is_shared_session_scope_id(scope) {
        return Ok(None);
    }
    if let Some(session) = session {
        validate_session_id(session, "session_id")?;
    }
    let state = server.memories_cursors.lock().await;
    Ok(Some(MutexGuard::map(state, |state| {
        state.session_reads(scope, session)
    })))
}
