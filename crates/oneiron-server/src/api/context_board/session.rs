//! Actor-bound session observations shared by core reads and board rendering.

use super::{is_shared_session_scope_id, validate_session_id};
use crate::{error::ApiError, server::SyncServer};
use oneiron::context_board::SessionReadSet;
use tokio::sync::{MappedMutexGuard, MutexGuard};

/// The session id a request reads, resolved once; `None` for a shared scope.
pub(crate) async fn resolved_session_id(
    server: &SyncServer,
    scope: &str,
    session: Option<&str>,
) -> Result<Option<String>, ApiError> {
    if is_shared_session_scope_id(scope) {
        return Ok(None);
    }
    if let Some(session) = session {
        validate_session_id(session, "session_id")?;
    }
    Ok(Some(
        server
            .memories_cursors
            .lock()
            .await
            .resolve_session(scope, session),
    ))
}

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

/// Closes the board session kept under `key` as its lifecycle ends it (FIX
/// 8143): a pumped run's, when its board connection's door goes. A session a
/// caller names by a free label has no close of its own, so it stays, as the
/// shared scope's does, with the process; nothing closes one by count, age or
/// memory pressure.
pub(crate) async fn close_board_session(server: &SyncServer, key: &str) {
    server.memories_cursors.lock().await.close(key);
}
