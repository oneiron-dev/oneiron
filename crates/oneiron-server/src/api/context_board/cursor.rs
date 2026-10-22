//! Server-owned MEMORIES cursors and session read sets, keyed by principal and session.
//! Each lives until its session closes or its run ends; a shared scope's lives with the
//! process. None is evicted by count (FIX 8143, CALLS P2-a).

use std::collections::BTreeMap;

use super::super::CoreContextPackEvidence;

pub(crate) const MEMORIES_CURSOR_SESSION_ID_MAX_BYTES: usize = 256;

pub(crate) const MEMORIES_CURSOR_LAST_RESULT_IDS_MAX: usize = 256;

pub(crate) const SHARED_SESSION_SCOPE_IDS: &[&str] =
    &["bearer", "dev-bearer", "default", "legacy-shared-secret"];

#[derive(Default)]
pub(crate) struct MemoriesCursorStore {
    pub(crate) entries: BTreeMap<String, oneiron::MemoriesCursor>,
    pub(crate) read_sets: BTreeMap<String, oneiron::context_board::SessionReadSet>,
    active_sessions: BTreeMap<String, String>,
}

impl MemoriesCursorStore {
    pub(crate) fn session_reads(
        &mut self,
        scope: &str,
        session: Option<&str>,
    ) -> &mut oneiron::context_board::SessionReadSet {
        let cursor = match session {
            Some(session) => self.current(session_key(scope, session), session),
            None => self.current_for_scope(scope.to_owned(), session_key(scope, scope), scope),
        };
        let key = session_key(scope, &cursor.session_id);
        self.active_sessions.insert(scope.to_owned(), key.clone());
        self.read_sets.entry(key).or_default()
    }

    /// The session a request naming `session`, or none, reads. A request
    /// resolves it once, so a later step never lands in another session that
    /// became active meanwhile.
    pub(crate) fn resolve_session(&mut self, scope: &str, session: Option<&str>) -> String {
        match session {
            Some(session) => session.to_owned(),
            None => {
                self.current_for_scope(scope.to_owned(), session_key(scope, scope), scope)
                    .session_id
            }
        }
    }

    pub(crate) fn current(&mut self, key: String, session_id: &str) -> oneiron::MemoriesCursor {
        if let Some(state) = self.entries.get(&key) {
            return state.clone();
        }

        let state = oneiron::MemoriesCursor::new(session_id);
        self.entries.insert(key, state.clone());
        state
    }

    fn current_for_scope(
        &mut self,
        scope_key: String,
        default_key: String,
        default_session_id: &str,
    ) -> oneiron::MemoriesCursor {
        if let Some(active_key) = self.active_sessions.get(&scope_key).cloned() {
            if let Some(state) = self.entries.get(&active_key) {
                return state.clone();
            }
            self.active_sessions.remove(&scope_key);
        }

        self.current(default_key, default_session_id)
    }

    pub(crate) fn advance(
        &mut self,
        scope_key: String,
        key: String,
        session_id: &str,
        pack: &oneiron::ContextPack,
        evidence: &CoreContextPackEvidence,
    ) -> oneiron::MemoriesCursor {
        if !self.entries.contains_key(&key) {
            self.entries
                .insert(key.clone(), oneiron::MemoriesCursor::new(session_id));
        }

        let state = self
            .entries
            .get_mut(&key)
            .expect("entry inserted before mutation");
        state.revision = state.revision.saturating_add(1);
        state.query_count = state.query_count.saturating_add(1);
        state.last_retrieval_run_id = evidence.retrieval_run_id.clone();
        state.last_result_ids = pack
            .results
            .iter()
            .take(MEMORIES_CURSOR_LAST_RESULT_IDS_MAX)
            .map(|entity| entity.id.to_hex())
            .collect();
        let state = state.clone();
        self.active_sessions.insert(scope_key, key);
        state
    }

    /// Closes the session kept under `key`, as its lifecycle ends it: its
    /// cursor, its read set (riders, loaded skills and explanations with it)
    /// and any scope's pointer to it as the active session. No other
    /// session's state is touched.
    pub(crate) fn close(&mut self, key: &str) {
        self.entries.remove(key);
        self.read_sets.remove(key);
        self.active_sessions
            .retain(|_, active_key| active_key != key);
    }

    /// Closes every pumped run session kept on board connection
    /// `connection` (`run:<run id>`), as the run ends: each key a run's read
    /// set is kept under (`run_read_set_key`: the "run" tag, the agent's
    /// class and id, the connection) that names it.
    pub(crate) fn close_run_connection(&mut self, connection: &str) {
        let runs: Vec<String> = self
            .entries
            .keys()
            .chain(self.read_sets.keys())
            .filter(|key| {
                serde_json::from_str::<(String, String, String, String)>(key)
                    .is_ok_and(|(tag, _, _, on)| tag == "run" && on == connection)
            })
            .cloned()
            .collect();
        for key in runs {
            self.close(&key);
        }
    }
}

pub(crate) fn memories_cursor_key(
    vault: &oneiron::Vault,
    scope_id: &str,
    session_id: &str,
) -> String {
    let _ = vault; // Server ownership is the vault boundary; keys cannot alias through pointers.
    session_key(scope_id, session_id)
}

pub(crate) fn memories_cursor_scope_key(vault: &oneiron::Vault, scope_id: &str) -> String {
    let _ = vault;
    scope_id.to_owned()
}

pub(crate) async fn current_memories_cursor(
    server: &crate::server::SyncServer,
    scope_id: &str,
) -> oneiron::MemoriesCursor {
    let vault = &server.vault;
    let scope_key = memories_cursor_scope_key(vault, scope_id);
    let default_key = memories_cursor_key(vault, scope_id, scope_id);
    server
        .memories_cursors
        .lock()
        .await
        .current_for_scope(scope_key, default_key, scope_id)
}

pub(crate) async fn advance_memories_cursor(
    server: &crate::server::SyncServer,
    scope_id: &str,
    session_id: &str,
    pack: &oneiron::ContextPack,
    evidence: &CoreContextPackEvidence,
    read: &oneiron::claim::ScopedRead<'_>,
) -> oneiron::Result<(oneiron::MemoriesCursor, oneiron::claim::ScopedReadReceipt)> {
    let vault = &server.vault;
    let scope_key = memories_cursor_scope_key(vault, scope_id);
    let key = memories_cursor_key(vault, scope_id, session_id);
    let mut store = server.memories_cursors.lock().await;
    let mut observed = store.session_reads(scope_id, Some(session_id)).clone();
    let mut ids: Vec<_> = pack
        .results
        .iter()
        .chain(&pack.neighbors)
        .map(|entity| entity.id)
        .collect();
    if let Some(base) = &pack.l2_base {
        ids.extend_from_slice(base.evidence_ids());
    }
    let receipt = observed.observe_rows(read, &ids)?;
    // Why each row appeared, for an explain read (OF-278): this run and the
    // row's place among its results, or a neighbor's reach.
    let run = evidence.retrieval_run_id.as_deref();
    for (rank, entity) in pack.results.iter().enumerate() {
        observed.served_from_run(entity.id.to_hex(), run, u32::try_from(rank + 1).ok(), false);
    }
    for entity in &pack.neighbors {
        observed.served_from_run(entity.id.to_hex(), run, None, true);
    }
    let cursor = store.advance(scope_key, key, session_id, pack, evidence);
    *store.session_reads(scope_id, Some(session_id)) = observed;
    Ok((cursor, receipt))
}

fn session_key(scope_id: &str, session_id: &str) -> String {
    serde_json::to_string(&(scope_id, session_id)).expect("string tuple serializes")
}
