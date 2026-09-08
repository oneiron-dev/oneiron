//! The per-process MEMORIES cursor store, keyed by vault, principal scope and session.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::sync::OnceLock;
use tokio::sync::Mutex;

use super::super::CoreContextPackEvidence;

pub(crate) const MEMORIES_CURSOR_MAX_ENTRIES: usize = 1024;

pub(crate) const MEMORIES_CURSOR_SESSION_ID_MAX_BYTES: usize = 256;

pub(crate) const MEMORIES_CURSOR_LAST_RESULT_IDS_MAX: usize = 256;

pub(crate) const SHARED_SESSION_SCOPE_IDS: &[&str] =
    &["bearer", "dev-bearer", "default", "legacy-shared-secret"];

pub(crate) static MEMORIES_CURSOR_STORE: OnceLock<Mutex<MemoriesCursorStore>> = OnceLock::new();

#[derive(Default)]
pub(crate) struct MemoriesCursorStore {
    pub(crate) entries: BTreeMap<String, oneiron::MemoriesCursor>,
    active_sessions: BTreeMap<String, String>,
    insertion_order: VecDeque<String>,
}

impl MemoriesCursorStore {
    pub(crate) fn current(&mut self, key: String, session_id: &str) -> oneiron::MemoriesCursor {
        if let Some(state) = self.entries.get(&key) {
            return state.clone();
        }

        self.evict_if_full();
        let state = oneiron::MemoriesCursor::new(session_id);
        self.entries.insert(key.clone(), state.clone());
        self.insertion_order.push_back(key);
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
            self.evict_if_full();
            self.entries
                .insert(key.clone(), oneiron::MemoriesCursor::new(session_id));
            self.insertion_order.push_back(key.clone());
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

    fn evict_if_full(&mut self) {
        while self.entries.len() >= MEMORIES_CURSOR_MAX_ENTRIES {
            let Some(key) = self.insertion_order.pop_front() else {
                self.entries.clear();
                self.active_sessions.clear();
                break;
            };
            if self.entries.remove(&key).is_some() {
                self.active_sessions
                    .retain(|_, active_key| active_key != &key);
                break;
            }
        }
    }
}

pub(crate) fn memories_cursor_store() -> &'static Mutex<MemoriesCursorStore> {
    MEMORIES_CURSOR_STORE.get_or_init(|| Mutex::new(MemoriesCursorStore::default()))
}

pub(crate) fn memories_cursor_key(
    vault: &oneiron::Vault,
    scope_id: &str,
    session_id: &str,
) -> String {
    format!("{vault:p}:{scope_id}:{session_id}")
}

pub(crate) fn memories_cursor_scope_key(vault: &oneiron::Vault, scope_id: &str) -> String {
    format!("{vault:p}:{scope_id}")
}

pub(crate) async fn current_memories_cursor(
    vault: &oneiron::Vault,
    scope_id: &str,
) -> oneiron::MemoriesCursor {
    let scope_key = memories_cursor_scope_key(vault, scope_id);
    let default_key = memories_cursor_key(vault, scope_id, scope_id);
    memories_cursor_store()
        .lock()
        .await
        .current_for_scope(scope_key, default_key, scope_id)
}

pub(crate) async fn advance_memories_cursor(
    vault: &oneiron::Vault,
    scope_id: &str,
    session_id: &str,
    pack: &oneiron::ContextPack,
    evidence: &CoreContextPackEvidence,
) -> oneiron::MemoriesCursor {
    let scope_key = memories_cursor_scope_key(vault, scope_id);
    let key = memories_cursor_key(vault, scope_id, session_id);
    memories_cursor_store()
        .lock()
        .await
        .advance(scope_key, key, session_id, pack, evidence)
}
