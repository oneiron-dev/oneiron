//! The session-only verb-hook record store (FIX 4283; ARCH-0052, ARCH-0080
//! §3, §6).
//!
//! A call that keeps no record still runs its verb hooks: a `no_record` row
//! (`NO_RECORD_ROWS`), or a call in an anonymous off-record session its
//! principal is verified in (`Memory::keeps_no_record`). Only where their
//! records go changes
//! ([`crate::task_verb::verb_hook_boundary::hook_session`]). What a chain's
//! commit writes (its receipts, saved runs, blocks with their lineage, and
//! its intents) and the call a hook's ask stopped stay here, in this
//! process's memory, for the live session the call ran in. None of it is
//! written to the vault.
//!
//! A session's records go once it is no longer live: the next touch of the
//! store drops them. All of them go with the process, so a hook's pause never
//! resumes after a restart, and its caller is told so. A `no_record` row
//! called outside a live session keeps its chain's records for no session:
//! only its ask's pause is held, for this process.
//!
//! Each chain record is kept as the side-table row the vault would hold (its
//! full stored key and its encoded value), so a reader in the session decodes
//! it with that table's own codec.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock, PoisonError};

use serde_json::Value;

use crate::skill_hub::pack_catalog::HookActorClass;
use crate::{EntityId, Vault};

/// Where a session-only call's hook records live.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SessionHookKey {
    /// A live off-record session: its registry key, and when it was entered,
    /// so a session entered again under the same name starts with none.
    Session { key: String, entered_at: u64 },
    /// No live session: the call's chain records go once its chain ends, and
    /// only its ask's pause is held, for this process.
    Process,
}

impl SessionHookKey {
    /// The key of a call whose surface binds `binding`'s session for its
    /// principal, read as [`Vault::off_record_session_is_anonymous_for`]
    /// reads it (a creator's name resolves to its instance). [`Self::Process`]
    /// when the surface binds none, or one that is not live now.
    pub(crate) fn of(vault: &Vault, binding: Option<(&str, Option<EntityId>)>) -> Self {
        let Some((session, principal)) = binding else {
            return Self::Process;
        };
        let session = session.trim();
        let registry = &vault.store.off_record_sessions;
        let key = principal
            .and_then(|principal| registry.created_key(session, principal))
            .unwrap_or_else(|| session.to_owned());
        match registry.record(&key) {
            Some(record) if !record.closing => Self::Session {
                key,
                entered_at: record.entered_at,
            },
            _ => Self::Process,
        }
    }

    /// Whether the session this key names is still the live one.
    fn live(&self, vault: &Vault) -> bool {
        match self {
            Self::Process => true,
            Self::Session { key, entered_at } => vault
                .store
                .off_record_sessions
                .record(key)
                .is_some_and(|record| record.entered_at == *entered_at && !record.closing),
        }
    }
}

/// One chain record, as the vault would hold it.
#[derive(Debug, Clone)]
pub(crate) struct SessionHookRow {
    /// Its full stored key, its table's prefix first.
    pub(crate) key: Vec<u8>,
    /// Its value, in its table's codec.
    pub(crate) value: Vec<u8>,
    /// Whether a later write of its key replaces it, as a retried call's
    /// saved run and receipt do; a block, its lineage and an intent are
    /// written once.
    pub(crate) replaces: bool,
}

/// A call a session-only call's hook ask stopped: what a retry of its
/// invocation in the same session reads.
#[derive(Debug, Clone)]
pub(crate) struct SessionVerbAsk {
    pub(crate) verb: String,
    pub(crate) actor: EntityId,
    pub(crate) class: HookActorClass,
    /// The args the asking hook saw, re-validated.
    pub(crate) args: Value,
    /// The asking hook's place in the pre chain.
    pub(crate) position: usize,
    pub(crate) binding: EntityId,
    /// `<pack>/<hook>`.
    pub(crate) hook: String,
    /// The hook's author, who asked and reads the answer.
    pub(crate) author: EntityId,
    pub(crate) author_class: HookActorClass,
    /// The ask's group: its handle.
    pub(crate) ask: EntityId,
    /// Set once a retry resumed the call on a proceed answer, which it used.
    pub(crate) used: bool,
}

/// This process's session-only hook records, by session. Nothing here is
/// stored.
#[derive(Default)]
pub(crate) struct SessionHookStore {
    sessions: Mutex<BTreeMap<SessionHookKey, SessionHooks>>,
    /// The key that hides a session-only call's invocation in the intent key
    /// of the ask its hook opens: drawn once per process, never stored.
    hiding: OnceLock<[u8; 32]>,
}

/// One session's records.
#[derive(Default)]
struct SessionHooks {
    /// What its chains' commits left, by full stored key.
    rows: BTreeMap<Vec<u8>, Vec<u8>>,
    /// The calls its hooks' asks stopped, by invocation.
    asks: BTreeMap<[u8; 16], SessionVerbAsk>,
}

impl SessionHookStore {
    /// Keeps a chain's `rows` for `session`: each replacing row over the one
    /// its key holds, any other only when its key holds none. A call with no
    /// live session keeps none of them.
    pub(crate) fn stage(&self, vault: &Vault, session: &SessionHookKey, rows: Vec<SessionHookRow>) {
        if *session == SessionHookKey::Process {
            return;
        }
        self.with(vault, session, |hooks| {
            for row in rows {
                if row.replaces {
                    hooks.rows.insert(row.key, row.value);
                } else {
                    hooks.rows.entry(row.key).or_insert(row.value);
                }
            }
        });
    }

    /// Saves the call `invocation`'s hook ask stopped, over any earlier one.
    pub(crate) fn save_ask(
        &self,
        vault: &Vault,
        session: &SessionHookKey,
        invocation: [u8; 16],
        ask: SessionVerbAsk,
    ) {
        self.with(vault, session, |hooks| {
            hooks.asks.insert(invocation, ask);
        });
    }

    /// The call `invocation`'s hook ask stopped in `session`, if this process
    /// holds one.
    pub(crate) fn ask(
        &self,
        vault: &Vault,
        session: &SessionHookKey,
        invocation: [u8; 16],
    ) -> Option<SessionVerbAsk> {
        self.with(vault, session, |hooks| hooks.asks.get(&invocation).cloned())
    }

    /// Uses up ask `ask`'s proceed answer for `invocation`, once: false when
    /// no unused call of that ask stands under it (used already, or a newer
    /// ask's call stands).
    pub(crate) fn use_ask(
        &self,
        vault: &Vault,
        session: &SessionHookKey,
        invocation: [u8; 16],
        ask: EntityId,
    ) -> bool {
        self.with(vault, session, |hooks| {
            match hooks.asks.get_mut(&invocation) {
                Some(row) if row.ask == ask && !row.used => {
                    row.used = true;
                    true
                }
                _ => false,
            }
        })
    }

    /// The id that stands for `invocation` of `session` in the intent key of
    /// its hook's ask: a hash under this process's own key, so the vault's
    /// ask never carries the caller's id, and a retry in this process meets
    /// the ask it opened.
    pub(crate) fn hidden_invocation(
        &self,
        session: &SessionHookKey,
        invocation: [u8; 16],
    ) -> [u8; 16] {
        let mut hasher = blake3::Hasher::new_keyed(self.hiding.get_or_init(rand::random));
        match session {
            SessionHookKey::Session { key, entered_at } => {
                hasher.update(b"session");
                hasher.update(&(key.len() as u64).to_le_bytes());
                hasher.update(key.as_bytes());
                hasher.update(&entered_at.to_le_bytes());
            }
            SessionHookKey::Process => {
                hasher.update(b"process");
            }
        }
        hasher.update(&invocation);
        let mut id = [0; 16];
        id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        id
    }

    /// Runs `f` on `session`'s records, once every session no longer live
    /// has dropped its own.
    fn with<T>(
        &self,
        vault: &Vault,
        session: &SessionHookKey,
        f: impl FnOnce(&mut SessionHooks) -> T,
    ) -> T {
        let mut sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
        sessions.retain(|key, _| key.live(vault));
        f(sessions.entry(session.clone()).or_default())
    }
}
