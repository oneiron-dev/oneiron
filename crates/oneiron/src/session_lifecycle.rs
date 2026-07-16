//! RT-03 (ONE-1685) SESSION lifecycle substrate — the durable mechanism the
//! in-process driver's session policy runs on.
//!
//! The SESSION entity (`ENTITY_TYPE_SESSION = 2`) is the canonical "one visit
//! to a thread" sitting (the 7-way "session" collision ruling in
//! ONEIRON-PLAN-agent-runtime-v1): opened on the app-open hint — a zero-turn
//! session is valid, presence IS signal — and closed by an explicit-end hint,
//! the driver's idle floor, or the hard wall-clock lifetime ceiling.
//!
//! Split of authority:
//!
//! * **This module is mechanism only.** It mints the canonical SESSION
//!   entity, keeps the lifecycle clock fields (`started_at`,
//!   `last_activity`, `ended_at`, `end_reason`) in a `vault_meta` record
//!   (the `off_record` pattern — high-churn activity bumps never rewrite
//!   the entity blob or its indexes), and tracks the single open session
//!   behind an open-pointer row.
//! * **The driver owns policy** (`oneiron-driver::SessionLifecycleDriver`):
//!   the 20-minute idle floor, the hard lifetime ceiling, hint handling,
//!   and firing SessionEnd → Meso consolidation. The engine owns no timer
//!   and no cutoff constant (ARCH-0026: hosts pump; ARCH-0002: open-ended
//!   sessions stay valid until the driver's floor fires). Policy values
//!   still ride into [`Vault::end_session_with_wake`] as data
//!   ([`SessionClosePredicate`]) because the close protocol is ATOMIC
//!   mechanism: identity check, predicate re-validation, `ended_at` stamp
//!   and the SessionEnd → Meso enqueue are one transaction.
//! * **Turn-witness bumps ride the witness write transaction**: the facade
//!   calls [`bump_open_session_activity_in_txn`] so a witnessed turn and its
//!   activity bump commit atomically.
//!
//! At most ONE session is open per vault: hints carry no app identity (the
//! typed `HintPusher` channel is deliberately payload-thin, H-S4), so a
//! second app-open while a session is open is a presence re-signal
//! ([`SessionMintOutcome::AlreadyOpen`]) — the driver bumps instead of
//! splitting the sitting. Ended records are retained for audit.

use heed::RwTxn;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::dreamer_consolidation::{
    ConsolidationPartitionPlan, advance_watermark_in_txn, enqueue_partition_attempts_in_txn,
    read_watermark_in_txn,
};
use crate::dreamer_runner::{DreamerConsolidationScope, DreamerRunnerStore};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_SESSION;
use crate::store::Store;
use crate::temporal::TimeRange;

/// `vault_meta` key of the single open-session pointer (value = 16-byte id).
const SESSION_LIFECYCLE_OPEN_KEY: &[u8] = b"session_lifecycle:v0:open";
/// `vault_meta` key prefix for per-session lifecycle records (suffix = id).
const SESSION_LIFECYCLE_RECORD_KEY_PREFIX: &[u8] = b"session_lifecycle:v0:record:";

const SESSION_LIFECYCLE_RECORD_VERSION: u8 = 0;

/// Why a session ended. `Explicit` is the app's own end hint; `IdleFloor`
/// is the driver's inactivity backstop; `LifetimeCeiling` is the hard
/// wall-clock cap that closes a session regardless of activity hints
/// (H-S4: forged typing hints reset `last_activity` forever, so the floor
/// alone is defeatable — the ceiling is not).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEndReason {
    Explicit,
    IdleFloor,
    LifetimeCeiling,
}

/// Durable lifecycle clock fields for one SESSION entity. Times are unix
/// SECONDS (the engine's `learned_at` / attempt-stamp convention).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionLifecycleRecord {
    pub version: u8,
    /// Stamped by the app-open hint — not by the first turn.
    pub started_at: u64,
    /// Bumped by turn-witness or an activity hint; never rewinds.
    pub last_activity: u64,
    /// Set exactly once, by explicit-end, idle floor, or lifetime ceiling.
    pub ended_at: Option<u64>,
    pub end_reason: Option<SessionEndReason>,
}

/// The currently open session, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenSession {
    pub session: EntityId,
    pub started_at: u64,
    pub last_activity: u64,
}

/// Outcome of [`Vault::mint_session`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMintOutcome {
    /// A new SESSION entity was minted and opened.
    Minted(EntityId),
    /// A session is already open — presence re-signal, nothing minted.
    /// The caller (driver policy) decides whether to bump activity.
    AlreadyOpen(EntityId),
}

/// Outcome of [`Vault::end_open_session`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndedSession {
    pub session: EntityId,
    pub started_at: u64,
    pub last_activity: u64,
    pub ended_at: u64,
    pub reason: SessionEndReason,
}

/// Close predicate for [`Vault::end_session_with_wake`], re-validated
/// against the DURABLE record inside the end transaction. The floor and
/// ceiling ride in as data: the engine stays free of cutoff constants
/// (driver policy, RT-03) while the check itself is atomic with the close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionClosePredicate {
    /// The app's explicit end: unconditional.
    Explicit,
    /// Idle-floor / lifetime-ceiling expiry: closes only when `now` has
    /// reached the earlier of `last_activity + idle_floor` and
    /// `started_at + ceiling` — computed from the record RE-READ in the
    /// transaction, so an activity bump that raced the close wins and the
    /// close no-ops. "First to fire" names the reason; a ceiling due at or
    /// before the idle floor closes as the ceiling however fresh the
    /// (possibly forged) activity clock looks (H-S4).
    Expiry {
        idle_floor_secs: u64,
        lifetime_ceiling_secs: u64,
    },
}

impl SessionClosePredicate {
    /// The end reason this predicate yields against `record` at `now`, or
    /// `None` when the close is not (or no longer) due.
    fn close_reason(self, record: &SessionLifecycleRecord, now: u64) -> Option<SessionEndReason> {
        match self {
            Self::Explicit => Some(SessionEndReason::Explicit),
            Self::Expiry {
                idle_floor_secs,
                lifetime_ceiling_secs,
            } => {
                let idle_due = record.last_activity.saturating_add(idle_floor_secs);
                let ceiling_due = record.started_at.saturating_add(lifetime_ceiling_secs);
                if now < idle_due.min(ceiling_due) {
                    return None;
                }
                if ceiling_due <= idle_due {
                    Some(SessionEndReason::LifetimeCeiling)
                } else {
                    Some(SessionEndReason::IdleFloor)
                }
            }
        }
    }
}

/// The pre-planned SessionEnd → Meso wake for [`Vault::end_session_with_wake`]:
/// the output of the production planning trio (`read_watermark` →
/// `scan_dirty_turns` → `plan_partitions`) run OUTSIDE the end transaction,
/// plus the facts the transaction needs to guard and settle the round.
#[derive(Debug, Clone)]
pub struct SessionEndWake {
    /// Partition plans over the dirty-turn backlog — the SAME payload and
    /// dedupe shape the production `ConsolidationExecutor` decodes. Empty
    /// when nothing is dirty: a zero-turn sitting has nothing to dream
    /// about, so no attempt is minted for it.
    pub plans: Vec<ConsolidationPartitionPlan>,
    /// The Meso watermark the plans were taken against. The transaction
    /// re-reads the watermark and skips the enqueue + advance when it
    /// moved — another planner already owns those turns.
    pub planned_watermark: u64,
    /// Where the watermark advances after the enqueue (the scan's max
    /// `learned_at`), if the scan found dirty turns.
    pub advance_watermark_to: Option<u64>,
}

impl SessionEndWake {
    /// The empty wake: close with nothing dirty to plan.
    #[must_use]
    pub const fn none(planned_watermark: u64) -> Self {
        Self {
            plans: Vec::new(),
            planned_watermark,
            advance_watermark_to: None,
        }
    }
}

fn session_record_key(id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(SESSION_LIFECYCLE_RECORD_KEY_PREFIX.len() + 16);
    key.extend_from_slice(SESSION_LIFECYCLE_RECORD_KEY_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key
}

fn encode_session_record(record: &SessionLifecycleRecord) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("session lifecycle record encode failed"))
}

fn decode_session_record(bytes: &[u8]) -> Result<SessionLifecycleRecord> {
    rmp_serde::from_slice(bytes).map_err(|_| Error::CorruptedIndex("session lifecycle record"))
}

fn decode_open_pointer(bytes: &[u8]) -> Result<EntityId> {
    let raw: [u8; 16] = bytes
        .try_into()
        .map_err(|_| Error::CorruptedIndex("session lifecycle open pointer"))?;
    EntityId::from_bytes(raw).map_err(|_| Error::CorruptedIndex("session lifecycle open pointer"))
}

/// Reads the open session (pointer + record) inside a transaction. A
/// pointer whose record row is missing is corruption, not "no session".
fn open_session_in_txn(
    store: &Store,
    txn: &RwTxn<'_>,
) -> Result<Option<(EntityId, SessionLifecycleRecord)>> {
    let Some(raw) = store.vault_meta.get(txn, SESSION_LIFECYCLE_OPEN_KEY)? else {
        return Ok(None);
    };
    let id = decode_open_pointer(raw)?;
    let Some(record) = store.vault_meta.get(txn, &session_record_key(&id))? else {
        return Err(Error::CorruptedIndex("session lifecycle record"));
    };
    Ok(Some((id, decode_session_record(record)?)))
}

/// Bumps the open session's `last_activity` (monotonic — never rewinds)
/// inside an existing write transaction. Returns the bumped session id, or
/// `None` when no session is open (a witnessed turn outside any session is
/// valid — ARCH-0002 open-endedness — so this is a no-op, not an error).
///
/// The facade's witness path calls this so a turn and its activity bump
/// commit atomically (RT-03: `last_activity` ← turn-witness OR an activity
/// hint).
pub(crate) fn bump_open_session_activity_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    now: u64,
) -> Result<Option<EntityId>> {
    let Some((id, mut record)) = open_session_in_txn(store, wtxn)? else {
        return Ok(None);
    };
    if now > record.last_activity {
        record.last_activity = now;
        store.vault_meta.put(
            wtxn,
            &session_record_key(&id),
            &encode_session_record(&record)?,
        )?;
    }
    Ok(Some(id))
}

impl Vault {
    /// The currently open session, if any.
    pub fn open_session(&self) -> Result<Option<OpenSession>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self
            .store
            .vault_meta
            .get(&rtxn, SESSION_LIFECYCLE_OPEN_KEY)?
        else {
            return Ok(None);
        };
        let id = decode_open_pointer(raw)?;
        let Some(record) = self.store.vault_meta.get(&rtxn, &session_record_key(&id))? else {
            return Err(Error::CorruptedIndex("session lifecycle record"));
        };
        let record = decode_session_record(record)?;
        Ok(Some(OpenSession {
            session: id,
            started_at: record.started_at,
            last_activity: record.last_activity,
        }))
    }

    /// Reads the lifecycle record for one session id (open or ended).
    pub fn session_lifecycle_record(
        &self,
        id: &EntityId,
    ) -> Result<Option<SessionLifecycleRecord>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.vault_meta.get(&rtxn, &session_record_key(id))? else {
            return Ok(None);
        };
        decode_session_record(raw).map(Some)
    }

    /// Mints and opens a canonical SESSION entity at `now` (unix seconds).
    /// A zero-turn session is valid — presence is signal, so this fires on
    /// the app-open hint, not on the first turn.
    ///
    /// If a session is already open this mints NOTHING and returns
    /// [`SessionMintOutcome::AlreadyOpen`]: the open sitting continues and
    /// the caller's policy decides whether the re-open counts as activity.
    pub fn mint_session(&self, now: u64) -> Result<SessionMintOutcome> {
        let id = EntityId::now();
        let record = SessionLifecycleRecord {
            version: SESSION_LIFECYCLE_RECORD_VERSION,
            started_at: now,
            last_activity: now,
            ended_at: None,
            end_reason: None,
        };
        let record_bytes = encode_session_record(&record)?;
        let mut body = Vec::new();
        rmpv::encode::write_value(&mut body, &rmpv::Value::Map(Vec::new()))
            .map_err(|_| Error::InvariantViolation("session entity body encode failed"))?;
        self.with_write_txn(|wtxn| {
            if let Some(raw) = self
                .store
                .vault_meta
                .get(wtxn, SESSION_LIFECYCLE_OPEN_KEY)?
            {
                let open = decode_open_pointer(raw)?;
                return Ok(SessionMintOutcome::AlreadyOpen(open));
            }
            self.batch_in()
                .put(
                    &id,
                    ENTITY_TYPE_SESSION,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &body,
                )
                .apply(wtxn)?;
            self.store
                .vault_meta
                .put(wtxn, &session_record_key(&id), &record_bytes)?;
            self.store
                .vault_meta
                .put(wtxn, SESSION_LIFECYCLE_OPEN_KEY, id.as_bytes())?;
            Ok(SessionMintOutcome::Minted(id))
        })
    }

    /// Bumps the open session's `last_activity` to `now` (unix seconds,
    /// monotonic). Returns `None` when no session is open — an activity
    /// hint alone never mints a session (fail-closed: presence is signaled
    /// by app-open only).
    pub fn bump_session_activity(&self, now: u64) -> Result<Option<EntityId>> {
        self.with_write_txn(|wtxn| bump_open_session_activity_in_txn(&self.store, wtxn, now))
    }

    /// Predicate-free close primitive retained for in-crate mechanism tests.
    /// Production closes use [`Self::end_session_with_wake`], keeping the
    /// session end and its planned attempts structurally inseparable.
    ///
    /// `ended_at` is clamped to never precede `started_at`/`last_activity`
    /// (a skewed clock must not produce a session that ends before it was
    /// last active).
    #[allow(dead_code)] // retained for in-crate mechanism tests; no production caller by design
    pub(crate) fn end_open_session(
        &self,
        now: u64,
        reason: SessionEndReason,
    ) -> Result<Option<EndedSession>> {
        self.with_write_txn(|wtxn| {
            let Some((id, mut record)) = open_session_in_txn(&self.store, wtxn)? else {
                return Ok(None);
            };
            let ended_at = now.max(record.last_activity).max(record.started_at);
            record.ended_at = Some(ended_at);
            record.end_reason = Some(reason);
            self.store.vault_meta.put(
                wtxn,
                &session_record_key(&id),
                &encode_session_record(&record)?,
            )?;
            self.store
                .vault_meta
                .delete(wtxn, SESSION_LIFECYCLE_OPEN_KEY)?;
            Ok(Some(EndedSession {
                session: id,
                started_at: record.started_at,
                last_activity: record.last_activity,
                ended_at,
                reason,
            }))
        })
    }

    /// Ends session `expected` in ONE transaction — the ONE-1685 atomic,
    /// identity-bound close protocol:
    ///
    /// * **(a) identity**: `expected` must STILL be the open session — a
    ///   stale closer holding a replaced session's id no-ops and can never
    ///   end (or enqueue for) the replacement;
    /// * **(b) predicate**: `predicate` is re-validated against the record
    ///   RE-READ inside the transaction — an activity bump that raced an
    ///   idle close wins and the close no-ops;
    /// * **(c) stamp**: `ended_at` is clamped not to precede activity; the
    ///   predicate-named reason lands on the retained record and the open
    ///   pointer clears;
    /// * **(d) wake**: the pre-planned SessionEnd → Meso partition attempts are
    ///   enqueued and the Meso watermark advanced in the SAME transaction.
    ///
    /// "Exactly-once wake" is therefore structural: a attempt row exists ⟺ this
    /// end committed, and re-ending an already-ended session is a no-op that
    /// can never re-enqueue — the dedupe key is back to being the advisory
    /// idempotency floor it is everywhere else, not correctness-bearing.
    pub fn end_session_with_wake(
        &self,
        expected: &EntityId,
        predicate: SessionClosePredicate,
        now: u64,
        wake: &SessionEndWake,
    ) -> Result<Option<EndedSession>> {
        self.with_write_txn(|wtxn| {
            let Some((id, mut record)) = open_session_in_txn(&self.store, wtxn)? else {
                return Ok(None);
            };
            if id != *expected {
                return Ok(None);
            }
            let Some(reason) = predicate.close_reason(&record, now) else {
                return Ok(None);
            };
            let ended_at = now.max(record.last_activity).max(record.started_at);
            record.ended_at = Some(ended_at);
            record.end_reason = Some(reason);
            self.store.vault_meta.put(
                wtxn,
                &session_record_key(&id),
                &encode_session_record(&record)?,
            )?;
            self.store
                .vault_meta
                .delete(wtxn, SESSION_LIFECYCLE_OPEN_KEY)?;

            // (d) The durable wake, same commit. Skipped wholesale when the
            // Meso watermark moved since the plan was taken: those turns
            // already belong to another planner's round.
            let scope = DreamerConsolidationScope::Meso;
            let current = read_watermark_in_txn(self, wtxn, scope)?;
            if current.last_learned_at == wake.planned_watermark {
                if !wake.plans.is_empty() {
                    let store = DreamerRunnerStore::new(self);
                    enqueue_partition_attempts_in_txn(&store, wtxn, scope, &wake.plans, None, now)?;
                }
                if let Some(advance_to) = wake.advance_watermark_to {
                    advance_watermark_in_txn(self, wtxn, scope, advance_to)?;
                }
            }

            Ok(Some(EndedSession {
                session: id,
                started_at: record.started_at,
                last_activity: record.last_activity,
                ended_at,
                reason,
            }))
        })
    }
}

#[cfg(test)]
mod tests;
