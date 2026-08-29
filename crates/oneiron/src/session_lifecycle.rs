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
//!   calls `bump_open_session_activity_in_txn` so a witnessed turn and its
//!   activity bump commit atomically.
//!
//! At most ONE session is open per vault: hints carry no app identity (the
//! typed `HintPusher` channel is deliberately payload-thin, H-S4), so a
//! second app-open while a session is open is a presence re-signal
//! ([`SessionMintOutcome::AlreadyOpen`]) — the driver bumps instead of
//! splitting the sitting. Ended records are retained for audit.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::actor_claims::register_session_end_distill_in_txn;
use crate::dreamer_consolidation::{
    ConsolidationPartitionPlan, advance_watermark_in_txn, collect_dirty_turn_ids_in_txn,
    decode_turn_body, enqueue_partition_attempts_in_txn, plan_partitions_in_txn,
    read_watermark_in_txn, register_substitution_mine_in_txn,
};
use crate::dreamer_runner::{DreamerConsolidationScope, DreamerRunnerStore, dreamer_turn_role};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_SESSION;
use crate::store::Store;
use crate::temporal::TimeRange;

/// `vault_meta` key of the single open-session pointer (value = 16-byte id).
const SESSION_LIFECYCLE_OPEN_KEY: &[u8] = b"session_lifecycle:v0:open";
/// `vault_meta` key prefix for per-session lifecycle records (suffix = id).
const SESSION_LIFECYCLE_RECORD_KEY_PREFIX: &[u8] = b"session_lifecycle:v0:record:";
/// `vault_meta` key prefix for TURN → SESSION membership rows (DREAM-008,
/// ONE-1250): suffix = 16-byte TURN id, value = 16-byte SESSION id. Its own
/// keyspace, so no existing record shape or version changes.
const SESSION_TURN_MEMBERSHIP_KEY_PREFIX: &[u8] = b"session_lifecycle:v0:turn_session:";

const SESSION_LIFECYCLE_RECORD_VERSION: u8 = 1;

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

/// The three timestamps retained for one driver-authored session hint.
///
/// `claimed_ms` is producer provenance and is never rewritten, even when the
/// driver rejects it for derivation. `arrival_ms` is the channel stamp, and
/// `effective_ms` is the driver's monotone, bounded decisional time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionHintTimestamp {
    pub claimed_ms: Option<u64>,
    pub arrival_ms: u64,
    pub effective_ms: u64,
}

/// A loss-aware rollup of adjacent activity hints. The endpoints retain the
/// complete timestamp provenance; `count` records how many hints the period
/// represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionActivityPeriod {
    pub first: SessionHintTimestamp,
    pub last: SessionHintTimestamp,
    pub count: u64,
}

/// Durable lifecycle clock fields for one SESSION entity. The legacy entity
/// clock fields remain unix SECONDS; hint provenance is stored in unix
/// MILLISECONDS so source data is never rounded away.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionLifecycleRecord {
    pub version: u8,
    /// Stamped by the app-open hint — not by the first turn.
    pub started_at: u64,
    /// Bumped by turn-witness or an activity hint; never rewinds.
    pub last_activity: u64,
    /// Set exactly once, by explicit-end, idle floor, or lifetime ceiling.
    pub ended_at: Option<u64>,
    pub end_reason: Option<SessionEndReason>,
    /// Effective timestamp of the minting app-open hint.
    #[serde(default)]
    pub started_effective_ms: u64,
    /// Monotone floor used to derive the next hint's effective timestamp.
    #[serde(default)]
    pub last_effective_ms: u64,
    /// Every app-open point applied to this sitting, including the mint.
    #[serde(default)]
    pub app_open_hints: Vec<SessionHintTimestamp>,
    /// Activity hints retained as endpoint-and-count periods.
    #[serde(default)]
    pub activity_periods: Vec<SessionActivityPeriod>,
    /// The explicit-end point, when this sitting ended explicitly.
    #[serde(default)]
    pub explicit_end_hint: Option<SessionHintTimestamp>,
}

/// The currently open session, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenSession {
    pub session: EntityId,
    pub started_at: u64,
    pub last_activity: u64,
    pub last_effective_ms: u64,
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

/// Outcome of [`Vault::end_session_with_wake`].
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
    /// Admissible dirty-turn IDs in the planned watermark window, in
    /// deterministic `(learned_at, id)` scan order. The transaction
    /// re-collects and exactly compares this identity set before settling.
    pub planned_turn_ids: Vec<EntityId>,
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
            planned_turn_ids: Vec::new(),
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

/// `vault_meta` key of one TURN's session-membership row (DREAM-008).
fn turn_session_membership_key(turn: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(SESSION_TURN_MEMBERSHIP_KEY_PREFIX.len() + 16);
    key.extend_from_slice(SESSION_TURN_MEMBERSHIP_KEY_PREFIX);
    key.extend_from_slice(turn.as_bytes());
    key
}

/// Decodes a membership row value (a bare 16-byte SESSION id).
fn decode_turn_session_membership(bytes: &[u8]) -> Result<EntityId> {
    let raw: [u8; 16] = bytes
        .try_into()
        .map_err(|_| Error::CorruptedIndex("session lifecycle turn membership"))?;
    EntityId::from_bytes(raw)
        .map_err(|_| Error::CorruptedIndex("session lifecycle turn membership"))
}

fn encode_session_record(record: &SessionLifecycleRecord) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("session lifecycle record encode failed"))
}

fn decode_session_record(bytes: &[u8]) -> Result<SessionLifecycleRecord> {
    let record: SessionLifecycleRecord = rmp_serde::from_slice(bytes)
        .map_err(|_| Error::CorruptedIndex("session lifecycle record"))?;
    if record.version != SESSION_LIFECYCLE_RECORD_VERSION {
        return Err(Error::CorruptedIndex(
            "unsupported session lifecycle record version",
        ));
    }
    Ok(record)
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
    let id = decode_open_pointer(&raw)?;
    let Some(record) = store.vault_meta.get(txn, &session_record_key(&id))? else {
        return Err(Error::CorruptedIndex("session lifecycle record"));
    };
    Ok(Some((id, decode_session_record(&record)?)))
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

/// Reads the SESSION a TURN was witnessed into, or `None` when no
/// membership fact was recorded for it (DREAM-008, ONE-1250).
///
/// `None` is an UNKNOWN answer, never "no session": turns witnessed before
/// [`record_turn_session_membership_in_txn`] landed carry no row at all, so
/// every consumer must fail closed on `None` rather than treat it as a
/// pass. The compaction door does exactly that
/// ([`crate::error::CompactionPacketError::SessionMembershipNotRecorded`]).
pub(crate) fn turn_session_membership_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<EntityId>> {
    let Some(raw) = store
        .vault_meta
        .get(rtxn, &turn_session_membership_key(turn))?
    else {
        return Ok(None);
    };
    decode_turn_session_membership(&raw).map(Some)
}

/// Records the TURN → SESSION membership fact inside the caller's write
/// transaction (DREAM-008, ONE-1250).
///
/// Called from the witness door beside the activity bump, so membership
/// commits ATOMICALLY with the TURN row: a crash can never leave a turn
/// recorded without its sitting. `session` is `None` when no session is
/// open (ARCH-0002 open-endedness — a sessionless turn stays valid) or
/// when the call is an APPEND to an already-stored turn; an append never
/// re-homes a turn into whatever sitting happens to be open now.
///
/// Idempotent and first-write-wins: an already-recorded membership is
/// returned unchanged rather than overwritten, so a turn never carries two
/// sittings.
///
/// # Why a `vault_meta` row and not a TURN → SESSION edge
///
/// Membership is lookup plumbing, not graph substance. A structural edge
/// would enter the TURN's PUBLIC out-edge set — which `Vault::edges_out`
/// exposes and existing witness-path callers count — so every turn
/// witnessed inside a sitting would silently grow an edge that retrieval,
/// PPR traversal and the `ChildOf` conversation binding never asked for.
/// The `off_record` `vault_meta` pattern this module already uses keeps the
/// fact durable, atomic with the turn write, and O(1) to resolve BY TURN —
/// which is exactly the direction validation reads it — without touching
/// the graph surface at all.
pub(crate) fn record_turn_session_membership_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    turn: &EntityId,
    session: Option<EntityId>,
) -> Result<Option<EntityId>> {
    let Some(session) = session else {
        return Ok(None);
    };
    if let Some(existing) = turn_session_membership_in_txn(store, &*wtxn, turn)? {
        return Ok(Some(existing));
    }
    store
        .vault_meta
        .put(wtxn, &turn_session_membership_key(turn), session.as_bytes())?;
    Ok(Some(session))
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
        let id = decode_open_pointer(&raw)?;
        let Some(record) = self.store.vault_meta.get(&rtxn, &session_record_key(&id))? else {
            return Err(Error::CorruptedIndex("session lifecycle record"));
        };
        let record = decode_session_record(&record)?;
        Ok(Some(OpenSession {
            session: id,
            started_at: record.started_at,
            last_activity: record.last_activity,
            last_effective_ms: record.last_effective_ms,
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
        decode_session_record(&raw).map(Some)
    }

    /// Mints and opens a canonical SESSION entity at `now` (unix seconds).
    /// A zero-turn session is valid — presence is signal, so this fires on
    /// the app-open hint, not on the first turn.
    ///
    /// If a session is already open this mints NOTHING and returns
    /// [`SessionMintOutcome::AlreadyOpen`]: the open sitting continues and
    /// the caller's policy decides whether the re-open counts as activity.
    pub fn mint_session(&self, now: u64) -> Result<SessionMintOutcome> {
        let timestamp_ms = now.saturating_mul(1_000);
        self.mint_session_from_hint(SessionHintTimestamp {
            claimed_ms: None,
            arrival_ms: timestamp_ms,
            effective_ms: timestamp_ms,
        })
    }

    /// Mints and opens a canonical SESSION entity from an app-open hint whose
    /// raw and derived millisecond timestamps have already been decided by the
    /// driver.
    pub(crate) fn mint_session_from_hint_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        timestamp: SessionHintTimestamp,
    ) -> Result<SessionMintOutcome> {
        let now = timestamp.effective_ms / 1_000;
        let id = EntityId::now();
        if let Some(raw) = self
            .store
            .vault_meta
            .get(wtxn, SESSION_LIFECYCLE_OPEN_KEY)?
        {
            return Ok(SessionMintOutcome::AlreadyOpen(decode_open_pointer(&raw)?));
        }
        let record = SessionLifecycleRecord {
            version: SESSION_LIFECYCLE_RECORD_VERSION,
            started_at: now,
            last_activity: now,
            ended_at: None,
            end_reason: None,
            started_effective_ms: timestamp.effective_ms,
            last_effective_ms: timestamp.effective_ms,
            app_open_hints: vec![timestamp],
            activity_periods: Vec::new(),
            explicit_end_hint: None,
        };
        let mut body = Vec::new();
        rmpv::encode::write_value(&mut body, &rmpv::Value::Map(Vec::new()))
            .map_err(|_| Error::InvariantViolation("session entity body encode failed"))?;
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
        self.store.vault_meta.put(
            wtxn,
            &session_record_key(&id),
            &encode_session_record(&record)?,
        )?;
        self.store
            .vault_meta
            .put(wtxn, SESSION_LIFECYCLE_OPEN_KEY, id.as_bytes())?;
        Ok(SessionMintOutcome::Minted(id))
    }

    pub fn mint_session_from_hint(
        &self,
        timestamp: SessionHintTimestamp,
    ) -> Result<SessionMintOutcome> {
        self.with_write_txn(|wtxn| self.mint_session_from_hint_in_txn(wtxn, timestamp))
    }

    /// Bumps the open session's `last_activity` to `now` (unix seconds,
    /// monotonic). Returns `None` when no session is open — an activity
    /// hint alone never mints a session (fail-closed: presence is signaled
    /// by app-open only).
    pub fn bump_session_activity(&self, now: u64) -> Result<Option<EntityId>> {
        self.with_write_txn(|wtxn| bump_open_session_activity_in_txn(&self.store, wtxn, now))
    }

    /// Records an app-open point on the current sitting and advances its
    /// decisional activity clock to the point's effective time.
    pub fn record_session_app_open_hint(
        &self,
        timestamp: SessionHintTimestamp,
    ) -> Result<Option<EntityId>> {
        self.with_write_txn(|wtxn| {
            let Some((id, mut record)) = open_session_in_txn(&self.store, wtxn)? else {
                return Ok(None);
            };
            record.last_effective_ms = record.last_effective_ms.max(timestamp.effective_ms);
            record.last_activity = record.last_activity.max(timestamp.effective_ms / 1_000);
            record.app_open_hints.push(timestamp);
            self.store.vault_meta.put(
                wtxn,
                &session_record_key(&id),
                &encode_session_record(&record)?,
            )?;
            Ok(Some(id))
        })
    }

    /// Records an activity period and advances the sitting to the period's
    /// last effective time. Stored periods whose arrival gap is strictly less
    /// than `rollup_gap_ms` merge; zero therefore preserves every delivered
    /// period losslessly.
    pub fn record_session_activity_period(
        &self,
        period: SessionActivityPeriod,
        rollup_gap_ms: u64,
    ) -> Result<Option<EntityId>> {
        self.with_write_txn(|wtxn| {
            let Some((id, mut record)) = open_session_in_txn(&self.store, wtxn)? else {
                return Ok(None);
            };
            record.last_effective_ms = record.last_effective_ms.max(period.last.effective_ms);
            record.last_activity = record.last_activity.max(period.last.effective_ms / 1_000);

            let merge = rollup_gap_ms > 0
                && record.activity_periods.last().is_some_and(|previous| {
                    period
                        .first
                        .arrival_ms
                        .checked_sub(previous.last.arrival_ms)
                        .is_some_and(|gap| gap < rollup_gap_ms)
                });
            if merge {
                let previous = record
                    .activity_periods
                    .last_mut()
                    .expect("merge requires a previous activity period");
                previous.last = period.last;
                previous.count = previous.count.saturating_add(period.count);
            } else {
                record.activity_periods.push(period);
            }

            self.store.vault_meta.put(
                wtxn,
                &session_record_key(&id),
                &encode_session_record(&record)?,
            )?;
            Ok(Some(id))
        })
    }

    /// Plans the standard session-end consolidation wake from current durable turns.
    pub fn plan_session_end_wake(&self) -> Result<SessionEndWake> {
        self.with_write_txn(|wtxn| self.plan_session_end_wake_in_txn(wtxn))
    }

    /// The production planning trio (`read_watermark` → dirty scan →
    /// `plan_partitions`) run over the CALLER's write transaction, so a close
    /// plans the turns its own transaction just staged (in-transaction readers
    /// see staged index rows — `batch::stage_entity_index_rows`).
    ///
    /// It is the SAME selection the driver's out-of-transaction close runs, and
    /// deliberately so:
    ///
    /// * selection is [`collect_dirty_turn_ids_in_txn`] — temporal
    ///   `(learned_at, id)` order, GATE-10 role admissibility, the compound
    ///   watermark lower bound and the Meso round cap, all shared with the
    ///   snapshot fence in [`Self::end_session_with_wake_and_hint_in_txn`];
    /// * an edge-less turn truncates the round at its `learned_at`, TIES
    ///   INCLUDED (`learned_at < cut`), so the watermark never settles past
    ///   work that was not planned;
    /// * roles decode through the shared [`decode_turn_body`], never a bespoke
    ///   alias preference;
    /// * partitions come from [`plan_partitions_in_txn`], which keeps the
    ///   production `world_ref`/`facet_ref` fallback chain (turn body key →
    ///   conversation body key → None).
    ///
    /// Because plan and fence are then the same read in one transaction, their
    /// identity comparison holds by construction rather than by luck.
    pub(crate) fn plan_session_end_wake_in_txn(&self, wtxn: &RwTxn<'_>) -> Result<SessionEndWake> {
        let scope = DreamerConsolidationScope::Meso;
        let watermark = read_watermark_in_txn(self, wtxn, scope)?;
        let dirty_ids =
            collect_dirty_turn_ids_in_txn(self, wtxn, scope, watermark.last_learned_at, u64::MAX)?;

        let mut scanned = Vec::with_capacity(dirty_ids.len());
        for turn_id in dirty_ids {
            let Some(raw) = self.get_raw_in(wtxn, &turn_id)? else {
                continue;
            };
            let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
                continue;
            };
            let facts = decode_turn_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]);
            let prefix = crate::vault::edge_kind_prefix(&turn_id, crate::edge::EdgeKind::ChildOf);
            let conversation = self
                .store
                .edges_out
                .prefix_iter(wtxn, &prefix)?
                .next()
                .transpose()?
                .and_then(|(key, _)| {
                    crate::edge::parse_strict_edge_record_key(&key)
                        .ok()
                        .map(|(_, _, target)| target)
                });
            scanned.push(crate::dreamer_consolidation::WorkingSetTurn {
                turn_id,
                role: dreamer_turn_role(facts.speaker.as_deref()),
                learned_at: header.learned_at,
                conversation,
            });
        }

        // The driver's exact cut rule: the first turn without its structural
        // CONVERSATION edge truncates the round at its second, dropping the
        // same-second ties with it.
        let dirty = if let Some(cut_learned_at) = scanned
            .iter()
            .find(|turn| turn.conversation.is_none())
            .map(|turn| turn.learned_at)
        {
            scanned
                .into_iter()
                .take_while(|turn| turn.learned_at < cut_learned_at)
                .collect()
        } else {
            scanned
        };

        let plans = plan_partitions_in_txn(self, scope, wtxn, &dirty, &watermark)?;
        Ok(SessionEndWake {
            plans,
            planned_watermark: watermark.last_learned_at,
            planned_turn_ids: dirty.iter().map(|turn| turn.turn_id).collect(),
            advance_watermark_to: dirty.iter().map(|turn| turn.learned_at).max(),
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
    ///   enqueued and the Meso watermark advanced in the SAME transaction;
    /// * **(e) distill job**: the CHAT-lane `actor.*` distill job is registered
    ///   for this sitting (ONE-1739), also in the SAME transaction;
    /// * **(f) substitution mine**: ED-04's recurring-substitution miner pass
    ///   (ONE-1760) is registered on the same Meso queue, same transaction.
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
            self.end_session_with_wake_and_hint_in_txn(wtxn, expected, predicate, now, wake, None)
        })
    }

    /// Timestamp-preserving form of [`Self::end_session_with_wake`]. Driver
    /// explicit-end closes pass their raw and effective point here so the
    /// retained lifecycle record is a complete audit trail; expiry closes
    /// pass `None` because their due instant is policy-derived, not a hint.
    pub(crate) fn end_session_with_wake_and_hint_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        expected: &EntityId,
        predicate: SessionClosePredicate,
        now: u64,
        wake: &SessionEndWake,
        end_hint: Option<SessionHintTimestamp>,
    ) -> Result<Option<EndedSession>> {
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
        if let Some(timestamp) = end_hint {
            record.last_effective_ms = record.last_effective_ms.max(timestamp.effective_ms);
            record.explicit_end_hint = Some(timestamp);
        }
        self.store.vault_meta.put(
            wtxn,
            &session_record_key(&id),
            &encode_session_record(&record)?,
        )?;
        self.store
            .vault_meta
            .delete(wtxn, SESSION_LIFECYCLE_OPEN_KEY)?;

        // (e) The CHAT-lane actor-distill job (ARCH-0053 §3, ONE-1739),
        // same commit as the close: "this sitting is over and not yet
        // learned from" becomes a durable fact rather than a live
        // process's intention. Unconditional — unlike the Meso wake below
        // it plans nothing in advance, so there is no snapshot to fence.
        register_session_end_distill_in_txn(self, wtxn, &id, ended_at)?;

        // (f) ED-04's recurring-substitution miner (ONE-1760), same commit
        // and for the same reason: a pass registered only in the closing
        // process's intentions is a pass a crash silently cancels. It rides
        // the Meso queue the wake below drains, dedupe-keyed per sitting,
        // and is unconditional — the corrections it mines are amendment
        // receipts, which have nothing to do with whether this sitting left
        // dirty turns behind.
        register_substitution_mine_in_txn(self, wtxn, &id, now)?;

        // (d) The durable wake, same commit. Skipped wholesale when the
        // Meso watermark or bounded dirty snapshot moved since the plan
        // was taken: those turns belong to a later planning round.
        let scope = DreamerConsolidationScope::Meso;
        let current = read_watermark_in_txn(self, wtxn, scope)?;
        if current.last_learned_at == wake.planned_watermark {
            let dirty_snapshot_matches = match wake.advance_watermark_to {
                Some(advance_to) => {
                    let in_txn_ids = collect_dirty_turn_ids_in_txn(
                        self,
                        wtxn,
                        scope,
                        wake.planned_watermark,
                        advance_to,
                    )?;
                    // EXACT identity is the only matching leg: a round whose
                    // turns vanished between plan and close is a stale round,
                    // and enqueuing it would settle the watermark COMPLETE past
                    // every key at that second — including turns no planner ever
                    // saw. Plan and fence are the same in-transaction read, so
                    // for a live round this holds by construction.
                    in_txn_ids.as_slice() == wake.planned_turn_ids.as_slice()
                }
                None => true,
            };
            if dirty_snapshot_matches {
                if !wake.plans.is_empty() {
                    let store = DreamerRunnerStore::new(self);
                    enqueue_partition_attempts_in_txn(&store, wtxn, scope, &wake.plans, None, now)?;
                }
                if let Some(advance_to) = wake.advance_watermark_to {
                    advance_watermark_in_txn(self, wtxn, scope, advance_to)?;
                }
            }
        }

        Ok(Some(EndedSession {
            session: id,
            started_at: record.started_at,
            last_activity: record.last_activity,
            ended_at,
            reason,
        }))
    }

    /// Closes the expected session and applies the standard wake in one
    /// caller-owned transaction, without an explicit timestamp hint.
    pub(crate) fn end_session_with_wake_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        expected: &EntityId,
        predicate: SessionClosePredicate,
        now: u64,
        wake: &SessionEndWake,
    ) -> Result<Option<EndedSession>> {
        self.end_session_with_wake_and_hint_in_txn(wtxn, expected, predicate, now, wake, None)
    }

    pub fn end_session_with_wake_and_hint(
        &self,
        expected: &EntityId,
        predicate: SessionClosePredicate,
        now: u64,
        wake: &SessionEndWake,
        end_hint: Option<SessionHintTimestamp>,
    ) -> Result<Option<EndedSession>> {
        self.with_write_txn(|wtxn| match end_hint {
            Some(hint) => self.end_session_with_wake_and_hint_in_txn(
                wtxn,
                expected,
                predicate,
                now,
                wake,
                Some(hint),
            ),
            None => self.end_session_with_wake_in_txn(wtxn, expected, predicate, now, wake),
        })
    }
}

#[cfg(test)]
mod tests;
