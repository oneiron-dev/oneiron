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
//!   the entity blob or its indexes), and keeps one open pointer per
//!   actor and machine (OF-536).
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
//! Many sessions may be open together. A second app-open by the same actor
//! on the same machine is a presence re-signal, not a split sitting. Closing
//! one session never closes another key's sitting. Ended records stay for audit.

use heed::RwTxn;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::Vault;
use crate::actor_claims::register_session_end_distill_in_txn;
use crate::dreamer_consolidation::{
    ConsolidationPartitionPlan, enqueue_partition_attempts_in_txn, plan_partitions_in_txn,
    read_partition_turns_in_txn, read_watermark_in_txn, register_substitution_mine_in_txn,
};
use crate::dreamer_runner::DreamerConsolidationScope;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_SESSION;
use crate::runtime_hooks::{InvocationId, VerbCall, VerbDomain};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::skill_hub::pack_catalog::HookActorClass;
use crate::store::Store;
use crate::temporal::TimeRange;

pub(crate) use crate::compaction::record_turn_session_membership_in_txn;

/// Open pointers keyed by actor and machine; values are session ids.
const OPEN_POINTER: SideTable<(EntityId, EntityId), EntityId, Raw> =
    SideTable::new(&side_table::SESSION_LIFECYCLE_OPEN);
/// Per-session lifecycle records. Key: the session id.
const RECORDS: SideTable<EntityId, SessionLifecycleRecord, Named> =
    SideTable::new(&side_table::SESSION_LIFECYCLE_RECORD);
const SESSION_TURNS: SideTable<(EntityId, EntityId), [u8; 1], Raw> =
    SideTable::new(&side_table::SESSION_TURNS);

const SESSION_LIFECYCLE_RECORD_VERSION: u8 = 1;

/// The host verb a sitting's open runs under (ARCH-0080 §5).
const HOST_SESSION_OPEN: &str = "host.session.open";
/// The host verb a sitting's close runs under (ARCH-0080 §5).
const HOST_SESSION_CLOSE: &str = "host.session.close";

/// One sitting's identity. Hosts bind it from their actor and machine context;
/// it confers no write authority and cannot shape a Dreamer pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SessionKey {
    pub actor: EntityId,
    pub machine: EntityId,
}

impl SessionKey {
    fn pointer(self) -> (EntityId, EntityId) {
        (self.actor, self.machine)
    }
}

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
    pub key: SessionKey,
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
    /// Why a `host.session.close` hook would have kept the sitting open,
    /// when one tried: no hook keeps a sitting open, so it closed anyway.
    #[serde(default)]
    pub close_hook_stop: Option<String>,
}

/// The currently open session, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenSession {
    pub key: SessionKey,
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

/// Preview of one sitting's SessionEnd → Meso work. Closing re-reads this
/// session's membership and rebuilds the plans in its own writer snapshot.
/// Another open sitting's turns and the global Meso watermark stay untouched.
#[derive(Debug, Clone)]
pub struct SessionEndWake {
    pub session: EntityId,
    pub plans: Vec<ConsolidationPartitionPlan>,
    /// The Meso watermark this preview was taken against. Close rebuilds
    /// the round in its own transaction, so a late arrival or a competing
    /// planner cannot make this preview skip consolidation.
    pub planned_watermark: u64,
    pub planned_turn_ids: Vec<EntityId>,
    /// Preview of this sitting's newest effective dirty key, bounded by store
    /// time. This never advances the global Meso watermark.
    pub advance_watermark_to: Option<u64>,
}

impl SessionEndWake {
    #[must_use]
    pub const fn none(session: EntityId, planned_watermark: u64) -> Self {
        Self {
            session,
            plans: Vec::new(),
            planned_watermark,
            planned_turn_ids: Vec::new(),
            advance_watermark_to: None,
        }
    }
}

/// A record decoded off-disk carries whatever `version` its bytes named;
/// this is the domain check the `Named` codec cannot express on its own.
fn validated_record(record: SessionLifecycleRecord) -> Result<SessionLifecycleRecord> {
    if record.version != SESSION_LIFECYCLE_RECORD_VERSION {
        return Err(Error::CorruptedIndex(
            "unsupported session lifecycle record version",
        ));
    }
    Ok(record)
}

/// Reads the open session (pointer + record) inside a transaction. A
/// pointer whose record row is missing is corruption, not "no session".
fn open_session_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: SessionKey,
) -> Result<Option<(EntityId, SessionLifecycleRecord)>> {
    let Some(id) = OPEN_POINTER.get(store, txn, &key.pointer())? else {
        return Ok(None);
    };
    let Some(record) = RECORDS.get(store, txn, &id)? else {
        return Err(Error::CorruptedIndex("session lifecycle record"));
    };
    let record = validated_record(record)?;
    if record.key != key || record.ended_at.is_some() {
        return Err(Error::CorruptedIndex("session lifecycle open pointer"));
    }
    Ok(Some((id, record)))
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
    key: SessionKey,
    now: u64,
) -> Result<Option<EntityId>> {
    let Some((id, mut record)) = open_session_in_txn(store, wtxn, key)? else {
        return Ok(None);
    };
    if now > record.last_activity {
        record.last_activity = now;
        RECORDS.put(store, wtxn, &id, &record)?;
    }
    Ok(Some(id))
}

impl Vault {
    /// Bind an actor's sitting on this install. No roster or write authority
    /// is inferred from this local identity.
    pub fn local_session_key(&self, actor: EntityId) -> Result<SessionKey> {
        self.with_write_txn_grouped(|txn| {
            let machine = crate::identity::load_or_mint_machine_id_in_txn(self, txn)?;
            Ok(SessionKey { actor, machine })
        })
    }

    /// The currently open sitting for this actor and machine, if any.
    pub fn open_session(&self, key: SessionKey) -> Result<Option<OpenSession>> {
        let txn = self.store.env.read_txn()?;
        Ok(
            open_session_in_txn(&self.store, &txn, key)?.map(|(session, record)| OpenSession {
                key,
                session,
                started_at: record.started_at,
                last_activity: record.last_activity,
                last_effective_ms: record.last_effective_ms,
            }),
        )
    }

    /// All open sittings, for the driver's independent expiry timers.
    pub fn open_sessions(&self) -> Result<Vec<OpenSession>> {
        let txn = self.store.env.read_txn()?;
        let mut sessions = Vec::new();
        for row in OPEN_POINTER.iter_from(&self.store, &txn, &[])? {
            let ((actor, machine), _) = row?;
            let key = SessionKey { actor, machine };
            let (session, record) = open_session_in_txn(&self.store, &txn, key)?
                .ok_or(Error::CorruptedIndex("session lifecycle open pointer"))?;
            sessions.push(OpenSession {
                key,
                session,
                started_at: record.started_at,
                last_activity: record.last_activity,
                last_effective_ms: record.last_effective_ms,
            });
        }
        Ok(sessions)
    }

    /// Reads the lifecycle record for one session id (open or ended).
    pub fn session_lifecycle_record(
        &self,
        id: &EntityId,
    ) -> Result<Option<SessionLifecycleRecord>> {
        let rtxn = self.store.env.read_txn()?;
        RECORDS
            .get(&self.store, &rtxn, id)?
            .map(validated_record)
            .transpose()
    }

    /// Mints and opens a canonical SESSION entity at `now` (unix seconds).
    /// A zero-turn session is valid — presence is signal, so this fires on
    /// the app-open hint, not on the first turn.
    ///
    /// If a session is already open this mints NOTHING and returns
    /// [`SessionMintOutcome::AlreadyOpen`]: the open sitting continues and
    /// the caller's policy decides whether the re-open counts as activity.
    pub fn mint_session(&self, key: SessionKey, now: u64) -> Result<SessionMintOutcome> {
        let timestamp_ms = now.saturating_mul(1_000);
        self.mint_session_from_hint(
            key,
            SessionHintTimestamp {
                claimed_ms: None,
                arrival_ms: timestamp_ms,
                effective_ms: timestamp_ms,
            },
        )
    }

    /// Mints and opens a canonical SESSION entity from an app-open hint whose
    /// raw and derived millisecond timestamps have already been decided by the
    /// driver.
    pub(crate) fn mint_session_from_hint_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        key: SessionKey,
        timestamp: SessionHintTimestamp,
    ) -> Result<SessionMintOutcome> {
        let id = self.store.clock.entity_id()?;
        self.mint_session_with_id_in_txn(wtxn, key, timestamp, id)
    }

    /// [`Self::mint_session_from_hint_in_txn`] with the sitting's id minted
    /// beforehand, so its open hooks can name it.
    fn mint_session_with_id_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        key: SessionKey,
        timestamp: SessionHintTimestamp,
        id: EntityId,
    ) -> Result<SessionMintOutcome> {
        let now = timestamp.effective_ms / 1_000;
        if let Some(existing) = OPEN_POINTER.get(&self.store, wtxn, &key.pointer())? {
            return Ok(SessionMintOutcome::AlreadyOpen(existing));
        }
        let record = SessionLifecycleRecord {
            version: SESSION_LIFECYCLE_RECORD_VERSION,
            key,
            started_at: now,
            last_activity: now,
            ended_at: None,
            end_reason: None,
            started_effective_ms: timestamp.effective_ms,
            last_effective_ms: timestamp.effective_ms,
            app_open_hints: vec![timestamp],
            activity_periods: Vec::new(),
            explicit_end_hint: None,
            close_hook_stop: None,
        };
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &rmpv::Value::Map(vec![
                (
                    rmpv::Value::from("actor"),
                    rmpv::Value::Binary(key.actor.as_bytes().to_vec()),
                ),
                (
                    rmpv::Value::from("machine"),
                    rmpv::Value::Binary(key.machine.as_bytes().to_vec()),
                ),
            ]),
        )
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
        RECORDS.put(&self.store, wtxn, &id, &record)?;
        OPEN_POINTER.put(&self.store, wtxn, &key.pointer(), &id)?;
        Ok(SessionMintOutcome::Minted(id))
    }

    /// The open runs `host.session.open`'s hooks (ARCH-0080 §5) around its
    /// commit. A re-signal on an open sitting opens nothing, so runs none.
    ///
    /// # Errors
    ///
    /// [`Error::VerbHook`] when a pre-hook skipped the open or asked first:
    /// nothing opens. Storage errors as they occur.
    pub fn mint_session_from_hint(
        &self,
        key: SessionKey,
        timestamp: SessionHintTimestamp,
    ) -> Result<SessionMintOutcome> {
        let open = {
            let rtxn = self.store.env.read_txn()?;
            OPEN_POINTER.get(&self.store, &rtxn, &key.pointer())?
        };
        if let Some(existing) = open {
            return Ok(SessionMintOutcome::AlreadyOpen(existing));
        }
        let id = self.store.clock.entity_id()?;
        let args = session_hook_args(id, "app_open");
        let check = |rewritten: &Value| host_args_kept(&args, rewritten);
        let call = session_hook_call(HOST_SESSION_OPEN, id, key.actor, 0);
        let pre = self
            .pre_verb_hooks(call, args.clone(), &check)?
            .map_err(Error::from)?;
        let outcome = self.with_write_txn_grouped(|wtxn| {
            self.mint_session_with_id_in_txn(wtxn, key, timestamp, id)
        })?;
        if let SessionMintOutcome::Minted(session) = outcome {
            // The sitting is open whatever a post-hook says.
            let result = json!({
                "session": session.to_hex(),
                "started_at": timestamp.effective_ms / 1_000,
            });
            if let Err(error) = self.post_verb_hooks(pre, result) {
                tracing::warn!(
                    ?error,
                    "host.session.open post-hooks failed on an opened sitting"
                );
            }
        }
        Ok(outcome)
    }

    /// Bumps the open session's `last_activity` to `now` (unix seconds,
    /// monotonic). Returns `None` when no session is open — an activity
    /// hint alone never mints a session (fail-closed: presence is signaled
    /// by app-open only).
    pub fn bump_session_activity(&self, key: SessionKey, now: u64) -> Result<Option<EntityId>> {
        self.with_write_txn_grouped(|wtxn| {
            bump_open_session_activity_in_txn(&self.store, wtxn, key, now)
        })
    }

    /// Records an app-open point on the current sitting and advances its
    /// decisional activity clock to the point's effective time.
    pub fn record_session_app_open_hint(
        &self,
        key: SessionKey,
        timestamp: SessionHintTimestamp,
    ) -> Result<Option<EntityId>> {
        self.with_write_txn_grouped(|wtxn| {
            let Some((id, mut record)) = open_session_in_txn(&self.store, wtxn, key)? else {
                return Ok(None);
            };
            record.last_effective_ms = record.last_effective_ms.max(timestamp.effective_ms);
            record.last_activity = record.last_activity.max(timestamp.effective_ms / 1_000);
            record.app_open_hints.push(timestamp);
            RECORDS.put(&self.store, wtxn, &id, &record)?;
            Ok(Some(id))
        })
    }

    /// Records an activity period and advances the sitting to the period's
    /// last effective time. Stored periods whose arrival gap is strictly less
    /// than `rollup_gap_ms` merge; zero therefore preserves every delivered
    /// period losslessly.
    pub fn record_session_activity_period(
        &self,
        key: SessionKey,
        period: SessionActivityPeriod,
        rollup_gap_ms: u64,
    ) -> Result<Option<EntityId>> {
        self.with_write_txn_grouped(|wtxn| {
            let Some((id, mut record)) = open_session_in_txn(&self.store, wtxn, key)? else {
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

            RECORDS.put(&self.store, wtxn, &id, &record)?;
            Ok(Some(id))
        })
    }

    /// Plans only the turns witnessed in this sitting. Each actor/machine
    /// session ends independently; an active neighbour is never swept into it.
    pub fn plan_session_end_wake(&self, session: &EntityId) -> Result<SessionEndWake> {
        self.with_write_txn_grouped(|txn| self.plan_session_end_wake_in_txn(txn, session))
    }

    fn session_turn_ids_in_txn(
        &self,
        txn: &RwTxn<'_>,
        session: &EntityId,
        admission_time: u64,
    ) -> Result<Vec<EntityId>> {
        let mut turns = Vec::new();
        for row in SESSION_TURNS.iter_from(&self.store, txn, session.as_bytes())? {
            let ((_, turn), _) = row?;
            let Some(raw) = self.get_raw_in(txn, &turn)? else {
                continue;
            };
            let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
                continue;
            };
            if header.entity_type != crate::registry::ENTITY_TYPE_TURN
                || header.learned_at > admission_time
            {
                continue;
            }
            let facts = crate::dreamer_consolidation::decode_turn_body(
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            );
            let role = crate::dreamer_runner::dreamer_turn_role(
                facts.speaker.as_deref(),
                &self.config.assistant_display_names,
            );
            if crate::dreamer_runner::dreamer_extraction_role_admissible(role) {
                turns.push((header.learned_at, turn));
            }
        }
        turns.sort_unstable();
        Ok(turns.into_iter().map(|(_, turn)| turn).collect())
    }

    pub(crate) fn plan_session_end_wake_in_txn(
        &self,
        txn: &RwTxn<'_>,
        session: &EntityId,
    ) -> Result<SessionEndWake> {
        let scope = DreamerConsolidationScope::Meso;
        let watermark = read_watermark_in_txn(self, txn, scope)?;
        let admission_time = crate::ports::job_recorded_at_in_txn(&self.store, txn)?;
        let ids = self.session_turn_ids_in_txn(txn, session, admission_time)?;
        let mut turns = read_partition_turns_in_txn(self, txn, scope, &ids)?;
        turns.retain(|turn| turn.learned_at <= admission_time);
        let ids = turns.iter().map(|turn| turn.turn_id).collect();
        let edged: Vec<_> = turns
            .iter()
            .filter(|turn| turn.conversation.is_some())
            .copied()
            .collect();
        let plans = plan_partitions_in_txn(self, scope, txn, &edged, &watermark)?;
        Ok(SessionEndWake {
            session: *session,
            plans,
            planned_watermark: watermark.last_learned_at,
            planned_turn_ids: ids,
            advance_watermark_to: turns.iter().map(|turn| turn.learned_at).max(),
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
    /// * **(d) wake**: this sitting's SessionEnd → Meso partition attempts are
    ///   planned and enqueued in the SAME transaction, without consuming
    ///   another open sitting's turns;
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
        self.end_session_with_wake_and_hint(expected, predicate, now, wake, None)
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
        self.end_session_in_txn(wtxn, expected, predicate, now, wake, end_hint, None)
    }

    /// The close, keeping on the record why a close hook would have kept
    /// the sitting open, when one tried.
    #[expect(
        clippy::too_many_arguments,
        reason = "the close protocol's inputs plus the hook's stop"
    )]
    fn end_session_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        expected: &EntityId,
        predicate: SessionClosePredicate,
        now: u64,
        wake: &SessionEndWake,
        end_hint: Option<SessionHintTimestamp>,
        close_hook_stop: Option<String>,
    ) -> Result<Option<EndedSession>> {
        if wake.session != *expected {
            return Err(Error::InvalidKey);
        }
        let Some(record) = RECORDS.get(&self.store, wtxn, expected)? else {
            return Ok(None);
        };
        let record = validated_record(record)?;
        let key = record.key;
        let Some((id, mut record)) = open_session_in_txn(&self.store, wtxn, key)? else {
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
        record.close_hook_stop = close_hook_stop;
        if let Some(timestamp) = end_hint {
            record.last_effective_ms = record.last_effective_ms.max(timestamp.effective_ms);
            record.explicit_end_hint = Some(timestamp);
        }
        RECORDS.put(&self.store, wtxn, &id, &record)?;
        OPEN_POINTER.delete(&self.store, wtxn, &key.pointer())?;

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

        // Re-plan this sitting in the close transaction, including a witness
        // that arrived after the preview. Never advance the global watermark
        // past another still-open session's turns.
        let scope = DreamerConsolidationScope::Meso;
        let wake = self.plan_session_end_wake_in_txn(wtxn, &id)?;
        let current = read_watermark_in_txn(self, wtxn, scope)?;
        enqueue_partition_attempts_in_txn(
            self,
            wtxn,
            scope,
            &wake.planned_turn_ids,
            &current,
            None,
            now,
        )?;

        Ok(Some(EndedSession {
            session: id,
            started_at: record.started_at,
            last_activity: record.last_activity,
            ended_at,
            reason,
        }))
    }

    /// The close runs `host.session.close`'s hooks (ARCH-0080 §5) around its
    /// commit, when the close is due. No hook keeps a sitting open: a pre-hook
    /// that skips or asks has its stop kept on the record, and the sitting
    /// closes anyway.
    pub fn end_session_with_wake_and_hint(
        &self,
        expected: &EntityId,
        predicate: SessionClosePredicate,
        now: u64,
        wake: &SessionEndWake,
        end_hint: Option<SessionHintTimestamp>,
    ) -> Result<Option<EndedSession>> {
        let (pre, stop) = match self.session_close_due(expected, predicate, now)? {
            Some((actor, reason)) => {
                let args = session_hook_args(*expected, end_reason_word(reason));
                let check = |rewritten: &Value| host_args_kept(&args, rewritten);
                let call = session_hook_call(HOST_SESSION_CLOSE, *expected, actor, 1);
                match self.pre_verb_hooks(call, args.clone(), &check)? {
                    Ok(pre) => (Some(pre), None),
                    Err(stop) => (None, Some(stop.to_string())),
                }
            }
            None => (None, None),
        };
        let ended = self.with_write_txn_grouped(|wtxn| {
            self.end_session_in_txn(wtxn, expected, predicate, now, wake, end_hint, stop)
        })?;
        if let (Some(pre), Some(ended)) = (pre, &ended) {
            let result = json!({
                "session": ended.session.to_hex(),
                "ended_at": ended.ended_at,
                "reason": end_reason_word(ended.reason),
            });
            if let Err(error) = self.post_verb_hooks(pre, result) {
                tracing::warn!(
                    ?error,
                    "host.session.close post-hooks failed on a closed sitting"
                );
            }
        }
        Ok(ended)
    }

    /// The actor of sitting `expected` and why it would close at `now`, when
    /// it is open and its close is due; checked again when it closes.
    fn session_close_due(
        &self,
        expected: &EntityId,
        predicate: SessionClosePredicate,
        now: u64,
    ) -> Result<Option<(EntityId, SessionEndReason)>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(record) = RECORDS.get(&self.store, &rtxn, expected)? else {
            return Ok(None);
        };
        let key = validated_record(record)?.key;
        let Some((id, record)) = open_session_in_txn(&self.store, &rtxn, key)? else {
            return Ok(None);
        };
        if id != *expected {
            return Ok(None);
        }
        Ok(predicate
            .close_reason(&record, now)
            .map(|reason| (key.actor, reason)))
    }
}

/// A sitting's host-verb call. Its actor is the sitting's, in the System
/// class a write a host verb causes stamps; `step` tells the open (0) from
/// the close (1), so a retry of either keeps its invocation.
fn session_hook_call(verb: &str, session: EntityId, actor: EntityId, step: u64) -> VerbCall {
    VerbCall {
        verb: verb.to_owned(),
        invocation: InvocationId::of_run_step(session.as_bytes(), step),
        actor,
        class: HookActorClass::System,
        scope: None,
        board_epoch: None,
        domain: VerbDomain::Write,
        // A host's own call reads as its actor.
        reader: None,
    }
}

/// A sitting's host-verb args. A sitting belongs to no room.
fn session_hook_args(session: EntityId, reason: &str) -> Value {
    json!({"session": session.to_hex(), "room": Value::Null, "reason": reason})
}

/// A host verb's args are the host's: a hook's rewrite of them is refused.
fn host_args_kept(args: &Value, rewritten: &Value) -> std::result::Result<(), String> {
    if rewritten == args {
        Ok(())
    } else {
        Err("a host verb's args are the host's".to_owned())
    }
}

/// An end reason as its record spells it.
const fn end_reason_word(reason: SessionEndReason) -> &'static str {
    match reason {
        SessionEndReason::Explicit => "explicit",
        SessionEndReason::IdleFloor => "idle_floor",
        SessionEndReason::LifetimeCeiling => "lifetime_ceiling",
    }
}

#[cfg(test)]
mod tests;
