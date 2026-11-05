//! TASK roles, canonical body fields, and deterministic check-in streak values.

use oneiron_contracts::error::{Error, RecordError, Result};
use rmpv::Value;
use std::io::Cursor;

pub const TASK_BODY_ROLE_KEY: &str = "role";

/// The two derived counter keys, spelled exactly as the TASK
/// `FieldProfile::Full` list already names them in `serialize.rs`.
pub const TASK_BODY_CURRENT_STREAK_KEY: &str = "currentStreak";
pub const TASK_BODY_LONGEST_STREAK_KEY: &str = "longestStreak";

/// Pinned TASK role byte for the productivity pack.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskRole {
    Task = 1,
    Goal = 2,
    Milestone = 3,
    Habit = 4,
    HabitCheckin = 5,
    /// Engine-authored companion carrying one replicated TASK authority fact
    /// (`task_authority`). RESERVED: the generic raw doors refuse it, so only
    /// `task_authority::put_task_authority_fact_in_txn` and the sync replay
    /// door can write one. It decodes here because facts replicate and are
    /// read back like any other TASK row.
    AuthorityFact = 6,
}

impl TaskRole {
    /// The five USER-FACING roles. `AuthorityFact` is deliberately absent: it
    /// is engine plumbing that no caller may write, nests with nothing, and
    /// never renders — the nesting matrix and role-surface consumers that read
    /// this list would all have to special-case it back out.
    pub const ALL: [Self; 5] = [
        Self::Task,
        Self::Goal,
        Self::Milestone,
        Self::Habit,
        Self::HabitCheckin,
    ];

    #[must_use]
    pub const fn role_byte(self) -> u8 {
        match self {
            Self::Task => 1,
            Self::Goal => 2,
            Self::Milestone => 3,
            Self::Habit => 4,
            Self::HabitCheckin => 5,
            Self::AuthorityFact => 6,
        }
    }

    /// The pinned productivity nesting matrix (STO-04), read
    /// `parent.allows_child(child)`.
    ///
    /// Three pairs are legal and every other TASK pair is rejected, including
    /// same-role nesting: `Goal -> Milestone`, `Milestone -> Task`, and
    /// `Habit -> HabitCheckin` — the last generalizing, not competing with,
    /// the landed check-in parent rule. `Task` and `HabitCheckin` parent
    /// nothing. Roots are unaffected: a TASK with no `ChildOf` edge has no
    /// nesting relation to validate, so a root of ANY role stays legal.
    pub const fn allows_child(self, child: Self) -> bool {
        matches!(
            (self, child),
            (Self::Goal, Self::Milestone)
                | (Self::Milestone, Self::Task)
                | (Self::Habit, Self::HabitCheckin)
        )
    }

    #[must_use]
    pub const fn from_role_byte(role: u8) -> Option<Self> {
        match role {
            1 => Some(Self::Task),
            2 => Some(Self::Goal),
            3 => Some(Self::Milestone),
            4 => Some(Self::Habit),
            5 => Some(Self::HabitCheckin),
            6 => Some(Self::AuthorityFact),
            _ => None,
        }
    }

    /// Roles no generic writer may mint: their bodies ARE engine authority,
    /// so a caller able to write one could prove its own ownership of someone
    /// else's task.
    pub const fn is_engine_reserved(self) -> bool {
        matches!(self, Self::AuthorityFact)
    }
}

/// Decodes a TASK body to its map entries, rejecting every shape two decoders
/// could read differently: invalid MessagePack, trailing bytes, a non-map
/// root, and non-string keys.
fn task_body_entries(bytes: &[u8]) -> Result<Vec<(Value, Value)>> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        Error::Record(RecordError::InvalidTaskBody(
            "body is not valid MessagePack",
        ))
    })?;
    if cursor.position() != bytes.len() as u64 {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "trailing bytes after body map",
        )));
    }
    let Value::Map(entries) = value else {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "body must be a MessagePack map",
        )));
    };
    if entries.iter().any(|(key, _)| key.as_str().is_none()) {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "body keys must be strings",
        )));
    }
    Ok(entries)
}

pub fn task_role_from_body_bytes(bytes: &[u8]) -> Result<TaskRole> {
    let mut role = None;
    for (key, value) in task_body_entries(bytes)? {
        if key.as_str() != Some(TASK_BODY_ROLE_KEY) {
            continue;
        }
        if role.is_some() {
            return Err(Error::Record(RecordError::InvalidTaskBody(
                "duplicate task role key",
            )));
        }
        let role_byte = value
            .as_u64()
            .and_then(|raw| u8::try_from(raw).ok())
            .ok_or(Error::Record(RecordError::InvalidTaskBody(
                "task role must be a byte",
            )))?;
        role = Some(TaskRole::from_role_byte(role_byte).ok_or(Error::Record(
            RecordError::InvalidTaskBody("unknown task role"),
        ))?);
    }
    role.ok_or(Error::Record(RecordError::InvalidTaskBody(
        "missing task role",
    )))
}

/// The two derived counters a Habit-role TASK stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HabitStreak {
    pub current: u32,
    pub longest: u32,
}

fn is_streak_key(key: &Value) -> bool {
    matches!(
        key.as_str(),
        Some(TASK_BODY_CURRENT_STREAK_KEY | TASK_BODY_LONGEST_STREAK_KEY)
    )
}

/// The reducer — PURE and ORDER-INDEPENDENT.
///
/// The input is a BAG of UTC day buckets; it is sorted and deduplicated here,
/// so a shuffle, a duplicate same-day check-in, and a repeated reduction all
/// land on the same pair. `longest` is the maximum consecutive-day run;
/// `current` is the run ending at the NEWEST observed day — never at "today",
/// because no clock is read. Empty input is `(0, 0)`.
///
/// Run lengths grow through `checked_add`: a child set pathological enough to
/// overflow `u32` aborts the caller's transaction instead of wrapping or
/// saturating to replica-dependent output.
pub fn streak_from_checkin_days<I>(days: I) -> Result<HabitStreak>
where
    I: IntoIterator<Item = u64>,
{
    let mut days: Vec<u64> = days.into_iter().collect();
    days.sort_unstable();
    days.dedup();

    let mut streak = HabitStreak::default();
    let mut previous: Option<u64> = None;
    for day in days {
        // Ascending and deduplicated, so `day > previous` holds and the
        // difference cannot underflow.
        streak.current = match previous {
            Some(previous) if day - previous == 1 => streak
                .current
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("habit streak run length"))?,
            _ => 1,
        };
        streak.longest = streak.longest.max(streak.current);
        previous = Some(day);
    }

    Ok(streak)
}

/// Rewrites ONLY the two derived keys, preserving every unrelated field and
/// leaving the caller's header bytes untouched.
///
/// Deterministic: surviving fields keep their order and the two counters are
/// appended in a fixed order, so replicas holding the same parent body and the
/// same child set store the same bytes. Rerunning on an already-rewritten body
/// reproduces it exactly.
pub fn rewrite_habit_streak_fields(body: &[u8], streak: HabitStreak) -> Result<Vec<u8>> {
    let mut entries = task_body_entries_without_streaks(body)?;
    entries.push((
        Value::from(TASK_BODY_CURRENT_STREAK_KEY),
        Value::from(streak.current),
    ));
    entries.push((
        Value::from(TASK_BODY_LONGEST_STREAK_KEY),
        Value::from(streak.longest),
    ));
    encode_task_body(entries)
}

fn task_body_entries_without_streaks(body: &[u8]) -> Result<Vec<(Value, Value)>> {
    Ok(task_body_entries(body)?
        .into_iter()
        .filter(|(key, _)| !is_streak_key(key))
        .collect())
}

fn encode_task_body(entries: Vec<(Value, Value)>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries))
        .map_err(|_| Error::InvariantViolation("habit streak body encode"))?;
    Ok(out)
}

/// DISCARDS caller-supplied streak counters from a TASK body of ANY role,
/// returning `None` when the body named none — the common case, which is then
/// stored byte-for-byte as it arrived.
///
/// The public doors REJECT these keys ([`reject_public_streak_fields`]). The
/// sync-replay door cannot: rejecting a peer's row would strand it and diverge
/// the replicas. So it discards instead, and the discard covers every role,
/// not just `Habit` — a `Habit`'s counters are afterwards written solely by
/// [`recompute_habit_streak_in_txn`] out of the LOCAL child set, and a `Task`
/// or `HabitCheckin` row (which the tail pass never visits) can therefore
/// never carry the keys at all. A peer cannot mint a streak on any row.
pub fn strip_streak_fields(body: &[u8]) -> Result<Option<Vec<u8>>> {
    let entries = task_body_entries(body)?;
    if !entries.iter().any(|(key, _)| is_streak_key(key)) {
        return Ok(None);
    }
    encode_task_body(
        entries
            .into_iter()
            .filter(|(key, _)| !is_streak_key(key))
            .collect(),
    )
    .map(Some)
}

/// The raw TASK doors' body refusal — the ONE entry point
/// `batch::validate_public_raw_put` gives this module for both of them, so it
/// holds both invariants a generic writer must never be able to state about
/// itself.
///
/// The streak counters are DERIVED; a writer who could name them could mint a
/// streak the check-in children do not support. A reserved role is ENGINE
/// AUTHORITY ([`TaskRole::is_engine_reserved`]); a writer who could mint one
/// could forge the proof that it owns another principal's task. The
/// sync-replay door runs neither check by design: a peer's row is already
/// written on the peer, and storage convergence outranks both — its counters
/// are replaced by the local reducer, and its authority facts are re-validated
/// strictly on every read.
pub fn reject_public_streak_fields(body: &[u8]) -> Result<()> {
    let entries = task_body_entries(body)?;
    if entries.iter().any(|(key, _)| is_streak_key(key)) {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "task streak counters are derived from check-ins",
        )));
    }
    if task_role_from_body_bytes(body)?.is_engine_reserved() {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "reserved task role is written only by its engine door",
        )));
    }
    Ok(())
}
