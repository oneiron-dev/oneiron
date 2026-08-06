//! Productivity-pack task-role vocabulary + task/habit checkin validators,
//! plus the derived Habit streak reducer (STO-03).
//!
//! `currentStreak` / `longestStreak` are DERIVED fields: nothing outside this
//! module may supply them. Every write that can change a Habit's check-in set
//! ends with [`recompute_habit_streak_in_txn`] in the SAME transaction, so the
//! stored counters are a function of the persisted children and of nothing
//! else — no clock, no insertion order, no peer-supplied value.

use std::io::Cursor;

use heed::RwTxn;
use rmpv::Value;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, child_of_prefix};
use crate::edge::parse_strict_edge_record;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_TASK;
use crate::store::Store;
use crate::temporal::TimeRange;

pub(crate) const TASK_BODY_ROLE_KEY: &str = "role";

/// The two derived counter keys, spelled exactly as the TASK
/// `FieldProfile::Full` list already names them in `serialize.rs`.
pub(crate) const TASK_BODY_CURRENT_STREAK_KEY: &str = "currentStreak";
pub(crate) const TASK_BODY_LONGEST_STREAK_KEY: &str = "longestStreak";

/// UTC day-bucket width. `occurred_start / STREAK_DAY_SECS` is the whole
/// normalization: integer division, no calendar, no local zone, no "today".
const STREAK_DAY_SECS: u64 = 86_400;

/// Pinned TASK role byte for the productivity pack.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskRole {
    Task = 1,
    Goal = 2,
    Milestone = 3,
    Habit = 4,
    HabitCheckin = 5,
}

impl TaskRole {
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
        }
    }

    #[must_use]
    pub const fn from_role_byte(role: u8) -> Option<Self> {
        match role {
            1 => Some(Self::Task),
            2 => Some(Self::Goal),
            3 => Some(Self::Milestone),
            4 => Some(Self::Habit),
            5 => Some(Self::HabitCheckin),
            _ => None,
        }
    }
}

#[cfg(test)]
pub(crate) fn task_body_for_test(role: TaskRole) -> Vec<u8> {
    let value = Value::Map(vec![(
        Value::from(TASK_BODY_ROLE_KEY),
        Value::from(role.role_byte()),
    )]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value)
        .expect("writing MessagePack TASK body to Vec cannot fail");
    bytes
}

/// Decodes a TASK body to its map entries, rejecting every shape two decoders
/// could read differently: invalid MessagePack, trailing bytes, a non-map
/// root, and non-string keys.
fn task_body_entries(bytes: &[u8]) -> Result<Vec<(Value, Value)>> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidTaskBody("body is not valid MessagePack"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(Error::InvalidTaskBody("trailing bytes after body map"));
    }
    let Value::Map(entries) = value else {
        return Err(Error::InvalidTaskBody("body must be a MessagePack map"));
    };
    if entries.iter().any(|(key, _)| key.as_str().is_none()) {
        return Err(Error::InvalidTaskBody("body keys must be strings"));
    }
    Ok(entries)
}

pub(crate) fn task_role_from_body_bytes(bytes: &[u8]) -> Result<TaskRole> {
    let mut role = None;
    for (key, value) in task_body_entries(bytes)? {
        if key.as_str() != Some(TASK_BODY_ROLE_KEY) {
            continue;
        }
        if role.is_some() {
            return Err(Error::InvalidTaskBody("duplicate task role key"));
        }
        let role_byte = value
            .as_u64()
            .and_then(|raw| u8::try_from(raw).ok())
            .ok_or(Error::InvalidTaskBody("task role must be a byte"))?;
        role = Some(
            TaskRole::from_role_byte(role_byte)
                .ok_or(Error::InvalidTaskBody("unknown task role"))?,
        );
    }
    role.ok_or(Error::InvalidTaskBody("missing task role"))
}

/// The two derived counters a Habit-role TASK stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct HabitStreak {
    pub(crate) current: u32,
    pub(crate) longest: u32,
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
pub(crate) fn streak_from_checkin_days<I>(days: I) -> Result<HabitStreak>
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

/// Recomputes one Habit's counters from its persisted check-in children and
/// rewrites the stored body, inside the caller's transaction.
///
/// The caller has already established that `habit_id` is a stored Habit-role
/// TASK. Children qualify only as `ENTITY_TYPE_TASK` with role `HabitCheckin`,
/// decoded from the FINAL `edges_in` state of this transaction — so a batch
/// that adds and removes the same edge sees what it left behind, not what it
/// staged. Any error here propagates and aborts the whole transaction,
/// including the check-in entity and the `ChildOf` edge that triggered it.
pub(crate) fn recompute_habit_streak_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    habit_id: &EntityId,
) -> Result<HabitStreak> {
    let mut days = Vec::new();
    for entry in store.edges_in.prefix_iter(wtxn, &child_of_prefix(habit_id))? {
        let (key, value) = entry?;
        let child = parse_strict_edge_record(&key, &value)?.target;
        let Some(raw) = store.entities.get(wtxn, child.as_bytes())? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Err(Error::CorruptedIndex("entity header"));
        };
        if header.entity_type != ENTITY_TYPE_TASK
            || task_role_from_body_bytes(&raw[ENTITY_METADATA_HEADER_LEN..])?
                != TaskRole::HabitCheckin
        {
            continue;
        }
        days.push(header.occurred_start / STREAK_DAY_SECS);
    }

    let streak = streak_from_checkin_days(days)?;

    let Some(raw) = store
        .entities
        .get(wtxn, habit_id.as_bytes())?
        .map(std::borrow::Cow::into_owned)
    else {
        return Ok(streak);
    };
    if raw.len() < ENTITY_METADATA_HEADER_LEN {
        return Err(Error::CorruptedIndex("entity header"));
    }
    let body = rewrite_habit_streak_fields(&raw[ENTITY_METADATA_HEADER_LEN..], streak)?;
    let mut rewritten = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
    rewritten.extend_from_slice(&raw[..ENTITY_METADATA_HEADER_LEN]);
    rewritten.extend_from_slice(&body);
    // Byte-idempotent: an unchanged child set stages no write at all, so the
    // metadata header cannot drift and a replay cannot churn the row.
    if rewritten != raw {
        store.entities.put(wtxn, habit_id.as_bytes(), &rewritten)?;
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
fn rewrite_habit_streak_fields(body: &[u8], streak: HabitStreak) -> Result<Vec<u8>> {
    let mut entries: Vec<(Value, Value)> = task_body_entries(body)?
        .into_iter()
        .filter(|(key, _)| !is_streak_key(key))
        .collect();
    entries.push((
        Value::from(TASK_BODY_CURRENT_STREAK_KEY),
        Value::from(streak.current),
    ));
    entries.push((
        Value::from(TASK_BODY_LONGEST_STREAK_KEY),
        Value::from(streak.longest),
    ));

    let mut out = Vec::with_capacity(body.len());
    rmpv::encode::write_value(&mut out, &Value::Map(entries))
        .map_err(|_| Error::InvariantViolation("habit streak body encode"))?;
    Ok(out)
}

/// Rejects a caller-supplied streak counter on the public TASK put doors. The
/// counters are derived; a writer who could name them could mint a streak the
/// check-in children do not support.
pub(crate) fn reject_public_streak_fields(body: &[u8]) -> Result<()> {
    if task_body_entries(body)?.iter().any(|(key, _)| is_streak_key(key)) {
        return Err(Error::InvalidTaskBody(
            "task streak counters are derived from check-ins",
        ));
    }
    Ok(())
}

impl Vault {
    /// Appends an immutable TASK/HabitCheckin child under a Habit-role TASK.
    pub fn put_habit_checkin(
        &self,
        habit_id: &EntityId,
        checkin_id: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Result<()> {
        self.batch()
            .put_habit_checkin(habit_id, checkin_id, occurred, learned_at, data)
            .commit()
    }
}

#[cfg(test)]
mod tests {
    use super::HabitStreak;
    use super::TASK_BODY_ROLE_KEY;
    use super::TaskRole;
    use super::Value;
    use super::reject_public_streak_fields;
    use super::rewrite_habit_streak_fields;
    use super::streak_from_checkin_days;
    use super::task_body_for_test;
    use super::task_role_from_body_bytes;

    #[test]
    fn task_role_from_body_bytes_rejects_malformed_bodies() {
        fn encode(value: &Value) -> Vec<u8> {
            let mut bytes = Vec::new();
            rmpv::encode::write_value(&mut bytes, value).expect("encode msgpack test body");
            bytes
        }

        let role_byte = TaskRole::Task.role_byte();

        // A map carrying two "role" entries: decoders that resolve first-vs-last
        // key differently must not silently disagree; this is rejected outright.
        let duplicate_role = encode(&Value::Map(vec![
            (Value::from(TASK_BODY_ROLE_KEY), Value::from(role_byte)),
            (Value::from(TASK_BODY_ROLE_KEY), Value::from(role_byte)),
        ]));
        match task_role_from_body_bytes(&duplicate_role) {
            Err(crate::error::Error::InvalidTaskBody(msg)) => {
                assert_eq!(msg, "duplicate task role key");
            }
            other => panic!("expected duplicate-role-key rejection, got {other:?}"),
        }

        let non_map = encode(&Value::from(role_byte));
        match task_role_from_body_bytes(&non_map) {
            Err(crate::error::Error::InvalidTaskBody(msg)) => {
                assert_eq!(msg, "body must be a MessagePack map");
            }
            other => panic!("expected non-map rejection, got {other:?}"),
        }

        let non_string_key = encode(&Value::Map(vec![(
            Value::from(1_u64),
            Value::from(role_byte),
        )]));
        match task_role_from_body_bytes(&non_string_key) {
            Err(crate::error::Error::InvalidTaskBody(msg)) => {
                assert_eq!(msg, "body keys must be strings");
            }
            other => panic!("expected non-string-key rejection, got {other:?}"),
        }
    }

    /// Every ordering of `days`, generated by Heap's algorithm. Exhaustive
    /// beats sampled here: order-independence is the whole property, so the
    /// test proves it over the full permutation group rather than over a seed.
    fn permutations(days: &[u64]) -> Vec<Vec<u64>> {
        fn walk(k: usize, buf: &mut Vec<u64>, out: &mut Vec<Vec<u64>>) {
            if k <= 1 {
                out.push(buf.clone());
                return;
            }
            for i in 0..k {
                walk(k - 1, buf, out);
                if k % 2 == 0 {
                    buf.swap(i, k - 1);
                } else {
                    buf.swap(0, k - 1);
                }
            }
        }
        let mut buf = days.to_vec();
        let mut out = Vec::new();
        walk(buf.len(), &mut buf, &mut out);
        out
    }

    fn streak(days: &[u64]) -> (u32, u32) {
        let reduced = streak_from_checkin_days(days.iter().copied()).expect("streak reduces");
        (reduced.current, reduced.longest)
    }

    #[test]
    fn streak_from_children_deterministic() {
        // Day buckets, not timestamps: 10-11-12 is a run of three, 12→15 is a
        // gap, and 15-16 is the run the NEWEST day ends. `current` is 2 and
        // `longest` is 3, so an implementation that returned "today's run" or
        // confused the two counters cannot pass.
        let days = [10_u64, 11, 12, 15, 16];
        let expected = (2_u32, 3_u32);
        assert_eq!(streak(&days), expected);

        // ORDER: every one of the 120 permutations reduces identically.
        for permuted in permutations(&days) {
            assert_eq!(
                streak(&permuted),
                expected,
                "shuffled check-in order changed the streak: {permuted:?}"
            );
        }

        // DUPLICATES: same-day check-ins are separate entities that contribute
        // one streak day, in any multiplicity and any order.
        let duplicated = [16_u64, 10, 11, 12, 11, 15, 16, 16, 10];
        assert_eq!(streak(&duplicated), expected);
        for permuted in permutations(&[10_u64, 10, 11, 11]) {
            assert_eq!(streak(&permuted), (2, 2));
        }

        // GAPS + boundaries: a lone day, a pure gap set, and the empty bag.
        assert_eq!(streak(&[7]), (1, 1));
        assert_eq!(streak(&[1, 3, 5, 7]), (1, 1));
        assert_eq!(streak(&[]), (0, 0));

        // NO CLOCK, NO FIXTURE DRIFT: shifting every day by the same offset
        // shifts nothing about the answer, so "now" cannot be an input.
        for offset in [0_u64, 1, 20_000, 4_000_000] {
            let shifted: Vec<u64> = days.iter().map(|day| day + offset).collect();
            assert_eq!(streak(&shifted), expected);
        }

        // REPEATED REDUCTION: reducing the same bag again is the same answer,
        // which is what makes the stored body byte-idempotent.
        for _ in 0..3 {
            assert_eq!(streak(&days), expected);
        }
    }

    #[test]
    fn streak_fields_are_rewritten_in_place_and_rejected_on_public_puts() {
        let body = task_body_for_test(TaskRole::Habit);
        let streak = HabitStreak {
            current: 2,
            longest: 5,
        };

        // A body without counters gains exactly the two derived keys.
        reject_public_streak_fields(&body).expect("a plain Habit body is a legal public put");
        let written = rewrite_habit_streak_fields(&body, streak).expect("rewrite");
        assert_eq!(
            task_role_from_body_bytes(&written).expect("role survives"),
            TaskRole::Habit,
            "the rewrite must preserve every unrelated field"
        );

        // Rewriting the rewritten body with the same streak is byte-stable,
        // and a stale counter is REPLACED, never duplicated.
        assert_eq!(
            rewrite_habit_streak_fields(&written, streak).expect("rewrite"),
            written
        );
        let stale = rewrite_habit_streak_fields(
            &written,
            HabitStreak {
                current: 9,
                longest: 9,
            },
        )
        .expect("rewrite");
        assert_eq!(
            rewrite_habit_streak_fields(&stale, streak).expect("rewrite"),
            written
        );

        // The public doors refuse a caller-supplied counter.
        match reject_public_streak_fields(&written) {
            Err(crate::error::Error::InvalidTaskBody(msg)) => {
                assert_eq!(msg, "task streak counters are derived from check-ins");
            }
            other => panic!("expected a derived-field rejection, got {other:?}"),
        }
    }
}
