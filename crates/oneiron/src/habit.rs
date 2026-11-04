//! Productivity-pack task-role vocabulary + task/habit checkin validators,
//! plus the derived Habit streak reducer (STO-03).
//!
//! `currentStreak` / `longestStreak` are DERIVED fields: nothing outside this
//! module may supply them. Every write that can change a Habit's check-in set
//! ends with `recompute_habit_streak_in_txn` in the SAME transaction, so the
//! stored counters are a function of the persisted children and of nothing
//! else — no clock, no insertion order, no peer-supplied value.

use crate::EdgeKind;
use crate::ports::EdgeStoreRead;
use crate::ports::EntityStoreRead;

use heed::RwTxn;
use rmpv::Value;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_TASK;
use crate::store::Store;
use crate::temporal::TimeRange;

pub use crate::write_envelope::task_body::TaskRole;
pub(crate) use crate::write_envelope::task_body::{
    HabitStreak, TASK_BODY_CURRENT_STREAK_KEY, TASK_BODY_LONGEST_STREAK_KEY, TASK_BODY_ROLE_KEY,
    reject_public_streak_fields, rewrite_habit_streak_fields, streak_from_checkin_days,
    strip_streak_fields, task_role_from_body_bytes,
};

/// UTC day-bucket width. `occurred_start / STREAK_DAY_SECS` is the whole
/// normalization: integer division, no calendar, no local zone, no "today".
const STREAK_DAY_SECS: u64 = 86_400;

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
    for entry in store.port_edges(
        wtxn,
        habit_id,
        crate::ports::EdgeDirection::In,
        Some(EdgeKind::ChildOf),
        None,
    )? {
        let edge_row = entry?;
        let child = edge_row.target;
        let Some(raw) = store
            .port_entity_record(wtxn, &child)?
            .map(|row| row.encode())
        else {
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

    crate::ports::EntityStoreMaintenance::port_habit_streak_materialize(
        store, wtxn, habit_id, streak,
    )?;
    Ok(streak)
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
    use super::task_body_for_test;
    use super::task_role_from_body_bytes;

    /// The reserved authority role DECODES — facts replicate and are read back
    /// like any other TASK row — but no generic writer may state one, so the
    /// raw doors refuse it where the derived-counter refusal already lives.
    #[test]
    fn the_reserved_authority_role_decodes_but_never_passes_a_raw_door() {
        assert_eq!(
            TaskRole::from_role_byte(TaskRole::AuthorityFact.role_byte()),
            Some(TaskRole::AuthorityFact)
        );
        assert_eq!(
            task_role_from_body_bytes(&task_body_for_test(TaskRole::AuthorityFact))
                .expect("a fact body decodes"),
            TaskRole::AuthorityFact
        );
        match reject_public_streak_fields(&task_body_for_test(TaskRole::AuthorityFact)) {
            Err(crate::error::Error::Record(crate::error::RecordError::InvalidTaskBody(msg))) => {
                assert_eq!(msg, "reserved task role is written only by its engine door");
            }
            other => panic!("expected a reserved-role rejection, got {other:?}"),
        }
        for role in TaskRole::ALL {
            assert!(!role.is_engine_reserved());
            reject_public_streak_fields(&task_body_for_test(role))
                .expect("every user-facing role stays a legal raw put");
        }
    }

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
            Err(crate::error::Error::Record(crate::error::RecordError::InvalidTaskBody(msg))) => {
                assert_eq!(msg, "duplicate task role key");
            }
            other => panic!("expected duplicate-role-key rejection, got {other:?}"),
        }

        let non_map = encode(&Value::from(role_byte));
        match task_role_from_body_bytes(&non_map) {
            Err(crate::error::Error::Record(crate::error::RecordError::InvalidTaskBody(msg))) => {
                assert_eq!(msg, "body must be a MessagePack map");
            }
            other => panic!("expected non-map rejection, got {other:?}"),
        }

        let non_string_key = encode(&Value::Map(vec![(
            Value::from(1_u64),
            Value::from(role_byte),
        )]));
        match task_role_from_body_bytes(&non_string_key) {
            Err(crate::error::Error::Record(crate::error::RecordError::InvalidTaskBody(msg))) => {
                assert_eq!(msg, "body keys must be strings");
            }
            other => panic!("expected non-string-key rejection, got {other:?}"),
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
            Err(crate::error::Error::Record(crate::error::RecordError::InvalidTaskBody(msg))) => {
                assert_eq!(msg, "task streak counters are derived from check-ins");
            }
            other => panic!("expected a derived-field rejection, got {other:?}"),
        }
    }
}
