## crate
crates/oneiron

## flat-name-check
yes

## allowed
crates/oneiron-server/tests/ws_sync.rs
crates/oneiron/src/anchored_annotation.rs
crates/oneiron/src/batch.rs
crates/oneiron/src/batch/tests.rs
crates/oneiron/src/critic/tests.rs
crates/oneiron/src/dreamer_runner/tests.rs
crates/oneiron/src/habit.rs
crates/oneiron/src/lib.rs
crates/oneiron/src/repo_mutation/tests.rs
crates/oneiron/src/sync/bridge/tests.rs
crates/oneiron/src/sync/client/tests.rs
crates/oneiron/src/sync/quarantine/tests.rs
crates/oneiron/src/sync/queue/tests.rs
crates/oneiron/src/tests.rs
crates/oneiron/src/tests_bug.rs
crates/oneiron/src/types.rs
crates/oneiron/src/vault/tests.rs
crates/oneiron/tests/sync_convergence_props.rs
crates/oneiron/tests/sync_quarantine.rs

## error-literal
crates/oneiron/src/habit.rs
crates/oneiron/src/types.rs

## decl
+ pub mod habit

## impl-delta
- crates/oneiron/src/types.rs	impl TaskRole
+ crates/oneiron/src/habit.rs	impl TaskRole

## edit
crates/oneiron/src/batch.rs	match crate::types::task_role_from_body_bytes(data)? {	match crate::habit::task_role_from_body_bytes(data)? {
crates/oneiron/src/batch.rs	let task_role = crate::types::task_role_from_body_bytes(data)?;	let task_role = crate::habit::task_role_from_body_bytes(data)?;
crates/oneiron/src/batch.rs	crate::types::task_role_from_body_bytes(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)	crate::habit::task_role_from_body_bytes(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
crates/oneiron/src/batch.rs	crate::types::task_role_from_body_bytes(&old_record[ENTITY_METADATA_HEADER_LEN..])?;	crate::habit::task_role_from_body_bytes(&old_record[ENTITY_METADATA_HEADER_LEN..])?;
crates/oneiron/src/batch.rs	let new_role = crate::types::task_role_from_body_bytes(data)?;	let new_role = crate::habit::task_role_from_body_bytes(data)?;
crates/oneiron/src/batch/tests.rs	let task_body = crate::types::task_body_for_test(TaskRole::Task);	let task_body = crate::habit::task_body_for_test(TaskRole::Task);
crates/oneiron/src/batch/tests.rs	let checkin_body = crate::types::task_body_for_test(TaskRole::HabitCheckin);	let checkin_body = crate::habit::task_body_for_test(TaskRole::HabitCheckin);
crates/oneiron/src/batch/tests.rs	let habit_body = crate::types::task_body_for_test(TaskRole::Habit);	let habit_body = crate::habit::task_body_for_test(TaskRole::Habit);
crates/oneiron/src/batch/tests.rs	let checkin_body = crate::types::task_body_for_test(TaskRole::HabitCheckin);	let checkin_body = crate::habit::task_body_for_test(TaskRole::HabitCheckin);
crates/oneiron/src/batch/tests.rs	let replacement_body = crate::types::task_body_for_test(TaskRole::Task);	let replacement_body = crate::habit::task_body_for_test(TaskRole::Task);
crates/oneiron/src/batch/tests.rs	let habit_body = crate::types::task_body_for_test(TaskRole::Habit);	let habit_body = crate::habit::task_body_for_test(TaskRole::Habit);
crates/oneiron/src/batch/tests.rs	let checkin_body = crate::types::task_body_for_test(TaskRole::HabitCheckin);	let checkin_body = crate::habit::task_body_for_test(TaskRole::HabitCheckin);
crates/oneiron/src/batch/tests.rs	let habit_body = crate::types::task_body_for_test(TaskRole::Habit);	let habit_body = crate::habit::task_body_for_test(TaskRole::Habit);
crates/oneiron/src/batch/tests.rs	let checkin_body = crate::types::task_body_for_test(TaskRole::HabitCheckin);	let checkin_body = crate::habit::task_body_for_test(TaskRole::HabitCheckin);
crates/oneiron/src/batch/tests.rs	let demoted_body = crate::types::task_body_for_test(TaskRole::Task);	let demoted_body = crate::habit::task_body_for_test(TaskRole::Task);
crates/oneiron/src/batch/tests.rs	&crate::types::task_body_for_test(crate::types::TaskRole::Task),	&crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
crates/oneiron/src/batch/tests.rs	&crate::types::task_body_for_test(crate::types::TaskRole::Task),	&crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
crates/oneiron/src/batch/tests.rs	&crate::types::task_body_for_test(crate::types::TaskRole::Task),	&crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
crates/oneiron/src/critic/tests.rs	&crate::types::task_body_for_test(crate::types::TaskRole::Task),	&crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
crates/oneiron/src/dreamer_runner/tests.rs	&crate::types::task_body_for_test(crate::types::TaskRole::Task),	&crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
crates/oneiron/src/dreamer_runner/tests.rs	&crate::types::task_body_for_test(crate::types::TaskRole::Task),	&crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
crates/oneiron/src/repo_mutation/tests.rs	&crate::types::task_body_for_test(crate::types::TaskRole::Task),	&crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
crates/oneiron/src/sync/bridge/tests.rs	crate::types::task_body_for_test(crate::types::TaskRole::Task)	crate::habit::task_body_for_test(crate::habit::TaskRole::Task)
crates/oneiron/src/sync/client/tests.rs	crate::types::task_body_for_test(crate::types::TaskRole::Task)	crate::habit::task_body_for_test(crate::habit::TaskRole::Task)
crates/oneiron/src/sync/quarantine/tests.rs	crate::types::task_body_for_test(crate::types::TaskRole::Task)	crate::habit::task_body_for_test(crate::habit::TaskRole::Task)
crates/oneiron/src/sync/queue/tests.rs	crate::types::task_body_for_test(crate::types::TaskRole::Task)	crate::habit::task_body_for_test(crate::habit::TaskRole::Task)
crates/oneiron/src/vault/tests.rs	&crate::types::task_body_for_test(crate::types::TaskRole::Task),	&crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
crates/oneiron/src/vault/tests.rs	&crate::types::task_body_for_test(crate::types::TaskRole::Task),	&crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
crates/oneiron/src/vault/tests.rs	&crate::types::task_body_for_test(crate::types::TaskRole::Task),	&crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
crates/oneiron/src/vault/tests.rs	&crate::types::task_body_for_test(crate::types::TaskRole::Task),	&crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
crates/oneiron/src/vault/tests.rs	&crate::types::task_body_for_test(crate::types::TaskRole::Task),	&crate::habit::task_body_for_test(crate::habit::TaskRole::Task),

## frag-edit

## comment

## add
crates/oneiron/src/habit.rs	//! Productivity-pack task-role vocabulary + task/habit checkin validators.
crates/oneiron/src/habit.rs	#[cfg(test)]
crates/oneiron/src/habit.rs	#[cfg(test)]
crates/oneiron/src/habit.rs	mod tests {
crates/oneiron/src/habit.rs	}
