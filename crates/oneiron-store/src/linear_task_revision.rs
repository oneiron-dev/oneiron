//! The tracker mirror's revision rows for a typed TASK (`LINEAR_TASK_REVISION`,
//! `LINEAR_TASK_DIRTY`, `LINEAR_TASK_WRITER`) and the batch-door bump a TASK
//! put makes. The tracker mirror (`task_verb::linear_store`) reads and stamps
//! these rows; the store's put staging bumps them on a typed TASK write.
use oneiron_base::error::Error;
use oneiron_base::error::RecordError;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

pub const TASK_VERB_BODY_SUBKIND: &str = "typed";

pub fn task_body_has_typed_subkind(body: &[u8]) -> Result<bool> {
    let mut cursor = body;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::Record(RecordError::InvalidTaskBody("tasks.create.body")))?;
    if !cursor.is_empty() {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "tasks.create.body",
        )));
    }
    let Some(entries) = value.as_map() else {
        return Ok(false);
    };
    Ok(entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some("subkind"))
        .count()
        == 1
        && entries
            .iter()
            .filter(|(key, value)| {
                key.as_str() == Some("subkind") && value.as_str() == Some(TASK_VERB_BODY_SUBKIND)
            })
            .count()
            == 1)
}
