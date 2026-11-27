//! Test-only entry to the read door used by an off-record code run.

use serde_json::Value;

use crate::WriteActor;
use crate::claim::ScopedReadActorKey;
use crate::memory::{MemoryResult, SessionAnswer, SessionRead};
use crate::off_record::OffRecordSession;

/// Calls the room hydrate door on the fixture owner's key.
///
/// # Errors
///
/// The room's route or the hydrate read refuses.
pub fn hydrate_as_owner(
    session: &OffRecordSession<'_>,
    actor: WriteActor,
    input: &Value,
) -> MemoryResult<Value> {
    let route = session.write_route()?;
    let key = ScopedReadActorKey::vault_owner(actor.entity_ref());
    let context = session.read_context(&route, key)?;
    let SessionAnswer::Answered { output, .. } =
        context.answer(SessionRead::Hydrate, actor, input)?;
    Ok(output)
}
