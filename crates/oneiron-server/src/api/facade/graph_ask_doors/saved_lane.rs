//! OF-506 (FIX 1857): a standing question saved through `vault.questions.create`
//! or `.edit` keeps the caller's own read lane, the one `vault.graph.ask`
//! reads under ([`super::asker_lane`]). The engine freezes it onto the
//! version it writes, so the pump and every later refresh read inside it and
//! a narrowed credential's question asks inside its narrowing.

use oneiron::EntityId;
use oneiron::WriteActor;
use oneiron::llm::decision::questions::{
    QuestionDefinitionInput, QuestionRecord, create_question_with_lane, edit_question_with_lane,
};
use oneiron::memory::MemoryResult;

use super::asker_lane;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The asker's new standing question, saved under the caller's own lane.
pub(super) fn create_under_caller_lane(
    server: &SyncServer,
    auth: &CoreAuth,
    asker: WriteActor,
    definition: QuestionDefinitionInput,
    verb: &str,
) -> MemoryResult<QuestionRecord> {
    let vault = server.vault();
    let lane = asker_lane(vault, auth, asker.entity_ref(), verb)?;
    Ok(create_question_with_lane(
        vault,
        asker,
        &lane,
        definition,
        oneiron_vault_contract::now_ts(),
    )?)
}

/// The asker's standing question's next version, saved under the caller's
/// own lane.
pub(super) fn edit_under_caller_lane(
    server: &SyncServer,
    auth: &CoreAuth,
    asker: WriteActor,
    id: EntityId,
    expected_version: u32,
    definition: QuestionDefinitionInput,
    verb: &str,
) -> MemoryResult<QuestionRecord> {
    let vault = server.vault();
    let lane = asker_lane(vault, auth, asker.entity_ref(), verb)?;
    Ok(edit_question_with_lane(
        vault,
        asker,
        &lane,
        id,
        expected_version,
        definition,
        oneiron_vault_contract::now_ts(),
    )?)
}
