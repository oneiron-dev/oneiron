//! The engine operations the core write doors run on conversation rows and
//! owner credentials: the trait the engine implements.

use heed::{RoTxn, RwTxn};
use oneiron_contracts::memory::MemoryResult;

use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::conversation_body::ConversationBody;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

/// The engine operations the core write doors call. A store holds one
/// implementation from the moment it is assembled (see
/// [`crate::store::StoreHooks`]). Each door calls each method at the point
/// where it called the engine function of the same name, with the same
/// arguments, and keeps its result.
pub(crate) trait StoreCoreWriteOperations: Send + Sync {
    /// The engine's `conversation::create_in_txn`: the shared atomic create
    /// door for ordinary conversations and project-leader chats.
    #[allow(clippy::too_many_arguments)]
    fn create_conversation_in_txn(
        &self,
        vault: &crate::Vault,
        txn: &mut RwTxn<'_>,
        id: EntityId,
        body: &ConversationBody,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
        text: &[(&str, &str)],
    ) -> Result<()>;

    /// The engine's `memory::actor_is_vault_owner_in_txn`: whether `actor`,
    /// as `actor_class`, is the vault owner.
    fn actor_is_vault_owner_in_txn(
        &self,
        vault: &crate::Vault,
        txn: &RoTxn<'_>,
        actor: EntityId,
        actor_class: EdgeActorClass,
    ) -> MemoryResult<bool>;
}
