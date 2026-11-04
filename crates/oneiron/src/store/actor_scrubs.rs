//! The actor scrubs of side tables whose eraser lives in the engine: the trait
//! the engine implements, and the store-layer scrub each declaration names.

use heed::RwTxn;

use crate::entity_id::EntityId;
use crate::error::Result;

/// The engine's actor scrubs for side tables the store layer declares. A store
/// holds one implementation from the moment it is assembled (see
/// [`crate::store::StoreHooks`]). Each method is the engine eraser of the same
/// name; the declaration's scrub below calls it with the same arguments.
pub trait StoreActorScrubs: Send + Sync {
    /// The engine's `workspace_roster::erase_card_actor_in_txn`
    /// (side table `PROJECT_PROPOSAL_CARD`).
    fn erase_card_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()>;

    /// The engine's `workspace_roster::erase_pending_actor_in_txn`
    /// (side table `PROJECT_PROPOSAL_PENDING`).
    fn erase_pending_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()>;

    /// The engine's `workspace_roster::erase_host_pin_actor_in_txn` (side table `ROOMS_HOST_PIN`).
    fn erase_host_pin_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()>;

    /// The engine's `workspace_roster::erase_join_actor_in_txn` (side table `ROOMS_JOIN`).
    fn erase_join_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()>;

    /// The engine's `workspace_roster::erase_offer_actor_in_txn` (side table `ROOMS_OFFER`).
    fn erase_offer_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()>;

    /// The engine's `workspace_roster::erase_turn_actor_in_txn` (side table `ROOMS_TURN`).
    fn erase_turn_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()>;

    /// The engine's `workspace_roster::erase_companion_principal_actor_in_txn`
    /// (side table `WORKSPACE_ROSTER_COMPANION_PRINCIPAL`).
    fn erase_companion_principal_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()>;

    /// The engine's `workspace_roster::erase_member_actor_in_txn`
    /// (side table `WORKSPACE_ROSTER_MEMBER`).
    fn erase_member_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()>;

    /// The engine's `workspace_roster::erase_member_intent_actor_in_txn`
    /// (side table `WORKSPACE_ROSTER_MEMBER_INTENT`).
    fn erase_member_intent_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()>;
}

/// The actor scrub `PROJECT_PROPOSAL_CARD` declares:
/// the engine's `workspace_roster::erase_card_actor_in_txn`.
pub(crate) fn erase_card_actor_in_txn(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    vault
        .store
        .actor_scrubs
        .erase_card_actor_in_txn(vault, wtxn, actor)
}

/// The actor scrub `PROJECT_PROPOSAL_PENDING` declares:
/// the engine's `workspace_roster::erase_pending_actor_in_txn`.
pub(crate) fn erase_pending_actor_in_txn(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    vault
        .store
        .actor_scrubs
        .erase_pending_actor_in_txn(vault, wtxn, actor)
}

/// The actor scrub `ROOMS_HOST_PIN` declares:
/// the engine's `workspace_roster::erase_host_pin_actor_in_txn`.
pub(crate) fn erase_host_pin_actor_in_txn(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    vault
        .store
        .actor_scrubs
        .erase_host_pin_actor_in_txn(vault, wtxn, actor)
}

/// The actor scrub `ROOMS_JOIN` declares: the engine's `workspace_roster::erase_join_actor_in_txn`.
pub(crate) fn erase_join_actor_in_txn(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    vault
        .store
        .actor_scrubs
        .erase_join_actor_in_txn(vault, wtxn, actor)
}

/// The actor scrub `ROOMS_OFFER` declares:
/// the engine's `workspace_roster::erase_offer_actor_in_txn`.
pub(crate) fn erase_offer_actor_in_txn(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    vault
        .store
        .actor_scrubs
        .erase_offer_actor_in_txn(vault, wtxn, actor)
}

/// The actor scrub `ROOMS_TURN` declares: the engine's `workspace_roster::erase_turn_actor_in_txn`.
pub(crate) fn erase_turn_actor_in_txn(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    vault
        .store
        .actor_scrubs
        .erase_turn_actor_in_txn(vault, wtxn, actor)
}

/// The actor scrub `WORKSPACE_ROSTER_COMPANION_PRINCIPAL` declares:
/// the engine's `workspace_roster::erase_companion_principal_actor_in_txn`.
pub(crate) fn erase_companion_principal_actor_in_txn(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    vault
        .store
        .actor_scrubs
        .erase_companion_principal_actor_in_txn(vault, wtxn, actor)
}

/// The actor scrub `WORKSPACE_ROSTER_MEMBER` declares:
/// the engine's `workspace_roster::erase_member_actor_in_txn`.
pub(crate) fn erase_member_actor_in_txn(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    vault
        .store
        .actor_scrubs
        .erase_member_actor_in_txn(vault, wtxn, actor)
}

/// The actor scrub `WORKSPACE_ROSTER_MEMBER_INTENT` declares:
/// the engine's `workspace_roster::erase_member_intent_actor_in_txn`.
pub(crate) fn erase_member_intent_actor_in_txn(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    vault
        .store
        .actor_scrubs
        .erase_member_intent_actor_in_txn(vault, wtxn, actor)
}
