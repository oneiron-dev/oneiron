//! Doors for `tests/epoch_lineage_pointer_form_summary.rs`
//! ([EPOCH-LINEAGE-POINTER-FORM-SUMMARY]): an inline epoch row minted as the
//! codec writes one, and the lineage census over a fixture vault's rows.

use crate::Vault;
use crate::compaction::{
    EPOCH_SUMMARY_BODY_VERSION, EPOCH_SUMMARY_LEVEL, EpochScope, EpochSummaryBody, PriorEpoch,
    encode_epoch_summary_body, prior_epoch_in_txn_for_test_door,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_SUMMARY;

/// Puts an inline epoch SUMMARY of `text` over `turn_start..=turn_end` in
/// `session`'s lineage (`conversation`'s within it when named), encoded by
/// the production codec, and returns its id.
///
/// # Errors
/// The codec's or the put's.
pub fn put_inline_epoch(
    vault: &Vault,
    session: &EntityId,
    conversation: Option<&EntityId>,
    epoch: u64,
    turn_start: u64,
    turn_end: u64,
    text: &str,
    actor: &EntityId,
) -> Result<EntityId> {
    let body = EpochSummaryBody {
        v: EPOCH_SUMMARY_BODY_VERSION,
        session: session.to_hex(),
        conversation: conversation.map(EntityId::to_hex),
        epoch,
        turn_start,
        turn_end,
        level: EPOCH_SUMMARY_LEVEL,
        text: text.to_owned(),
        actor: actor.to_hex(),
    };
    let id = EntityId::now();
    vault.put_entity(
        &id,
        ENTITY_TYPE_SUMMARY,
        crate::TimeRange { start: 1, end: 1 },
        1,
        &encode_epoch_summary_body(&body)?,
    )?;
    Ok(id)
}

/// Whether the lineage census reads `epoch` ending at `turn_end` as the
/// prior of `session`'s lineage (`conversation`'s within it when named).
///
/// # Errors
/// The census's: a conflicting or malformed highest epoch.
pub fn prior_epoch_matches(
    vault: &Vault,
    session: &EntityId,
    conversation: Option<&EntityId>,
    epoch: u64,
    turn_end: u64,
) -> Result<bool> {
    let scope = match conversation {
        Some(conversation) => EpochScope::of_conversation(*session, *conversation),
        None => EpochScope::of_session(*session),
    };
    let rtxn = vault.store.env.read_txn()?;
    let prior = prior_epoch_in_txn_for_test_door(&vault.store, &rtxn, &scope)?;
    Ok(prior == Some(PriorEpoch::new(epoch, turn_end)))
}
