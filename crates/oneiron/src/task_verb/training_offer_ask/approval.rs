//! Which words of a training offer ask approve its act, and whether that
//! act still stands (row OWNER-CONFIRM-SHEET, PR 4b-4). A person's word is
//! as important as the act it approves, so a device asks for the person
//! before an approving word, and only for an act the store still admits
//! (`crate::task_verb::ask_guard`).

use super::{OPTIONS, offered_answer, routed_in};
use crate::error::Result;
use crate::skill_optimize::OfferAnswer;
use crate::task_verb::ask_record::AskGroup;
use crate::task_verb::ask_types::{TaskAskOptionId, TaskAskWord};
use crate::{EntityId, Vault};

/// Whether `option` approves what a training offer ask asks for: the switch
/// to the offered model or the training of the custom one. Keep, decline
/// and postpone leave today's setup.
pub(in crate::task_verb) fn approves(option: &TaskAskOptionId) -> bool {
    OPTIONS.iter().any(|(id, answer, _)| {
        *id == option.as_str()
            && matches!(
                answer,
                OfferAnswer::ApproveSwitch | OfferAnswer::ApproveTrain
            )
    })
}

/// Refuses a `word` that approves a stock switch which would not bind now,
/// from a read: the refusals the offer's settlement gives the same word on
/// its cut before the switch's first write
/// (`crate::skill_optimize::training_offer_switch_stands_in_txn`), made
/// before a device asks for the person. The offer's own checks are the
/// word's admission's (`super::offered_in`); an approval to train records
/// an intent and binds nothing, so it passes.
///
/// # Errors
///
/// A switch the seat's binding, the registry or the manifest no longer
/// admits; storage errors.
pub(in crate::task_verb) fn approved_act_stands_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
    word: &TaskAskWord,
) -> Result<()> {
    let Some(route) = routed_in(vault, txn, id, group)? else {
        return Ok(());
    };
    let Some(offer) =
        crate::skill_optimize::pending_training_offer_in_txn(vault, txn, &route.offer)?
            .filter(|offer| offer.digest == route.digest)
    else {
        return Ok(());
    };
    let answer = word
        .option
        .as_ref()
        .and_then(|option| offered_answer(&offer, option));
    if matches!(answer, Some(OfferAnswer::ApproveSwitch)) {
        crate::skill_optimize::training_offer_switch_stands_in_txn(vault, txn, &offer)?;
    }
    Ok(())
}
