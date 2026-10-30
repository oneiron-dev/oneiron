//! A base landing's staging inside the witness write: its rows, the outbox marks a turn
//! with new words owes, held tags settled in the same write, and the receipt read there.

use super::in_txn::WitnessWrite;
use super::*;

impl Memory<'_> {
    pub(super) fn stage_base_landing_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        write: &WitnessWrite<'_, '_, '_, '_, '_>,
        base: &BaseSink<'_>,
        admission: &WitnessAdmission<'_>,
        mint_conversation: bool,
        quoted: Option<&crate::conversation_dag::QuotedReply>,
    ) -> MemoryResult<WitnessReceipt> {
        let WitnessWrite {
            plan, held, door, ..
        } = *write;
        self.stage_in_base(plan, admission, base, mint_conversation, quoted, wtxn)?;
        // The outbox rule (write-path hub; ARCH-0036): a turn that
        // gained text owes the vault's tagger a pass, and its
        // embedder a vector of the new text (ARCH-0004), committed
        // with the turn. An exact retry stages nothing and owes
        // nothing.
        if matches!(admission.turn, AdmittedTurn::Mint { .. }) || admission.has_new_messages() {
            // A chat or voice commit owes a live pass; an import,
            // held tags and the host executor a bulk one (FIX 6755).
            let work = if plan.imported.is_some()
                || held.is_some()
                || matches!(door, WitnessDoor::HostExecutor)
            {
                crate::memory::extraction::ExtractionWork::Bulk
            } else {
                crate::memory::extraction::ExtractionWork::Live
            };
            crate::tagging::mark_turn_in_txn(self.vault, wtxn, plan.turn_id, work)?;
            crate::embed::mark_turn_in_txn(self.vault, wtxn, plan.turn_id)?;
            crate::workspace_roster::stage_project_detection_in_txn(
                self.vault,
                wtxn,
                plan.conversation_id,
                plan.turn_id,
                plan.messages
                    .iter()
                    .rev()
                    .find(|planned| {
                        planned.message.author == WitnessAuthor::User
                            && planned.message.is_visible
                            && !planned.message.content.is_empty()
                    })
                    .map(|planned| planned.id),
                (self.actor_class == crate::edge::EdgeActorClass::Human && plan.imported.is_none())
                    .then_some(self.actor),
                plan.learned_at,
            )?;
        }
        // Held tags settle the marker just committed, in this
        // write, so no worker ever claims it. Their spans index
        // the messages as sent.
        if let Some(held) = held {
            let sent: Vec<_> = plan
                .messages
                .iter()
                .map(|planned| (planned.id, planned.message.content.as_str()))
                .collect();
            held.outcome
                .set(Some(crate::tagging::settle_held_tags_in_txn(
                    self.vault,
                    wtxn,
                    &plan.turn_id,
                    held.tags,
                    Some(&sent),
                )?));
        }
        // Read here: a body put after this commit is not its receipt.
        self.base_receipt_in_txn(plan, wtxn)
    }
}
