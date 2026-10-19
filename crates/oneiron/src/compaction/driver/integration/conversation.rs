//! A conversation's self-written summary lands (FIX 4465 D): its packet is
//! admitted on the door's conversation binding, each turn proven a member of
//! the window's SESSION; the packet must be the gated request's own, over
//! exactly the evidence's turns, written by the run's byline. One write
//! transaction re-proves the SESSION and its turns, mints the epoch with its
//! writer, puts the durable receipt keyed by the SUMMARY and declares the
//! Dreamer's check, so a crash loses all of them or none.

use super::*;
use crate::compaction::{CompactionEvidence, CompactionExecution, ConversationEvidence};

impl CompactionDriver {
    /// Lands `gated`, a conversation window's accepted summary, with
    /// `execution`, the host's record of what wrote it, its conversation
    /// evidence set.
    pub(crate) fn integrate_conversation(
        &mut self,
        vault: &Vault,
        byline: WriteActor,
        gated: GatedCompaction,
        execution: CompactionExecution,
    ) -> Result<SwapPlan> {
        let Some(CompactionEvidence::Conversation(evidence)) = execution.evidence.clone() else {
            return Err(Error::InvariantViolation(
                "a conversation's summary carries no conversation evidence",
            ));
        };
        let landing = crate::compaction::self_writer::admit_self_conversation_landing(
            vault, &gated, execution,
        )?;
        Self::check_conversation_landing(&gated, byline, &landing, &evidence)?;
        let session = gated.request.session_ref;
        let turns: Vec<EntityId> = evidence.turns.iter().map(|span| span.turn).collect();
        let writer = landing.execution;
        self.integrate_inner(gated, &[], |request, product| {
            crate::compaction::epoch::mint_epoch_summary_guarded(
                vault,
                &session,
                byline,
                request,
                product,
                Some(&writer),
                |txn| {
                    crate::compaction::validate_session(&vault.store, txn, session)?;
                    crate::compaction::validate_turn_membership(&vault.store, txn, &turns, session)
                },
                |txn, mint| {
                    crate::compaction::put_conversation_receipt_in_txn(vault, txn, mint, &writer)?;
                    crate::dreamer_runner::maintenance::compaction_check::declare_conversation_check_in_txn(
                        vault,
                        txn,
                        mint.summary_id(),
                        mint.epoch(),
                        &writer,
                    )
                },
            )
        })
    }

    /// A conversation summary's packet belongs to its gated request: a
    /// conversation window's, in its SESSION, over its turns in order, which
    /// are the evidence's, as a digest of exactly the gated prose with the
    /// snapshot its pass stamped, written by the byline.
    fn check_conversation_landing(
        gated: &GatedCompaction,
        byline: WriteActor,
        landing: &crate::compaction::SelfLanding,
        evidence: &ConversationEvidence,
    ) -> Result<()> {
        let request = &gated.request;
        let mut turns: Vec<EntityId> = Vec::new();
        for message in &request.window {
            if !turns.contains(&message.turn_id) {
                turns.push(message.turn_id);
            }
        }
        let declared: Vec<EntityId> = evidence.turns.iter().map(|span| span.turn).collect();
        let packet = &landing.packet;
        if request.log != WindowLog::Conversation
            || packet.host_log().is_some()
            || packet.session() != request.session_ref
            || evidence.session != request.session_ref
            || packet.turn_ids() != turns.as_slice()
            || declared != turns
            || packet.digest_text() != Some(gated.product.summary_text.as_str())
            || landing.execution.snapshot().as_ref() != Some(packet.snapshot())
            || landing.execution.writer != byline.entity_ref()
        {
            return Err(Error::InvariantViolation(
                "a conversation summary's packet is not its gated request's",
            ));
        }
        Ok(())
    }
}
