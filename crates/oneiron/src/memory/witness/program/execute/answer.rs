//! A landed witness, after its write commits: the receipt it answers with, and the
//! on-record copy, live window or overlay segment it updates.

use super::*;

impl Memory<'_> {
    pub(super) fn answer_landed_witness(
        &self,
        landed: Landed,
        plan: &WitnessPlan<'_>,
        sink: WitnessSink<'_, '_>,
        on_record_session: Option<&OffRecordSession<'_>>,
    ) -> MemoryResult<WitnessReceipt> {
        match landed {
            Landed::HardDeleted(id) => Err(hard_deleted_refusal(&id)),
            Landed::Base(receipt) => {
                // A stretch on record took this turn into base; a copy of the
                // talk reads its messages there.
                if let Some(session) = on_record_session {
                    let messages: Vec<(EntityId, u64, &[u8])> = plan
                        .messages
                        .iter()
                        .map(|planned| {
                            (planned.id, planned.occurred.start, planned.body.as_slice())
                        })
                        .collect();
                    session.note_on_record_messages(plan.turn_id, &messages);
                }
                // A room row this turn extended reaches the room's live window
                // after commit: an append-only extension re-puts no TURN for
                // the live mirror to carry. No room row, no window: a no-op.
                #[cfg(feature = "sync")]
                self.vault.refresh_room_turn_in_live_window(&plan.turn_id);
                Ok(receipt)
            }
            Landed::Overlay { segment, aliases } => {
                // The overlay segment and the base txn commit together: the
                // segment applies staged rows only now, so a failure anywhere
                // in staging left the room byte-unchanged.
                segment.commit()?;
                if let WitnessSink::Overlay(overlay) = sink {
                    overlay.commit_shell();
                }
                overlay_receipt(plan, aliases)
            }
        }
    }
}
