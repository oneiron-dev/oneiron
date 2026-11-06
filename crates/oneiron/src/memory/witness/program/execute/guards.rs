//! The overlay witness write's composed-view guards and full-envelope admission.

use super::in_txn::WitnessWrite;
use super::*;

impl Memory<'_> {
    pub(super) fn admit_overlay_in_txn<'w>(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        write: &WitnessWrite<'w, '_, '_, '_, '_>,
        overlay: &OverlaySink<'_, '_>,
    ) -> MemoryResult<WitnessAdmission<'w>> {
        let WitnessWrite {
            plan,
            room_speech,
            assertion_lane,
            refused,
            unproven,
            ..
        } = *write;
        let rostered = room_speech.is_some();
        let person_author = self.overlay_guards_in_txn(plan, overlay, rostered, wtxn)?;
        // The writer's own key reads the composed room view, as
        // recall's session lane does; both drop here.
        let view = overlay.read_view()?;
        // A thread turn staged here is born bound as on base, to
        // the stretch's room and read against its base members
        // (FIX 3122); a stored one keeps its thread and takes
        // words from its audience alone.
        let thread = crate::workspace_roster::overlay_thread_binding_in(
            self.vault,
            &view.read(),
            wtxn,
            overlay.room()?,
            plan.conversation_id,
            plan.turn_id,
            self.actor,
            plan.turn,
        )?;
        let session_lane = assertion_lane.map(|lane| {
            self.vault
                .scoped_read_in_session(lane.actor_key().clone(), &view)
                .with_claim_status(ClaimReadStatus::Recorded)
        });
        let assertions = session_lane.as_ref().map(|lane| AssertionRead {
            lane,
            refused,
            unproven,
        });
        self.admit_witness_in_txn(
            plan,
            &view,
            wtxn,
            assertions,
            person_author,
            None,
            thread.as_ref(),
        )
    }
}
