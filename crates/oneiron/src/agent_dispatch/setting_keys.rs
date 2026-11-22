//! The agent dispatcher's owner Setting keys (DESIGN 15-setting-primitive): rows the setting
//! catalogue reads from this file.

use crate::check_in::ActClass;
use crate::setting::Kind;

/// Off: a plan run's result is filed only in a room its owner alone reads.
fn owner_alone_rooms() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Let a shared room take a plan run's result (PLAN-RUN-RESULT-SHARED-ROOM-SETTING; Engine
    /// ANSWER PLAN-RUN-TRACE-INTO-SUB-SESSION, 17 Nov 00:11). A settled plan run's result is
    /// filed into the run's sub-session as one record of typed refs under the approving TURN,
    /// HEAD unmoved. Off by default: only a room its owner alone reads takes it, so a run that
    /// used the owner's reach never posts its answer to another reader. On, a shared room takes
    /// it too, filed by the owner who approved the run while that owner is a live vault owner
    /// who stands in the room; the filing never seats them. A thread's turn keeps its run's
    /// result out either way. On is the looser value, so only the owner turns it on; an agent's
    /// change waits on the owner's answer.
    pub(crate) PLAN_RUN_RESULT_IN_SHARED_ROOM: bool = "agent_dispatch.plan_run.result_in_shared_room" {
        kind: Kind::new(owner_alone_rooms)
            .strictest(owner_alone_rooms)
            .lower(),
        act: ActClass::GrantWiden,
    };
}
