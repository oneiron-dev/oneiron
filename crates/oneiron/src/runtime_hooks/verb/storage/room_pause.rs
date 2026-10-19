//! A room's hook pause (FIX 5524; Engine 10-20, a widening of the 2c-3
//! call): a hook in an off-record room asks as a roomless session-only
//! call's hook does. The call it paused waits in the in-memory keep under
//! the room's own stretch (its registry key and when it was entered), in RAM
//! only, with its args and the route its run captured; nothing of it reaches
//! the room's overlay or base. Its caller's retry in the same stretch resumes
//! it once the room's route and the run's place on the roster hold again; a
//! named pause that the stretch's close or a restart dropped refuses, never
//! running as a new call. 2c's other Room rules stay: a room still lands no
//! block, proposal, queued task or effect.

use std::sync::Arc;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::off_record::SessionWriteRoute;
use crate::work_line::TaskWorkTurn;

use super::{HooksTarget, SessionHookKey, SessionHooks};

/// What a call in a room carries into its pre chain (FIX 5524): whether it
/// answers when its hooks cannot be read (`SessionHooks::answering_unread`),
/// the task-work turn its operation holds, which a hook's ask runs on, and
/// the hook pause it names as the one it resumes.
#[derive(Default)]
pub(crate) struct RoomHookCall {
    pub(crate) answers_unread: bool,
    pub(crate) turn: Option<Arc<TaskWorkTurn>>,
    pub(crate) resume: Option<EntityId>,
}

/// The route a room's call ran on when its hook asked, as the pause keeps
/// it, in RAM only.
#[derive(Clone)]
pub(in crate::runtime_hooks::verb) struct PausedRoute(Arc<SessionWriteRoute>);

impl std::fmt::Debug for PausedRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PausedRoute")
    }
}

impl SessionHooks<'_> {
    /// Where a hook's pause on these hooks' call waits: the room's stretch,
    /// or, with no room overlay, the call's own session or the process.
    pub(in crate::runtime_hooks::verb) fn pause_key(&self) -> &SessionHookKey {
        match &self.target {
            HooksTarget::Room { key, .. } | HooksTarget::Kept { key, .. } => key,
        }
    }

    /// The route a room's call runs on, for its hook's pause to keep; `None`
    /// with no room overlay.
    pub(in crate::runtime_hooks::verb) fn paused_route(&self) -> Option<PausedRoute> {
        match &self.target {
            HooksTarget::Room { route, .. } => Some(PausedRoute(Arc::new((*route).clone()))),
            HooksTarget::Kept { .. } => None,
        }
    }

    /// Admits a room's call again as it resumes a pause (FIX 5524): the route
    /// the pause kept and the one the call runs on now both still hold (the
    /// room published no mode since), and the run's participant is still on
    /// the room's roster. A call with no room overlay has none to check.
    ///
    /// # Errors
    ///
    /// The room's authority refusals: a stale route, a participant no longer
    /// in the room.
    pub(in crate::runtime_hooks::verb) fn readmit(
        &self,
        paused: Option<&PausedRoute>,
    ) -> Result<()> {
        let HooksTarget::Room { session, route, .. } = &self.target else {
            return Ok(());
        };
        if let Some(PausedRoute(paused)) = paused {
            paused.revalidate()?;
        }
        route.revalidate()?;
        session.admit_participant()
    }
}
