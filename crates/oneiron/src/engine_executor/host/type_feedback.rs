//! The type checks of the callable skills a run's program calls (FIX
//! 10389): each admitted once, at the call's preparation, and kept beside
//! the run on its own route as the call ends, however it ends. A call is
//! kept by the run, the program step whose calls these are and its bridge
//! position past that step's own program (invocation 0), so two real calls
//! of one skill are two invocations, and a call nested in another is its
//! own. A pinned entry's own call is its program: every entry that replays
//! it reads the one check its first entry admitted, never a new one (CALLS
//! "pinned program feedback identity").

use super::super::code_check::{CheckedDoor, ProgramAdmission, ProgramCheck, TypeFeedback};
use super::super::types::CallableProgram;
use super::RecordingJsHost;
use crate::EntityId;
use crate::code_run::StepKey;

/// The program step a pinned entry's own call is checked as: the turn
/// program's own, whose identity holds across every entry that replays it
/// (CALLS "pinned program feedback identity").
pub(in crate::engine_executor) const PINNED_PROGRAM_STEP: u64 = 0;

/// The checks a host's callable calls start, and what they are kept by.
#[derive(Default)]
pub(in crate::engine_executor) struct CallableChecks<'s> {
    service: Option<&'s TypeFeedback>,
    /// The program step whose calls these are.
    program_seq: u64,
    /// The bridge position of a pinned entry's own call.
    pinned: Option<u64>,
    /// The checks started and not yet kept, by their call's bridge position.
    started: Vec<(u64, ProgramCheck)>,
}

impl<'s> CallableChecks<'s> {
    /// The checks of the calls program step `program_seq` makes, on
    /// `service`; none attached when it is `None`.
    pub(in crate::engine_executor) fn new(
        service: Option<&'s TypeFeedback>,
        program_seq: u64,
    ) -> Self {
        Self {
            service,
            program_seq,
            pinned: None,
            started: Vec::new(),
        }
    }

    /// The same, for a pinned entry whose own call takes bridge position
    /// `seq`.
    pub(in crate::engine_executor) fn pinned(mut self, seq: u64) -> Self {
        self.pinned = Some(seq);
        self
    }

    /// What the call at bridge position `seq` of `run` is kept by.
    fn key(&self, run: EntityId, seq: u64) -> StepKey {
        if self.pinned == Some(seq) {
            (run, self.program_seq, 0)
        } else {
            (run, self.program_seq, seq.saturating_add(1))
        }
    }
}

impl RecordingJsHost<'_, '_> {
    /// The host's `start_callable_check`: starts the check of the call at
    /// `seq` under the run's identity for it, as the actor the run runs as,
    /// on the route the run keeps its feedback on. A pinned entry's own call
    /// whose program a row already holds reads that row again. A host with
    /// no store keeps nothing.
    pub(super) fn start_callable_check_at(&mut self, seq: u64, program: CallableProgram<'_>) {
        let Some(storage) = self.storage else {
            return;
        };
        let key = self.callable_checks.key(self.run_id, seq);
        if self.callable_checks.pinned == Some(seq)
            && matches!(storage.type_diagnostics_row(key), Ok(Some(_)))
        {
            return;
        }
        let admission = ProgramAdmission {
            key,
            actor: Some(self.gated_write.actor().entity_ref()),
            door: CheckedDoor::Callable,
            route: storage.feedback_route(),
        };
        let check = ProgramCheck::start(
            self.callable_checks.service,
            admission,
            program.original,
            program.prepared,
        );
        self.callable_checks.started.push((seq, check));
    }

    /// Keeps the check of the call at `seq` beside the run as the call
    /// ends, `completed` or not: on the run's own route, landed or pending.
    pub(super) fn keep_callable_check(&mut self, seq: u64, completed: bool) {
        let started = &mut self.callable_checks.started;
        let Some(at) = started.iter().position(|(call, _)| *call == seq) else {
            return;
        };
        let (_, mut check) = started.swap_remove(at);
        if let Some(storage) = self.storage {
            check.keep(storage);
        }
        if completed {
            check.completed();
        }
    }
}
