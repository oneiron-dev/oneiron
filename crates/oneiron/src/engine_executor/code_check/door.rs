//! A program a door other than a run's own step runs, checked as a step's
//! program is (FIX 10389): a callable skill a run's program calls, a foreign
//! program, a pack script and a shadow arm's step. The door admits the
//! program once, as its author wrote it, against the declaration files its
//! runtime teaches, under the identity its feedback is kept by and with the
//! route it is kept on. Nothing the door runs waits on the check, and
//! nothing is refused for it: a checker that is absent, off or failed is a
//! typed fact on the program's feedback.

use std::sync::Arc;

use oneiron_code_check::{Declaration, ProgramLanguage};

use super::super::host::executor_declarations;
use super::{CheckJob, StepCell, StepCheck, TypeFeedback};
use crate::code_run::{
    ExecutorStorage, FeedbackRoute, ProgramPreparationNote, ProgramStepFeedback, StepKey,
    TYPE_CHECK_NOT_ATTACHED, TypeDiagnostics,
};
use crate::code_sandbox::source::{PreparedSource, SourceLanguage};
use crate::engine_executor::EngineExecutorStatus;
use crate::{EntityId, Vault};

/// The executor's catalog of `self.*` verbs, which only a door that lends
/// its program the run's host bridge teaches.
const CODE_MODE_DTS: &str = "code-mode.d.ts";

/// The arguments a callable skill's program reads: the host's prelude line
/// binds them, so its stored file never declares them.
const CALLABLE_ARGS_DTS: Declaration<'static> = Declaration {
    name: "callable.d.ts",
    text: "/** The call's arguments, as its contract admitted them. */\n\
           declare const skillArgs: any;\n",
};

/// The grants a pack script's program reads: the host's prelude binds each
/// granted connection's opaque handle by the name the pack requested it as.
const PACK_GRANTS_DTS: Declaration<'static> = Declaration {
    name: "pack-grants.d.ts",
    text: "/** Each granted connection's opaque handle, by its requested name. */\n\
           declare const packGrants: Readonly<Record<string, {\n  \
           readonly handle: string;\n  readonly scheme: string;\n  readonly host: string;\n}>>;\n",
};

/// The door a program runs by, for the declaration files it is checked
/// against.
#[derive(Debug, Clone, Copy)]
pub(crate) enum CheckedDoor {
    /// A shadow arm's step: the executor's own runtime and catalog.
    ShadowArm,
    /// A callable skill a run's program calls, through the run's host.
    Callable,
    /// A foreign program: its interpreter, with no host catalog lent.
    Foreign,
    /// A pack's adapter script: the foreign interpreter and its grants.
    PackScript,
}

/// The declaration files a door's program is checked against (CALLS "door
/// declarations", FIX 10389): those its runtime and its door teach it, owned
/// by its check. A shadow arm's step takes the executor's three; a callable
/// takes them with its arguments, whatever its tier, as its host lends it
/// the run's catalog; a foreign program takes the runtime's two without the
/// catalog, as no host bridge is lent to it; a pack script takes those with
/// its grants' shape, never a concrete grant's handle.
fn door_declarations(door: CheckedDoor) -> Vec<Declaration<'static>> {
    let executor = executor_declarations();
    let runtime = executor
        .into_iter()
        .filter(|file| file.name != CODE_MODE_DTS);
    match door {
        CheckedDoor::ShadowArm => executor.to_vec(),
        CheckedDoor::Callable => executor.into_iter().chain([CALLABLE_ARGS_DTS]).collect(),
        CheckedDoor::Foreign => runtime.collect(),
        CheckedDoor::PackScript => runtime.chain([PACK_GRANTS_DTS]).collect(),
    }
}

/// What a door admits its program's check under.
pub(crate) struct ProgramAdmission {
    /// The run, step and invocation the program's feedback is kept by.
    pub(crate) key: StepKey,
    /// The actor the program runs as, whose erase takes its feedback.
    pub(crate) actor: Option<EntityId>,
    pub(crate) door: CheckedDoor,
    /// Where a check that lands after the door ends keeps its result.
    pub(crate) route: FeedbackRoute,
}

/// One door's check of its program, held by the door: its feedback as it
/// stands, kept on its run's own route as the door ends. Dropping it counts
/// the program as failed unless [`Self::completed`] said otherwise. It never
/// waits.
pub(crate) struct ProgramCheck {
    check: StepCheck,
    /// Whether a collection past one reply goes to a body of the run.
    bodies: bool,
}

impl ProgramCheck {
    /// Starts the check of `program`, as its author wrote it, in the
    /// language its preparation `prepared` found, with that preparation's
    /// note. A door with no checker answers that none is attached.
    pub(crate) fn start(
        service: Option<&TypeFeedback>,
        admission: ProgramAdmission,
        program: &str,
        prepared: &PreparedSource<'_>,
    ) -> Self {
        let bodies = admission.route.keeps_bodies();
        let job = CheckJob {
            key: admission.key,
            program: program.to_owned(),
            language: match prepared.language() {
                SourceLanguage::JavaScript => ProgramLanguage::JavaScript,
                SourceLanguage::TypeScript => ProgramLanguage::TypeScript,
            },
            note: prepared.note().map(ProgramPreparationNote::of),
            actor: admission.actor,
            source: None,
            declarations: door_declarations(admission.door),
            route: admission.route,
        };
        let check = match service {
            Some(feedback) => feedback.start(job),
            None => {
                let unattached = TypeDiagnostics::unavailable(TYPE_CHECK_NOT_ATTACHED, None);
                StepCheck::unavailable(&job, unattached)
            }
        };
        Self { check, bodies }
    }

    /// The program's feedback as it stands now.
    pub(crate) fn feedback(&self) -> ProgramStepFeedback {
        self.check.cell().feedback()
    }

    /// Keeps the program's feedback as it stands on `storage`, its run's own
    /// route: landed once, or pending once, the check then writing its own
    /// result when it lands. A write that fails is traced, never the run's
    /// failure.
    pub(crate) fn keep(&self, storage: &ExecutorStorage<'_>) {
        let cell = self.check.cell();
        if self.bodies {
            cell.finalize(storage);
        }
        if let Some(row) = cell.claim_row()
            && let Err(error) = storage.put_type_diagnostics(cell.key(), &row)
        {
            tracing::warn!(target: "oneiron::code_check", %error, "type feedback not kept");
        }
    }

    /// The program ran to its end: counted so, not as failed.
    pub(crate) fn completed(&mut self) {
        self.check.ended(Some(&EngineExecutorStatus::Complete));
    }

    /// A reader of the program's feedback as it stands, for as long as its
    /// holder keeps it.
    pub(crate) fn latest(&self) -> LatestFeedback {
        LatestFeedback(self.check.cell())
    }
}

/// A program's feedback as it stands, read again on each call: a shadow
/// arm's, under its lease (FIX 10389, fork d).
#[derive(Clone)]
pub(crate) struct LatestFeedback(Arc<StepCell>);

impl LatestFeedback {
    /// The program's feedback as it stands now.
    pub(crate) fn feedback(&self) -> ProgramStepFeedback {
        self.0.feedback()
    }
}

/// A foreign program's or a pack script's check, kept on the vault's own
/// rows however its run ends (FIX 10389): dropping it keeps the program's
/// feedback as it stands, landed or pending, its whole collection in its
/// row for the owner's read by its `check_ref`.
pub(crate) struct RowsCheck<'v> {
    check: ProgramCheck,
    vault: &'v Vault,
}

impl<'v> RowsCheck<'v> {
    /// Starts the check of `program`, run `run`'s only program, admitted as
    /// `actor` by `door` ([`ProgramCheck::start`]).
    pub(crate) fn start(
        service: Option<&TypeFeedback>,
        vault: &'v Vault,
        (run, actor, door): (EntityId, EntityId, CheckedDoor),
        program: &str,
        prepared: &PreparedSource<'_>,
    ) -> Self {
        let admission = ProgramAdmission {
            key: (run, 0, 0),
            actor: Some(actor),
            door,
            route: FeedbackRoute::RowsOnly(vault.vault_id()),
        };
        Self {
            check: ProgramCheck::start(service, admission, program, prepared),
            vault,
        }
    }

    /// The program's feedback as it stands now.
    pub(crate) fn feedback(&self) -> ProgramStepFeedback {
        self.check.feedback()
    }

    /// The program's run answered: counted so, not as failed.
    pub(crate) fn completed(&mut self) {
        self.check.completed();
    }
}

impl Drop for RowsCheck<'_> {
    fn drop(&mut self) {
        self.check.keep(&ExecutorStorage::Canonical(self.vault));
    }
}
