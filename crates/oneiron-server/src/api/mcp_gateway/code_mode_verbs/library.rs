//! The vault's browser workflow library as a code-mode run's guest reads and files it.
//! `VaultLibrary` (its `WorkflowLibrary` impl) is its call surface.
//! The code_mode_verbs root defines `VaultLibrary`; `oneiron::browser_library` owns the records.

use super::*;

pub(super) fn library_failed(error: oneiron::Error) -> BrowserError {
    BrowserError::Library(error.to_string())
}

impl WorkflowLibrary for VaultLibrary {
    fn find(
        &mut self,
        site: &str,
        subgoal: Option<&str>,
        type_ref: Option<&str>,
    ) -> Result<Vec<LibraryCard>, BrowserError> {
        // A filter that names no task type is the caller's input refused.
        let type_ref = type_ref
            .map(type_filter)
            .transpose()
            .map_err(|malformed| BrowserError::Input(malformed.to_string()))?;
        let records = site_workflows(&self.server.vault, site, subgoal, type_ref.as_ref())
            .map_err(library_failed)?;
        Ok(records.iter().map(WorkflowRecord::card).collect())
    }

    fn program(&mut self, workflow: &str) -> Result<Option<FiledWorkflow>, BrowserError> {
        let Ok(id) = oneiron::EntityId::from_hex(workflow) else {
            return Ok(None);
        };
        Ok(oneiron::browser_library::workflow(&self.server.vault, id)
            .map_err(library_failed)?
            .map(|record| FiledWorkflow {
                program: record.program,
                proof: record.proof,
            }))
    }

    fn admit(
        &mut self,
        site: &str,
        program: &WorkflowProgram,
        proof: &WorkflowProof,
        supersedes: Option<&str>,
    ) -> Result<Admitted, BrowserError> {
        let Ok(supersedes) = supersedes.map(oneiron::EntityId::from_hex).transpose() else {
            return Ok(Admitted::Refused(SupersedeRefusal::Malformed));
        };
        let deadline = RetrievalDeadline::hard(Instant::now(), PLACEMENT_BUDGET);
        let decisions = self
            .server
            .decision_host()
            .placement_decisions(self.by, &deadline);
        let filing = file_workflow(
            &self.server.vault,
            self.by,
            site,
            program,
            proof,
            self.server.vault.now_recorded_at(),
            Some(&decisions),
            supersedes,
        )
        .map_err(library_failed)?;
        Ok(match filing {
            Filing::Filed { id, superseded } => Admitted::Filed {
                workflow: id.to_hex(),
                superseded,
            },
            Filing::Refused(why) => Admitted::Refused(why),
        })
    }

    /// Whether the vault's record of a retire proves `workflow` retired (FIX
    /// 8073); a ref that does not parse names none.
    fn is_retired(&mut self, workflow: &str) -> Result<bool, BrowserError> {
        let Ok(id) = oneiron::EntityId::from_hex(workflow) else {
            return Ok(false);
        };
        oneiron::browser_library::retired_workflow(&self.server.vault, id)
            .map(|retired| retired.is_some())
            .map_err(library_failed)
    }

    /// The proposal's `supersedes` link, read before its replay (FIX 7876):
    /// a ref that does not parse, or names no program of `site` the caller
    /// may succeed. The filing's write checks it again.
    fn supersedes_refused(
        &mut self,
        site: &str,
        supersedes: &str,
    ) -> Result<Option<SupersedeRefusal>, BrowserError> {
        let Ok(old) = oneiron::EntityId::from_hex(supersedes) else {
            return Ok(Some(SupersedeRefusal::Malformed));
        };
        oneiron::browser_library::supersedes_refusal(&self.server.vault, self.by, site, old)
            .map_err(library_failed)
    }

    fn record_run(&mut self, workflow: &str, outcome: &RunOutcome) -> Result<(), BrowserError> {
        let Ok(id) = oneiron::EntityId::from_hex(workflow) else {
            return Ok(());
        };
        record_workflow_run(
            &self.server.vault,
            id,
            outcome,
            self.by,
            self.server.vault.now_recorded_at(),
        )
        .map_err(library_failed)
    }

    fn retire(
        &mut self,
        workflow: &str,
        reason: Option<&str>,
    ) -> Result<Option<LibraryCard>, BrowserError> {
        let Ok(id) = oneiron::EntityId::from_hex(workflow) else {
            return Ok(None);
        };
        let retired = retire_workflow(
            &self.server.vault,
            id,
            self.by,
            reason,
            self.server.vault.now_recorded_at(),
        )
        .map_err(library_failed)?;
        match retired {
            Retired::Taken(record) => Ok(Some(record.card())),
            Retired::NotFiled => Ok(None),
            Retired::NotFiler => Err(BrowserError::Library(format!(
                "workflow {workflow} was filed from another caller's run; only that caller retires it"
            ))),
        }
    }

    fn retired(&mut self, site: &str) -> Result<Vec<RetiredCard>, BrowserError> {
        Ok(retired_workflows(&self.server.vault, site)
            .map_err(library_failed)?
            .iter()
            .map(RetiredWorkflow::card)
            .collect())
    }
}
