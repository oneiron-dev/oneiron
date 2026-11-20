//! Records what the session forwards; it does not filter, sort or apply vault policy.

use oneiron_browser::{
    Admitted, BatchStep, BrowserEngine, BrowserError, ExpectInput, FiledWorkflow, LibraryCard,
    ReplayGuest, RetiredCard, RunOutcome, SupersedeRefusal, WorkflowLibrary, WorkflowProgram,
    WorkflowProof,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// The page opened by the canned workflow.
pub(crate) const PAGE_URL: &str = "https://shop.example/form";
const RETIRED_AT: u64 = 20;

/// Store calls and their arguments, in order, including failed calls.
#[derive(Debug, PartialEq)]
pub(crate) enum StoreCall {
    Find(String, Option<String>, Option<String>),
    Program(String),
    Admit(String, Value, Value, Option<String>),
    RecordRun(String, RunOutcome),
    Retire(String, Option<String>),
    IsRetired(String),
    SupersedesRefused(String, String),
    Retired(String),
}

/// The cards and canned answers held by the in-memory store.
#[derive(Default)]
pub(crate) struct StoreState {
    pub(crate) calls: Vec<StoreCall>,
    pub(crate) live: BTreeMap<String, (LibraryCard, FiledWorkflow)>,
    pub(crate) retired: Vec<RetiredCard>,
    pub(crate) find_cards: Vec<LibraryCard>,
    pub(crate) admission: Option<Admitted>,
    pub(crate) predecessor_refusal: Option<Option<SupersedeRefusal>>,
    pub(crate) record_run_error: Option<BrowserError>,
    pub(crate) recorded_runs: Vec<(String, RunOutcome)>,
}

/// The library installed on the session, with its state shared with the test.
pub(crate) struct WorkflowStore(pub(crate) Arc<Mutex<StoreState>>);

impl WorkflowLibrary for WorkflowStore {
    fn find(
        &mut self,
        site: &str,
        subgoal: Option<&str>,
        type_ref: Option<&str>,
    ) -> Result<Vec<LibraryCard>, BrowserError> {
        let mut state = self.0.lock().expect("workflow store state");
        state.calls.push(StoreCall::Find(
            site.to_owned(),
            subgoal.map(str::to_owned),
            type_ref.map(str::to_owned),
        ));
        Ok(state.find_cards.clone())
    }

    fn program(&mut self, workflow: &str) -> Result<Option<FiledWorkflow>, BrowserError> {
        let mut state = self.0.lock().expect("workflow store state");
        state.calls.push(StoreCall::Program(workflow.to_owned()));
        Ok(state.live.get(workflow).map(|(_, filed)| filed.clone()))
    }

    fn admit(
        &mut self,
        site: &str,
        program: &WorkflowProgram,
        proof: &WorkflowProof,
        supersedes: Option<&str>,
    ) -> Result<Admitted, BrowserError> {
        let mut state = self.0.lock().expect("workflow store state");
        state.calls.push(StoreCall::Admit(
            site.to_owned(),
            serde_json::to_value(program).expect("the admitted program serializes"),
            serde_json::to_value(proof).expect("the admitted proof serializes"),
            supersedes.map(str::to_owned),
        ));
        let admission = state
            .admission
            .clone()
            .ok_or_else(|| BrowserError::Library("unexpected admission".to_owned()))?;
        if let Admitted::Filed { workflow, .. } = &admission {
            let filed_card = LibraryCard {
                site: site.to_owned(),
                subgoal: program.subgoal.clone(),
                params: program.params.clone(),
                secret_params: program.secret_params.clone(),
                held_out: proof.held_out,
                supersedes: supersedes.map(str::to_owned),
                seed: proof.seed.clone(),
                ..card(workflow)
            };
            state.live.insert(
                workflow.clone(),
                (
                    filed_card,
                    FiledWorkflow {
                        program: program.clone(),
                        proof: proof.clone(),
                    },
                ),
            );
        }
        Ok(admission)
    }

    fn record_run(&mut self, workflow: &str, outcome: &RunOutcome) -> Result<(), BrowserError> {
        let mut state = self.0.lock().expect("workflow store state");
        state
            .calls
            .push(StoreCall::RecordRun(workflow.to_owned(), outcome.clone()));
        if let Some(error) = &state.record_run_error {
            return Err(error.clone());
        }
        state
            .recorded_runs
            .push((workflow.to_owned(), outcome.clone()));
        Ok(())
    }

    fn retire(
        &mut self,
        workflow: &str,
        reason: Option<&str>,
    ) -> Result<Option<LibraryCard>, BrowserError> {
        let mut state = self.0.lock().expect("workflow store state");
        state.calls.push(StoreCall::Retire(
            workflow.to_owned(),
            reason.map(str::to_owned),
        ));
        let Some((card, _)) = state.live.remove(workflow) else {
            return Ok(None);
        };
        state.retired.push(trace(card.clone(), RETIRED_AT, reason));
        Ok(Some(card))
    }

    fn is_retired(&mut self, workflow: &str) -> Result<bool, BrowserError> {
        let mut state = self.0.lock().expect("workflow store state");
        state.calls.push(StoreCall::IsRetired(workflow.to_owned()));
        Ok(state
            .retired
            .iter()
            .any(|trace| trace.card.workflow == workflow))
    }

    fn supersedes_refused(
        &mut self,
        site: &str,
        supersedes: &str,
    ) -> Result<Option<SupersedeRefusal>, BrowserError> {
        let mut state = self.0.lock().expect("workflow store state");
        state.calls.push(StoreCall::SupersedesRefused(
            site.to_owned(),
            supersedes.to_owned(),
        ));
        state
            .predecessor_refusal
            .ok_or_else(|| BrowserError::Library("unexpected predecessor lookup".to_owned()))
    }

    fn retired(&mut self, site: &str) -> Result<Vec<RetiredCard>, BrowserError> {
        let mut state = self.0.lock().expect("workflow store state");
        state.calls.push(StoreCall::Retired(site.to_owned()));
        Ok(state.retired.clone())
    }
}

/// A card for the form workflow under the supplied reference.
pub(crate) fn card(workflow: &str) -> LibraryCard {
    LibraryCard {
        workflow: workflow.to_owned(),
        site: "shop.example".to_owned(),
        subgoal: "Ready form".to_owned(),
        type_ref: "forms.fill@2".to_owned(),
        params: Vec::new(),
        secret_params: Vec::new(),
        runs: 0,
        failures: 0,
        recent: Default::default(),
        held_out: false,
        supersedes: None,
        seed: None,
        filed_at: 5,
        last_run_at: None,
        strict_misses: 0,
    }
}

/// A workflow that opens the fixture page and checks its Ready heading.
pub(crate) fn filed_workflow() -> FiledWorkflow {
    FiledWorkflow {
        program: WorkflowProgram {
            subgoal: "Ready form".to_owned(),
            params: Vec::new(),
            secret_params: Vec::new(),
            steps: vec![BatchStep::Open {
                url: PAGE_URL.to_owned(),
            }],
            postcondition: vec![ExpectInput {
                role: Some("heading".to_owned()),
                name: Some("Ready".to_owned()),
                ..Default::default()
            }],
        },
        proof: WorkflowProof {
            args: BTreeMap::new(),
            replay_args: BTreeMap::new(),
            held_out: false,
            seed: None,
            solved_url: PAGE_URL.to_owned(),
            solved_title: "Ready".to_owned(),
            replay_receipts: Vec::new(),
            replay_decisions: Vec::new(),
            replay_url: PAGE_URL.to_owned(),
            replay_guest: ReplayGuest {
                engine: BrowserEngine::Chromium,
                carried: Vec::new(),
                not_carried: Vec::new(),
            },
        },
    }
}

/// A retired trace with a deterministic timestamp and unchanged card.
pub(crate) fn trace(card: LibraryCard, retired_at: u64, reason: Option<&str>) -> RetiredCard {
    RetiredCard {
        card,
        retired_at,
        reason: reason.map(str::to_owned),
    }
}
