//! Post-settlement evidence for house reads on their actual admitted run.
use oneiron::code_run::model_call::{NativeReadFailure, NativeReadOutcome, NativeReadRunSource};
use oneiron::llm::decision::{DecisionReadObserver, DecisionReadOutcome};
use oneiron::llm::run_admission::RunAdmission;
use oneiron::llm::{LabelReadFailure, LabelReadRequest};

use crate::decision_verdict::{ModelCallCaller, model_call_context};
use crate::models::native_call_capture::{NativeReadCapture, native_read_failure};

use super::HouseRead;

pub(super) enum HouseReadRun<'a> {
    Caller(&'a RunAdmission),
    HouseGate,
}

pub(super) struct HouseReadObserver<'a> {
    house: &'a HouseRead,
    run: HouseReadRun<'a>,
    caller: Option<ModelCallCaller>,
    no_record_at_arrival: bool,
}

impl<'a> HouseReadObserver<'a> {
    pub(super) fn new(house: &'a HouseRead, run: HouseReadRun<'a>) -> Self {
        let caller = model_call_context();
        let no_record_at_arrival = caller.as_ref().is_some_and(|caller| {
            house
                .vault
                .model_call_keeps_no_record_for(caller.session.as_deref(), Some(caller.principal))
        });
        Self {
            house,
            run,
            caller,
            no_record_at_arrival,
        }
    }
}

impl DecisionReadObserver for HouseReadObserver<'_> {
    fn observe(
        &self,
        request: &LabelReadRequest<'_>,
        outcome: DecisionReadOutcome<'_>,
        gate_run: Option<&RunAdmission>,
    ) {
        let Some(caller) = &self.caller else {
            return;
        };
        let (run, run_source) = match (&self.run, gate_run) {
            (HouseReadRun::Caller(run), None) => (*run, NativeReadRunSource::Caller),
            (HouseReadRun::HouseGate, Some(run)) => (run, NativeReadRunSource::HouseGate),
            _ => {
                tracing::warn!("decision-read evidence skipped: gate run source differs");
                return;
            }
        };
        let outcome = match outcome {
            DecisionReadOutcome::Failed(error) => {
                let Some(failure) = native_read_failure(error) else {
                    tracing::warn!("decision-read evidence skipped: unmapped terminal failure");
                    return;
                };
                // Only the content-free failure class survives; never retain the error.
                NativeReadOutcome::Failed {
                    failure,
                    usage: None,
                }
            }
            DecisionReadOutcome::Malformed(answer) => NativeReadOutcome::Failed {
                failure: NativeReadFailure::LabelRead(LabelReadFailure::Malformed),
                usage: Some(answer.usage.clone()),
            },
            DecisionReadOutcome::Completed(answer) => NativeReadOutcome::Completed {
                usage: answer.usage.clone(),
            },
        };
        let Some(capture) = NativeReadCapture::new(
            self.house.vault.as_ref(),
            request,
            Some(caller.principal),
            caller.session.clone(),
            self.no_record_at_arrival,
            run_source,
        ) else {
            return;
        };
        capture.record(
            run,
            || run.next_model_call_index(),
            self.house.reader.model(),
            self.house.reader.revision(),
            self.house.gate.connector.locality,
            outcome,
        );
    }
}
