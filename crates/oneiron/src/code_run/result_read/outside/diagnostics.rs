//! One read of a code run's result through the MCP door, with the feedback
//! of the step whose stored diagnostics it shows (FIX 10614). A step's
//! diagnostics past one reply are kept whole in a body the run owns
//! (`DiagnosticCollection::Stored`). A read resolves that body as it
//! resolves any result of the run, under the same checks. This read also
//! gives the step's feedback from its durable row, so the door can judge the
//! view the reply shows as that step's feedback and withhold only the
//! feedback's text. The body is the output the reader selected, matched to
//! its row by the run's own occurrence of it, never by its bytes.

use super::{
    CodeRunRawOutput, EntityId, ExecutorStorage, Result, ResultFacet, Value, Vault,
    read_selected_in, unknown_handle,
};
use crate::code_run::ProgramStepFeedback;

impl Vault {
    /// [`Vault::read_code_run_result`], with the feedback of the step whose
    /// stored diagnostics body the read shows (FIX 10614): the step's
    /// feedback as its row holds it now, when the reply is an `output` of
    /// that body. `None` for a refusal, and for a read of any other result.
    /// The reply is the one [`Vault::read_code_run_result`] gives, from the
    /// same reader under the same checks.
    pub fn read_code_run_result_with_feedback(
        &self,
        run_id: EntityId,
        reference: &str,
        facet: Option<ResultFacet>,
        input: Value,
        withholds: impl FnOnce(Option<&[EntityId]>) -> Result<bool>,
    ) -> Result<(Value, Option<ProgramStepFeedback>)> {
        let Some(record) = self.get_code_run_replay_record(&run_id)? else {
            return Ok((unknown_handle(&[]), None));
        };
        let stored = self.type_diagnostics_stored(run_id);
        let bodies: Vec<CodeRunRawOutput> =
            stored.iter().map(|(_, _, body)| body.clone()).collect();
        let (reply, selected) = read_selected_in(
            &ExecutorStorage::Canonical(self),
            &record,
            &bodies,
            reference,
            facet,
            input,
            withholds,
        )?;
        if reply.get("output").is_none() {
            return Ok((reply, None));
        }
        // The run's occurrence of a body is its path in the run, and no
        // result of the run's own sits at a diagnostics body's path.
        let feedback = selected.and_then(|output| {
            stored
                .iter()
                .find(|(_, _, body)| body.path == output.path && body.handle == output.handle)
                .map(|(key, row, _)| row.feedback(*key))
        });
        Ok((reply, feedback))
    }
}
