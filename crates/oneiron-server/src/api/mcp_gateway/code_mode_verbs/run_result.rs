//! `vault.runs.read_result` (FIX EXECUTE-CALLER-CODE; the Engine's option D,
//! 26 Nov 23:20): a caller's code reads a window of one stored result of one
//! of its own runs, so an `execute` result past its 20,000-character cut is
//! read in code rather than through a third MCP tool. This door answers it,
//! never the tool-first surface: the run is derived from the caller's own
//! MCP credential, which only this door holds.

use super::*;
use oneiron::code_run::run_result_read::RunResultReadRequest;
use serde::Deserialize;

impl McpCodeModeVerbs {
    /// One window of a stored result of the run `run_ref` names under this
    /// run's own credential. The run id is that credential's derivation
    /// (`mcp_code_run_id`), never an id the caller sends, so only the
    /// caller's own runs resolve. The read first meets the credential's own
    /// binding of `vault.runs.read_result` and its unrestricted record scope,
    /// as every verb call from code meets its row's binding (a credential
    /// bound to `execute` alone is refused `mcp_verb_not_bound`), then the
    /// session gate `execute` met, and the device-local check of the rows
    /// that result was served from. Those rows join this run's served rows,
    /// so this run's release withholds them as it withholds any read. A
    /// step's stored diagnostics body is not read here: its feedback leaves
    /// only through its own release (FIX 10614).
    pub(super) fn read_run_result(
        &self,
        input: &Value,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        let verb = AgentVerb::VaultRunsReadResult;
        if let Err(error) = mcp_admit_host_verb(&self.actor, verb)
            .and_then(|()| mcp_host_verb_gate(&self.server, &self.actor, verb))
        {
            return refused(error);
        }
        let request: RunResultReadRequest = match RunResultReadRequest::deserialize(input) {
            Ok(request) => request,
            Err(error) => return refused(McpGatewayError::typed_input_refused(&error)),
        };
        let run_id = crate::mcp::mcp_code_run_id(&request.run_ref, &self.actor);
        let destination = self.actor.destination();
        // `None` until the read resolves a result: an unknown ref read no row.
        let mut served = None;
        let read = self.server.vault.read_code_run_result_with_feedback(
            run_id,
            &request.result_ref,
            Some(oneiron::code_run::ResultFacet::Slice),
            request.slice_input(),
            |rows| {
                served = Some(rows.map(<[oneiron::EntityId]>::to_vec));
                if !destination.is_off_device() {
                    return Ok(false);
                }
                rows.map_or(Ok(true), |rows| {
                    crate::device_local::withholds_retained(
                        &self.server.vault,
                        destination,
                        rows,
                        &[],
                    )
                })
            },
        );
        let refusal = |code: &str, reason: Option<&str>| AgentVerbRefusal {
            hook_notice: None,
            code: code.to_owned(),
            reason_codes: reason.map(str::to_owned).into_iter().collect(),
        };
        let Ok((reply, feedback)) = read else {
            return Ok(Err(refusal("engine_error", None)));
        };
        if feedback.is_some() {
            return Ok(Err(refusal(
                "wrong_input",
                Some("run_result.diagnostics_body"),
            )));
        }
        // A run that kept no row set serves rows nobody knows: the answer's
        // rows are unknown, and its release withholds it off this device.
        let rows = served.unwrap_or_else(|| Some(Vec::new()));
        self.served
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(rows.iter().flatten().copied());
        Ok(Ok(AgentVerbAnswer::new(reply, rows)))
    }
}
