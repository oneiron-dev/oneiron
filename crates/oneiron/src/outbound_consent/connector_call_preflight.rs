//! `can({effect: {connector_call}})`: the scoped tool call `connector.call`
//! would make, judged read-only as its first chokepoint admission judges it
//! (FIX 22102).

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::error::Error;
use crate::memory::{CanEffectAnswer, CanEffectVerdict, Memory};
use crate::outbound_intent_ledger::IntentLedgerError;

use super::connector_call::{ConnectorCallRequest, ConnectorSource, Step};
use super::connector_call_driver::{ConnectorCallPassInput, PreparedConnectorCall};

impl Vault {
    /// The dated preflight of the scoped tool call `connector.call` with
    /// `request` would make for the caller `memory` is bound to (C2:207, FIX
    /// 22102). It runs the call's own request checks and its route, grant,
    /// key, manifest and preparation checks, then judges the pinned call on
    /// one read snapshot as its first chokepoint admission judges it. A stop
    /// before the Gate answers with the driver's own stop code. It writes
    /// nothing: no pending row, owner question, ledger intent, Gate decision
    /// or clock floor, and it presents no credential and sends nothing. A
    /// held or replayed call is not resumed: a preflight judges a fresh
    /// call. The answer is dated, and the call is judged again when it runs.
    pub(crate) fn can_connector_call(
        &self,
        memory: &Memory<'_>,
        request: &ConnectorCallRequest,
    ) -> Result<CanEffectAnswer, IntentLedgerError> {
        if !std::ptr::eq(memory.vault(), self) {
            return Err(IntentLedgerError::InvalidInput(
                "the caller's scope is bound to another vault",
            ));
        }
        // The served door's source choice: a builtin is not a catalog
        // connector's scoped call, and neither is a built-in workspace module
        // (`google.sheets`), which answers before the MCP driver.
        match ConnectorSource::resolve(request.source, &request.name) {
            ConnectorSource::Builtin
                if request.name != crate::web_connector::WEB_CONNECTOR_NAME =>
            {
                return Err(IntentLedgerError::InvalidInput("unknown builtin connector"));
            }
            ConnectorSource::Builtin => {
                return Err(IntentLedgerError::InvalidInput(
                    "can judges catalog connector calls; the built-in web connector is not judged here",
                ));
            }
            ConnectorSource::Catalog
                if crate::channel_identity_provider::workspace_connector::module(&request.name)
                    .is_some() =>
            {
                return Err(IntentLedgerError::InvalidInput(
                    "can judges catalog connector calls; a built-in workspace connector is not judged here",
                ));
            }
            ConnectorSource::Catalog => {}
        }
        let arguments = serde_json::to_string(&request.arguments).map_err(|_| {
            IntentLedgerError::InvalidInput("connector call arguments are not JSON")
        })?;
        let principal_ref = memory.actor().to_hex();
        let input = ConnectorCallPassInput {
            name: &request.name,
            tool: &request.tool,
            arguments: &arguments,
            mutation: request.mutation,
            principal_ref: &principal_ref,
            preferred_grant: None,
            remember_context: super::connector_remember::capture(memory),
        };
        // The endpoint the served connector host sends this route to, as
        // this host installed it.
        let pass = self.read_connector_call_pass(&input, |route| {
            self.served_transports()
                .connector_endpoint(&route.name)
                .map(str::to_owned)
        })?;
        let PreparedConnectorCall {
            prepared, grant_id, ..
        } = match pass.outcome {
            Ok(prepared) => prepared,
            Err(step) => {
                let (verdict, reasons, holds) = match step {
                    Step::Refused { reasons, .. } => (CanEffectVerdict::Deny, reasons, Vec::new()),
                    // Every hold the driver makes before the Gate is
                    // administrative: it names no press.
                    Step::Held { reasons, .. } => {
                        (CanEffectVerdict::Held, reasons.clone(), reasons)
                    }
                    _ => {
                        return Err(IntentLedgerError::InvalidRecord(
                            "a connector call preflight stopped on a send step",
                        ));
                    }
                };
                let txn = self.store.env.read_txn().map_err(Error::from)?;
                let at = crate::ports::job_recorded_at_in_txn(&self.store, &txn)?;
                return Ok(CanEffectAnswer::stopped(verdict, reasons, holds, at));
            }
        };

        // a call not yet made has no attempt; the zero attempt, which no
        // derived or minted attempt equals, names it, so no press bound to a
        // real call matches it, and a standing grant, remembered setting or
        // slate is judged as for any fresh call
        let effect = super::execution::scoped_prepared_effect(
            self,
            grant_id,
            &principal_ref,
            AttemptId::from_bytes(&[0; 16])?,
            0,
            &prepared,
        )?;

        // One read snapshot for the admission's rechecks, the policy and the
        // judgment, as the admission writer's.
        let txn = self.store.env.read_txn().map_err(Error::from)?;
        let at = crate::ports::job_recorded_at_in_txn(&self.store, &txn)?;
        let judgment =
            crate::outbound_chokepoint::judge_new_effect_in_txn(self, &txn, &effect, at)?;
        // A scoped call's admission paces at a full count-bound window and
        // reserves its tool's declared price before it charges.
        let budget = crate::gate::PreflightBudget {
            send_like: effect.budget_class.is_send(),
            paces: true,
            priced_tool: Some(&effect.tool),
        };
        let preflight =
            crate::gate::preflight_answer_in_txn(&self.store, &txn, &judgment, budget, at)?;
        Ok(CanEffectAnswer::judged(preflight, at))
    }
}
