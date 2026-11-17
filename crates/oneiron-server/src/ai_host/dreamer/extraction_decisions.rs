//! The Dreamer pass's live extraction and settlement loans.
//!
//! Both loans share the bound server's pause and home check: with no bound
//! server, under the host's pause or off the home node neither lends. The
//! settlement loan lends the host's live ladder and bands, while the
//! extraction gate re-reads the owner's route defaults for the prepared
//! verdict route. The prepared model and run never switch.

use std::sync::Arc;

use oneiron::dreamer_consolidation::DREAMER_VERDICT_ROLE;
use oneiron::dreamer_runner::DreamerDecisionLender;
use oneiron::llm::decision::{DecisionBandPolicy, DecisionLadder, TypedDecision};
use oneiron::llm::manifest::ModelRole;
use oneiron::{CallPurpose, ModelLocality};
use oneiron_driver::ExtractionDecisionGate;

use crate::models::RoleRoute;
use crate::runtime::wall_clock_ms as now_ms;
use crate::server::SyncServer;

use super::super::policy::{DreamerRoute, dreamer_role_purpose, dreamer_route};
use super::{CONFLICT_SETTLE_RETRY_AFTER_SECS, PassAdmission, QuestionTimer, pause, paused};

/// Returns the bound server only while its live pause and home checks admit a loan.
///
/// Checks for a missing server, the host's pause and the home election in that order.
fn loan_server(
    question_timer: &QuestionTimer,
    admission: &PassAdmission,
) -> oneiron::Result<Option<Arc<SyncServer>>> {
    let Some(server) = question_timer.get().and_then(std::sync::Weak::upgrade) else {
        return Ok(None);
    };
    if paused(pause(admission).as_ref())
        || !crate::decision_graph::at_home(&server, now_ms() / 1_000)?
    {
        return Ok(None);
    }
    Ok(Some(server))
}

/// Lends the host's live ladder for one admitted conflict settlement ask.
///
/// The attempt's binding proves the lease; this loan also checks the host's
/// current pause and home election before every next ask starts (FIX 7376).
/// With no bound server, under the pause or off the home node it lends no
/// ladder: the ask refuses `MODEL_UNAVAILABLE` and the job stops there,
/// landing what it ruled before.
pub(super) struct ConflictSettleLender {
    /// Holds the bound server's weak handle, upgraded on every ask.
    pub(super) question_timer: QuestionTimer,
    /// Holds the host control whose pause is read on every ask.
    pub(super) admission: PassAdmission,
}

impl DreamerDecisionLender for ConflictSettleLender {
    /// Lends the host's live ladder and bands when the server may still lend.
    fn lend(
        &self,
        decide: &mut dyn FnMut(
            &DecisionLadder<'_>,
            &DecisionBandPolicy,
        ) -> oneiron::Result<TypedDecision>,
    ) -> oneiron::Result<TypedDecision> {
        let withheld = oneiron::Error::ProviderUnavailable {
            retry_after: CONFLICT_SETTLE_RETRY_AFTER_SECS,
        };
        let Some(server) = loan_server(&self.question_timer, &self.admission)? else {
            return Err(withheld);
        };
        let host = server.decision_host();
        decide(&host.ladder().ladder(), &host.bands())
    }
}

/// Rechecks live permission for one pass's prepared extraction verdict route.
///
/// The pass's model and run never switch: every loan re-reads the owner's
/// route defaults for the verdict route the pass prepared, and refuses when
/// the bound server is gone, paused, off the home node, unrouted or blocked.
pub(super) struct ExtractionLoanGate {
    /// Holds the bound server's weak handle, upgraded on every admission check.
    question_timer: QuestionTimer,
    /// Holds the host control whose pause is read on every admission check.
    admission: PassAdmission,
    /// Holds the prepared verdict purpose and locality, or `None` when it was unrouted.
    verdict: Option<(CallPurpose, ModelLocality)>,
    /// Retains the startup host permission for extraction to leave the device.
    allow_egress: bool,
}

impl ExtractionLoanGate {
    /// Captures the prepared verdict route's purpose and locality from the pass's routes.
    ///
    /// Keeps `None` when the pass routed no verdict role, which every later admission refuses.
    pub(super) fn new(
        question_timer: QuestionTimer,
        admission: PassAdmission,
        routes: &[(ModelRole, RoleRoute)],
        allow_egress: bool,
    ) -> Self {
        let verdict = routes
            .iter()
            .find(|(role, _)| *role == DREAMER_VERDICT_ROLE)
            .map(|(role, route)| (dreamer_role_purpose(*role), route.locality));
        Self {
            question_timer,
            admission,
            verdict,
            allow_egress,
        }
    }
}

impl ExtractionDecisionGate for ExtractionLoanGate {
    /// Re-reads the owner's route defaults for the prepared verdict route.
    ///
    /// Returns `true` when the bound server may still lend and the owner defaults allow the route.
    fn admits(&self) -> oneiron::Result<bool> {
        let Some(server) = loan_server(&self.question_timer, &self.admission)? else {
            return Ok(false);
        };
        let Some((purpose, locality)) = &self.verdict else {
            return Ok(false);
        };
        match dreamer_route(
            server.vault(),
            &[(purpose.clone(), *locality)],
            self.allow_egress,
        )? {
            DreamerRoute::Ready { .. } => Ok(true),
            DreamerRoute::Blocked(_) => Ok(false),
        }
    }
}
