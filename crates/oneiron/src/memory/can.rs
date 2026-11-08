//! `can`: the read-only preflight of an ask, or the dated preflight of one
//! effect (C2:207, FIX 22102). Neither mints a TASK, schedules a send or
//! records a decision.

use serde::{Deserialize, Serialize};

use super::{Memory, MemoryResult};
use crate::task_verb::TaskAskPreflight;
use crate::verbs::{CanEffect, CanRequest};

/// What `can` answers: an ask's preflight, or one effect's dated verdict
/// (FIX 22102). Untagged, so an ask's answer keeps its wire shape; the two
/// never decode as each other (an ask's answer has `recipients`, an
/// effect's `verdict`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CanAnswer {
    Ask(TaskAskPreflight),
    Effect(CanEffectAnswer),
}

/// The dated preflight of one effect (C2:207, FIX 22102): allow, deny,
/// would-ask or a named hold, judged as the act would be judged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanEffectAnswer {
    pub verdict: CanEffectVerdict,
    /// The Gate's reason codes (`GateReasonCode::as_str` tokens, without
    /// `allow`), or, when the act stops before the Gate, the connector
    /// driver's stop code (for example `connector_endpoint_not_installed`).
    pub reasons: Vec<String>,
    /// Each administrative hold, its reason token without its
    /// `gate.pending.` prefix (for example `charter_drift`), or, when the act
    /// stops before the Gate, the connector driver's hold code (for example
    /// `standing_grant_required`).
    pub holds: Vec<String>,
    /// An allowed send would take its place in a full envelope window
    /// rather than go now.
    pub waits_for_envelope_window: bool,
    /// An allowed act whose governing key's count-bound window is full would
    /// wait until this recording time (seconds, as `checked_at`), charged
    /// nothing until then. `null` when it would go now.
    pub rate_window_opens_at: Option<u64>,
    /// The recording time the judgment read, Unix seconds. The answer is
    /// dated: the act itself is judged again when it runs.
    pub checked_at: u64,
}

/// The word a dated effect preflight answers (C2:207). An administrative
/// hold is `held`, never `allow`, `deny` or `would_ask` (Engine 11:16).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanEffectVerdict {
    /// The Gate allows the act.
    Allow,
    /// The Gate refuses the act.
    Deny,
    /// The Gate would ask the owner before the act.
    WouldAsk,
    /// An administrative hold holds the act; each is named in `holds`.
    Held,
}

impl CanEffectVerdict {
    /// The word the Gate's preflight verdict `verdict` names.
    pub(crate) fn of_preflight(verdict: crate::gate::PreflightVerdict) -> Self {
        match verdict {
            crate::gate::PreflightVerdict::Allow => Self::Allow,
            crate::gate::PreflightVerdict::Deny => Self::Deny,
            crate::gate::PreflightVerdict::WouldAsk => Self::WouldAsk,
            crate::gate::PreflightVerdict::Held => Self::Held,
        }
    }
}

impl CanEffectAnswer {
    /// The answer `preflight` reads off a judgment dated `checked_at`.
    pub(crate) fn judged(preflight: crate::gate::ExternalEffectPreflight, checked_at: u64) -> Self {
        Self {
            verdict: CanEffectVerdict::of_preflight(preflight.verdict),
            reasons: preflight.reasons.into_iter().map(str::to_owned).collect(),
            holds: preflight.holds.into_iter().map(str::to_owned).collect(),
            waits_for_envelope_window: preflight.waits_for_envelope_window,
            rate_window_opens_at: preflight.rate_window_opens_at,
            checked_at,
        }
    }

    /// The answer of an act that stops before the Gate judges it, dated
    /// `checked_at`: `verdict` with the stop's own `reasons` and `holds`.
    pub(crate) fn stopped(
        verdict: CanEffectVerdict,
        reasons: Vec<String>,
        holds: Vec<String>,
        checked_at: u64,
    ) -> Self {
        Self {
            verdict,
            reasons,
            holds,
            waits_for_envelope_window: false,
            rate_window_opens_at: None,
            checked_at,
        }
    }
}

impl Memory<'_> {
    /// `can`: the read-only preflight of `request`. `{ask}` is the ask's
    /// preflight, exactly as [`Self::tasks_can_ask`] answers it; `{effect}`
    /// is the dated preflight of that one effect.
    pub fn can(&self, request: &CanRequest) -> MemoryResult<CanAnswer> {
        match request {
            CanRequest::Ask(can_ask) => Ok(CanAnswer::Ask(self.tasks_can_ask(&can_ask.ask)?)),
            CanRequest::Effect(effect) => match &effect.effect {
                CanEffect::OutboundSchedule(schedule) => Ok(CanAnswer::Effect(
                    self.can_outbound_schedule(&schedule.outbound_schedule)?,
                )),
                CanEffect::ConnectorCall(call) => Ok(CanAnswer::Effect(
                    self.vault
                        .can_connector_call(self, &call.connector_call)
                        .map_err(crate::verbs::connector_call_error)?,
                )),
            },
        }
    }
}
