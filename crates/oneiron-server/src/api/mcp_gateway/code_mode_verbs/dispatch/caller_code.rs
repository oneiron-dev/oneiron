//! The refusal a caller's own code answers with (FIX EXECUTE-CALLER-CODE;
//! what it may not call is decided in `static_admission`), and the binding
//! its speech needs.

use super::*;

/// A caller's own code's refusal: [`CALLER_CODE_REFUSED`] and the reason.
pub(super) fn caller_code_refused(reason: &str) -> AgentVerbRefusal {
    AgentVerbRefusal {
        hook_notice: None,
        code: CALLER_CODE_REFUSED.to_owned(),
        reason_codes: vec![reason.to_owned()],
    }
}

/// The binding a caller's own speech needs (FIX EXECUTE-CALLER-CODE): the
/// effect's own run row when the run table holds one (`self.think.aloud`),
/// else the public `say` row, which a plain `say(text)` and the run's other
/// speech (`self.speak`, `self.think`, `self.express`) are made through.
pub(super) fn caller_speech_binding(
    actor: &McpCallContext,
    effect: SelfEffect,
) -> Result<(), McpGatewayError> {
    match RunVerb::ALL.iter().find(|verb| verb.effect() == effect) {
        Some(verb) => mcp_admit_run_verb(actor, *verb),
        None => mcp_admit_host_verb(actor, AgentVerb::Say),
    }
}
