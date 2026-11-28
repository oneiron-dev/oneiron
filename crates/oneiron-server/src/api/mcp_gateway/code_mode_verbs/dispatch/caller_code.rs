//! What a caller's own code may not call, whatever its credential holds (FIX
//! EXECUTE-CALLER-CODE), and the binding its speech needs.

use super::*;

/// The reason a caller's own code may not call `verb`, whatever its
/// credential holds (FIX EXECUTE-CALLER-CODE): a browser or desktop row
/// starts the host's guest, which no direct door lends a Read grant (FIX
/// EXECUTE-SOURCE-BROWSER-PARITY), and a row marked `"caller_code":
/// "refused"` answers with a credential or a secret value.
pub(super) fn caller_code_verb_refusal(verb: AgentVerb) -> Option<&'static str> {
    if verb.is_browser() {
        return Some("caller_code.host_guest");
    }
    verb.refused_to_caller_code()
        .then_some("caller_code.credential_answer")
}

/// The reason a caller's own code may not make a run call with `effect`: a
/// reader child or a summary job queues model work on the host's meter,
/// which no direct call reaches; and a run row whose answer can carry a
/// secret value (the run table holds no `caller_code` key, so the list is
/// here): a repo snapshot or view read with the original file, a skill call's
/// or a connector's foreign answer, a leader's advice or pattern.
pub(super) fn caller_code_run_refusal(effect: SelfEffect) -> Option<&'static str> {
    match effect {
        SelfEffect::ReaderSpawn => Some("caller_code.reader_child"),
        SelfEffect::Summarize => Some("caller_code.summary_job"),
        SelfEffect::RepoSnapshotsRead
        | SelfEffect::RepoViewsRead
        | SelfEffect::SkillsCall
        | SelfEffect::ConnectorAnswer
        | SelfEffect::Leader => Some("caller_code.credential_answer"),
        _ => None,
    }
}

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
