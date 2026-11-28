//! Static admission checks for resolved callers and trusted verb rows.
//!
//! A static decision uses only the row name (or its typed metadata) and the
//! resolved caller, including the run author where relevant. It needs no vault,
//! request input, landing, liveness or record lookup. Each call path checks its
//! own guard in order and builds its own error. A later discovery view can use
//! these same checks to hide rows without calling them.

use super::McpCallContext;
use super::tasks_response::RunAuthor;
use crate::auth::{CoreAuth, CoreScope};
use crate::mcp::McpResolvedActor;
use oneiron::code_run::{RunCall, SelfEffect};
use oneiron::federation::ScopeAxis;
use oneiron::task_verb::sdk::AgentVerb;

#[derive(Clone, Copy)]
pub(in crate::api) struct StaticCaller<'a> {
    auth: Option<&'a CoreAuth>,
    connector: Option<&'a McpResolvedActor>,
    author: Option<RunAuthor>,
}

impl<'a> StaticCaller<'a> {
    pub(in crate::api) fn connector(context: &'a McpCallContext) -> Self {
        Self {
            auth: context.actor.auth.as_ref(),
            connector: Some(&context.actor),
            author: None,
        }
    }

    pub(in crate::api) fn authored(mut self, author: RunAuthor) -> Self {
        self.author = Some(author);
        self
    }

    pub(in crate::api) fn facade(auth: &'a CoreAuth) -> Self {
        Self {
            auth: Some(auth),
            ..Self::row_only()
        }
    }

    pub(super) fn row_only() -> Self {
        Self {
            auth: None,
            connector: None,
            author: None,
        }
    }

    fn auth(self) -> Result<&'a CoreAuth, StaticRefusal> {
        self.auth.ok_or(StaticRefusal::NoCredential)
    }
}

pub(in crate::api) enum StaticCheck<'a> {
    CallerCodeAgentRow(AgentVerb),
    CallerCodeRunCall(RunCall),
    BoundName(&'a str),
    UnscopedExecution,
    DesktopRow(AgentVerb),
    ConnectorRunCall(RunCall),
    LaneRecordScope,
    UnrestrictedRecordScope,
    Grant {
        scope: CoreScope,
        bounds: GrantBounds,
    },
    OwnerGrade,
    NonOwnerAgent,
    HostTriggerCredential(&'a str),
    HandlerCredential(&'a str),
}

pub(in crate::api) enum GrantBounds {
    Checked,
    Carried,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::api) enum NarrowAxis {
    World,
    Facet,
    WorldAndFacet,
}

impl NarrowAxis {
    pub(in crate::api) fn as_str(self) -> &'static str {
        match self {
            Self::World => "world",
            Self::Facet => "facet",
            Self::WorldAndFacet => "world and facet",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(in crate::api) enum StaticRefusal {
    CallerCode(&'static str),
    NotBound,
    NarrowRegistration(NarrowAxis),
    Desktop,
    WorldPrivacy,
    RecordScope,
    Grant(CoreScope),
    OwnerGrade,
    NotNonOwnerAgent,
    HostTriggerCredential,
    HandlerCredential,
    NoCredential,
}

pub(in crate::api) fn static_admission(
    caller: StaticCaller<'_>,
    check: StaticCheck<'_>,
) -> Result<(), StaticRefusal> {
    match check {
        StaticCheck::CallerCodeAgentRow(verb) => {
            if caller.author == Some(RunAuthor::Caller)
                && let Some(reason) = caller_code_verb_refusal(verb)
            {
                return Err(StaticRefusal::CallerCode(reason));
            }
            Ok(())
        }
        StaticCheck::CallerCodeRunCall(call) => {
            if caller.author == Some(RunAuthor::Caller)
                && let RunCall::Bridge(effect) = call
                && let Some(reason) = caller_code_run_refusal(effect)
            {
                return Err(StaticRefusal::CallerCode(reason));
            }
            Ok(())
        }
        StaticCheck::BoundName(name) => caller
            .connector
            .is_none_or(|connector| connector.admits_tool(name))
            .then_some(())
            .ok_or(StaticRefusal::NotBound),
        StaticCheck::UnscopedExecution => {
            let Some(connector) = caller.connector else {
                return Ok(());
            };
            let scope = &connector.scope;
            let facets = !matches!(scope.facets, ScopeAxis::All);
            let axis = match (scope.world_ref.is_some(), facets) {
                (false, false) => return Ok(()),
                (true, false) => NarrowAxis::World,
                (false, true) => NarrowAxis::Facet,
                (true, true) => NarrowAxis::WorldAndFacet,
            };
            Err(StaticRefusal::NarrowRegistration(axis))
        }
        StaticCheck::DesktopRow(verb) => (!verb.as_str().starts_with("self.desktop."))
            .then_some(())
            .ok_or(StaticRefusal::Desktop),
        StaticCheck::ConnectorRunCall(call) => {
            if matches!(call, RunCall::Bridge(SelfEffect::WorldPrivacySet)) {
                Err(StaticRefusal::WorldPrivacy)
            } else {
                Ok(())
            }
        }
        StaticCheck::LaneRecordScope => caller
            .auth()?
            .require_lane_record_scope()
            .map_err(|_| StaticRefusal::RecordScope),
        StaticCheck::UnrestrictedRecordScope => caller
            .auth()?
            .require_unrestricted_record_scope()
            .map_err(|_| StaticRefusal::RecordScope),
        StaticCheck::Grant { scope, bounds } => {
            let auth = caller.auth()?;
            match bounds {
                GrantBounds::Checked => auth.require(scope),
                GrantBounds::Carried => auth.require_granted(scope),
            }
            .map_err(|_| StaticRefusal::Grant(scope))
        }
        StaticCheck::OwnerGrade => caller
            .auth()?
            .is_owner_grade()
            .then_some(())
            .ok_or(StaticRefusal::OwnerGrade),
        StaticCheck::NonOwnerAgent => {
            let auth = caller.auth()?;
            (auth.actor_class() == Some("agent") && !auth.is_owner_grade())
                .then_some(())
                .ok_or(StaticRefusal::NotNonOwnerAgent)
        }
        StaticCheck::HostTriggerCredential(tool) => {
            if caller.auth.is_none() && host_trigger_row(tool) {
                Err(StaticRefusal::HostTriggerCredential)
            } else {
                Ok(())
            }
        }
        StaticCheck::HandlerCredential(tool) => {
            if caller.auth.is_none() && crate::api::facade::needs_caller_credential(tool) {
                Err(StaticRefusal::HandlerCredential)
            } else {
                Ok(())
            }
        }
    }
}

pub(in crate::api) fn owner_fallback_row(verb: &str) -> bool {
    matches!(
        verb,
        "vault.artifacts.live_preview.revoke_invite"
            | "vault.artifacts.live_preview.revoke_share"
            | "vault.authority.handoff_alarms.acknowledge"
            | "vault.coach.training_offers.candidates.prepare"
            | "vault.coach.training_offers.pilots.complete"
            | "vault.coach.training_offers.pilots.prepare"
            | "vault.federation.connect.world_privacy.export"
            | "vault.federation.connect.world_privacy.receive"
            | "vault.federation.coreference.share_consent"
            | "vault.skills.attribution.evidence.record"
            | "vault.skills.attribution.positive.retire"
    )
}

pub(in crate::api) fn owner_agent_exception_row(verb: &str) -> bool {
    matches!(
        verb,
        "vault.runs.review"
            | "vault.runs.settlement"
            | "vault.runs.changes.get"
            | "vault.hooks.regen.due"
            | "vault.hooks.regen.get"
            | "vault.hooks.regen.adopt"
    )
}

pub(in crate::api) fn host_trigger_row(tool: &str) -> bool {
    matches!(tool, "host.compact" | "host.wake" | "host.budget.hit")
}

/// The reason a caller's own code may not call `verb`, whatever its
/// credential holds (FIX EXECUTE-CALLER-CODE): a browser or desktop row
/// starts the host's guest, which no direct door lends a Read grant (FIX
/// EXECUTE-SOURCE-BROWSER-PARITY), and a row marked `"caller_code":
/// "refused"` answers with a credential or a secret value.
fn caller_code_verb_refusal(verb: AgentVerb) -> Option<&'static str> {
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
fn caller_code_run_refusal(effect: SelfEffect) -> Option<&'static str> {
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
