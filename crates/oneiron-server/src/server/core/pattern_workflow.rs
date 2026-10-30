//! The house pattern runner (DOOR-111 S4b): the start a planned team's
//! pattern skill writes, run on the house generative seat.
//!
//! The owner's planned launch hands the runner the exact pack its plan froze.
//! That pack's SKILL.md is the system text. The host adds one short frame
//! that asks for the launch start alone (the leader's briefing, one briefing
//! per member and the axis) and sends what was asked, the owner's prompt and
//! the plan as JSON task data. The call is house work for the owner: one
//! model turn on the generative role's live route, metered on the house chat
//! turn's line under the vault's policy budget guard for the caller who
//! pays, so the manifest's `budget_policy` rows bind it (FIX 4638), with no
//! tool, so nothing it asks for ever runs. The reply must stop naturally and
//! match a schema built for the plan's width.
//!
//! A leased agent's planned team runs the same request, schema and decode
//! on its own seat and line instead (DOOR-111 S4c-4,
//! `resident_pump::pattern_launch`); only this runner is the house's.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::agent_dispatch::{CareLevel, CostEnvelope, ExpectedSpend, SpawnNeed, TeamPlan};
use oneiron::llm::{
    BudgetExhaustionPolicy, CallClass, CallEnvelope, CallPurpose, ContentPart,
    DEFAULT_BUDGET_RESERVE_UNITS, FinishReason, LlmCapability, LlmError, LlmMessage,
    LlmMessageRole, LlmRequest, LlmResponse, ModelId, ModelLocality, ModelTierRef, ReasoningEffort,
    ResponseFormat, RetryableLlmError, SpentKind, TierPrecedence, validate_json_schema,
};
use oneiron::skill::{LoadedSkillPack, SkillRole};
use oneiron::team::{PatternLaunchRunner, PatternLaunchSpec, TeamAxis};
use oneiron::{EntityId, Error, ErrorKind, Result, Vault, WriteActor};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::SyncServer;
use crate::ai_host::{AiHandle, CHAT_ROLE};
use crate::config::models::role_key;
use crate::models::RoleRefusal;

/// The call's purpose and tier label, and its run's prefix.
const LAUNCH_PURPOSE: &str = "team.pattern_launch";
/// The host's frame after the skill's own text: the start, and nothing later.
const LAUNCH_FRAME: &str = "The text above is the workflow skill a planned team runs. Write \
     only its start, before any agent runs: the briefing the leader reads after the supplied \
     prompt, one briefing for each member the plan launches, in launch order, and the axis the \
     team runs on. The task data names what was asked, the supplied prompt, the plan and the \
     skill's revision. Leave the workflow's later steps, its reports and its decision, to the \
     team, and call no tool. Answer with one JSON object that matches the schema below, and \
     nothing else.";

const NOT_A_TEAM: &str = "this plan names no pattern skill, so there is no team start to \
     write; a solo launches without one";
const SKILL_MOVED: &str = "the pattern pack handed to the runner is not the skill revision this \
     plan froze; ask again under a new intent key";
const NOT_A_WORKFLOW: &str = "the pattern pack handed to the runner is not a workflow skill; \
     ask again under a new intent key";
const NO_LEADER: &str = "this plan's team has no width, so there is no leader to brief; ask \
     again under a new intent key";
const NO_SKILL_MD: &str = "the pattern skill's package holds no SKILL.md to run; install a \
     package that does, then ask again under a new intent key";
const SKILL_MD_NOT_TEXT: &str = "the pattern skill's SKILL.md is not UTF-8 text; install a \
     package whose SKILL.md is, then ask again under a new intent key";
const TOOL_CALL: &str = "the pattern run asked for a tool, and a team start calls none; nothing \
     it asked for ran; ask again";
const TRUNCATED: &str = "the pattern run's start was cut off before it ended; ask again, or \
     seat a generative model with more output room";
const STOPPED: &str = "the pattern run stopped before its model answered; ask again";

/// The house runner: the vault and the AI handle, never the server, and for
/// one owner's call, that caller's clock (FIX 9535).
struct HostPatternLaunchRunner {
    vault: Arc<Vault>,
    ai: AiHandle,
    /// `None` on the server-wide runner, which waits as it always has.
    caller: Option<CallerClock>,
}

/// One caller's absolute deadline, and the key its fair task-work turn
/// waits under.
#[derive(Clone, Copy)]
struct CallerClock {
    deadline: Instant,
    key: EntityId,
}

impl CallerClock {
    /// What is left of the caller's time.
    fn remaining(self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
}

/// The runner [`SyncServer::with_ai`] binds: none when no rung serves the
/// house generative seat, so an inert server keeps a team plan refusing.
pub(super) fn bind(vault: Arc<Vault>, ai: AiHandle) -> Option<Arc<dyn PatternLaunchRunner>> {
    if ai.chat_seat().is_none() {
        return None;
    }
    Some(Arc::new(HostPatternLaunchRunner {
        vault,
        ai,
        caller: None,
    }))
}

impl SyncServer {
    /// The runner a planned team's pattern skill writes its start on
    /// (DOOR-111): the house generative seat's, once a rung serves it.
    /// `None` refuses a team plan and leaves it planned.
    #[must_use]
    pub fn pattern_launch_runner(&self) -> Option<&dyn PatternLaunchRunner> {
        self.pattern_launch_runner.as_deref()
    }

    /// The house runner for one caller's call (FIX 9535): the same seat,
    /// waiting for an offer back until `deadline`, the caller's absolute
    /// deadline, where that is later than the host's own longest wait, in a
    /// fair task-work turn keyed to `caller`. The server-wide runner is left
    /// as it is. `None` where no rung serves the house seat.
    #[must_use]
    pub fn pattern_launch_runner_until(
        &self,
        deadline: Instant,
        caller: EntityId,
    ) -> Option<Box<dyn PatternLaunchRunner>> {
        self.pattern_launch_runner.as_ref()?;
        Some(Box::new(HostPatternLaunchRunner {
            vault: Arc::clone(&self.vault),
            ai: self.ai.clone(),
            caller: Some(CallerClock {
                deadline,
                key: caller,
            }),
        }))
    }
}

impl PatternLaunchRunner for HostPatternLaunchRunner {
    /// The pack must be the workflow revision `plan` froze; its start
    /// briefs the leader and exactly the width less one members.
    fn run(
        &self,
        skill: &LoadedSkillPack,
        asked: &SpawnNeed,
        prompt: &str,
        plan: &TeamPlan,
        payer: &WriteActor,
    ) -> Result<PatternLaunchSpec> {
        let members = launch_members(skill, plan)?;
        let seat = self.ai.chat_seat().ok_or_else(no_seat)?;
        let schema = launch_spec_schema(members);
        let request = launch_request(
            &seat.model,
            seat.locality,
            skill,
            asked,
            prompt,
            plan,
            &schema,
        )?;
        let run_id = format!(
            "{LAUNCH_PURPOSE}:{}:{}",
            skill.entity.to_hex(),
            self.vault.now_recorded_at()
        );
        let response = self.capture(request, run_id, payer)?;
        decode_launch_spec(&response, &schema)
    }
}

impl HostPatternLaunchRunner {
    /// One model turn: admitted as a call of the house generative role on
    /// the vault's live route, asked in plain text where that route holds no
    /// reply to a schema, and sent on the house chat turn's line, metered to
    /// `payer` under the manifest's `budget_policy` rows (FIX 4638). The
    /// ladder owns its retries and fallback. The call drives its own runtime
    /// on a thread of its own, since a caller may sit inside a runtime, which
    /// cannot block on another. A caller's call first takes its fair
    /// task-work turn, waiting no longer than the caller's time and running
    /// without one past it, as the line's own wait does; it then waits for
    /// an offer back until the caller's deadline where that is later than
    /// the host's longest wait (FIX 9535). No transaction is held.
    fn capture(
        &self,
        request: LlmRequest,
        run_id: String,
        payer: &WriteActor,
    ) -> Result<LlmResponse> {
        // A running turn to shutdown's grace and the Dreamer's idle sample,
        // until the capture returns on any path (FIX 4639).
        let _turn = self.ai.enter_turn();
        let mut call = self
            .ai
            .admit_role(&self.vault, CHAT_ROLE, request)
            .map_err(|refusal| match refusal {
                RoleRefusal::NoSeat => no_seat(),
                // A store fault inside admission is the host's, not a bound
                // the owner can act on (FIX 5045); a typed refusal keeps its
                // own text.
                RoleRefusal::Refused(error) if store_fault(&error) => fault(format!(
                    "the house generative seat's admission failed on a store fault: {error}"
                )),
                RoleRefusal::Refused(error) if matches!(*error, Error::Refused(_)) => *error,
                refusal => stop(format!(
                    "the house generative seat refused the pattern run: {refusal}; fix the \
                     vault's model route for {}, then ask again",
                    role_key(CHAT_ROLE)
                )),
            })?;
        // The prompt carries the same schema, and the reply is checked
        // against it either way.
        if !call
            .ladder
            .supports(&call.request.model, &LlmCapability::JsonResponse)
        {
            call.request.envelope.response_format = ResponseFormat::Text;
        }
        warn_launch_input(&self.vault, &call.request);
        let units = self.ai.chat_settings().turn_budget_units;
        let meter = self
            .vault
            .policy_budget_guard(
                run_id.clone(),
                units,
                DEFAULT_BUDGET_RESERVE_UNITS.min(units),
                BudgetExhaustionPolicy::Suspend,
                *payer,
            )
            .map_err(|error| {
                if store_fault(&error) {
                    fault(format!(
                        "the pattern run's budget policy failed on a store fault: {error}"
                    ))
                } else if matches!(error, Error::Refused(_)) {
                    error
                } else {
                    stop(format!(
                        "the vault's budget policy refused the pattern run: {error}; fix the \
                         vault's policy manifest, then ask again"
                    ))
                }
            })?;
        let run = self.ai.undeclared_run(run_id, meter);
        let wait = self.offer_wait();
        let caller = self.caller;
        let vault = &self.vault;
        std::thread::scope(|scope| {
            scope
                .spawn(move || -> Result<LlmResponse> {
                    let reactor = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|error| {
                            fault(format!(
                                "the pattern run's runtime did not start: {error}; ask again"
                            ))
                        })?;
                    reactor
                        .block_on(async move {
                            let _work = match caller {
                                Some(caller) => tokio::time::timeout(
                                    caller.remaining(),
                                    vault.admit_task_work(caller.key),
                                )
                                .await
                                .ok(),
                                None => None,
                            };
                            call.ladder
                                .generate_within(&run, call.request, None, &|| true, wait)
                                .await
                        })
                        .map_err(unanswered)
                })
                .join()
        })
        .unwrap_or_else(|_| Err(fault(STOPPED)))
    }

    /// How long the call waits for an offer back: the host's longest wait
    /// for a cooling chain, as it always has; for a caller's call, until its
    /// own deadline where that is later.
    fn offer_wait(&self) -> Duration {
        let host = Duration::from_secs(
            self.vault
                .provider_cooldown_policy()
                .unwrap_or_default()
                .max_wait_secs,
        );
        self.caller
            .map_or(host, |caller| host.max(caller.remaining()))
    }
}

/// How many members the start briefs: the plan's width less the leader,
/// once the pack handed in is the workflow revision the plan froze.
pub(in crate::server) fn launch_members(skill: &LoadedSkillPack, plan: &TeamPlan) -> Result<u32> {
    let pattern = plan
        .pattern_skill
        .as_ref()
        .ok_or_else(|| fault(NOT_A_TEAM))?;
    if skill.entity != pattern.skill || skill.record.version != pattern.version {
        return Err(stop(SKILL_MOVED));
    }
    if skill.record.role != SkillRole::Workflow {
        return Err(stop(NOT_A_WORKFLOW));
    }
    plan.shape
        .width
        .checked_sub(1)
        .ok_or_else(|| fault(NO_LEADER))
}

/// The pack's SKILL.md, exactly as it loaded.
fn skill_text(skill: &LoadedSkillPack) -> Result<&str> {
    let file = skill
        .source_files
        .iter()
        .flatten()
        .find(|file| file.path == "SKILL.md")
        .ok_or_else(|| stop(NO_SKILL_MD))?;
    let text = std::str::from_utf8(&file.content).map_err(|_| stop(SKILL_MD_NOT_TEXT))?;
    if text.trim().is_empty() {
        return Err(stop(NO_SKILL_MD));
    }
    Ok(text)
}

/// The reply's schema for `members` members: the leader's briefing, exactly
/// that many member briefings, and the axis; nothing else.
pub(in crate::server) fn launch_spec_schema(members: u32) -> Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["leader_briefing", "member_briefings", "axis"],
        "properties": {
            "leader_briefing": {"type": "string"},
            "member_briefings": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": members,
                "maxItems": members,
            },
            "axis": {"type": "string", "enum": ["converge", "diverge"]},
        },
    })
}

/// The task data a pattern run reads: what was asked, the asker's prompt
/// (the owner's, or a leased agent's briefing or need), the frozen plan's
/// team, and the skill revision it runs.
#[derive(Serialize)]
struct LaunchTask<'a> {
    asked: &'a SpawnNeed,
    prompt: &'a str,
    width: u32,
    model: &'a ModelId,
    care: CareLevel,
    effort: ReasoningEffort,
    envelope: LaunchEnvelope<'a>,
    skill: LaunchSkill<'a>,
}

/// The cost envelope as the pattern run's model reads it (FIX 9536): whole,
/// by default; without the balance where the ask chose a balance-free
/// prompt. The host enforces, and the owner's plan receipt shows, the whole
/// envelope either way.
#[derive(Serialize)]
#[serde(untagged)]
enum LaunchEnvelope<'a> {
    Whole(&'a CostEnvelope),
    BalanceFree(BalanceFreeEnvelope<'a>),
}

/// A [`CostEnvelope`] without its `available_units`.
#[derive(Serialize)]
struct BalanceFreeEnvelope<'a> {
    agent_count: u32,
    expected_spend_units: u64,
    hard_cap_units: Option<u64>,
    per_agent: &'a ExpectedSpend,
}

impl<'a> LaunchEnvelope<'a> {
    fn of(envelope: &'a CostEnvelope, asked: &SpawnNeed) -> Self {
        if !asked.balance_free_prompt {
            return Self::Whole(envelope);
        }
        Self::BalanceFree(BalanceFreeEnvelope {
            agent_count: envelope.agent_count,
            expected_spend_units: envelope.expected_spend_units,
            hard_cap_units: envelope.hard_cap_units,
            per_agent: &envelope.per_agent,
        })
    }
}

/// The pattern skill revision a run reads, as the plan froze it.
#[derive(Serialize)]
struct LaunchSkill<'a> {
    #[serde(rename = "ref")]
    reference: String,
    name: &'a str,
    version: &'a str,
}

/// The one request, on `model` at `locality`: the pack's SKILL.md as the
/// system text, the host's frame and the reply's schema after it, and the
/// task data as the user turn. It offers no tool and caps nothing.
pub(in crate::server) fn launch_request(
    model: &ModelId,
    locality: ModelLocality,
    skill: &LoadedSkillPack,
    asked: &SpawnNeed,
    prompt: &str,
    plan: &TeamPlan,
    schema: &Value,
) -> Result<LlmRequest> {
    let task = LaunchTask {
        asked,
        prompt,
        width: plan.shape.width,
        model: &plan.model,
        care: plan.care,
        effort: plan.effort,
        envelope: LaunchEnvelope::of(&plan.envelope, asked),
        skill: LaunchSkill {
            reference: skill.entity.to_hex(),
            name: &skill.record.skill_id,
            version: &skill.record.version,
        },
    };
    let task = serde_json::to_string(&task).map_err(|error| {
        fault(format!(
            "the pattern run's task data did not encode: {error}"
        ))
    })?;
    // Machine-readable schema data, as a one-shot structured call carries it.
    let descriptor = serde_json::json!({
        "response_format": {"type": "json_schema", "schema": schema},
    });
    let part = |text: String| ContentPart::Text { text };
    let purpose = CallPurpose::Other {
        name: LAUNCH_PURPOSE.to_owned(),
    };
    Ok(LlmRequest {
        model: model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(&purpose, ModelTierRef(LAUNCH_PURPOSE.to_owned())),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Json {
                schema: schema.clone(),
            },
            locality,
            host_keyless: false,
        },
        messages: vec![
            LlmMessage {
                role: LlmMessageRole::System,
                content: vec![part(skill_text(skill)?.to_owned())],
            },
            LlmMessage {
                role: LlmMessageRole::System,
                content: vec![part(LAUNCH_FRAME.to_owned()), part(descriptor.to_string())],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![part(task)],
            },
        ],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    })
}

/// Warns, and only warns, when the request's text reads larger than the
/// catalog's context value for the exact model it goes to (FIX 4640). The
/// count is an offline o200k estimate of the text parts, not the provider's
/// own count, so the request is sent unchanged either way.
pub(in crate::server) fn warn_launch_input(vault: &Vault, request: &LlmRequest) {
    let window = match vault.model_registry_row(&request.model) {
        Ok(Some(row)) if row.catalog.context_window_tokens > 0 => row.catalog.context_window_tokens,
        Ok(_) => return,
        Err(error) => {
            tracing::warn!(
                model = %request.model,
                %error,
                "the pattern run's model row did not read; its input goes unestimated"
            );
            return;
        }
    };
    let estimate = request
        .messages
        .iter()
        .flat_map(|message| &message.content)
        .map(|part| match part {
            ContentPart::Text { text } => oneiron::count_context_pack_tokens(text) as u64,
            _ => 0,
        })
        .fold(0_u64, u64::saturating_add);
    if estimate > window {
        tracing::warn!(
            model = %request.model,
            estimate,
            catalog_window = window,
            "the pattern request's text estimate is above the model's catalog context value; \
             an estimate only, sent unchanged"
        );
    }
}

/// A reply's start, as the schema shapes it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchStart {
    leader_briefing: String,
    member_briefings: Vec<String>,
    axis: TeamAxis,
}

/// The start a reply writes: a natural stop with no tool call, then one
/// JSON object that matches the width's schema, decoded with nothing beyond
/// its three keys.
pub(in crate::server) fn decode_launch_spec(
    response: &LlmResponse,
    schema: &Value,
) -> Result<PatternLaunchSpec> {
    if response.finish_reason == FinishReason::ToolCalls
        || response
            .message
            .content
            .iter()
            .any(|part| matches!(part, ContentPart::ToolCall { .. }))
    {
        return Err(stop(TOOL_CALL));
    }
    match &response.finish_reason {
        FinishReason::Stop => {}
        FinishReason::Length => return Err(stop(TRUNCATED)),
        other => {
            return Err(stop(format!(
                "the pattern run ended {other:?}, not at a natural stop; ask again"
            )));
        }
    }
    let text: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let value: Value = serde_json::from_str(text.trim()).map_err(off_schema)?;
    validate_json_schema(schema, &value).map_err(off_schema)?;
    let start: LaunchStart = serde_json::from_value(value).map_err(off_schema)?;
    Ok(PatternLaunchSpec {
        leader_briefing: start.leader_briefing,
        member_briefings: start.member_briefings,
        axis: start.axis,
    })
}

/// No rung serves the house generative seat.
fn no_seat() -> Error {
    stop(format!(
        "no [models] rung serves the house generative seat ({}); bind one, then ask again",
        role_key(CHAT_ROLE)
    ))
}

/// The ladder answered nothing: its line refused the call, every offer
/// rested past the call's wait, or every rung failed. A wait is typed, not a
/// refusal (FIX 9535): the launch stays planned under its intent key, and
/// the same ask continues it once an offer is back.
fn unanswered(error: LlmError) -> Error {
    if let LlmError::Retryable(retryable) = &error
        && let Some(retry_after) = offer_back_in(retryable)
    {
        return Error::ProviderUnavailable { retry_after };
    }
    match &error {
        LlmError::BudgetDenied(_) => stop(format!(
            "the house chat turn's line refused the pattern run: {error}; raise [models.chat] \
             turn_budget_units, or wait for its spend to settle, then ask again"
        )),
        _ => stop(format!(
            "the house generative seat did not answer the pattern run: {error}; ask again"
        )),
    }
}

/// Seconds until the soonest known offer is back, for a failure that is a
/// wait on rested offers (0 where none says when); `None` for one that is
/// not: spent credit, a server error, a cut stream, an offer kept on the
/// device with none resting.
fn offer_back_in(error: &RetryableLlmError) -> Option<u64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let soonest = |retry_after: Option<u64>, resets_at: &[u64]| {
        retry_after.or_else(|| resets_at.iter().find(|at| **at > now).map(|at| at - now))
    };
    match error {
        RetryableLlmError::RateLimited {
            retry_after,
            resets_at,
        }
        | RetryableLlmError::QuotaSpent {
            kind: SpentKind::Window,
            retry_after,
            resets_at,
        } => Some(soonest(*retry_after, resets_at).unwrap_or(0)),
        RetryableLlmError::KeptOnDevice {
            retry_after,
            resets_at,
            ..
        } => soonest(*retry_after, resets_at),
        RetryableLlmError::Timeout => Some(0),
        _ => None,
    }
}

/// The reply is not the start the schema asks for.
fn off_schema(detail: impl std::fmt::Display) -> Error {
    stop(format!(
        "the pattern run's start does not match the team start's schema: {detail}; ask again"
    ))
}

/// Why a pattern run wrote no start, and what the owner can do next: a
/// refusal that names its bound, which the planner answers as it is.
pub(in crate::server) fn stop(reason: impl Into<String>) -> Error {
    Error::Refused(reason.into())
}

/// Whether an admission error is the store's, as the doors' error map reads
/// it (INTERNAL), rather than a bound the caller can act on.
fn store_fault(error: &Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::Storage
            | ErrorKind::Io
            | ErrorKind::CorruptedIndex
            | ErrorKind::SideTableRow
            | ErrorKind::InvariantViolation
            | ErrorKind::MapFull
            | ErrorKind::IndexOverflow
            | ErrorKind::MissingPostingEntry
    )
}

/// A host fault that stopped a pattern run: a solo or zero-width plan, task
/// data that did not encode, a runtime that did not start, a capture that
/// panicked. The host log keeps it, and the planner answers its own fixed
/// refusal.
pub(in crate::server) fn fault(reason: impl Into<String>) -> Error {
    Error::InvalidConfig(reason.into())
}
