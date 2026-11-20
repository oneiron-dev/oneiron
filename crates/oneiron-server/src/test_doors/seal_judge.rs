//! Doors for `tests/seal_judge_host_wire.rs`
//! ([SEAL-JUDGE-HOST-WIRE-UNTESTED]): the host seal check over a stub of
//! the Coach's models, the check's budget, the checker's protocol digest,
//! and judge answers keyed by the check's own question ids.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use oneiron::code_run::{CapsuleRungBinding, ReplayRoutePin};
use oneiron::dreamer_runner::maintenance::seal_checks::SealCheck;
use oneiron::llm::manifest::ModelRole;
use oneiron::self_heal::audit::{SealCheckKind, SealCheckRequest};
use oneiron::{ContentPart, LlmMessage, LlmMessageRole, ModelId, ModelLocality};

use crate::ai_host::coach_host::seal_checks::{SealJudgeModels, check_on};
use crate::models::ModelCallBinding;
use crate::server::SyncServer;

/// One scripted judge answer: the model's text, served by `model`
/// (`provider/name@revision`) on its rung's route.
#[derive(Debug, Clone)]
pub struct SealScriptAnswer {
    pub text: String,
    pub model: String,
}

/// One call the judge made: the role whose seat it ran on, and the data it
/// was shown (the questions asked and the check's state, as JSON).
#[derive(Debug, Clone)]
pub struct SealJudgeCall {
    pub role: ModelRole,
    pub user_text: String,
}

/// The Coach's models as the seal's judge calls them, answered from
/// `script` in order: `None` serves nothing, as no seat serving the call.
struct StubModels {
    script: Mutex<VecDeque<Option<SealScriptAnswer>>>,
    seen: Mutex<Vec<SealJudgeCall>>,
}

impl SealJudgeModels for StubModels {
    fn generate_recorded(
        &self,
        role: ModelRole,
        messages: Vec<LlmMessage>,
    ) -> oneiron::Result<Option<(String, ModelCallBinding)>> {
        let user_text = messages
            .iter()
            .find(|message| message.role == LlmMessageRole::User)
            .map(|message| {
                message
                    .content
                    .iter()
                    .filter_map(|part| match part {
                        ContentPart::Text { text, .. } => Some(text.as_str()),
                        _ => None,
                    })
                    .collect::<String>()
            })
            .unwrap_or_default();
        self.seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(SealJudgeCall { role, user_text });
        let answer = self
            .script
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
            .flatten();
        let Some(answer) = answer else {
            return Ok(None);
        };
        let model = ModelId::new(answer.model)
            .map_err(|error| oneiron::Error::InvalidConfig(format!("stub seal answer: {error}")))?;
        let binding = ModelCallBinding::saved(
            CapsuleRungBinding {
                model,
                locality: ModelLocality::OwnServer,
                prompt: None,
            },
            Some(ReplayRoutePin {
                route_id: "stub@stub".to_owned(),
                offer_id: "stub-offer".to_owned(),
                catalog_revision: None,
                wire_model: "stub".to_owned(),
                route_prompt_digest: [0; 32],
            }),
        );
        Ok(Some((answer.text, binding)))
    }
}

/// The host seal check of `request` by a judge that is not `executor`, with
/// the judge's calls answered from `script` in order, and the calls the
/// judge made. Past the script's end a call is unserved.
///
/// # Errors
///
/// What the check returns: the ladder's or the judge's errors.
pub fn check_with_scripted_answers(
    server: &SyncServer,
    request: &SealCheckRequest,
    executor: &str,
    script: Vec<Option<SealScriptAnswer>>,
    now: u64,
) -> oneiron::Result<(SealCheck, Vec<SealJudgeCall>)> {
    let models = StubModels {
        script: Mutex::new(script.into()),
        seen: Mutex::new(Vec::new()),
    };
    let check = check_on(server, &models, request, executor, now)?;
    let seen = models
        .seen
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    Ok((check, seen))
}

/// The judge's answer over `objectives` of a check of `kind`: one JSON
/// object keyed by each objective's question id, `flaws` saying per
/// objective whether a flaw is present.
///
/// # Errors
///
/// A question the catalogue refuses, a repeated objective, or `flaws`
/// naming another count than `objectives`.
pub fn scripted_answer(
    kind: SealCheckKind,
    objectives: &[&str],
    flaws: &[bool],
) -> oneiron::Result<String> {
    crate::ai_host::coach_host::seal_checks::scripted_answer(kind, objectives, flaws)
}

/// One check's clock on the decision ladder.
pub fn check_budget() -> Duration {
    crate::ai_host::coach_host::seal_checks::check_budget()
}

/// The digest of the checker's protocol.
pub fn seal_protocol_digest() -> [u8; 32] {
    crate::ai_host::coach_host::seal_checks::seal_protocol_digest()
}
