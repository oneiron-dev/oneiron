//! Selected-message conversion and the owner's skill library, through the same facade and MCP doors.
use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError};
use oneiron::skill_convert::{RefineVerdict, RefinedSkill, SkillRefineBrief, SkillRefiner};
use oneiron::skill_hub::HubFile;
use oneiron::task_verb::sdk::{self, *};
use oneiron::{
    CallClass, CallEnvelope, ContentPart, LlmMessage, LlmMessageRole, LlmRequest, ModelTierRef,
    ResponseFormat, TierPrecedence,
};
use serde::Deserialize;

use super::host_doors::{Listed, owner_proof, refused};
use super::hub_doors::owner_call;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_skills_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HubSkillRequest,
) -> Listed<SkillLibraryView> {
    owner_call(server, auth, "vault.skills.get", move |server, owner| {
        let view = sdk::skill_library_get_as_owner(server.vault(), owner, &input)?;
        let rows = view.rows();
        Ok((view, rows))
    })
    .await
}

pub(crate) async fn vault_skills_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillLibraryListRequest,
) -> Listed<SkillLibraryPage> {
    owner_call(server, auth, "vault.skills.list", move |server, owner| {
        let page = sdk::skill_library_list_as_owner(server.vault(), owner, &input)?;
        let rows = page
            .skills
            .iter()
            .flat_map(SkillLibraryView::rows)
            .collect();
        Ok((page, rows))
    })
    .await
}

pub(crate) async fn vault_skills_archive(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HubSkillRequest,
) -> Listed<SkillLibraryView> {
    owner_call(
        server,
        auth,
        "vault.skills.archive",
        move |server, owner| {
            let view = sdk::skill_archive_as_owner(server.vault(), owner, &input)?;
            let rows = view.rows();
            Ok((view, rows))
        },
    )
    .await
}

pub(crate) async fn vault_skills_fork(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillLibraryForkRequest,
) -> Listed<SkillLibraryView> {
    owner_call(server, auth, "vault.skills.fork", move |server, owner| {
        let view = sdk::skill_library_fork_as_owner(server.vault(), owner, &input)?;
        let rows = view.rows();
        Ok((view, rows))
    })
    .await
}

pub(crate) async fn vault_skills_restore(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillLibraryRestoreRequest,
) -> Listed<SkillLibraryRestoreReceipt> {
    owner_call(
        server,
        auth,
        "vault.skills.restore",
        move |server, owner| {
            let scorer = crate::replay_judge::registered()
                .map(|judge| judge as &dyn oneiron::skill_optimize::HeldOutReplayNotes);
            let answer = sdk::skill_restore_as_owner(server.vault(), owner, &input, scorer)?;
            let mut rows = match &answer {
                SkillLibraryRestoreReceipt::Restored { skill, .. } => skill.rows(),
                _ => vec![input.entity],
            };
            if let Some(admission) = &input.admission {
                rows.extend([admission.source.hub_id, admission.evidence_skill]);
            }
            Ok((answer, rows))
        },
    )
    .await
}

pub(crate) async fn vault_skills_rules_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillHashRuleRequest,
) -> Listed<HubConsentReceipt> {
    owner_call(
        server,
        auth,
        "vault.skills.rules.set",
        move |server, owner| {
            Ok((
                sdk::skill_hash_rule_as_owner(server.vault(), owner, &input)?,
                Vec::new(),
            ))
        },
    )
    .await
}

pub(crate) async fn vault_skills_code_auto_install_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillCodeAutoInstallRequest,
) -> Listed<HubConsentReceipt> {
    owner_call(
        server,
        auth,
        "vault.skills.code_auto_install.set",
        move |server, owner| {
            Ok((
                sdk::skill_code_auto_install_as_owner(server.vault(), owner, &input)?,
                Vec::new(),
            ))
        },
    )
    .await
}

pub(crate) async fn vault_skills_convert(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillConvertRequest,
) -> Listed<SkillConvertReceipt> {
    // Refuse before constructing an adapter, as well as in door_admits before hooks.
    if let Err(error) = owner_proof(auth, server, "vault.skills.convert") {
        return refused(error);
    }
    if server.ai.chat_seat().is_none()
        || server.llm.is_none()
        || server
            .config
            .skills
            .conversion_prompt
            .as_deref()
            .is_none_or(|prompt| prompt.trim().is_empty())
    {
        return refused(MemoryError::new(
            MEMORY_CODE_MODEL_UNAVAILABLE,
            "skill conversion needs a generative seat, raw inference and skills.conversion_prompt",
            &[],
        ));
    }
    let auth_for_refiner = auth.clone();
    let handle = tokio::runtime::Handle::current();
    owner_call(
        server,
        auth,
        "vault.skills.convert",
        move |server, owner| {
            let refiner = HostSkillRefiner {
                server,
                auth: &auth_for_refiner,
                owner,
                handle,
                read_rows: std::cell::RefCell::new(Vec::new()),
            };
            let answer = sdk::skill_convert_as_owner(server.vault(), owner, &input, &refiner)?;
            let rows = input
                .message_refs
                .into_iter()
                .chain(refiner.read_rows.into_inner())
                .chain(answer.rows())
                .collect();
            Ok((answer, rows))
        },
    )
    .await
}

/// The sync engine seam blocks only its worker, on the caller's admitted inference ladder.
struct HostSkillRefiner<'a> {
    server: &'a SyncServer,
    auth: &'a CoreAuth,
    owner: &'a AuthenticatedOwner,
    handle: tokio::runtime::Handle,
    read_rows: std::cell::RefCell<Vec<oneiron::EntityId>>,
}

impl SkillRefiner for HostSkillRefiner<'_> {
    fn refine(&self, brief: &SkillRefineBrief) -> oneiron::Result<RefinedSkill> {
        self.owner.revalidate(self.server.vault())?;
        *self.read_rows.borrow_mut() = brief
            .said
            .iter()
            .map(|said| said.source)
            .chain(brief.neighbors.iter().map(|neighbor| neighbor.entity))
            .collect();
        let failed =
            |message: &str| oneiron::Error::InvalidConfig(format!("skill conversion: {message}"));
        let seat = self
            .server
            .ai
            .chat_seat()
            .ok_or_else(|| failed("no generative seat"))?;
        let prompt = self
            .server
            .config
            .skills
            .conversion_prompt
            .as_ref()
            .ok_or_else(|| failed("no conversion prompt configured"))?;
        let said: Vec<_> = brief
            .said
            .iter()
            .map(|said| {
                serde_json::json!({
                    "source": said.source, "speaker": said.speaker, "text": said.text,
                })
            })
            .collect();
        let neighbors: Vec<_> = brief
            .neighbors
            .iter()
            .map(|neighbor| {
                serde_json::json!({
                    "entity": neighbor.entity, "skill_id": neighbor.skill_id, "desc": neighbor.desc,
                })
            })
            .collect();
        let data = serde_json::json!({"said": said, "hint": brief.hint, "neighbors": neighbors});
        let purpose = oneiron::skill_convert::skill_convert_call_purpose();
        let mut request = LlmRequest {
            model: seat.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: Default::default(),
                tier: TierPrecedence::for_purpose(
                    &purpose,
                    ModelTierRef(
                        oneiron::skill_convert::SKILL_CONVERT_CALL_PURPOSE_NAME.to_owned(),
                    ),
                ),
                purpose,
                class: CallClass::BestEffort,
                response_format: ResponseFormat::Text,
                locality: seat.locality,
            },
            messages: vec![
                message(LlmMessageRole::System, prompt.clone()),
                message(LlmMessageRole::User, data.to_string()),
            ],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        };
        let (ladder, run) = crate::api::llm::admit(self.server, self.auth, &mut request)
            .map_err(|response| failed(&format!("inference refused ({})", response.status())))?;
        let response = self
            .handle
            .block_on(ladder.generate(&run, request, None))
            .map_err(|error| failed(&error.to_string()))?;
        let text: String = response
            .message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        let refined: RefinedSkillWire = serde_json::from_str(&text)
            .map_err(|_| failed("refiner did not return its typed JSON result"))?;
        // Recheck the caller after the remote call, before the engine lands the candidate.
        self.owner.revalidate(self.server.vault())?;
        Ok(RefinedSkill {
            skill_id: refined.skill_id,
            desc: refined.desc,
            files: refined
                .files
                .into_iter()
                .map(|file| HubFile::new(file.path, file.content.into_bytes()))
                .collect(),
            verdict: match refined.verdict {
                RefineVerdictWire::Mint { justification } => RefineVerdict::Mint { justification },
                RefineVerdictWire::MergeInto {
                    existing,
                    rationale,
                } => RefineVerdict::MergeInto {
                    existing,
                    rationale,
                },
            },
        })
    }
}

fn message(role: LlmMessageRole, text: String) -> LlmMessage {
    LlmMessage {
        role,
        content: vec![ContentPart::Text { text }],
    }
}

/// The configured prompt returns a native tree; the engine recomputes its hash and provenance.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefinedSkillWire {
    skill_id: String,
    desc: String,
    files: Vec<oneiron::skill::helper::SkillSourceFile>,
    verdict: RefineVerdictWire,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RefineVerdictWire {
    Mint {
        justification: String,
    },
    MergeInto {
        existing: oneiron::EntityId,
        rationale: String,
    },
}
