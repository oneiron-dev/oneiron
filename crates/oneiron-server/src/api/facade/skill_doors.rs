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

use super::host_doors::support::{Listed, credential_listing, owner_proof, refused};
use super::hub_doors::owner_call;
use crate::auth::CoreAuth;
use crate::models::Seat;
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

/// A person or agent forking as itself (FIX 8167): its actor and own slip.
type Forker = (
    (oneiron::EntityId, oneiron::EdgeActorClass),
    oneiron::authority::VerifiedSlip,
);

/// Who forks a skill: the owner under its proof, as before (`None`), or a
/// person or agent on a verified slip of its own, as itself (`Some`, FIX
/// 8167), whose read of the source and live write Grant the fork's own
/// writer checks. Anyone else keeps the owner refusal it had.
pub(super) fn forker(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> oneiron::memory::MemoryResult<Option<Forker>> {
    use oneiron::EdgeActorClass::{Agent, Human};
    match owner_proof(auth, server, verb) {
        Ok(_) => Ok(None),
        Err(refusal) => match (auth.verified_slip(), super::facade_actor(server, auth)) {
            (Some(slip), Ok(caller @ (_, Human | Agent))) => Ok(Some((caller, slip.clone()))),
            _ => Err(refusal),
        },
    }
}

pub(crate) async fn vault_skills_fork(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillLibraryForkRequest,
) -> Listed<SkillLibraryView> {
    const VERB: &str = "vault.skills.fork";
    let (caller, slip) = match forker(server, auth, VERB) {
        Ok(Some(forker)) => forker,
        Ok(None) => {
            return owner_call(server, auth, VERB, move |server, owner| {
                let view = sdk::skill_library_fork_as_owner(server.vault(), owner, &input)?;
                let rows = view.rows();
                Ok((view, rows))
            })
            .await;
        }
        Err(refusal) => return refused(refusal),
    };
    let (answer, mut rows) = credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        sdk::skill_library_fork_by_caller(&memory, &slip, &input)
    })
    .await;
    if let Ok(view) = &answer {
        rows.extend(view.rows());
    }
    (answer, rows)
}

pub(crate) async fn vault_skills_optimize_start(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillOptimizeStartRequest,
) -> Listed<SkillOptimizeStartReceipt> {
    owner_call(
        server,
        auth,
        "vault.skills.optimize.start",
        move |server, owner| {
            let answer = sdk::skill_optimize_start_as_owner(server.vault(), owner, &input)?;
            let rows = answer.rows();
            Ok((answer, rows))
        },
    )
    .await
}

pub(crate) async fn vault_skills_optimize_result(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillOptimizeResultRequest,
) -> Listed<SkillOptimizeResultView> {
    owner_call(
        server,
        auth,
        "vault.skills.optimize.result",
        move |server, owner| {
            let answer = sdk::skill_optimize_result_as_owner(server.vault(), owner, &input)?;
            let rows = answer.rows();
            Ok((answer, rows))
        },
    )
    .await
}

pub(crate) async fn vault_skills_governance_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HubSkillRequest,
) -> Listed<SkillGovernanceView> {
    owner_call(
        server,
        auth,
        "vault.skills.governance.get",
        move |server, owner| {
            let answer = sdk::skill_governance_get_as_owner(server.vault(), owner, &input)?;
            Ok((answer, vec![input.entity]))
        },
    )
    .await
}

pub(crate) async fn vault_skills_governance_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillGovernanceSetRequest,
) -> Listed<SkillGovernanceView> {
    owner_call(
        server,
        auth,
        "vault.skills.governance.set",
        move |server, owner| {
            let entity = input.entity;
            let answer = sdk::skill_governance_set_as_owner(server.vault(), owner, &input)?;
            Ok((answer, vec![entity]))
        },
    )
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
        let seat = self
            .server
            .ai
            .chat_seat()
            .ok_or_else(|| refine_failed("no generative seat"))?;
        let prompt = self
            .server
            .config
            .skills
            .conversion_prompt
            .as_ref()
            .ok_or_else(|| refine_failed("no conversion prompt configured"))?;
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
        let said_rows: Vec<oneiron::EntityId> = brief.said.iter().map(|said| said.source).collect();
        let neighbor_rows: Vec<oneiron::EntityId> = brief
            .neighbors
            .iter()
            .map(|neighbor| neighbor.entity)
            .collect();
        // FIX 8989: every selected utterance and neighbour is read. A
        // selection that fits the seat's window, or one whose window is
        // unknown, goes in one request, as it always has; a longer one goes
        // a page at a time, each answered over the pages before it.
        let data = serde_json::json!({"said": said, "hint": brief.hint, "neighbors": neighbors});
        let window = refine_window(self.server.vault(), seat)
            .filter(|window| !fits(*window, prompt, &data.to_string()));
        let refined = match window {
            None => {
                self.ask(seat, prompt, &data, Some(self.read_rows.borrow().to_vec()))?
                    .1
            }
            Some(window) => {
                let selection = Selection {
                    said: &said,
                    said_rows: &said_rows,
                    hint: brief.hint.as_deref(),
                    neighbors: &neighbors,
                    neighbor_rows: &neighbor_rows,
                };
                self.ask_in_pages(seat, prompt, window, &selection)?
            }
        };
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

/// A selection's refiner input, each utterance and neighbour as its request
/// carries it, with the vault row each was read from beside it (FIX 11397):
/// a page's call rows are sliced with the same bounds as its JSON, so no id
/// is ever parsed back out of it.
struct Selection<'a> {
    said: &'a [serde_json::Value],
    said_rows: &'a [oneiron::EntityId],
    hint: Option<&'a str>,
    neighbors: &'a [serde_json::Value],
    neighbor_rows: &'a [oneiron::EntityId],
}

/// What a paged selection's request says of its part, beside its page.
const REFINE_PART_NOTE: &str = "The selection is read in parts, in order. `draft` is your answer \
     over the parts before this one, or null on the first. Answer with the same JSON shape: the \
     draft updated with this part's said and neighbors, keeping all that earlier parts gave it, \
     its verdict judged against every neighbor read so far. `last` marks the final part.";

impl HostSkillRefiner<'_> {
    /// The refined skill over `selection` read a page at a time (FIX
    /// 8989): each page takes as many of the utterances left, then of the
    /// neighbours left, in order, as fit `window` beside the prompt and the
    /// answer over the pages before it, and at least one. None is left out
    /// and none is cut; the last page's answer is the result.
    fn ask_in_pages(
        &self,
        seat: &Seat,
        prompt: &str,
        window: u64,
        selection: &Selection<'_>,
    ) -> oneiron::Result<RefinedSkillWire> {
        let (said, neighbors) = (selection.said, selection.neighbors);
        let (mut said_at, mut neighbors_at) = (0, 0);
        let mut draft = serde_json::Value::Null;
        let mut index = 0_u64;
        loop {
            index += 1;
            let frame = page_data(selection.hint, &[], &[], index, &draft, false).to_string();
            let mut left = window.saturating_sub(tokens(&[prompt, frame.as_str()].join("\n")));
            let mut said_end = said_at + take(&said[said_at..], &mut left);
            let mut neighbors_end = neighbors_at;
            if said_end == said.len() {
                neighbors_end += take(&neighbors[neighbors_at..], &mut left);
            }
            if said_end == said_at && neighbors_end == neighbors_at {
                if said_at < said.len() {
                    said_end += 1;
                } else if neighbors_at < neighbors.len() {
                    neighbors_end += 1;
                }
            }
            let last = said_end == said.len() && neighbors_end == neighbors.len();
            let data = page_data(
                selection.hint,
                &said[said_at..said_end],
                &neighbors[neighbors_at..neighbors_end],
                index,
                &draft,
                last,
            );
            // Each page's call carries the rows its prompt was read from (FIX
            // 11397): this page's and every earlier page's, since the draft it
            // carries is text written from them. Attribution only.
            let rows = oneiron::skill_optimize::union_source_rows([
                Some(&selection.said_rows[..said_end]),
                Some(&selection.neighbor_rows[..neighbors_end]),
            ]);
            let (answer, refined) = self.ask(seat, prompt, &data, rows)?;
            if last {
                return Ok(refined);
            }
            draft = answer;
            (said_at, neighbors_at) = (said_end, neighbors_end);
        }
    }

    /// One refiner request over `data` on the caller's admitted inference
    /// ladder: its answer as JSON, and as the typed result it must parse
    /// to. `rows` are the vault rows the prompt was read from (FIX 11397);
    /// the call carries them as attribution only. The caller is checked
    /// again after the remote call, before the engine lands the candidate or
    /// a next page is asked.
    fn ask(
        &self,
        seat: &Seat,
        prompt: &str,
        data: &serde_json::Value,
        rows: Option<Vec<oneiron::EntityId>>,
    ) -> oneiron::Result<(serde_json::Value, RefinedSkillWire)> {
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
                message(LlmMessageRole::System, prompt.to_owned()),
                message(LlmMessageRole::User, data.to_string()),
            ],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
            host_segments: None,
        };
        let (ladder, run) =
            crate::api::llm::admit(self.server, self.auth, &mut request).map_err(|response| {
                refine_failed(&format!("inference refused ({})", response.status()))
            })?;
        let run = run.sourced(rows);
        let response = self
            .handle
            .block_on(ladder.generate(&run, request, None))
            .map_err(|error| refine_failed(&error.to_string()))?;
        let text: String = response
            .message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        let typed = || refine_failed("refiner did not return its typed JSON result");
        let answer: serde_json::Value = serde_json::from_str(&text).map_err(|_| typed())?;
        let refined = RefinedSkillWire::deserialize(&answer).map_err(|_| typed())?;
        self.owner.revalidate(self.server.vault())?;
        Ok((answer, refined))
    }
}

/// A paged selection's request data: today's shape, its page of
/// utterances and neighbours, with the part it is (`index`, from one), the
/// answer over the parts before it (`draft`) and whether it is the `last`.
fn page_data(
    hint: Option<&str>,
    said: &[serde_json::Value],
    neighbors: &[serde_json::Value],
    index: u64,
    draft: &serde_json::Value,
    last: bool,
) -> serde_json::Value {
    serde_json::json!({
        "said": said,
        "hint": hint,
        "neighbors": neighbors,
        "part": {"index": index, "last": last, "draft": draft, "note": REFINE_PART_NOTE},
    })
}

/// How many of `items`, in order, fit in what is `left` of a page's window,
/// each counted as its request sends it; `left` keeps what they leave.
fn take(items: &[serde_json::Value], left: &mut u64) -> usize {
    let mut taken = 0;
    for item in items {
        let cost = tokens(&item.to_string()).saturating_add(1);
        if cost > *left {
            break;
        }
        *left -= cost;
        taken += 1;
    }
    taken
}

/// `text`'s tokens in the engine's count.
fn tokens(text: &str) -> u64 {
    u64::try_from(oneiron::count_context_pack_tokens(text)).unwrap_or(u64::MAX)
}

/// Whether the System `prompt` and the User `data` fit `window`, counted as
/// one text.
fn fits(window: u64, prompt: &str, data: &str) -> bool {
    tokens(&[prompt, data].join("\n")) <= window
}

/// What the provider's tokenizer may count above the engine's on a model
/// whose ratio was never measured, and the reply frame that margin leaves,
/// as a Coach triage part's window takes them (FIX 10305).
const UNMEASURED_COUNT_FACTOR: u64 = 2;
const REPLY_FRAME_TOKENS: u64 = 64;

/// The tokens one refiner request may fill on `seat` (FIX 8989): the
/// smallest window any of its rungs may serve it on, less the prompt the
/// rung prepends, else its own model's. `None` while no window is known.
fn refine_window(vault: &oneiron::Vault, seat: &Seat) -> Option<u64> {
    seat.rung_models()
        .into_iter()
        .filter_map(|(model, prompt)| {
            let input = input_tokens(vault, &model)?;
            Some(input.saturating_sub(prompt.as_deref().map_or(0, tokens)))
        })
        .min()
        .or_else(|| input_tokens(vault, &seat.model))
}

/// `model`'s window less the output its catalog row reserves, in the
/// engine's count: divided by the tokens its tokenizer counts per o200k
/// token where it counts more, and while that ratio is unmeasured, cut to
/// what twice the engine's count and a reply frame fill. `None` while its
/// row or window is unknown.
fn input_tokens(vault: &oneiron::Vault, model: &oneiron::ModelId) -> Option<u64> {
    let row = vault.model_registry_row(model).ok().flatten()?;
    let context = row.catalog.context_window_tokens;
    if context == 0 {
        return None;
    }
    let output = row
        .catalog
        .max_output_tokens
        .filter(|output| *output < context)
        .unwrap_or(0);
    let input = context - output;
    Some(match row.tokens_per_o200k {
        Some(ratio) if ratio > 1.0 => (input as f64 / ratio) as u64,
        Some(_) => input,
        None => (input / UNMEASURED_COUNT_FACTOR).saturating_sub(REPLY_FRAME_TOKENS),
    })
}

/// A skill conversion's failure, for `message`, a static reason or a
/// typed status.
fn refine_failed(message: &str) -> oneiron::Error {
    oneiron::Error::InvalidConfig(format!("skill conversion: {message}"))
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
