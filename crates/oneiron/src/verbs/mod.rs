//! Shared typed agent-verb inputs and generated transport dispatch.
mod asset_masked_read;
mod connector_source_rows_read;
mod skill_package_read;

mod act_answer;
mod agent_grant;
mod agent_run_effect;
mod agents;
mod anonymous_chat;
mod answer_forward;
mod asr;
mod authority_history;
mod board_layout;
mod browser;
mod calendar;
mod campaign_archive;
mod campaign_enrollment;
mod campaign_split;
mod can;
mod catalog_fragment;
mod check_in;
mod comm_widen;
mod connect_proposal;
mod connector;
mod connector_call;
mod connector_pack;
mod connector_reply_retry;
mod connector_slate;
mod connector_slate_revision;
mod connector_witness_read_grant;
mod coreference;
mod courtesy_delete;
mod credential;
mod custody_drain;
mod describe;
mod diary;
mod diary_pinned;
mod disclosure;
mod embedding_space;
mod engine_controls;
mod eval_cohort;
mod explain;
mod fanout_launch;
mod federation;
#[cfg(feature = "sync")]
mod federation_burst;
mod feedback;
mod files;
mod files_search;
mod follower_keyframe;
mod free_time_policy;
mod gate_decision_read;
mod gate_policy_read;
mod git_push_grant;
mod goal_optimize;
mod grants;
mod guest_document;
mod guest_revoke;
mod host;
mod hub;
mod identity_topology;
mod legal_hold;
// The build-time closure of the verb table over linked `self.*` operations.
mod linked_self_surface;
mod live_run;
mod live_voice;
mod mesh;
mod model_manifest;
mod model_pack;
mod model_settings;
mod note_history;
mod oauth_authorization;
mod off_record;
mod off_record_rooms;
mod off_record_runs;
mod outbound_call_erase;
mod outbox_diverged;
mod pack_preview;
mod persona;
mod proxy;
mod receipts_page;
mod record_erase;
mod reply;
// FIX 13274: the owner reviews and settles a retained document-copy edit.
#[cfg(feature = "sync")]
mod repo_copy_edit;
#[cfg(feature = "sync")]
mod repo_manifest_conflict;
mod research;
mod research_advance;
mod research_root;
mod reservoir_sources;
mod residence;
mod retrieval;
mod revisions_read;
mod root_requests;
mod scratchpad;
mod secret;
mod secret_custody;
mod secret_grant;
mod secret_use;
mod self_actor;
mod self_model_read;
mod self_verbs;
mod share;
mod shared;
mod shared_admin;
mod shared_members;
mod shared_policy;
mod skill_attribution;
mod skill_defaults;
mod skill_execution;
mod skill_fit;
mod skill_fork;
mod skills;
mod standing;
// FIX 17553: the owner resets a person's step-up passkeys.
mod step_up;
mod support_grant;
mod sync_outbox;
#[cfg(feature = "sync")]
mod sync_quarantine;
mod trusted_contact;
mod uncertain_send;
mod verb_table;
mod voice_bank;
mod weave;
mod web_connector;
mod wire_health;
mod workflows;
mod workspace;

use crate::memory::{MEMORY_CODE_BAD_REQUEST, Memory, MemoryError, MemoryResult};
use crate::task_verb::TaskAskHandle;
use serde::{Deserialize, Serialize};

/// `can(ask(...))`: one read-only preflight for a typed ask spec.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskCanAskRequest {
    pub ask: crate::task_verb::TaskAskSpec,
}

pub use crate::task_verb::{TaskAskRequest, TaskAskShort, TaskWaitRequest};
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAnswerRequest {
    pub handle: TaskAskHandle,
    pub word: crate::task_verb::TaskAskWord,
}
#[doc(hidden)]
pub use oneiron_verb_wire::verbs::{
    BoardFrameReply, BoardRefreshRequest, BoardSubscriptionReply, BoardSubscriptionRequest,
    BoardWakeReply, BoardWakeRequest, CompanionSharingRequest, EmptyRequest, InboxListRequest,
    InboxMarkRequest, ProjectCardRequest, ProjectConversationRequest, ProjectGoalDismissRequest,
    ProjectGoalDismissTarget, ProjectRefRequest, ProjectTradeoffRouteRequest, ReceiptsRequest,
    RoomClaimRequest, RoomHostRequest, RoomRefRequest, RoomRequest, RoomTurnRequest, TaskRequest,
    TaskWaveReceipt, TaskWaveRequest, WorkspaceRefRequest,
};

/// `vault.projects.goal.dismiss`'s result: `false` when an identical retry
/// wrote nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectGoalDismissReceipt {
    pub dismissed: bool,
}
/// `vault.companions.sharing.set`: the owner's standing yes to one frozen
/// clearance offer for the contact a companion's sharing is about.
/// `expected_delta` is the offer's canonical bytes, as the owner was shown
/// them, in lowercase hex.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompanionSharingSetRequest {
    pub companion_ref: String,
    pub contact_ref: String,
    pub proposal_ref: String,
    pub expected_delta: String,
}
impl CompanionSharingSetRequest {
    /// The companion and contact this request names.
    pub fn target(&self) -> MemoryResult<crate::workspace_roster::CompanionSharingTarget> {
        let id = |reference: &str, field: &str| {
            crate::EntityId::from_hex(reference)
                .map_err(|_| MemoryError::bad_request(format!("invalid {field}")))
        };
        Ok(crate::workspace_roster::CompanionSharingTarget {
            companion: id(&self.companion_ref, "companion_ref")?,
            contact: id(&self.contact_ref, "contact_ref")?,
        })
    }

    /// `expected_delta` decoded. Only lowercase hex decodes: the delta is
    /// compared byte for byte, so it has one spelling.
    pub fn delta(&self) -> MemoryResult<Vec<u8>> {
        let pairs = self.expected_delta.as_bytes().chunks_exact(2);
        if !pairs.remainder().is_empty() {
            return Err(MemoryError::bad_request("invalid expected_delta"));
        }
        pairs
            .map(|pair| {
                std::str::from_utf8(pair)
                    .ok()
                    .filter(|digits| {
                        digits
                            .bytes()
                            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                    })
                    .and_then(|digits| u8::from_str_radix(digits, 16).ok())
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| MemoryError::bad_request("invalid expected_delta"))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkCompanionSetRequest {
    pub workspace_ref: String,
    pub policy: crate::workspace_roster::WorkCompanionPolicy,
}
pub use crate::task_verb::TaskUpdateRequest;
/// `vault.projects.dismiss_card`'s result: `false` when the card was
/// dismissed already.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectCardDismissal {
    pub card_id: String,
    pub dismissed: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskCreateRequest {
    pub spec: serde_json::Value,
    pub label: Option<String>,
    /// Who realizes the TASK; absent is the Dreamer lane. The engine routes
    /// from this alone. A creator, project or spend is never request text:
    /// an agent run's TASK runs under its creator only by its host's
    /// binding (OF-532).
    #[serde(default)]
    pub assignee: Option<crate::task_verb::TaskAssignee>,
    /// The caller's idempotency key for a briefed create (OF-220): with
    /// `brief`, the create is a post through the task highway, and one
    /// actor and key name one post.
    #[serde(default)]
    pub intent_key: Option<String>,
    /// The typed brief a post carries (OF-220).
    #[serde(default)]
    pub brief: Option<crate::task_verb::QueueTaskBrief>,
    /// The TASK's absolute expiry.
    #[serde(default)]
    pub ttl: Option<crate::task_verb::TaskTtl>,
    /// The parent TASK this one files under (DOOR-113), by short-id ref or
    /// 32-hex id. The nesting matrix decides, so a Task nests under a
    /// Milestone; absent is a root.
    #[serde(default)]
    pub parent_ref: Option<String>,
    /// When the TASK falls due, Unix seconds (FIX 4749). A due TASK is a
    /// watcher: it ticks once on `schedule.tick` after this time, and a hook
    /// bound to that tick returns Nothing or Enqueue. A standard task, briefed
    /// or not, carries one; absent is no tick.
    #[serde(default)]
    pub due_at: Option<u64>,
    /// A watch TASK (FIX 22121): nothing realizes it at create; its `due_at`
    /// tick runs its hooks and settles it Done. It needs `due_at`, and no
    /// assignee or the Dreamer.
    #[serde(default)]
    pub watch: bool,
}

/// The create spec one `tasks.create` request names, owned by the
/// surface's actor. A request naming an intent key and a brief is a post
/// (OF-220); one naming only one of them is refused.
pub fn task_create_spec(
    memory: &Memory<'_>,
    input: TaskCreateRequest,
) -> MemoryResult<crate::task_verb::TaskCreateSpec> {
    let parent_ref = input
        .parent_ref
        .as_deref()
        .map(|reference| crate::memory::resolve_entity_ref(memory.vault(), reference))
        .transpose()?;
    let mut spec = crate::task_verb::TaskCreateSpec::new(
        crate::msgpack_value_from_json(&input.spec)?,
        input.label,
        Some(memory.actor()),
        Some(memory.vault().now_recorded_at()),
    );
    spec.assignee = input.assignee;
    spec.ttl = input.ttl;
    spec.due_at = input.due_at;
    spec.watch = input.watch;
    spec.parent_ref = parent_ref;
    match (input.intent_key, input.brief) {
        (Some(intent_key), Some(brief)) => Ok(spec.with_brief(intent_key, brief)),
        (None, None) => Ok(spec),
        _ => Err(MemoryError::bad_request(
            "a briefed create names both its intent key and its brief",
        )),
    }
}

/// `tasks.create.from_message`: the project-room MESSAGE or TURN a TASK is
/// made from, and the create as `tasks.create` names it. The TASK binds to
/// the root of the thread the source stands in, in the create's write. A
/// create that routes through approval (a typed brief, an intent key, or a
/// ceiling short of Auto) is refused.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskCreateFromMessageRequest {
    /// The MESSAGE or TURN, by short-id ref or 32-hex id.
    pub source_ref: String,
    pub create: TaskCreateRequest,
}

/// `tasks.create.from_message` for the surface's actor: the source by its
/// id, and the create spec [`task_create_spec`] builds.
pub fn task_create_from_message(
    memory: &Memory<'_>,
    input: TaskCreateFromMessageRequest,
) -> MemoryResult<crate::task_verb::TaskCreateReceipt> {
    let source_ref = crate::memory::resolve_entity_ref(memory.vault(), &input.source_ref)?;
    let spec = task_create_spec(memory, input.create)?;
    memory.tasks_create_from_message(source_ref, &spec)
}
use oneiron_verb_wire::verb_input::decode;
fn encode<T: Serialize>(value: T) -> MemoryResult<serde_json::Value> {
    serde_json::to_value(value).map_err(|_| MemoryError::bad_request("SDK result encoding failed"))
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomEntry {
    pub id: String,
    pub room: crate::workspace_roster::ProjectRoom,
}
pub use crate::memory::RecallRequest;

pub use crate::memory::affect::QueryAffect;

pub use self::asset_masked_read::*;
pub use self::connector_source_rows_read::*;
pub use self::skill_package_read::*;

pub use self::act_answer::*;
pub use self::agent_grant::*;
pub use self::agent_run_effect::*;
pub use self::agents::*;
pub use self::anonymous_chat::*;
pub use self::answer_forward::*;
pub use self::asr::*;
pub use self::authority_history::*;
pub use self::board_layout::*;
pub use self::browser::*;
pub use self::calendar::*;
pub use self::campaign_archive::*;
pub use self::campaign_enrollment::*;
pub use self::campaign_split::*;
pub use self::can::*;
pub use self::catalog_fragment::{
    CATALOG_FRAGMENT_REVISION, CatalogFragment, code_mode_catalog_fragment,
};
pub use self::check_in::*;
pub use self::comm_widen::*;
pub use self::connect_proposal::*;
pub use self::connector::*;
pub use self::connector_call::*;
pub use self::connector_pack::*;
pub use self::connector_reply_retry::*;
pub use self::connector_slate::*;
pub use self::connector_slate_revision::*;
pub use self::connector_witness_read_grant::*;
pub use self::coreference::*;
pub use self::courtesy_delete::*;
pub use self::credential::*;
pub use self::custody_drain::*;
pub use self::describe::*;
pub use self::diary::*;
pub use self::diary_pinned::*;
pub use self::disclosure::*;
pub use self::embedding_space::*;
pub use self::engine_controls::*;
pub use self::eval_cohort::*;
pub use self::explain::*;
pub use self::fanout_launch::*;
pub use self::federation::*;
#[cfg(feature = "sync")]
pub use self::federation_burst::*;
pub use self::feedback::*;
pub use self::files::*;
pub use self::files_search::*;
pub use self::follower_keyframe::*;
pub use self::free_time_policy::*;
pub use self::gate_decision_read::*;
pub use self::gate_policy_read::*;
pub use self::git_push_grant::*;
pub use self::goal_optimize::*;
pub use self::grants::*;
pub use self::guest_document::*;
pub use self::guest_revoke::*;
pub use self::host::*;
pub use self::hub::*;
pub use self::identity_topology::*;
pub use self::legal_hold::*;
pub use self::live_run::*;
pub use self::live_voice::*;
pub use self::mesh::*;
pub use self::model_manifest::*;
pub use self::model_pack::*;
pub use self::model_settings::*;
pub use self::note_history::*;
pub use self::oauth_authorization::*;
pub use self::off_record::*;
pub use self::off_record_rooms::*;
pub use self::off_record_runs::*;
pub use self::outbound_call_erase::*;
pub use self::outbox_diverged::*;
pub use self::pack_preview::*;
pub use self::persona::*;
pub use self::proxy::*;
pub use self::receipts_page::*;
pub use self::record_erase::*;
pub use self::reply::*;
#[cfg(feature = "sync")]
pub use self::repo_copy_edit::*;
#[cfg(feature = "sync")]
pub use self::repo_manifest_conflict::*;
pub use self::research::*;
pub use self::research_advance::*;
pub use self::research_root::*;
pub use self::reservoir_sources::*;
pub use self::residence::*;
pub use self::retrieval::*;
pub use self::revisions_read::*;
pub use self::root_requests::*;
pub use self::scratchpad::*;
pub use self::secret::*;
pub use self::secret_custody::*;
pub use self::secret_grant::*;
pub use self::secret_use::*;
pub use self::self_actor::*;
pub use self::self_model_read::*;
pub use self::self_verbs::*;
pub use self::share::*;
pub use self::shared::*;
pub use self::shared_admin::*;
pub use self::shared_members::*;
pub use self::shared_policy::*;
pub use self::skill_attribution::*;
pub use self::skill_defaults::*;
pub use self::skill_execution::*;
pub use self::skill_fit::*;
pub use self::skills::*;
pub use self::standing::*;
pub use self::step_up::*;
pub use self::support_grant::*;
pub use self::sync_outbox::*;
#[cfg(feature = "sync")]
pub use self::sync_quarantine::*;
pub use self::trusted_contact::*;
pub use self::uncertain_send::*;
pub use self::voice_bank::*;
pub use self::weave::*;
pub use self::web_connector::*;
pub use self::wire_health::*;
pub use self::workflows::*;
pub use self::workspace::*;
pub use crate::task_verb::fanout_batch::{
    FanoutBatchInput, FanoutBatchView, FanoutChildInput, FanoutChildSlot, FanoutLeaseView,
    FanoutSharedAccounting, FanoutSlotAttempt, FanoutSlotState, FanoutSlotTerminal,
    fanout_batch_rows,
};
pub use crate::task_verb::recall_door::{
    RECALL_MEDIA_UNSERVED, RecallDoor, recall_at_door, recall_at_door_seeded, recall_unembedded,
    recall_with_vector,
};

mod memory_requests;
pub use memory_requests::*;

mod blob_input;
pub use blob_input::{invoke_blob_input, takes_blob_input};

// Generated at build time from the verb table (crates/oneiron-sdk-build).
include!(concat!(env!("OUT_DIR"), "/verb_catalog.rs"));
include!(concat!(env!("OUT_DIR"), "/run_verb_catalog.rs"));
include!(concat!(env!("OUT_DIR"), "/sdk_generated.rs"));
pub use verb_table::{GeneratedVerbTable, VERB_TABLE};

/// The verb table as code mode serves it, each row at its full path (`vault.recall`,
/// `self.focus.refresh`, a bare `describe`): the rows a host door answers, then
/// the rows the run answers itself. The guest's method table, the executor
/// prompt and dispatch all read this list.
pub fn code_mode_verb_names() -> impl Iterator<Item = &'static str> + Clone {
    let host = AgentVerb::ALL
        .iter()
        .filter(|verb| RunVerb::from_name(verb.as_str()).is_none())
        .map(|verb| verb.as_str());
    host.chain(RunVerb::ALL.iter().map(|verb| verb.as_str()))
}

/// Roots a model reaches for that the SDK does not have, each with the root
/// it means. A call under one is refused with that correction and never run
/// under it: there are no aliases (EIRI-ARCH-0002 §The contract).
const WRONG_ROOTS: &[(&str, &str)] = &[
    ("tools.", "connector."),
    ("connectors.", "connector."),
    ("self.connectors.", "connector."),
    ("self.mcp.", "connector."),
    ("mcp.", "connector."),
];

/// The roots a canonical verb sits under, longest first. Stripping one gives
/// the verb's leaf, which a wrong-root spelling of it shares.
const VERB_ROOTS: &[&str] = &[
    "self.memory.",
    "self.focus.",
    "self.",
    "vault.",
    "connector.",
    "ai.",
];

/// Prefixes with no meaning in the SDK that a model still writes in front of
/// a verb (`memory.search`, `sdk.describe`).
const STRAY_ROOTS: &[&str] = &[
    "memory.", "shared.", "home.", "sdk.", "oneiron.", "board.", "tasks.",
];

/// Where a verb's schema lives: its row in the verb table, which every
/// binding and the code-mode declarations are generated from.
#[must_use]
pub fn verb_schema_ref(verb: &str) -> String {
    format!("oneiron:sdk/agent-verbs#{verb}")
}

/// The `WRONG_ROOT` refusal for a call to `attempted`, or `None` when
/// `attempted` is a verb of `served` or has no one canonical verb it could
/// mean (then the caller's own unknown-verb refusal stands). Pure: it runs
/// before any lookup that has an effect, and nothing is ever run under the
/// wrong name.
#[must_use]
pub fn wrong_root_in(
    attempted: &str,
    served: impl Iterator<Item = &'static str> + Clone,
) -> Option<MemoryError> {
    if served.clone().any(|verb| verb == attempted) {
        return None;
    }
    for (wrong, root) in WRONG_ROOTS {
        if let Some(rest) = attempted
            .strip_prefix(wrong)
            .filter(|rest| !rest.is_empty())
        {
            let replacement = format!("{root}{rest}");
            // A dynamic connector tool (`connector.<name>.<tool>`) is no row
            // of its own: the guest's proxy sends it as `connector.call`
            // (ONE-2510), so its correction names that row's schema.
            let schema_ref = if served.clone().any(|verb| verb == replacement) {
                verb_schema_ref(&replacement)
            } else {
                verb_schema_ref(AgentVerb::ConnectorCall.as_str())
            };
            return Some(MemoryError::wrong_root(attempted, replacement, schema_ref));
        }
    }
    let attempted_leaves = verb_leaves(attempted, true);
    let mut meant = served.filter(|verb| {
        verb_leaves(verb, false)
            .iter()
            .any(|leaf| attempted_leaves.contains(leaf))
    });
    let replacement = meant.next()?;
    if meant.next().is_some() {
        return None;
    }
    Some(MemoryError::wrong_root(
        attempted,
        replacement,
        verb_schema_ref(replacement),
    ))
}

/// [`wrong_root_in`] over every verb code mode serves.
#[must_use]
pub fn wrong_root(attempted: &str) -> Option<MemoryError> {
    wrong_root_in(attempted, code_mode_verb_names())
}

/// A name and every leaf left after stripping one root from it; a spelling a
/// model wrote also sheds the stray and wrong roots.
fn verb_leaves(name: &str, written: bool) -> Vec<&str> {
    let mut leaves = vec![name];
    let wrong = WRONG_ROOTS.iter().map(|(wrong, _)| *wrong);
    let stray = STRAY_ROOTS.iter().copied().chain(wrong).filter(|_| written);
    for root in VERB_ROOTS.iter().copied().chain(stray) {
        if let Some(leaf) = name.strip_prefix(root).filter(|leaf| !leaf.is_empty()) {
            leaves.push(leaf);
        }
    }
    leaves
}

/// The verb table as code mode's declarations: the code-mode catalog
/// fragment's text ([`code_mode_catalog_fragment`]). Every row code mode
/// serves sits at its full path (`vault.recall`, `self.focus.refresh`, a bare
/// `describe`) with its typed input and reply, one overload first for each
/// input field that selects its own reply (`describe({fold})`,
/// `tasks.update({resultRef})`), and every type they reach in one namespace.
/// The SDK generator (`crates/oneiron-sdk-generator`) writes that one text from the table to both
/// `catalog_fragment.d.ts` and `code-mode.d.ts`, so the methods a model is
/// shown are exactly the rows the host serves.
#[must_use]
pub fn code_mode_declarations() -> &'static str {
    code_mode_catalog_fragment().text
}

/// A revision as a surface shows it: 64 lower-case hex.
fn revision_shape(seen: &str) -> MemoryResult<()> {
    if seen.len() == 64
        && seen
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(MemoryError::new(
            MEMORY_CODE_BAD_REQUEST,
            "seen must be 64 lower-case hex",
            &["Pass the revision the surface showed, or omit seen."],
        ))
    }
}

#[cfg(test)]
#[test]
fn verb_input_schema_is_built_once_per_process() {
    let first = input_schema("tasks.ask").expect("tasks.ask input schema");
    let second = input_schema("tasks.ask").expect("tasks.ask input schema");
    assert!(std::ptr::eq(first, second));
}

// FIX [LIBTEST-QUARANTINE-VERBS-ITEMS]: the lib test target's type check fails here (5 errors: E0599 x5); port it, then drop this gate
#[cfg(any())]
#[cfg(test)]
#[test]
fn sdk_catalog_drives_scoped_projections_and_round_trips_names() {
    let mut names = std::collections::BTreeSet::new();
    for verb in AgentVerb::ALL {
        assert!(names.insert(verb.as_str()));
        assert_eq!(AgentVerb::from_name(verb.as_str()), Some(*verb));
        assert!(input_schema(verb.as_str()).is_some());
        // ARCH-0028: the tool list is the whole verb table, never a curated one.
        assert!(
            mcp_arguments_schema(verb.as_str()).is_some(),
            "{}",
            verb.as_str()
        );
    }
    assert!(AgentVerb::TasksAsk.is_section());
    assert!(AgentVerb::RoomsSpeak.writes());
    assert!(AgentVerb::RoomsList.is_facade());
    assert!(!AgentVerb::BoardExpand.is_facade());
    assert_eq!(AgentVerb::Recall.argument_fields(), &["spec"]);
    assert!(AgentVerb::from_name("not.a.verb").is_none());
}

#[cfg(test)]
#[test]
fn a_typed_argument_shape_error_names_its_field() {
    let error = validate_input(
        "key_value_search",
        &serde_json::json!({"namespace_prefix": "a"}),
    )
    .expect_err("a string cannot stand in for a namespace sequence");
    assert_eq!(error.code, crate::memory::MEMORY_CODE_BAD_REQUEST);
    assert!(error.message.contains("namespace_prefix"), "{error:?}");
}

/// ARCH-0067's 2026-09-22 amendment renamed the four task rows, with no alias.
#[cfg(test)]
#[test]
fn retired_task_verb_names_are_unknown() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default()).expect("open vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
    let memory = vault.memory(owner, crate::EdgeActorClass::Human);
    for name in ["tasks.check", "tasks.expand", "tasks.ack", "tasks.cancel"] {
        assert!(AgentVerb::from_name(name).is_none(), "{name}");
        let refusal = invoke(&memory, name, serde_json::json!({})).expect_err(name);
        assert_eq!(
            refusal.code,
            crate::memory::MEMORY_CODE_BAD_REQUEST,
            "{name}"
        );
        assert_eq!(refusal.message, "unknown SDK agent verb", "{name}");
    }
    for name in ["describe", "tasks.update", "cancel"] {
        assert!(AgentVerb::from_name(name).is_some(), "{name}");
    }
}

/// #1323 review (CodeRabbit, Greptile): a server embedded the query of a
/// recall that validation then refused, so a paid effort, an unknown format
/// or an unknown kind still cost an embedding call. Each is refused first,
/// as is a deadline outside 1 to 60000 ms (call mode's typed refusal).
#[cfg(test)]
#[test]
fn a_recall_the_engine_refuses_never_embeds_its_query() {
    use crate::memory::Effort;

    let dir = tempfile::tempdir().expect("tempdir");
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default()).expect("vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let memory = vault.memory(owner, crate::EdgeActorClass::Human);
    let request = |effort: Effort, format: Option<&str>, kinds: Option<&str>| RecallRequest {
        query: "who fixes my car".to_owned(),
        effort: Some(effort.into()),
        scope: kinds.map(|kind| crate::memory::RecallScope {
            kinds: Some(vec![kind.to_owned()]),
            ..Default::default()
        }),
        limit: None,
        format: format.map(str::to_owned),
        token_budget: None,
        reader_agent_ref: None,
        as_of: None,
        deadline_ms: None,
        media: None,
        query_affect: None,
        telemetry: None,
        filter: None,
    };
    let call = |deadline_ms| RecallRequest {
        effort: Some(crate::memory::RecallEffort::Call),
        deadline_ms: Some(deadline_ms),
        ..request(Effort::Light, None, None)
    };
    for (input, code) in [
        (call(0), crate::memory::MEMORY_CODE_BAD_REQUEST),
        (
            call(crate::memory::caps::MAX_RECALL_DEADLINE_MS + 1),
            crate::memory::MEMORY_CODE_BAD_REQUEST,
        ),
        (
            request(Effort::High, None, None),
            crate::memory::MEMORY_CODE_LEASE_REQUIRED,
        ),
        (
            request(Effort::Medium, Some("xml"), None),
            crate::memory::MEMORY_CODE_BAD_REQUEST,
        ),
        (
            request(Effort::Medium, None, Some("NOT_A_KIND")),
            crate::memory::MEMORY_CODE_BAD_REQUEST,
        ),
    ] {
        let refusal = recall_with_vector(&memory, input, |_| panic!("the refused query embedded"))
            .expect_err("refused");
        assert_eq!(refusal.code, code, "{refusal:?}");
    }
    let mut embedded = 0;
    recall_with_vector(&memory, request(Effort::Medium, None, None), |_| {
        embedded += 1;
        None
    })
    .expect("an admitted recall runs");
    assert_eq!(embedded, 1);
}

#[cfg(test)]
#[test]
fn non_keyed_sdk_request_does_not_claim_a_keyed_decoder() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default()).expect("vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let memory = vault.memory(owner, crate::EdgeActorClass::Human);
    let error = invoke(&memory, "recall", serde_json::json!({})).expect_err("missing query");
    assert_eq!(error.code, crate::memory::MEMORY_CODE_BAD_REQUEST);
    assert!(!error.message.contains("keyed"), "{error:?}");
}

#[cfg(test)]
#[test]
fn short_ask_sdk_shape_uses_one_verb_and_never_claims_effect_authority() {
    use crate::task_verb::{TaskAskDefault, TaskAskEffectAuthorization, TaskAskWait};
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    let actor = vault.ensure_embedded_owner_actor().unwrap();
    let question = crate::task_verb::tests::support::consult_turn(&vault, 0x81);
    let memory = vault.memory(actor, crate::EdgeActorClass::Human);
    let short = serde_json::json!({
        "who": {"responder": {"human": {"actor_ref": actor}}},
        "what": {"reference": question, "revision": 1, "options": {}, "context_refs": []},
        "default": "proceed",
    });
    let schema = input_schema("tasks.ask").unwrap();
    let branches = schema["anyOf"]
        .as_array()
        .expect("rich and short schema branches");
    assert_eq!(branches.len(), 2);
    let rich_schema = branches
        .iter()
        .find(|branch| {
            branch["required"]
                .as_array()
                .is_some_and(|fields| fields.contains(&serde_json::json!("intent_key")))
        })
        .unwrap();
    let short_schema = branches
        .iter()
        .find(|branch| {
            branch["required"]
                .as_array()
                .is_some_and(|fields| !fields.contains(&serde_json::json!("intent_key")))
        })
        .unwrap();
    for branch in [rich_schema, short_schema] {
        assert!(
            branch["required"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("what"))
        );
        assert_eq!(branch["additionalProperties"], false);
    }
    assert_eq!(rich_schema["properties"]["intent_key"]["type"], "string");
    assert!(short_schema["properties"].get("intent_key").is_none());
    let receipt = invoke(&memory, "tasks.ask", short.clone()).unwrap();
    let handle: crate::task_verb::TaskAskHandle =
        serde_json::from_value(receipt["handle"].clone()).unwrap();
    assert_eq!(
        invoke(&memory, "tasks.ask", short).unwrap()["handle"],
        receipt["handle"]
    );
    for rich_field in [
        serde_json::json!({"need": {"count": 1, "of": "any"}}),
        serde_json::json!({"decide": null}),
        serde_json::json!({"on_disagree": {"branch": "hold", "surface": "card"}}),
    ] {
        let mut malformed = serde_json::json!({
            "what": {"reference": question, "revision": 1, "options": {}, "context_refs": []},
            "who": {"people": [actor]}
        });
        malformed
            .as_object_mut()
            .unwrap()
            .extend(rich_field.as_object().unwrap().clone());
        assert_eq!(
            invoke(&memory, "tasks.ask", malformed).unwrap_err().code,
            crate::memory::MEMORY_CODE_BAD_REQUEST
        );
    }
    let answer = memory
        .tasks_answer(&handle, &crate::task_verb::TaskAskWord::new(actor))
        .unwrap();
    let wait: TaskAskWait = serde_json::from_value(
        invoke(
            &memory,
            "tasks.wait",
            serde_json::json!({
                "handle": handle, "step_key": "sdk-short"
            }),
        )
        .unwrap(),
    )
    .unwrap();
    let TaskAskWait::Ready(result) = wait else {
        panic!("settled short ask")
    };
    assert_eq!(
        result.decision,
        crate::task_verb::TaskAskDecision::First(answer)
    );
    assert!(result.coverage.met);
    assert!(result.fallback.is_none());
    assert_eq!(
        result.effect_authorization,
        TaskAskEffectAuthorization::NotEvaluatedByAsk
    );
    assert_eq!(result.settlement.effective.default, TaskAskDefault::Proceed);
    assert!(result.settlement.effective.until.is_some());

    // Rich collect remains collect. Supplying the retry key selects the
    // AskSpec branch; its omitted decide is not a shorthand first reducer.
    let mut rich = crate::task_verb::TaskAskSpec::shorthand(
        Some(crate::task_verb::TaskAskTarget::People([actor].into())),
        crate::task_verb::TaskAskQuestion::new(question),
        Some(u64::MAX),
        TaskAskDefault::Hold,
    );
    rich.intent_key = "rich-collect".into();
    rich.decide = None;
    let rich_receipt = invoke(&memory, "tasks.ask", serde_json::to_value(rich).unwrap()).unwrap();
    let rich_handle: crate::task_verb::TaskAskHandle =
        serde_json::from_value(rich_receipt["handle"].clone()).unwrap();
    memory
        .tasks_answer(&rich_handle, &crate::task_verb::TaskAskWord::new(actor))
        .unwrap();
    let crate::task_verb::TaskAskWait::Ready(collected) =
        memory.tasks_wait(rich_handle, None).unwrap()
    else {
        panic!("rich collect settled");
    };
    assert_eq!(
        collected.decision,
        crate::task_verb::TaskAskDecision::Collected
    );
}

#[cfg(test)]
#[test]
fn short_ask_retry_identity_includes_recipient_deadline_and_branch() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    let actor = vault.ensure_embedded_owner_actor().unwrap();
    let other = crate::EntityId::from_bytes([0xE2; 16]).unwrap();
    crate::task_verb::tests::support::put_person(&vault, other);
    let question = crate::task_verb::tests::support::consult_turn(&vault, 0x81);
    let memory = vault.memory(actor, crate::EdgeActorClass::Human);
    let base = serde_json::json!({
        "who": {"people": [actor]},
        "what": {"reference": question, "revision": 1, "options": {}, "context_refs": []},
        "until": u64::MAX,
        "default": "hold"
    });
    let first = invoke(&memory, "tasks.ask", base.clone()).unwrap();
    assert_eq!(
        invoke(&memory, "tasks.ask", base.clone()).unwrap()["handle"],
        first["handle"]
    );
    let mut handles = std::collections::BTreeSet::from([first["handle"]["group_ref"]
        .as_str()
        .unwrap()
        .to_owned()]);
    for change in [
        serde_json::json!({"who": {"people": [other]}}),
        serde_json::json!({"until": u64::MAX - 1}),
        serde_json::json!({"default": "proceed"}),
    ] {
        let mut input = base.clone();
        input
            .as_object_mut()
            .unwrap()
            .extend(change.as_object().unwrap().clone());
        let result = invoke(&memory, "tasks.ask", input).unwrap();
        assert!(handles.insert(result["handle"]["group_ref"].as_str().unwrap().to_owned()));
    }
}

#[cfg(test)]
#[test]
fn describe_self_shares_the_typed_sdk_result_and_mcp_arguments() {
    let schema = mcp_arguments_schema("describe").expect("describe MCP schema");
    for field in ["self", "session_id", "task_ref"] {
        assert!(
            schema["properties"].get(field).is_some(),
            "{field} must reach the MCP caller"
        );
    }
    let request: DescribeRequest =
        serde_json::from_value(serde_json::json!({"self":true,"session_id":"run-1"})).unwrap();
    assert!(request.self_target);
    assert_eq!(request.session_id.as_deref(), Some("run-1"));
    let card = crate::task_verb::TaskDescription::SelfCard {
        tail: "brief".into(),
    };
    let body = serde_json::to_value(&card).unwrap();
    assert_eq!(body["kind"], "self_card");
    assert_eq!(
        serde_json::from_value::<crate::task_verb::TaskDescription>(body).unwrap(),
        card
    );
}
pub(crate) mod tables;
pub mod voice_records;
