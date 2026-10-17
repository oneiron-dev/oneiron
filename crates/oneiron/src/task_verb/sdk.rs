//! Shared typed agent-verb inputs and generated transport dispatch.
use super::{TaskAskDefault, TaskAskHandle, TaskAskQuestion, TaskAskSpec, TaskAskTarget};
use crate::memory::{Memory, MemoryError, MemoryResult};
use serde::{Deserialize, Serialize};

/// `can(ask(...))`: one read-only preflight for a typed ask spec.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskCanAskRequest {
    pub ask: super::TaskAskSpec,
}

/// One SDK verb with two disjoint wire shapes. Rich fields cannot be
/// reinterpreted as first-answer shorthand after Serde drops field presence.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum TaskAskRequest {
    Rich(Box<TaskAskSpec>),
    Short(Box<TaskAskShort>),
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAskShort {
    #[serde(default)]
    pub who: Option<TaskAskTarget>,
    pub what: TaskAskQuestion,
    #[serde(default)]
    pub until: Option<u64>,
    #[serde(default)]
    pub default: TaskAskDefault,
}

impl TaskAskRequest {
    /// The ask spec this request names: a short call's retry key is derived
    /// from exactly what it requested.
    pub fn into_spec(self) -> MemoryResult<TaskAskSpec> {
        match self {
            Self::Rich(spec) => Ok(*spec),
            Self::Short(short) => {
                // The key names the *requested* short call, never a cutoff
                // derived from the current clock or the resolved electorate.
                let bytes =
                    rmp_serde::to_vec_named(&(&short.who, &short.what, short.until, short.default))
                        .map_err(|_| MemoryError::bad_request("short ask encoding"))?;
                let mut spec =
                    TaskAskSpec::shorthand(short.who, short.what, short.until, short.default);
                spec.intent_key = format!("short/v1/{}", blake3::hash(&bytes).to_hex());
                Ok(spec)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskWaitRequest {
    pub handle: TaskAskHandle,
    pub step_key: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAnswerRequest {
    pub handle: TaskAskHandle,
    pub word: super::TaskAskWord,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmptyRequest {}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomRequest {
    pub room_ref: String,
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomRefRequest {
    pub room_ref: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomTurnRequest {
    pub room_ref: String,
    pub turn_ref: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomClaimRequest {
    pub room_ref: String,
    pub turn_ref: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectRefRequest {
    pub project_ref: String,
}
/// `vault.projects.goal.dismiss`'s input: the proposal one tradeoff question
/// made, under the goal claim the caller saw in force.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalDismissRequest {
    pub project_ref: String,
    pub expected_goal_ref: String,
    pub question_digest: String,
}
/// `vault.projects.goal.dismiss`'s result: `false` when an identical retry
/// wrote nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectGoalDismissReceipt {
    pub dismissed: bool,
}
/// `vault.projects.route_tradeoff`'s input: the project TASK to ask on and
/// the skill proposal whose tradeoff question it carries.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectTradeoffRouteRequest {
    pub task_ref: String,
    pub proposal_ref: String,
}
/// `vault.rooms.host`: the room, and the live session whose participants
/// count as present beside the caller.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomHostRequest {
    pub room_ref: String,
    #[serde(default)]
    pub session_ref: Option<String>,
}
/// `vault.companions.sharing.get`: a companion's PERSON and the contact her
/// source vault's clearance is about.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompanionSharingRequest {
    pub companion_ref: String,
    pub contact_ref: String,
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
pub struct WorkspaceRefRequest {
    pub workspace_ref: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkCompanionSetRequest {
    pub workspace_ref: String,
    pub policy: crate::workspace_roster::WorkCompanionPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskRequest {
    pub task_ref: String,
}
/// `tasks.update`: the owner's acknowledgement of a TASK, or, from a code
/// run's reader child, the finding its result name `resultRef` holds. Only a
/// run resolves its result names, so a host door refuses `resultRef`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskUpdateRequest {
    pub task_ref: String,
    #[serde(default, rename = "resultRef", skip_serializing_if = "Option::is_none")]
    pub result_ref: Option<String>,
}
/// `vault.projects.proposals`: the conversation whose project cards to read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectConversationRequest {
    pub conversation_ref: String,
}
/// `vault.projects.dismiss_card`: one host-held project card.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectCardRequest {
    pub card_id: String,
}
/// `vault.projects.dismiss_card`'s result: `false` when the card was
/// dismissed already.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectCardDismissal {
    pub card_id: String,
    pub dismissed: bool,
}
/// `describe`'s one input: the task to describe, a board card's key, or
/// none for the whole TASKS section.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescribeRequest {
    #[serde(default)]
    pub task_ref: Option<String>,
    #[serde(default, rename = "self")]
    pub self_target: bool,
    #[serde(default)]
    pub session_id: Option<String>,
    /// A board card's key: describe expands that card, under the board's
    /// scope and frame-epoch checks.
    #[serde(default)]
    pub key: Option<String>,
    /// The board frame the card key was read from; a stale one is refused.
    #[serde(default)]
    pub frame_epoch: Option<u64>,
    /// A fold of the run's own log (`f1`): its span, its stub and the ids it
    /// holds. Only the run that folded it answers this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fold: Option<String>,
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
    pub assignee: Option<super::TaskAssignee>,
}

/// The create spec one `tasks.create` request names, owned by the
/// surface's actor.
pub fn task_create_spec(
    memory: &Memory<'_>,
    input: TaskCreateRequest,
) -> MemoryResult<super::TaskCreateSpec> {
    let spec = super::TaskCreateSpec::new(
        crate::msgpack_value_from_json(&input.spec)?,
        input.label,
        Some(memory.actor()),
        Some(memory.vault().now_recorded_at()),
    );
    Ok(match input.assignee {
        Some(assignee) => spec.with_assignee(assignee),
        None => spec,
    })
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardRefreshRequest {
    pub frame_epoch: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardSubscriptionRequest {
    pub scopes: std::collections::BTreeSet<crate::context_board::SubscriptionScope>,
}

fn decode<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> MemoryResult<T> {
    serde_path_to_error::deserialize(value)
        .map_err(|error| MemoryError::bad_request(format!("invalid SDK request: {error}")))
}
fn encode<T: Serialize>(value: T) -> MemoryResult<serde_json::Value> {
    serde_json::to_value(value).map_err(|_| MemoryError::bad_request("SDK result encoding failed"))
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomEntry {
    pub id: String,
    pub room: crate::workspace_roster::ProjectRoom,
}
/// `vault.recall`'s inputs, spelled exactly as §HEAD-CONTRACT does.
///
/// Every field but `query` is optional and defaults to the contract's default,
/// so an omitting client and a spelling-everything client reach the same
/// engine call.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RecallRequest {
    pub query: String,
    /// One of the five effort levels, or `call`: call mode for live calls,
    /// light effort under a hard deadline. Omitted means `medium`.
    #[serde(default)]
    pub effort: Option<crate::memory::RecallEffort>,
    #[serde(default)]
    pub scope: Option<crate::memory::RecallScope>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub format: Option<String>,
    /// Unix seconds the query's time words resolve against: `yesterday` is
    /// the day before it. Omitted, they resolve against now.
    #[serde(default)]
    pub as_of: Option<u64>,
    /// A hard deadline, in milliseconds from when the request arrives,
    /// 1 to 60000: at it, recall answers with the best results ready, marked
    /// `partial`. Omitted, recall runs to the end, except call mode, which
    /// takes the vault's call-mode deadline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
    /// A media query (OF-370): bytes the host embeds into one declared space
    /// through the `ai.embed` rung that space's id names, searched as that
    /// space's list beside the query's. A host that serves no such rung
    /// refuses the recall with `MODEL_UNAVAILABLE`; it never recalls without
    /// the media.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media: Option<crate::code_run::vault_read::ContextPackMediaQuery>,
}

pub use super::recall_door::{
    RECALL_MEDIA_UNSERVED, RecallDoor, recall_at_door, recall_at_door_seeded, recall_unembedded,
    recall_with_vector,
};
pub use super::sdk_catalog_fragment::{
    CATALOG_FRAGMENT_REVISION, CatalogFragment, code_mode_catalog_fragment,
};
pub use super::sdk_connector::*;
pub use super::sdk_diary::*;
pub use super::sdk_disclosure::*;
pub use super::sdk_embedding_space::*;
pub use super::sdk_guest_revoke::*;
pub use super::sdk_host::*;
pub use super::sdk_legal_hold::*;
pub use super::sdk_self::*;
pub use super::sdk_share::*;
pub use super::sdk_shared::*;
pub use super::sdk_shared_members::*;

/// `vault.writes.pending`'s one input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReceiptsRequest {
    #[serde(default)]
    pub limit: Option<usize>,
}
/// `vault.receipts`'s input: a page size, and the receipt kinds to list as
/// `ReceiptKind` names them (`gate`, `hook`, `outbound`, ...). With no kinds
/// it lists the gate decision ledger; an unknown kind is refused.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VaultReceiptsRequest {
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<String>,
}
/// `inbox.list`'s one input (OF-221): the exclusive entity-ID cursor a
/// previous page returned as `next_after`, and a page size
/// ([`crate::inbox::INBOX_PAGE_DEFAULT`] when absent).
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboxListRequest {
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}
/// `inbox.mark`'s one input (OF-221): one delivered notification and the
/// mark to record for the caller.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboxMarkRequest {
    pub notification_ref: String,
    pub mark: crate::inbox::NotificationMark,
}

#[path = "sdk_memory.rs"]
mod memory_requests;
pub use memory_requests::*;

include!("verb_catalog.rs");
include!("run_verb_catalog.rs");
include!("sdk_generated.rs");

/// The verb table as code mode serves it, each row at its full path (`vault.recall`,
/// `self.focus.refresh`, a bare `describe`): the rows a host door answers, then
/// the rows the run answers itself. The guest's method table, the executor
/// prompt and dispatch all read this list.
pub fn code_mode_verb_names() -> impl Iterator<Item = &'static str> + Clone {
    let host = AgentVerb::ALL.iter().map(|verb| verb.as_str());
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
            let schema_ref = verb_schema_ref(&replacement);
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

/// The verb table as code mode's declarations: one signature per row at its
/// full path, rendered from that verb's own input schema, so the methods a
/// model is shown are exactly the rows the host serves. `self` is a namespace
/// of object-typed members, every other root an object-typed constant and a
/// bare verb a function, so a row named by a reserved word (`vault.export`)
/// is a valid method: a namespace's `function export` does not parse.
#[must_use]
pub fn code_mode_declarations() -> &'static str {
    // GLOBAL STATE: rendered once from compiled verb schemas, which are
    // immutable and vault-independent.
    static DECLARATIONS: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        let mut tree = DeclarationNode::default();
        for verb in code_mode_verb_names() {
            let mut node = &mut tree;
            for part in verb.split('.') {
                node = node.children.entry(part).or_default();
            }
            node.verb = Some(verb);
        }
        let mut out = String::new();
        for (root, node) in &tree.children {
            match (*root, node.verb) {
                ("self", _) => {
                    out.push_str("declare namespace self {\n");
                    for (name, child) in &node.children {
                        let kind = declaration_type(child, 1);
                        out.push_str(&format!("  const {name}: {kind};\n"));
                    }
                    out.push_str("}\n");
                }
                (root, Some(verb)) if node.children.is_empty() => {
                    let input = verb_input_type(verb);
                    out.push_str(&format!(
                        "declare function {root}(input: {input}): Promise<unknown>;\n"
                    ));
                }
                (root, _) => {
                    let kind = declaration_type(node, 0);
                    out.push_str(&format!("declare const {root}: {kind};\n"));
                }
            }
        }
        out
    });
    &DECLARATIONS
}

/// One path segment of the verb tree. A segment can be a verb and hold verbs
/// at once (`self.memory.diary` and `self.memory.diary.query`), so a verb is
/// a callable that may carry children rather than a leaf that replaces them.
#[derive(Default)]
struct DeclarationNode {
    verb: Option<&'static str>,
    children: std::collections::BTreeMap<&'static str, DeclarationNode>,
}

fn render_declarations(
    tree: &std::collections::BTreeMap<&'static str, DeclarationNode>,
    depth: usize,
    out: &mut String,
) {
    let indent = "  ".repeat(depth);
    for (name, node) in tree {
        match node.verb {
            Some(verb) if node.children.is_empty() => {
                let input = verb_input_type(verb);
                out.push_str(&format!(
                    "{indent}{name}(input: {input}): Promise<unknown>;\n"
                ));
            }
            _ => {
                let kind = declaration_type(node, depth);
                out.push_str(&format!("{indent}{name}: {kind};\n"));
            }
        }
    }
}

/// One declaration's type: a verb's call signature, the members it holds, or
/// both at once.
fn declaration_type(node: &DeclarationNode, depth: usize) -> String {
    let call = node.verb.map(verb_call_signature);
    if node.children.is_empty() {
        return call.unwrap_or_else(|| "{}".to_owned());
    }
    let mut members = String::from("{\n");
    render_declarations(&node.children, depth + 1, &mut members);
    members.push_str(&"  ".repeat(depth));
    members.push('}');
    match call {
        Some(call) => format!("({call}) & {members}"),
        None => members,
    }
}

/// A verb's call signature. `self.fold` is the one positional verb
/// (ARCH-0067 #folds: `self.fold(span, {note?})`, Docs Q25); every other verb
/// takes one input object.
fn verb_call_signature(verb: &str) -> String {
    if verb == "self.fold" {
        return "(span: readonly [number, number], options?: { note?: string | null }) => \
                Promise<unknown>"
            .to_owned();
    }
    format!("(input: {}) => Promise<unknown>", verb_input_type(verb))
}

fn verb_input_type(verb: &str) -> String {
    input_schema(verb).map_or_else(|| "object".to_owned(), schema_type)
}

/// A schema's TypeScript spelling, one level deep: nested objects stay `object`.
fn schema_type(schema: &serde_json::Value) -> String {
    let required: Vec<&str> = schema["required"]
        .as_array()
        .map(|fields| {
            fields
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect()
        })
        .unwrap_or_default();
    let Some(properties) = schema["properties"].as_object() else {
        return "object".to_owned();
    };
    let fields: Vec<String> = properties
        .iter()
        .map(|(field, property)| {
            let optional = if required.contains(&field.as_str()) {
                ""
            } else {
                "?"
            };
            format!("{field}{optional}: {}", property_type(property))
        })
        .collect();
    format!("{{ {} }}", fields.join("; "))
}

fn property_type(property: &serde_json::Value) -> String {
    if let Some(values) = property["enum"].as_array() {
        return values
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join(" | ");
    }
    if let Some(branches) = property["anyOf"]
        .as_array()
        .or_else(|| property["oneOf"].as_array())
    {
        return branches
            .iter()
            .map(property_type)
            .collect::<Vec<_>>()
            .join(" | ");
    }
    let types: Vec<&str> = match &property["type"] {
        serde_json::Value::String(kind) => vec![kind.as_str()],
        serde_json::Value::Array(kinds) => {
            kinds.iter().filter_map(serde_json::Value::as_str).collect()
        }
        _ => return "unknown".to_owned(),
    };
    types
        .into_iter()
        .map(|kind| match kind {
            "string" => "string".to_owned(),
            "integer" | "number" => "number".to_owned(),
            "boolean" => "boolean".to_owned(),
            "null" => "null".to_owned(),
            "array" => format!(
                "{}[]",
                match property_type(&property["items"]).as_str() {
                    item if item.contains(' ') => format!("({item})"),
                    item => item.to_owned(),
                }
            ),
            _ => "object".to_owned(),
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

#[cfg(test)]
#[test]
fn verb_input_schema_is_built_once_per_process() {
    let first = input_schema("tasks.ask").expect("tasks.ask input schema");
    let second = input_schema("tasks.ask").expect("tasks.ask input schema");
    assert!(std::ptr::eq(first, second));
}

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
        as_of: None,
        deadline_ms: None,
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
    let question = super::tests::support::consult_turn(&vault, 0x81);
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
    super::tests::support::put_person(&vault, other);
    let question = super::tests::support::consult_turn(&vault, 0x81);
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
