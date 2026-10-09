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
    fn into_spec(self) -> MemoryResult<TaskAskSpec> {
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
pub struct TaskRequest {
    pub task_ref: String,
}
/// `describe`'s one input: the task to describe, or none for the whole
/// TASKS section.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescribeRequest {
    #[serde(default)]
    pub task_ref: Option<String>,
    #[serde(default, rename = "self")]
    pub self_target: bool,
    #[serde(default)]
    pub session_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskCreateRequest {
    pub spec: serde_json::Value,
    pub label: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardExpandRequest {
    pub key: String,
    pub frame_epoch: Option<u64>,
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
/// `recall`'s inputs, spelled exactly as §HEAD-CONTRACT does.
///
/// Every field but `query` is optional and defaults to the contract's default,
/// so an omitting client and a spelling-everything client reach the same
/// engine call.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RecallRequest {
    pub query: String,
    #[serde(default)]
    pub effort: Option<crate::memory::Effort>,
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
}

/// `recall` with a host's query vector. Every SDK door lands here: the
/// generated [`recall`] embeds nothing, and a server whose embedder is serving
/// embeds the query. `embed` runs only once the request is admitted.
pub fn recall_with_vector(
    memory: &Memory<'_>,
    input: RecallRequest,
    embed: impl FnOnce(&str) -> Option<Vec<f32>>,
) -> MemoryResult<crate::memory::MemoryPack> {
    crate::memory::caps::check_query(&input.query)?;
    crate::memory::caps::check_limit(input.limit.unwrap_or(10))?;
    crate::memory::caps::check_as_of(input.as_of)?;
    let embedding = embed(&input.query);
    memory.recall_with_execution(
        &input.query,
        input.effort.unwrap_or(crate::memory::Effort::Medium),
        &input.scope.unwrap_or_default(),
        input.limit.unwrap_or(10),
        input.format.as_deref(),
        None,
        &crate::retrieval_depth::RecallExecution {
            embedding: embedding.as_deref(),
            as_of: input.as_of,
            ..Default::default()
        },
    )
}

/// `receipts`'s one input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReceiptsRequest {
    #[serde(default)]
    pub limit: Option<usize>,
}

include!("verb_catalog.rs");
include!("sdk_generated.rs");

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
