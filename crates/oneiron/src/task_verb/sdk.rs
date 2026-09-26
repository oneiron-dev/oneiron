//! Shared typed agent-verb inputs and generated transport dispatch.
use super::TaskAskHandle;
use crate::memory::{Memory, MemoryError, MemoryResult};
use serde::{Deserialize, Serialize};

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
        assert_eq!(verb.argument_fields().is_some(), verb.is_mcp());
        assert_eq!(verb.required_fields().is_some(), verb.is_mcp());
        assert_eq!(mcp_arguments_schema(verb.as_str()).is_some(), verb.is_mcp());
    }
    assert!(AgentVerb::TasksAsk.is_section());
    assert!(AgentVerb::RoomsSpeak.writes());
    assert!(AgentVerb::RoomsList.is_facade());
    assert!(!AgentVerb::BoardExpand.is_facade());
    assert!(!AgentVerb::Recall.is_mcp());
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
    use crate::task_verb::{TaskAskDefault, TaskAskEffectAuthorization, TaskAskSpec, TaskAskWait};
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
    assert!(
        !schema["required"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("intent_key"))
    );
    assert!(
        schema["required"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("what"))
    );
    let receipt = invoke(&memory, "tasks.ask", short.clone()).unwrap();
    let handle: crate::task_verb::TaskAskHandle =
        serde_json::from_value(receipt["handle"].clone()).unwrap();
    assert_eq!(
        invoke(&memory, "tasks.ask", short).unwrap()["handle"],
        receipt["handle"]
    );
    let spec: TaskAskSpec = serde_json::from_value(serde_json::json!({
        "what": {"reference": question, "revision": 1, "options": {}, "context_refs": []}
    }))
    .unwrap();
    assert_eq!(
        spec.normalize_sdk_input().unwrap().decide,
        Some(crate::task_verb::TaskAskDecide::First)
    );
    let bad = serde_json::json!({
        "what": {"reference": question, "revision": 1, "options": {}, "context_refs": []},
        "need": {"count": 2}
    });
    assert_eq!(
        invoke(&memory, "tasks.ask", bad).unwrap_err().code,
        crate::memory::MEMORY_CODE_BAD_REQUEST
    );
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
}
