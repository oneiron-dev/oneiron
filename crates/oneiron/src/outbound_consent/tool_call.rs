//! Resolve header parameters once and freeze them with the consent-visible tool call.
//! Header parameters form an independent grant class, not a sensitivity rank.
use super::{FrozenMcpPayload, ScopedMcpCallContext};
use crate::outbound_intent_ledger::OutboundToolDescriptor;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolGrantDataClass {
    Arguments,
    XMcpHeader,
}
impl ToolGrantDataClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Arguments => "arguments",
            Self::XMcpHeader => "x_mcp_header",
        }
    }
    pub(crate) fn valid_grant_set(classes: &[Self]) -> bool {
        matches!(
            classes,
            [Self::Arguments] | [Self::XMcpHeader] | [Self::Arguments, Self::XMcpHeader]
        )
    }
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "arguments" => Some(Self::Arguments),
            "x_mcp_header" => Some(Self::XMcpHeader),
            _ => None,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderGrantRequirement {
    pub parameter: String,
    pub header: String,
    pub data_class: ToolGrantDataClass,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationIntent {
    #[default]
    Preview,
    ExplicitMutation,
}

/// Resolved descriptor supplied by the tool registry, not by the argument map.
#[derive(Debug, Clone, Copy)]
pub struct ToolCallDescriptor<'a> {
    pub schema: &'a Value,
    pub destructive_hint: bool,
    pub replay: OutboundToolDescriptor,
}

/// Engine-owned prepared request. This is the only input that can authorize a
/// scoped outbound payload. Preparation does not grant permission to send.
#[derive(Clone)]
pub struct PreparedToolCall {
    payload: FrozenMcpPayload,
    frozen: FrozenToolCall,
}
impl PreparedToolCall {
    pub fn header_grants(&self) -> &[HeaderGrantRequirement] {
        &self.frozen.grant_requirements
    }
    pub fn is_preview(&self) -> bool {
        self.frozen.destructive_hint && self.frozen.mutation == MutationIntent::Preview
    }
    pub fn frozen_bytes(&self) -> &[u8] {
        &self.payload.bytes
    }
    pub(crate) fn decision(
        &self,
        grant: super::ScopedMcpGrantRef<'_>,
    ) -> super::ScopedMcpConsentDecision {
        self.frozen.decision(grant)
    }
    pub fn call(&self) -> &ScopedMcpCallContext {
        &self.frozen.call
    }
    pub fn idempotency_supported(&self) -> bool {
        self.frozen.idempotency_supported()
    }
    /// Extracting bytes cannot confer authority. Authorization accepts only
    /// the intact prepared request, never a raw frozen payload.
    pub fn into_frozen_payload(self) -> FrozenMcpPayload {
        self.payload
    }
    #[cfg(test)]
    pub(crate) fn freeze_event_baseline(&self) -> usize {
        self.payload.freeze_event_baseline()
    }

    /// Executes through the existing gate, durable ledger and recovery lane.
    #[expect(clippy::too_many_arguments)]
    pub fn execute<S: super::OutboundResultSender>(
        self,
        vault: &crate::Vault,
        authority: &super::OutboundBindingAuthority,
        grant_id: crate::entity_id::EntityId,
        grant: &crate::outbound_grant::StandingOutboundGrant,
        principal_ref: &str,
        attempt_id: crate::attempt_queue::AttemptId,
        call_seq: u64,
        now_ms: u64,
        sender: &mut S,
    ) -> std::result::Result<
        super::ScopedMcpDispatchResult,
        crate::outbound_intent_ledger::IntentLedgerError,
    > {
        super::execution::execute_scoped_mcp_outbound_call(
            vault,
            authority,
            grant_id,
            grant,
            principal_ref,
            attempt_id,
            call_seq,
            self,
            now_ms,
            sender,
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FrozenToolCall {
    pub(super) call: ScopedMcpCallContext,
    arguments: BTreeMap<String, Value>,
    headers: BTreeMap<String, String>,
    grant_requirements: Vec<HeaderGrantRequirement>,
    destructive_hint: bool,
    mutation: MutationIntent,
    read_only_hint: Option<bool>,
    idempotency_supported_hint: Option<bool>,
}

impl FrozenToolCall {
    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        let frozen: Self = serde_json::from_slice(bytes).map_err(|_| invalid_schema())?;
        // Canonical encoding rejects duplicate map keys and alternate spellings.
        if serde_json::to_vec(&frozen).map_err(|_| invalid_schema())? != bytes {
            return Err(invalid_schema());
        }
        if frozen.destructive_hint {
            let valid = match frozen.mutation {
                MutationIntent::Preview => {
                    frozen.arguments.get("dry_run") == Some(&Value::Bool(true))
                }
                MutationIntent::ExplicitMutation => matches!(
                    frozen.arguments.get("dry_run"),
                    None | Some(Value::Bool(false))
                ),
            };
            if !valid {
                return Err(invalid_schema());
            }
        }
        let mut headers = std::collections::BTreeSet::new();
        let mut parameters = std::collections::BTreeSet::new();
        for requirement in &frozen.grant_requirements {
            if requirement.data_class != ToolGrantDataClass::XMcpHeader
                || canonical_header(&requirement.header)? != requirement.header
                || !headers.insert(requirement.header.clone())
                || !parameters.insert(requirement.parameter.clone())
                || frozen.arguments.contains_key(&requirement.parameter)
                || !frozen.headers.contains_key(&requirement.header)
            {
                return Err(invalid_schema());
            }
        }
        if headers.len() != frozen.headers.len()
            || frozen
                .headers
                .values()
                .any(|value| !value.bytes().all(|c| c == b'\t' || (32..=126).contains(&c)))
        {
            return Err(invalid_schema());
        }
        Ok(frozen)
    }

    pub(super) fn decision(
        &self,
        grant: super::ScopedMcpGrantRef<'_>,
    ) -> super::ScopedMcpConsentDecision {
        let decision = super::evaluate_scoped_mcp_call(grant, self.call.as_call());
        if decision == super::ScopedMcpConsentDecision::AutoFire
            && !self.headers.is_empty()
            && !grant
                .tool_data_classes
                .contains(&ToolGrantDataClass::XMcpHeader)
        {
            return super::ScopedMcpConsentDecision::Escalate(
                super::ScopedMcpEscalationReason::ToolDataClassNotGranted,
            );
        }
        decision
    }

    pub(super) fn idempotency_supported(&self) -> bool {
        self.idempotency_supported_hint == Some(true)
            || (self.read_only_hint == Some(true) && !self.destructive_hint)
    }
}

/// Resolve headers and destructive preview from the descriptor once. The
/// default mutation intent is preview; explicit mutation still needs consent.
pub fn prepare_tool_call(
    call: ScopedMcpCallContext,
    descriptor: ToolCallDescriptor<'_>,
    arguments: &Value,
    mutation: MutationIntent,
) -> Result<PreparedToolCall> {
    let ToolCallDescriptor {
        schema,
        destructive_hint,
        replay,
    } = descriptor;
    reject_unresolved(schema)?;
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(invalid_schema)?;
    let args = arguments.as_object().ok_or_else(invalid_schema)?;
    let declares_preview = properties
        .get("dry_run")
        .and_then(|schema| schema.get("type"))
        .and_then(Value::as_str)
        == Some("boolean");
    if destructive_hint {
        // An unknown extra argument is not a non-mutation guarantee. A tool
        // without a declared preview refuses by default, rather than sending
        // a potentially destructive call with a flag it may ignore.
        if mutation == MutationIntent::Preview && !declares_preview {
            return Err(Error::InvalidConfig(
                "destructive tool does not declare a dry_run preview".into(),
            ));
        }
        if !declares_preview && (properties.contains_key("dry_run") || args.contains_key("dry_run"))
        {
            return Err(invalid_schema());
        }
    }
    let mut body: BTreeMap<String, Value> =
        args.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let mut headers = BTreeMap::new();
    let mut requirements = Vec::new();
    for (parameter, property) in properties {
        let Some(annotation) = property.get("x-mcp-header") else {
            continue;
        };
        let name = match annotation {
            Value::Bool(true) => parameter.as_str(),
            Value::String(name) => name.as_str(),
            Value::Bool(false) => continue,
            _ => return Err(invalid_schema()),
        };
        let name = canonical_header(name)?;
        if destructive_hint && parameter == "dry_run" {
            return Err(invalid_schema());
        }
        let Some(value) = body.remove(parameter) else {
            continue;
        };
        let value = value.as_str().ok_or_else(invalid_schema)?;
        if !value.bytes().all(|c| c == b'\t' || (32..=126).contains(&c)) {
            return Err(invalid_schema());
        }
        if headers.insert(name.clone(), value.to_owned()).is_some() {
            return Err(invalid_schema());
        }
        requirements.push(HeaderGrantRequirement {
            parameter: parameter.clone(),
            header: name,
            data_class: ToolGrantDataClass::XMcpHeader,
        });
    }
    requirements.sort_by(|a, b| a.parameter.cmp(&b.parameter));
    let preview = destructive_hint && mutation == MutationIntent::Preview;
    if destructive_hint && declares_preview {
        body.insert("dry_run".into(), Value::Bool(preview));
    }
    let frozen = FrozenToolCall {
        call,
        arguments: body,
        headers,
        grant_requirements: requirements,
        destructive_hint,
        mutation,
        read_only_hint: replay.read_only_hint,
        idempotency_supported_hint: replay.idempotency_supported_hint,
    };
    let bytes = serde_json::to_vec(&frozen).map_err(|_| invalid_schema())?;
    Ok(PreparedToolCall {
        payload: FrozenMcpPayload::new(bytes),
        frozen,
    })
}
fn invalid_schema() -> Error {
    Error::InvalidConfig("tool schema or resolved header parameters are invalid".into())
}
fn reject_unresolved(value: &Value) -> Result<()> {
    match value {
        Value::Object(map) => {
            if ["$ref", "allOf", "anyOf", "oneOf"]
                .iter()
                .any(|key| map.contains_key(*key))
            {
                return Err(invalid_schema());
            }
            for child in map.values() {
                reject_unresolved(child)?;
            }
        }
        Value::Array(items) => {
            for child in items {
                reject_unresolved(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn canonical_header(name: &str) -> Result<String> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
    {
        return Err(invalid_schema());
    }
    let name = name.to_ascii_lowercase();
    if matches!(
        name.as_str(),
        "authorization"
            | "host"
            | "cookie"
            | "connection"
            | "transfer-encoding"
            | "mcp-method"
            | "mcp-name"
    ) || name.starts_with("content-")
        || name.starts_with("proxy-")
    {
        return Err(invalid_schema());
    }
    Ok(name)
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn prepare(
        schema: &Value,
        arguments: &Value,
        destructive_hint: bool,
        mutation: MutationIntent,
    ) -> Result<PreparedToolCall> {
        prepare_tool_call(
            ScopedMcpCallContext {
                server: "files".to_owned(),
                tool: "read_file".to_owned(),
                payload_data_class: super::super::DataClass::Personal,
                resolved_endpoint: "https://files.internal.example".to_owned(),
            },
            ToolCallDescriptor {
                schema,
                destructive_hint,
                replay: OutboundToolDescriptor {
                    read_only_hint: Some(false),
                    idempotency_supported_hint: Some(true),
                },
            },
            arguments,
            mutation,
        )
    }
    #[test]
    fn an_unsupported_preview_refuses_instead_of_sending_an_ignored_flag() {
        let schema = json!({"type":"object","properties":{"record":{"type":"string"}}});
        let args = json!({"record":"r1"});
        assert!(prepare(&schema, &args, true, MutationIntent::Preview).is_err());
        let explicit = prepare(&schema, &args, true, MutationIntent::ExplicitMutation).unwrap();
        let wire: Value = serde_json::from_slice(explicit.frozen_bytes()).unwrap();
        assert_eq!(wire["arguments"], args);
        assert!(!explicit.is_preview());
        assert!(
            prepare(
                &schema,
                &json!({"record":"r1","dry_run":true}),
                true,
                MutationIntent::ExplicitMutation
            )
            .is_err()
        );
    }
    #[test]
    fn headers_have_their_own_frozen_grant_class_and_destructive_tools_preview() {
        let schema = json!({"type":"object","properties":{"tenant":{"type":"string","x-mcp-header":"X-Tenant"},"record":{"type":"string"},"dry_run":{"type":"boolean"}}});
        let mut args = json!({"tenant":"original","record":"r1","dry_run":false});
        let preview = prepare(&schema, &args, true, MutationIntent::Preview).unwrap();
        assert!(preview.is_preview());
        assert_eq!(
            preview.header_grants()[0].data_class,
            ToolGrantDataClass::XMcpHeader
        );
        args["tenant"] = json!("changed after consent");
        let frozen: Value = serde_json::from_slice(preview.frozen_bytes()).unwrap();
        assert_eq!(frozen["headers"]["x-tenant"], "original");
        assert!(frozen["arguments"].get("tenant").is_none());
        assert_eq!(frozen["arguments"]["dry_run"], true);
        assert_eq!(
            frozen["grant_requirements"][0]["data_class"],
            "x_mcp_header"
        );
        let mutation = prepare(&schema, &args, true, MutationIntent::ExplicitMutation).unwrap();
        assert!(!mutation.is_preview());
        let bytes = mutation.into_frozen_payload().into_bytes();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap()["arguments"]["dry_run"],
            false
        );
    }
    #[test]
    fn unresolved_schema_header_smuggling_and_wrong_values_fail_closed() {
        for schema in [
            json!({"$ref":"hidden"}),
            json!({"properties":{"x":{"x-mcp-header":"Mcp-Name"}}}),
            json!({"properties":{"x":{"x-mcp-header":"bad\r\nname"}}}),
        ] {
            assert!(
                prepare(
                    &schema,
                    &json!({"x":"value"}),
                    true,
                    MutationIntent::Preview
                )
                .is_err()
            );
        }
        let schema = json!({"properties":{"x":{"x-mcp-header":"x-client"}}});
        assert!(
            prepare(
                &schema,
                &json!({"x":"one\r\nHost: bad"}),
                false,
                MutationIntent::Preview
            )
            .is_err()
        );
    }
}
