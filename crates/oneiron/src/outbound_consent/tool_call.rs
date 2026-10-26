//! Resolve header parameters once and freeze them with the consent-visible tool call.
//! Header parameters form an independent grant class, not a sensitivity rank.
use super::{DataClass, FrozenMcpPayload, ScopedMcpCallContext};
use crate::outbound_intent_ledger::OutboundToolDescriptor;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

mod headers;

pub use self::headers::header_parameters;

use self::headers::{canonical_header, declared_headers, dynamic_header};

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
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
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

/// Frozen identity of the exact qualified connector manifest that rendered a
/// tool call. Set only by the vault-bound preparation door; the gate and
/// recovery compare it against the current key in their own snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConnectorManifestBinding {
    pub(crate) key_ref: String,
    pub(crate) manifest_hash: [u8; 32],
    pub(crate) protocol_revision: String,
}

/// Engine-owned prepared request. This is the only input that can authorize a
/// scoped outbound payload. Preparation does not grant permission to send.
#[derive(Clone)]
pub struct PreparedToolCall {
    payload: FrozenMcpPayload,
    frozen: FrozenToolCall,
    /// The caller keeps no record (FIX 9372): its admitted ledger row keeps
    /// the request sealed. Set only from the pending call's trusted flag,
    /// never from the request's own arguments or headers.
    keeps_no_record: bool,
}
impl PreparedToolCall {
    /// This call as an off-record caller's, when `off_record` says so (FIX
    /// 9372): its admitted ledger row keeps the request sealed.
    #[must_use]
    pub(crate) fn keeping_no_record(mut self, off_record: bool) -> Self {
        self.keeps_no_record = off_record;
        self
    }
    /// Whether the caller keeps no record (FIX 9372).
    pub(crate) const fn keeps_no_record(&self) -> bool {
        self.keeps_no_record
    }
    pub(crate) fn manifest_binding(&self) -> Option<&ConnectorManifestBinding> {
        self.frozen.manifest_binding.as_ref()
    }
    fn with_manifest_binding(mut self, binding: ConnectorManifestBinding) -> Result<Self> {
        self.frozen.manifest_binding = Some(binding);
        self.payload =
            FrozenMcpPayload::new(serde_json::to_vec(&self.frozen).map_err(|_| invalid_schema())?);
        Ok(self)
    }
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
    /// Whether the approved tool declared itself read-only and not
    /// destructive: retrieval, for its budget class (FIX 8688).
    pub(crate) fn is_read_only(&self) -> bool {
        self.frozen.read_only_hint == Some(true) && !self.frozen.destructive_hint
    }

    pub fn idempotency_supported(&self) -> bool {
        self.frozen.idempotency_supported()
    }
    /// Extracting bytes cannot confer authority. Authorization accepts only
    /// the intact prepared request, never a raw frozen payload.
    pub fn into_frozen_payload(self) -> FrozenMcpPayload {
        self.payload
    }
    /// The prepared request an admitted ledger row froze, read back from its
    /// exact bytes (FIX 990): decoding is canonical, so the payload is those
    /// bytes unchanged. It only recomposes the row's own approve-once target
    /// and ask; it is never sent or admitted again.
    pub(super) fn from_frozen(bytes: &[u8]) -> Result<Self> {
        let frozen = FrozenToolCall::decode(bytes)?;
        Ok(Self {
            payload: FrozenMcpPayload::new(bytes.to_vec()),
            frozen,
            keeps_no_record: false,
        })
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

/// What preparing one connector tool call came to under its tool's current
/// capability setting (DEC-0006, FIX 990), read in the snapshot that read its
/// key and approved schema. Preparing never sends and never spends a press.
pub enum ConnectorToolCallPreparation {
    /// `auto` or `always allow`: the call meets the Gate's per-call verdict.
    Ready(PreparedToolCall),
    /// `always ask`: the exact call the Gate admits only on the owner's press
    /// for it. Its admission selects and spends an available press, or holds
    /// the call naming its approve-once digest.
    ConsentRequired { candidate: PreparedToolCall },
    /// `never allow`: the tool is not callable; no usable call was minted.
    Denied {
        reason: super::ScopedMcpEscalationReason,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FrozenToolCall {
    pub(super) call: ScopedMcpCallContext,
    arguments: BTreeMap<String, Value>,
    headers: BTreeMap<String, String>,
    grant_requirements: Vec<HeaderGrantRequirement>,
    manifest_binding: Option<ConnectorManifestBinding>,
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

/// Read-only view of one authorized frozen tool call, for a real sender.
///
/// A sender sends the envelope's `arguments` as the tool's arguments and its
/// `headers` as HTTP headers, never the whole envelope. Decoding and its
/// validation stay here, so a sender outside the engine never parses the
/// internal payload itself.
pub struct FrozenToolCallView {
    frozen: FrozenToolCall,
}

impl FrozenToolCallView {
    /// Decodes the frozen payload and checks it against the call's own
    /// server, tool and endpoint axes.
    pub fn read(call: &crate::outbound_intent_ledger::FrozenOutboundCall) -> Result<Self> {
        let frozen = FrozenToolCall::decode(call.payload())?;
        if frozen.call.server != call.server()
            || frozen.call.tool != call.tool()
            || call.resolved_endpoint() != Some(frozen.call.resolved_endpoint.as_str())
        {
            return Err(invalid_schema());
        }
        Ok(Self { frozen })
    }

    #[must_use]
    pub fn server(&self) -> &str {
        &self.frozen.call.server
    }

    #[must_use]
    pub fn tool(&self) -> &str {
        &self.frozen.call.tool
    }

    /// The endpoint the grant's allowlist admitted.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.frozen.call.resolved_endpoint
    }

    /// The tool's arguments, with header parameters already moved out.
    #[must_use]
    pub fn arguments(&self) -> &BTreeMap<String, Value> {
        &self.frozen.arguments
    }

    /// Canonical lowercase header names and their printable-ASCII values.
    #[must_use]
    pub fn headers(&self) -> &BTreeMap<String, String> {
        &self.frozen.headers
    }

    /// The protocol revision the connector key pinned when it was approved.
    #[must_use]
    pub fn protocol_revision(&self) -> Option<&str> {
        self.frozen
            .manifest_binding
            .as_ref()
            .map(|binding| binding.protocol_revision.as_str())
    }

    /// The governing connector key the call was prepared against (hex).
    #[must_use]
    pub fn key_ref(&self) -> Option<&str> {
        self.frozen
            .manifest_binding
            .as_ref()
            .map(|binding| binding.key_ref.as_str())
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
    super::tool_schema::reject_unresolved(schema)?;
    // A schema with no root `properties` (`{"type":"object"}`) names none: an
    // empty map, the arguments still checked against the whole schema (FIX 8811).
    let none = serde_json::Map::new();
    let properties = match schema.get("properties") {
        Some(properties) => properties.as_object().ok_or_else(invalid_schema)?,
        None => &none,
    };
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
    if destructive_hint && declares_preview {
        if body.get("dry_run").is_some_and(|value| !value.is_boolean()) {
            return Err(invalid_schema());
        }
        body.insert(
            "dry_run".into(),
            Value::Bool(mutation == MutationIntent::Preview),
        );
    }
    let checked = serde_json::to_value(&body).map_err(|_| invalid_schema())?;
    super::tool_schema::validate(schema, &checked, &call.tool)?;
    let mut headers = BTreeMap::new();
    let mut requirements = Vec::new();
    let declared = declared_headers(schema, &checked, &call.tool)?;
    for (parameter, names) in declared.named {
        let names = names
            .into_iter()
            .map(canonical_header)
            .collect::<Result<std::collections::BTreeSet<_>>>()?;
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
        // Each header the parameter is named under carries it, each under its
        // own header grant; one header two values would need refuses.
        for name in names {
            if headers
                .insert(name.clone(), value.to_owned())
                .is_some_and(|before| before != value)
            {
                return Err(invalid_schema());
            }
            requirements.push(HeaderGrantRequirement {
                parameter: parameter.to_owned(),
                header: name,
                data_class: ToolGrantDataClass::XMcpHeader,
            });
        }
    }
    // A key a pattern or `additionalProperties` declares goes as its header
    // when it can by the same rules; else it stays in the body (FIX 9284).
    for (parameter, names) in declared.dynamic {
        let Some((header, value)) =
            dynamic_header(&body, parameter, &names, &headers, destructive_hint)
        else {
            continue;
        };
        body.remove(parameter);
        headers.insert(header.clone(), value);
        requirements.push(HeaderGrantRequirement {
            parameter: parameter.to_owned(),
            header,
            data_class: ToolGrantDataClass::XMcpHeader,
        });
    }
    requirements.sort_by(|a, b| a.parameter.cmp(&b.parameter));
    // The frozen content's own class raises the tool's (FIX 8807): every
    // check of this call, its retries' too, reads the class frozen here.
    let mut call = call;
    let sent = serde_json::json!([&body, &headers]);
    call.payload_data_class = call.payload_data_class.max(content_data_class(&sent));
    let preview = destructive_hint && mutation == MutationIntent::Preview;
    if destructive_hint && declares_preview {
        body.insert("dry_run".into(), Value::Bool(preview));
    }
    let frozen = FrozenToolCall {
        call,
        arguments: body,
        headers,
        grant_requirements: requirements,
        manifest_binding: None,
        destructive_hint,
        mutation,
        read_only_hint: replay.read_only_hint,
        idempotency_supported_hint: replay.idempotency_supported_hint,
    };
    let bytes = serde_json::to_vec(&frozen).map_err(|_| invalid_schema())?;
    Ok(PreparedToolCall {
        payload: FrozenMcpPayload::new(bytes),
        frozen,
        keeps_no_record: false,
    })
}
/// Decode a durable payload before recovery uses its manifest identity.
pub(crate) fn frozen_manifest_binding(bytes: &[u8]) -> Result<Option<ConnectorManifestBinding>> {
    Ok(FrozenToolCall::decode(bytes)?.manifest_binding)
}

impl crate::Vault {
    /// Prepare against the current approved schema. An unqualified key or a
    /// descriptor not identical to the approved resolved schema cannot mint
    /// a manifest-bound call. Gate admission rechecks this binding in-txn.
    /// The tool's capability setting is read with the key (FIX 990): `never
    /// allow` mints nothing, and `always ask` marks the call as one only the
    /// owner's press on it admits.
    pub fn prepare_connector_tool_call(
        &self,
        key_ref: &crate::EntityId,
        call: ScopedMcpCallContext,
        descriptor: ToolCallDescriptor<'_>,
        arguments: &Value,
        mutation: MutationIntent,
    ) -> Result<ConnectorToolCallPreparation> {
        use crate::connector_key::SlateDisposition;
        let (key, setting) = {
            let txn = self.store.env.read_txn()?;
            let key = crate::connector_key::read_key_for_pack_in_txn(self, &txn, key_ref)?
                .ok_or(crate::Error::EntityNotFound)?;
            let setting = crate::connector_key::connector_tool_setting_in_txn(
                &self.store,
                &txn,
                key_ref,
                &key,
                &call.tool,
            )?;
            (key, setting)
        };
        if setting == SlateDisposition::NeverAllow {
            return Ok(ConnectorToolCallPreparation::Denied {
                reason: super::ScopedMcpEscalationReason::ConnectorSlateNeverAllow,
            });
        }
        let manifest = key.retained_manifest.as_ref().ok_or_else(invalid_schema)?;
        if key.status != crate::connector_key::ConnectorKeyStatus::Active
            || key.tool_requires_confirmation(&call.tool)
            || !manifest
                .tools()
                .iter()
                .any(|tool| tool.name == call.tool && tool.input_schema == *descriptor.schema)
        {
            return Err(invalid_schema());
        }
        let binding = ConnectorManifestBinding {
            key_ref: key_ref.to_hex(),
            manifest_hash: manifest.hash()?,
            protocol_revision: key.protocol_revision.ok_or_else(invalid_schema)?,
        };
        let prepared = prepare_tool_call(call, descriptor, arguments, mutation)?
            .with_manifest_binding(binding)?;
        Ok(if setting == SlateDisposition::AlwaysAsk {
            ConnectorToolCallPreparation::ConsentRequired {
                candidate: prepared,
            }
        } else {
            ConnectorToolCallPreparation::Ready(prepared)
        })
    }
}

pub(super) fn invalid_schema() -> Error {
    Error::InvalidConfig("tool schema or resolved header parameters are invalid".into())
}

/// The class `content` shows by itself (FIX 8807): `Secret` when the shared
/// release check finds a credential or secret in it, read on a copy;
/// otherwise the lowest, so the tool's slate class (its trusted provenance)
/// stands. Nothing here classifies personal content.
pub(super) fn content_data_class(content: &Value) -> DataClass {
    if crate::batch::export::redact_credentials(&mut content.clone()) {
        DataClass::Secret
    } else {
        DataClass::Public
    }
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
    fn schema_validation_precedes_header_extraction_and_freezing() {
        let schema = json!({"type":"object","required":["tenant","record"],"additionalProperties":false,
            "properties":{"tenant":{"type":"string","x-mcp-header":"x-tenant"},
                "record":{"type":"object","required":["ids"],"additionalProperties":false,
                    "properties":{"ids":{"type":"array","items":{"type":"integer"}}}},
                "dry_run":{"type":"boolean"}}});
        for args in [
            json!({"record":{"ids":[1]}}),
            json!({"tenant":7,"record":{"ids":[1]}}),
            json!({"tenant":"a","record":{"ids":[1]},"secret":"leak"}),
            json!({"tenant":"a","record":{"ids":["wrong"]}}),
            json!({"tenant":"a","record":{"ids":[1],"extra":true}}),
        ] {
            assert!(prepare(&schema, &args, true, MutationIntent::Preview).is_err());
        }
        let valid = prepare(
            &schema,
            &json!({"tenant":"a","record":{"ids":[1]}}),
            true,
            MutationIntent::Preview,
        )
        .unwrap();
        let wire: Value = serde_json::from_slice(valid.frozen_bytes()).unwrap();
        assert_eq!(wire["headers"]["x-tenant"], "a");
        assert_eq!(
            wire["arguments"],
            json!({"record":{"ids":[1]},"dry_run":true})
        );
        let open =
            json!({"type":"object","properties":{},"additionalProperties":{"type":"string"}});
        assert!(
            prepare(
                &open,
                &json!({"extra":"allowed"}),
                false,
                MutationIntent::Preview
            )
            .is_ok()
        );
        assert!(prepare(&open, &json!({"extra":1}), false, MutationIntent::Preview).is_err());
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
