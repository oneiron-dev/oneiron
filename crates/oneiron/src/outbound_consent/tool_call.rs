//! Resolve header parameters once and freeze them with the consent-visible tool call.
//! Header parameters form an independent grant class, not a sensitivity rank.
use super::FrozenMcpPayload;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolGrantDataClass {
    Arguments,
    XMcpHeader,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderGrantRequirement {
    pub parameter: String,
    pub header: String,
    pub data_class: ToolGrantDataClass,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationIntent {
    Preview,
    ExplicitMutation,
}

/// Engine-owned frozen request. The transport reads headers and arguments from
/// these bytes; it must not resolve header values again after consent.
pub struct PreparedToolCall {
    payload: FrozenMcpPayload,
    requirements: Vec<HeaderGrantRequirement>,
    preview: bool,
}
impl PreparedToolCall {
    pub fn header_grants(&self) -> &[HeaderGrantRequirement] {
        &self.requirements
    }
    pub fn is_preview(&self) -> bool {
        self.preview
    }
    pub fn frozen_bytes(&self) -> &[u8] {
        &self.payload.bytes
    }
    /// The normal scoped outbound gate remains mandatory after preparation.
    pub fn into_frozen_payload(self) -> FrozenMcpPayload {
        self.payload
    }
}

#[derive(Serialize)]
struct FrozenToolCall {
    arguments: BTreeMap<String, Value>,
    headers: BTreeMap<String, String>,
    grant_requirements: Vec<HeaderGrantRequirement>,
}

/// Takes a fully resolved schema. Unresolved compositions fail closed rather
/// than letting a hidden x-mcp-header escape the frozen consent buffer.
pub fn prepare_tool_call(
    schema: &Value,
    arguments: &Value,
    destructive_hint: bool,
    mutation: MutationIntent,
) -> Result<PreparedToolCall> {
    reject_unresolved(schema)?;
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(invalid_schema)?;
    let args = arguments.as_object().ok_or_else(invalid_schema)?;
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
    if destructive_hint {
        body.insert("dry_run".into(), Value::Bool(preview));
    }
    let frozen = FrozenToolCall {
        arguments: body,
        headers,
        grant_requirements: requirements.clone(),
    };
    let bytes = serde_json::to_vec(&frozen).map_err(|_| invalid_schema())?;
    Ok(PreparedToolCall {
        payload: FrozenMcpPayload::new(bytes),
        requirements,
        preview,
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
    #[test]
    fn headers_have_their_own_frozen_grant_class_and_destructive_tools_preview() {
        let schema = json!({"type":"object","properties":{"tenant":{"type":"string","x-mcp-header":"X-Tenant"},"record":{"type":"string"}}});
        let mut args = json!({"tenant":"original","record":"r1","dry_run":false});
        let preview = prepare_tool_call(&schema, &args, true, MutationIntent::Preview).unwrap();
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
        let mutation =
            prepare_tool_call(&schema, &args, true, MutationIntent::ExplicitMutation).unwrap();
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
                prepare_tool_call(
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
            prepare_tool_call(
                &schema,
                &json!({"x":"one\r\nHost: bad"}),
                false,
                MutationIntent::Preview
            )
            .is_err()
        );
    }
}
