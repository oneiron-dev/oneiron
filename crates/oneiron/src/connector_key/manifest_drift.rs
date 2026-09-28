//! Resolved connector-schema snapshots and conservative, typed drift classification.
//! A changed resolved schema is never treated as an unchanged grant, even when
//! the literal document differs only in its reference target.
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

fn invalid() -> Error {
    Error::InvalidConfig("invalid resolved connector manifest".to_owned())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorToolSchema {
    pub name: String,
    pub permissions: BTreeSet<String>,
    pub triggers: BTreeSet<String>,
    pub input_schema: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedConnectorManifest {
    tools: Vec<ConnectorToolSchema>,
}
impl ResolvedConnectorManifest {
    /// Resolve local references and composition before any comparison or
    /// consent-visible use. Unsupported or cyclic references refuse admission.
    pub fn resolve(mut tools: Vec<ConnectorToolSchema>) -> Result<Self> {
        if tools.is_empty() || tools.len() > 4096 {
            return Err(invalid());
        }
        for tool in &mut tools {
            if tool.name.trim().is_empty()
                || tool.name.len() > 256
                || tool.permissions.len() > 4096
                || tool.triggers.len() > 4096
                || tool
                    .permissions
                    .iter()
                    .chain(&tool.triggers)
                    .any(|v| v.trim().is_empty() || v.len() > 256)
            {
                return Err(invalid());
            }
            if serde_json::to_vec(&tool.input_schema)
                .map_err(|_| invalid())?
                .len()
                > 65_536
            {
                return Err(invalid());
            }
            tool.input_schema =
                resolve_schema(&tool.input_schema, &tool.input_schema, &mut Vec::new(), 0)?;
        }
        tools.sort_by(|a, b| a.name.cmp(&b.name));
        if tools.windows(2).any(|w| w[0].name == w[1].name) {
            return Err(invalid());
        }
        Ok(Self { tools })
    }
    /// Mutable admission capacity comes from a vault policy snapshot. It is
    /// deliberately NOT used by persisted-body validation: later policy
    /// tightening cannot make an already admitted key unreadable.
    pub(crate) fn validate_admission(
        &self,
        quotas: crate::gate::ConnectorAdmissionQuotas,
    ) -> Result<()> {
        if self.tools.len() > quotas.max_tools
            || self.tools.iter().any(|tool| {
                tool.permissions.len() > quotas.max_permissions_per_tool
                    || tool.triggers.len() > quotas.max_triggers_per_tool
            })
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn tools(&self) -> &[ConnectorToolSchema] {
        &self.tools
    }
    /// Digest of the canonical, fully resolved consent-visible tool set.
    pub fn hash(&self) -> Result<[u8; 32]> {
        self.validate_snapshot()?;
        Ok(*blake3::hash(&serde_json::to_vec(self).map_err(|_| invalid())?).as_bytes())
    }
    pub(crate) fn validate_snapshot(&self) -> Result<()> {
        let resolved = Self::resolve(self.tools.clone())?;
        if resolved != *self {
            return Err(invalid());
        }
        Ok(())
    }
}

fn resolve_schema(
    node: &Value,
    root: &Value,
    stack: &mut Vec<String>,
    depth: usize,
) -> Result<Value> {
    if depth > 24 {
        return Err(invalid());
    }
    let Some(obj) = node.as_object() else {
        return if node.is_boolean() {
            Ok(node.clone())
        } else {
            Err(invalid())
        };
    };
    if let Some(reference) = obj.get("$ref") {
        if obj.len() != 1 {
            return Err(invalid());
        }
        let reference = reference.as_str().ok_or_else(invalid)?;
        if !reference.starts_with("#/") || stack.iter().any(|s| s == reference) {
            return Err(invalid());
        }
        let target = root.pointer(&reference[1..]).ok_or_else(invalid)?;
        stack.push(reference.to_owned());
        let result = resolve_schema(target, root, stack, depth + 1);
        stack.pop();
        return result;
    }
    let mut result = serde_json::Map::new();
    let mut all_of = None;
    for (key, value) in obj {
        match key.as_str() {
            "$defs" | "definitions" => {}
            "properties" => {
                let properties = value.as_object().ok_or_else(invalid)?;
                let mut out = serde_json::Map::new();
                for (name, child) in properties {
                    out.insert(name.clone(), resolve_schema(child, root, stack, depth + 1)?);
                }
                result.insert(key.clone(), Value::Object(out));
            }
            "items" | "additionalProperties" => {
                result.insert(key.clone(), resolve_schema(value, root, stack, depth + 1)?);
            }
            "allOf" => {
                let variants = value
                    .as_array()
                    .filter(|a| !a.is_empty() && a.len() <= 64)
                    .ok_or_else(invalid)?;
                let mut out = Vec::with_capacity(variants.len());
                for variant in variants {
                    out.push(resolve_schema(variant, root, stack, depth + 1)?);
                }
                all_of = Some(out);
            }
            // The current call validator does not implement union validation.
            // Keeping these keywords would make a resolved schema unusable;
            // dropping them would broaden it, so refuse them at admission.
            "anyOf" | "oneOf" => return Err(invalid()),
            "type" | "required" | "enum" | "const" | "title" | "description" | "default"
            | "examples" | "$schema" | "$id" | "deprecated" | "readOnly" | "writeOnly"
            | "x-mcp-header" => {
                result.insert(key.clone(), value.clone());
            }
            // Unknown schema-bearing keywords (for example `if` or
            // `dependentSchemas`) can hide refs. Reject, never strip them.
            _ => return Err(invalid()),
        }
    }
    let resolved = if let Some(variants) = all_of {
        let mut conjuncts = Vec::with_capacity(variants.len() + 1);
        conjuncts.push(Value::Object(result));
        conjuncts.extend(variants);
        merge_all_of(&conjuncts)?
    } else {
        Value::Object(result)
    };
    if serde_json::to_vec(&resolved).map_err(|_| invalid())?.len() > 65_536 {
        return Err(invalid());
    }
    Ok(resolved)
}

/// Compile a supported JSON Schema conjunction into the subset consumed by
/// `prepare_tool_call`. `additionalProperties` is deliberately refused when
/// multiple schemas are combined: its property-name scope is local to each
/// conjunct, and merging property declarations can otherwise widen it.
fn merge_all_of(schemas: &[Value]) -> Result<Value> {
    let mut objects = Vec::new();
    for schema in schemas {
        match schema {
            Value::Bool(false) => return Ok(Value::Bool(false)),
            Value::Bool(true) => {}
            Value::Object(object) => objects.push(object),
            _ => return Err(invalid()),
        }
    }
    objects.retain(|object| !object.is_empty());
    if objects.is_empty() {
        return Ok(Value::Object(serde_json::Map::new()));
    }
    if objects.len() == 1 {
        return Ok(Value::Object((*objects[0]).clone()));
    }
    if objects
        .iter()
        .any(|object| object.contains_key("additionalProperties"))
    {
        return Err(invalid());
    }

    let mut keys = BTreeSet::new();
    for object in &objects {
        keys.extend(object.keys().cloned());
    }
    let mut merged = serde_json::Map::new();
    for key in keys {
        let values: Vec<&Value> = objects
            .iter()
            .filter_map(|object| object.get(&key))
            .collect();
        match key.as_str() {
            "type" => match intersect_types(&values)? {
                Some(kind) => {
                    merged.insert(key, kind);
                }
                None => return Ok(Value::Bool(false)),
            },
            "required" => {
                let mut required = BTreeSet::new();
                for value in values {
                    for name in value.as_array().ok_or_else(invalid)? {
                        required.insert(name.as_str().ok_or_else(invalid)?.to_owned());
                    }
                }
                merged.insert(
                    key,
                    Value::Array(required.into_iter().map(Value::String).collect()),
                );
            }
            "properties" => {
                let mut properties: BTreeMap<String, Vec<Value>> = BTreeMap::new();
                for value in values {
                    for (name, schema) in value.as_object().ok_or_else(invalid)? {
                        properties
                            .entry(name.clone())
                            .or_default()
                            .push(schema.clone());
                    }
                }
                let mut result = serde_json::Map::new();
                for (name, schemas) in properties {
                    result.insert(name, merge_all_of(&schemas)?);
                }
                merged.insert(key, Value::Object(result));
            }
            "items" => {
                let schemas: Vec<Value> = values.into_iter().cloned().collect();
                merged.insert(key, merge_all_of(&schemas)?);
            }
            "enum" => match intersect_enums(&values)? {
                Some(options) => {
                    merged.insert(key, Value::Array(options));
                }
                None => return Ok(Value::Bool(false)),
            },
            "const" => {
                let first = values[0];
                if values.iter().any(|value| *value != first) {
                    return Ok(Value::Bool(false));
                }
                merged.insert(key, first.clone());
            }
            "title" | "description" | "default" | "examples" | "$schema" | "$id" | "deprecated"
            | "readOnly" | "writeOnly" | "x-mcp-header" => {
                let first = values[0];
                if values.iter().any(|value| *value != first) {
                    // Annotations can affect defaults and header extraction at
                    // consent time, so do not choose one branch arbitrarily.
                    return Err(invalid());
                }
                merged.insert(key, first.clone());
            }
            // This also guards future keyword additions from silently being
            // copied through a composition path with unknown semantics.
            _ => return Err(invalid()),
        }
    }
    if let (Some(options), Some(constant)) = (merged.get("enum"), merged.get("const"))
        && !options.as_array().ok_or_else(invalid)?.contains(constant)
    {
        return Ok(Value::Bool(false));
    }
    Ok(Value::Object(merged))
}

/// JSON Schema's `integer` is a subset of `number`; model integer and
/// non-integer numbers separately so conjunctions do not broaden constraints.
fn intersect_types(values: &[&Value]) -> Result<Option<Value>> {
    let mut accepted: Option<BTreeSet<&'static str>> = None;
    for value in values {
        let types: Vec<&str> = if let Some(kind) = value.as_str() {
            vec![kind]
        } else {
            value
                .as_array()
                .filter(|kinds| !kinds.is_empty())
                .ok_or_else(invalid)?
                .iter()
                .map(|kind| kind.as_str().ok_or_else(invalid))
                .collect::<Result<_>>()?
        };
        let mut current = BTreeSet::new();
        for kind in types {
            match kind {
                "null" => {
                    current.insert("null");
                }
                "boolean" => {
                    current.insert("boolean");
                }
                "string" => {
                    current.insert("string");
                }
                "object" => {
                    current.insert("object");
                }
                "array" => {
                    current.insert("array");
                }
                "integer" => {
                    current.insert("integer");
                }
                "number" => {
                    current.insert("integer");
                    current.insert("non_integer_number");
                }
                _ => return Err(invalid()),
            }
        }
        accepted = Some(match accepted {
            Some(previous) => previous.intersection(&current).copied().collect(),
            None => current,
        });
    }
    let accepted = accepted.ok_or_else(invalid)?;
    if accepted.is_empty() {
        return Ok(None);
    }
    let has_integer = accepted.contains("integer");
    let has_non_integer = accepted.contains("non_integer_number");
    if has_non_integer && !has_integer {
        // No supported JSON Schema type denotes only non-integer numbers.
        return Err(invalid());
    }
    let mut result = Vec::new();
    for kind in ["array", "boolean", "null", "object", "string"] {
        if accepted.contains(kind) {
            result.push(kind.to_owned());
        }
    }
    if has_integer && has_non_integer {
        result.push("number".to_owned());
    } else if has_integer {
        result.push("integer".to_owned());
    }
    result.sort();
    if result.len() == 1 {
        Ok(Some(Value::String(result.remove(0))))
    } else {
        Ok(Some(Value::Array(
            result.into_iter().map(Value::String).collect(),
        )))
    }
}

fn intersect_enums(values: &[&Value]) -> Result<Option<Vec<Value>>> {
    let mut intersection: Option<Vec<Value>> = None;
    for value in values {
        let options = value
            .as_array()
            .filter(|options| !options.is_empty())
            .ok_or_else(invalid)?;
        let mut normalized = options.clone();
        normalized.sort_by_key(std::string::ToString::to_string);
        normalized.dedup();
        intersection = Some(match intersection {
            Some(mut previous) => {
                previous.retain(|candidate| normalized.contains(candidate));
                previous
            }
            None => normalized,
        });
    }
    let intersection = intersection.ok_or_else(invalid)?;
    Ok((!intersection.is_empty()).then_some(intersection))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorDriftKind {
    Permission,
    Trigger,
    ParameterDefault,
    Schema,
    ProtocolRevision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorManifestDrift {
    /// All detected changes, including narrows and removals.
    pub kinds: BTreeSet<ConnectorDriftKind>,
    /// Rows held during qualification; a removed tool also belongs here.
    pub affected_tools: BTreeSet<String>,
    /// Only widening or otherwise non-monotone rows need a new owner tap.
    pub reconsent_tools: BTreeSet<String>,
    /// Revision changes need re-registration, independently of tool deltas.
    pub requires_reregistration: bool,
}
impl ConnectorManifestDrift {
    pub fn first_registration(manifest: &ResolvedConnectorManifest) -> Self {
        let tools: BTreeSet<_> = manifest.tools().iter().map(|t| t.name.clone()).collect();
        Self {
            kinds: [ConnectorDriftKind::Permission].into(),
            affected_tools: tools.clone(),
            reconsent_tools: tools,
            requires_reregistration: false,
        }
    }
    pub fn between(
        old: &ResolvedConnectorManifest,
        new: &ResolvedConnectorManifest,
        old_revision: &str,
        new_revision: &str,
    ) -> Self {
        let mut kinds = BTreeSet::new();
        let mut affected_tools = BTreeSet::new();
        let mut reconsent_tools = BTreeSet::new();
        if old_revision != new_revision {
            kinds.insert(ConnectorDriftKind::ProtocolRevision);
        }
        let before: BTreeMap<_, _> = old.tools().iter().map(|t| (t.name.as_str(), t)).collect();
        let after: BTreeMap<_, _> = new.tools().iter().map(|t| (t.name.as_str(), t)).collect();
        for name in before.keys().chain(after.keys()) {
            let name = (*name).to_owned();
            let (Some(a), Some(b)) = (before.get(name.as_str()), after.get(name.as_str())) else {
                kinds.insert(ConnectorDriftKind::Permission);
                affected_tools.insert(name.clone());
                if !before.contains_key(name.as_str()) {
                    reconsent_tools.insert(name);
                }
                continue;
            };
            if a.permissions != b.permissions {
                kinds.insert(ConnectorDriftKind::Permission);
                // A strict subset narrows authority and carries forward. A
                // replacement or added permission can widen; re-ask its row.
                if !b.permissions.is_subset(&a.permissions) {
                    reconsent_tools.insert(name.clone());
                }
            }
            if a.triggers != b.triggers {
                kinds.insert(ConnectorDriftKind::Trigger);
                reconsent_tools.insert(name.clone());
            }
            if defaults(&a.input_schema) != defaults(&b.input_schema) {
                kinds.insert(ConnectorDriftKind::ParameterDefault);
                reconsent_tools.insert(name.clone());
            }
            if a.input_schema != b.input_schema {
                kinds.insert(ConnectorDriftKind::Schema);
                reconsent_tools.insert(name.clone());
            }
            if a != b {
                affected_tools.insert(name);
            }
        }
        Self {
            requires_reregistration: old_revision != new_revision,
            kinds,
            affected_tools,
            reconsent_tools,
        }
    }
    pub fn has_change(&self) -> bool {
        !self.kinds.is_empty()
    }
    pub fn needs_reconsent(&self) -> bool {
        self.requires_reregistration || !self.reconsent_tools.is_empty()
    }
}

fn defaults(value: &Value) -> Vec<(String, Value)> {
    fn visit(value: &Value, path: &str, out: &mut Vec<(String, Value)>) {
        if let Some(object) = value.as_object() {
            if let Some(default) = object.get("default") {
                out.push((path.to_owned(), default.clone()));
            }
            for (key, child) in object {
                if key != "default" {
                    visit(child, &format!("{path}/{key}"), out);
                }
            }
        } else if let Some(array) = value.as_array() {
            for (index, child) in array.iter().enumerate() {
                visit(child, &format!("{path}/{index}"), out);
            }
        }
    }
    let mut result = Vec::new();
    visit(value, "", &mut result);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn manifest(schema: Value, permission: &str, trigger: &str) -> ResolvedConnectorManifest {
        ResolvedConnectorManifest::resolve(vec![ConnectorToolSchema {
            name: "send".into(),
            permissions: [permission.into()].into(),
            triggers: [trigger.into()].into(),
            input_schema: schema,
        }])
        .unwrap()
    }
    #[test]
    fn resolved_ref_swap_and_every_typed_change_reconsent() {
        let old = manifest(
            json!({"$defs":{"argument":{"type":"string","default":"safe"}},"properties":{"arg":{"$ref":"#/$defs/argument"}}}),
            "read",
            "manual",
        );
        let swapped = manifest(
            json!({"$defs":{"argument":{"type":"string","default":"unsafe"}},"properties":{"arg":{"$ref":"#/$defs/argument"}}}),
            "read",
            "manual",
        );
        let diff = ConnectorManifestDrift::between(&old, &swapped, "2026-07-28", "2026-07-28");
        assert!(diff.kinds.contains(&ConnectorDriftKind::ParameterDefault));
        assert!(diff.affected_tools.contains("send"));
        assert!(
            ConnectorManifestDrift::between(
                &old,
                &manifest(old.tools()[0].input_schema.clone(), "write", "manual"),
                "r1",
                "r1"
            )
            .kinds
            .contains(&ConnectorDriftKind::Permission)
        );
        assert!(
            ConnectorManifestDrift::between(
                &old,
                &manifest(old.tools()[0].input_schema.clone(), "read", "timer"),
                "r1",
                "r1"
            )
            .kinds
            .contains(&ConnectorDriftKind::Trigger)
        );
        let revision = ConnectorManifestDrift::between(&old, &old, "r1", "r2");
        assert!(revision.requires_reregistration && revision.needs_reconsent());
        assert!(ResolvedConnectorManifest::resolve(vec![ConnectorToolSchema { name:"send".into(), permissions: BTreeSet::new(), triggers: BTreeSet::new(), input_schema:json!({"$ref":"#/$defs/loop","$defs":{"loop":{"$ref":"#/$defs/loop"}}}) }]).is_err());
        assert!(ResolvedConnectorManifest::resolve(vec![ConnectorToolSchema { name:"send".into(), permissions: BTreeSet::new(), triggers: BTreeSet::new(), input_schema:json!({"if":{"properties":{"secret":{"$ref":"#/$defs/power"}}}, "$defs":{"power":{"type":"string"}}}) }]).is_err());
    }

    fn prepare_resolved(
        schema: &Value,
        arguments: &Value,
    ) -> crate::Result<crate::outbound_consent::tool_call::PreparedToolCall> {
        use crate::outbound_consent::tool_call::{
            MutationIntent, ToolCallDescriptor, prepare_tool_call,
        };
        prepare_tool_call(
            crate::outbound_consent::ScopedMcpCallContext {
                server: "connector".into(),
                tool: "send".into(),
                payload_data_class: crate::outbound_consent::DataClass::Personal,
                resolved_endpoint: "https://connector.example".into(),
            },
            ToolCallDescriptor {
                schema,
                destructive_hint: false,
                replay: crate::outbound_intent_ledger::OutboundToolDescriptor {
                    read_only_hint: Some(true),
                    idempotency_supported_hint: Some(true),
                },
            },
            arguments,
            MutationIntent::Preview,
        )
    }

    #[test]
    fn all_of_refs_resolve_to_a_schema_accepted_by_prepare_tool_call() {
        let resolved = manifest(
            json!({
                "$defs": {"name": {"type":"string", "enum":["alpha", "beta"]}},
                "type":"object",
                "allOf":[
                    {"properties":{"recipient":{"$ref":"#/$defs/name"}}},
                    {"required":["recipient"], "properties":{"recipient":{"enum":["beta", "gamma"]}}}
                ]
            }),
            "send",
            "manual",
        );
        let schema = &resolved.tools()[0].input_schema;
        assert!(schema.get("allOf").is_none());
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["required"], json!(["recipient"]));
        assert_eq!(schema["properties"]["recipient"]["type"], "string");
        assert_eq!(schema["properties"]["recipient"]["enum"], json!(["beta"]));

        let prepared = prepare_resolved(schema, &json!({"recipient":"beta"})).unwrap();
        let frozen: Value = serde_json::from_slice(prepared.frozen_bytes()).unwrap();
        assert_eq!(frozen["arguments"], json!({"recipient":"beta"}));
        assert!(prepare_resolved(schema, &json!({"recipient":"alpha"})).is_err());
        assert!(prepare_resolved(schema, &json!({})).is_err());
    }

    #[test]
    fn all_of_ref_target_swap_is_visible_to_drift_classification() {
        let schema = |default: &str| {
            json!({
                "$defs":{"argument":{"type":"string", "default":default}},
                "type":"object",
                "allOf":[
                    {"properties":{"arg":{"$ref":"#/$defs/argument"}}},
                    {"required":["arg"]}
                ]
            })
        };
        let old = manifest(schema("safe"), "send", "manual");
        let swapped = manifest(schema("unsafe"), "send", "manual");
        assert!(old.tools()[0].input_schema.get("allOf").is_none());
        let drift = ConnectorManifestDrift::between(&old, &swapped, "r1", "r1");
        assert!(drift.kinds.contains(&ConnectorDriftKind::ParameterDefault));
        assert!(drift.kinds.contains(&ConnectorDriftKind::Schema));
        assert!(drift.affected_tools.contains("send"));
    }

    #[test]
    fn unsupported_union_or_unsafe_additional_properties_composition_is_rejected() {
        for schema in [
            json!({"type":"object", "properties":{"value":{"anyOf":[{"type":"string"},{"type":"integer"}]}}}),
            json!({"oneOf":[{"type":"string"},{"type":"integer"}]}),
            json!({
                "type":"object",
                "properties":{"known":{"type":"string"}},
                "additionalProperties":false,
                "allOf":[{"properties":{"other":{"type":"string"}}}]
            }),
        ] {
            assert!(
                ResolvedConnectorManifest::resolve(vec![ConnectorToolSchema {
                    name: "send".into(),
                    permissions: BTreeSet::new(),
                    triggers: BTreeSet::new(),
                    input_schema: schema,
                }])
                .is_err()
            );
        }
    }
}
