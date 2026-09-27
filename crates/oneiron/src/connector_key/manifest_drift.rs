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
        if tools.is_empty() || tools.len() > 256 {
            return Err(invalid());
        }
        for tool in &mut tools {
            if tool.name.trim().is_empty()
                || tool.name.len() > 256
                || tool.permissions.len() > 128
                || tool.triggers.len() > 128
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
            "allOf" | "anyOf" | "oneOf" => {
                let variants = value
                    .as_array()
                    .filter(|a| !a.is_empty() && a.len() <= 64)
                    .ok_or_else(invalid)?;
                let mut out = Vec::new();
                for variant in variants {
                    out.push(resolve_schema(variant, root, stack, depth + 1)?);
                }
                // Keep union alternatives explicit: collapsing them into one
                // permissive object would erase a permission boundary.
                result.insert(key.clone(), Value::Array(out));
            }
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
    let bytes = serde_json::to_vec(&result).map_err(|_| invalid())?;
    if bytes.len() > 65_536 {
        return Err(invalid());
    }
    Ok(Value::Object(result))
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
    pub kinds: BTreeSet<ConnectorDriftKind>,
    pub affected_tools: BTreeSet<String>,
    /// Revision changes need re-registration; ordinary drift re-asks only
    /// affected rows and leaves unrelated rows available.
    pub requires_reregistration: bool,
}
impl ConnectorManifestDrift {
    pub fn first_registration(manifest: &ResolvedConnectorManifest) -> Self {
        Self {
            kinds: [ConnectorDriftKind::Permission].into(),
            affected_tools: manifest.tools().iter().map(|t| t.name.clone()).collect(),
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
        if old_revision != new_revision {
            kinds.insert(ConnectorDriftKind::ProtocolRevision);
        }
        let before: BTreeMap<_, _> = old.tools().iter().map(|t| (t.name.as_str(), t)).collect();
        let after: BTreeMap<_, _> = new.tools().iter().map(|t| (t.name.as_str(), t)).collect();
        for name in before.keys().chain(after.keys()) {
            let (Some(a), Some(b)) = (before.get(name), after.get(name)) else {
                kinds.insert(ConnectorDriftKind::Permission);
                affected_tools.insert((*name).to_owned());
                continue;
            };
            if a.permissions != b.permissions {
                kinds.insert(ConnectorDriftKind::Permission);
            }
            if a.triggers != b.triggers {
                kinds.insert(ConnectorDriftKind::Trigger);
            }
            if defaults(&a.input_schema) != defaults(&b.input_schema) {
                kinds.insert(ConnectorDriftKind::ParameterDefault);
            }
            if a.input_schema != b.input_schema {
                kinds.insert(ConnectorDriftKind::Schema);
            }
            if a != b {
                affected_tools.insert((*name).to_owned());
            }
        }
        Self {
            requires_reregistration: old_revision != new_revision,
            kinds,
            affected_tools,
        }
    }
    pub fn needs_reconsent(&self) -> bool {
        !self.kinds.is_empty()
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
}
