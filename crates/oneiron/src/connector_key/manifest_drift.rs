//! Resolved connector-schema snapshots and conservative, typed drift classification.
//! A changed resolved schema is never treated as an unchanged grant, even when
//! the literal document differs only in its reference target.
use super::slate::ELICITATION_ROW_KEY;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[doc(hidden)]
pub use oneiron_records::connector_key::manifest_drift::{ConnectorDriftKind, ConnectorToolSchema};
#[doc(hidden)]
use oneiron_records::connector_key::manifest_drift::{
    defaults, intersect_enums, intersect_types, invalid, merge_all_of, resolve_schema, tightest,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedConnectorManifest {
    tools: Vec<ConnectorToolSchema>,
    /// The connector's elicitation declaration (ARCH-0072). Elicitation is
    /// a client capability no server lists, so no tool listing proves or
    /// refutes it: MCP admission declares it for every connector it admits.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    elicitation: bool,
}
impl ResolvedConnectorManifest {
    /// Resolve local references and composition before any comparison or
    /// consent-visible use. Unsupported or cyclic references refuse admission;
    /// how many tools, permissions or triggers it declares never does (FIX
    /// 8684): admission measures those counts ([`Self::admission_counts`]).
    pub fn resolve(mut tools: Vec<ConnectorToolSchema>) -> Result<Self> {
        if tools.is_empty() {
            return Err(invalid());
        }
        for tool in &mut tools {
            if tool.name.trim().is_empty()
                || tool.name.len() > 256
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
        Ok(Self {
            tools,
            elicitation: false,
        })
    }
    /// The same snapshot, declaring elicitation or not.
    #[must_use]
    pub fn with_elicitation(mut self, declared: bool) -> Self {
        self.elicitation = declared;
        self
    }
    pub fn declares_elicitation(&self) -> bool {
        self.elicitation
    }
    /// Each counted collection of the manifest beside the vault policy's
    /// quota for it, as `(quota, measured)`: its tools, and the most
    /// permissions and the most triggers one tool declares. The quotas are
    /// work thresholds, never refusals (FIX 8758): admission measures them
    /// and serves the whole manifest. Persisted-body validation never reads
    /// them, so later policy tightening cannot make an admitted key
    /// unreadable.
    pub(crate) fn admission_counts(
        &self,
        quotas: crate::gate::ConnectorAdmissionQuotas,
    ) -> [(u64, u64); 3] {
        let count = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        let most = |of: fn(&ConnectorToolSchema) -> usize| {
            count(self.tools.iter().map(of).max().unwrap_or(0))
        };
        [
            (count(quotas.max_tools), count(self.tools.len())),
            (
                count(quotas.max_permissions_per_tool),
                most(|tool| tool.permissions.len()),
            ),
            (
                count(quotas.max_triggers_per_tool),
                most(|tool| tool.triggers.len()),
            ),
        ]
    }
    pub fn tools(&self) -> &[ConnectorToolSchema] {
        &self.tools
    }
    /// Digest of the canonical, fully resolved consent-visible tool set and
    /// elicitation declaration.
    pub fn hash(&self) -> Result<[u8; 32]> {
        self.validate_snapshot()?;
        Ok(*blake3::hash(&serde_json::to_vec(self).map_err(|_| invalid())?).as_bytes())
    }
    pub(crate) fn validate_snapshot(&self) -> Result<()> {
        let resolved = Self::resolve(self.tools.clone())?.with_elicitation(self.elicitation);
        if resolved != *self {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorManifestDrift {
    /// All detected changes, including narrows and removals.
    pub kinds: BTreeSet<ConnectorDriftKind>,
    /// Rows held during qualification, by row key (a tool name, or
    /// [`ELICITATION_ROW_KEY`]); a removed row also belongs here.
    pub affected_tools: BTreeSet<String>,
    /// Only widening or otherwise non-monotone rows need a new owner tap:
    /// a new elicitation declaration does, its removal does not.
    pub reconsent_tools: BTreeSet<String>,
    /// Revision changes need re-registration, independently of tool deltas.
    pub requires_reregistration: bool,
}
impl ConnectorManifestDrift {
    pub fn first_registration(manifest: &ResolvedConnectorManifest) -> Self {
        let mut tools: BTreeSet<_> = manifest.tools().iter().map(|t| t.name.clone()).collect();
        if manifest.elicitation {
            tools.insert(ELICITATION_ROW_KEY.to_owned());
        }
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
        if old.elicitation != new.elicitation {
            kinds.insert(ConnectorDriftKind::Permission);
            affected_tools.insert(ELICITATION_ROW_KEY.to_owned());
            if new.elicitation {
                reconsent_tools.insert(ELICITATION_ROW_KEY.to_owned());
            }
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
                // A provable restriction carries its consent, as the slate
                // judges one (FIX 2604); anything else re-asks its row.
                if !super::slate::schema_narrows(Some(&a.input_schema), Some(&b.input_schema)) {
                    reconsent_tools.insert(name.clone());
                }
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
