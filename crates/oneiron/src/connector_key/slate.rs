//! ARCH-0072 typed per-tool grant slates. The drafter's floor is not an
//! owner restriction: only an authenticated owner can set override columns.
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::side_table::{self, LegacyJson, Raw, SideTable};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const GRANT_SLATE: SideTable<EntityId, ConnectorGrantSlate, LegacyJson> =
    SideTable::new(&side_table::CONNECTOR_GRANT_SLATE);
/// The one connector key a stamped slate admits. Key: slate id.
const SLATE_BINDING: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::CONNECTOR_GRANT_SLATE_BINDING);

fn invalid() -> Error {
    Error::InvalidConfig("invalid typed connector grant slate".to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlateDisposition {
    Auto,
    ConfirmFirst,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlateDataClass {
    Public,
    Personal,
    Secret,
    Header,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlateToolManifest {
    pub name: String,
    pub data_class: SlateDataClass,
    pub header_parameters: Vec<String>,
    /// Host-resolved input declaration, including defaults and constraints.
    /// Unresolved refs/composition are refused rather than guessed at admission.
    #[serde(default)]
    pub resolved_input_schema: Option<serde_json::Value>,
    #[serde(default)]
    pub trigger: Option<String>,
    pub destroys: bool,
    pub spends: bool,
    pub sends_outward: bool,
    pub legacy_ask: bool,
}
impl SlateToolManifest {
    fn floor(&self) -> bool {
        self.destroys
            || self.spends
            || self.sends_outward
            || !self.header_parameters.is_empty()
            || self.data_class == SlateDataClass::Header
            || self.legacy_ask
    }
}

/// The only model-output shape admitted. Owner overrides are deliberately not
/// fields of this type; serde rejects them rather than trusting a model stamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlateDraftRow {
    pub tool: String,
    pub disposition: SlateDisposition,
    pub data_class: SlateDataClass,
    pub rationale: String,
    pub enabled: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlateOwnerOverride {
    pub disposition: SlateDisposition,
    pub enabled: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlateRow {
    pub draft: SlateDraftRow,
    pub owner_override: Option<SlateOwnerOverride>,
}
impl SlateRow {
    pub fn effective_disposition(&self) -> SlateDisposition {
        self.owner_override
            .as_ref()
            .map_or(self.draft.disposition, |o| o.disposition)
    }
    pub fn enabled(&self) -> bool {
        self.owner_override
            .as_ref()
            .map_or(self.draft.enabled, |o| o.enabled)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorGrantSlate {
    manifest: Vec<SlateToolManifest>,
    rows: Vec<SlateRow>,
    manifest_hash: [u8; 32],
    revision: u64,
    owner_actor: Option<String>,
    owner_authentication: Option<String>,
}
impl ConnectorGrantSlate {
    pub fn rows(&self) -> &[SlateRow] {
        &self.rows
    }
    pub(in crate::connector_key) fn resolved_schemas(
        &self,
    ) -> Option<BTreeMap<String, (serde_json::Value, Option<String>)>> {
        self.manifest
            .iter()
            .map(|tool| {
                Some((
                    tool.name.clone(),
                    (tool.resolved_input_schema.clone()?, tool.trigger.clone()),
                ))
            })
            .collect()
    }
    pub fn tool_names(&self) -> BTreeSet<&str> {
        self.manifest
            .iter()
            .map(|tool| tool.name.as_str())
            .collect()
    }
    pub fn manifest_hash(&self) -> [u8; 32] {
        self.manifest_hash
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn owner_actor(&self) -> Option<&str> {
        self.owner_actor.as_deref()
    }
}

/// Draft deterministic defaults, suitable as the typed input for a host model.
/// The model may rewrite rationale/disposition only within the floor.
pub fn draft_connector_slate(manifest: &[SlateToolManifest]) -> Vec<SlateDraftRow> {
    manifest
        .iter()
        .map(|tool| SlateDraftRow {
            tool: tool.name.clone(),
            disposition: if tool.floor() {
                SlateDisposition::ConfirmFirst
            } else {
                SlateDisposition::Auto
            },
            data_class: if tool.header_parameters.is_empty() {
                tool.data_class
            } else {
                SlateDataClass::Header
            },
            rationale: if tool.floor() {
                "external-effect-or-header"
            } else {
                "scoped-read"
            }
            .to_owned(),
            enabled: !tool.legacy_ask,
        })
        .collect()
}

fn validate(manifest: &[SlateToolManifest], rows: &[SlateDraftRow]) -> Result<()> {
    if manifest.is_empty() || manifest.len() != rows.len() || manifest.len() > 4096 {
        return Err(invalid());
    }
    let tools: BTreeMap<_, _> = manifest
        .iter()
        .map(|tool| (tool.name.as_str(), tool))
        .collect();
    if tools.len() != manifest.len() || manifest.iter().any(|tool| tool.name.trim().is_empty()) {
        return Err(invalid());
    }
    let mut seen = BTreeSet::new();
    for row in rows {
        let tool = tools.get(row.tool.as_str()).ok_or_else(invalid)?;
        if !seen.insert(&row.tool)
            || row.rationale.trim().is_empty()
            || row.rationale.len() > 4096
            || tool.floor() && row.disposition != SlateDisposition::ConfirmFirst
            || tool.legacy_ask && row.enabled
            || !tool
                .resolved_input_schema
                .as_ref()
                .is_some_and(|schema| schema.is_object() && is_resolved_schema(schema))
            || row.data_class
                != if tool.header_parameters.is_empty() {
                    tool.data_class
                } else {
                    SlateDataClass::Header
                }
        {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Compare the fully typed grant declaration and the effective owner-approved
/// dispositions. Unchanged or reduced authority carries its earlier consent;
/// new tools, richer declarations and any enabled/auto expansion need a tap.
pub(in crate::connector_key) fn slate_expands(
    old: &ConnectorGrantSlate,
    next: &ConnectorGrantSlate,
    carry: &BTreeSet<(String, String)>,
) -> bool {
    next.manifest.iter().any(|tool| {
        let row = next
            .rows
            .iter()
            .find(|row| row.draft.tool == tool.name)
            .expect("validated slate has one row per tool");
        if !row.enabled() {
            return false;
        }
        let Some(old_tool) = old.manifest.iter().find(|prior| prior.name == tool.name) else {
            return true;
        };
        let old_row = old
            .rows
            .iter()
            .find(|row| row.draft.tool == tool.name)
            .expect("validated slate has one row per tool");
        !old_row.enabled()
            || tool.data_class != old_tool.data_class
                && !carry.contains(&(
                    tool.data_class.as_str().into(),
                    old_tool.data_class.as_str().into(),
                ))
            || tool
                .header_parameters
                .iter()
                .any(|param| !old_tool.header_parameters.contains(param))
            || tool.destroys && !old_tool.destroys
            || tool.spends && !old_tool.spends
            || tool.sends_outward && !old_tool.sends_outward
            || tool.legacy_ask && !old_tool.legacy_ask
            || tool.trigger != old_tool.trigger
            || !schema_narrows(
                old_tool.resolved_input_schema.as_ref(),
                tool.resolved_input_schema.as_ref(),
            )
            || row.effective_disposition() == SlateDisposition::Auto
                && old_row.effective_disposition() == SlateDisposition::ConfirmFirst
    })
}

impl SlateDataClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Personal => "personal",
            Self::Secret => "secret",
            Self::Header => "header",
        }
    }
}

/// Only a provable restriction carries consent. Anything unknown re-asks.
fn schema_narrows(old: Option<&serde_json::Value>, next: Option<&serde_json::Value>) -> bool {
    let (Some(old), Some(next)) = (old, next) else {
        return old == next;
    };
    if old == next {
        return true;
    }
    let (Some(a), Some(b)) = (old.as_object(), next.as_object()) else {
        return false;
    };
    if a.get("type") != b.get("type") || a.get("default") != b.get("default") {
        return false;
    }
    if a.get("additionalProperties") != b.get("additionalProperties") {
        return false;
    }
    let (Some(ap), Some(bp)) = (
        a.get("properties").and_then(|v| v.as_object()),
        b.get("properties").and_then(|v| v.as_object()),
    ) else {
        return false;
    };
    if bp.keys().collect::<BTreeSet<_>>() != ap.keys().collect::<BTreeSet<_>>() {
        return false;
    }
    let required = |obj: &serde_json::Map<String, serde_json::Value>| -> Option<BTreeSet<String>> {
        obj.get("required")
            .map_or(Some(&[][..]), |v| v.as_array().map(Vec::as_slice))?
            .iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect::<Option<BTreeSet<_>>>()
    };
    let (Some(ar), Some(br)) = (required(a), required(b)) else {
        return false;
    };
    if !ar.is_subset(&br) {
        return false;
    }
    if a.keys().any(|k| {
        !matches!(
            k.as_str(),
            "type" | "default" | "properties" | "required" | "additionalProperties"
        )
    }) || b.keys().any(|k| {
        !matches!(
            k.as_str(),
            "type" | "default" | "properties" | "required" | "additionalProperties"
        )
    }) {
        return false;
    }
    ap.iter().all(|(name, prior)| {
        let Some(current) = bp.get(name) else {
            return false;
        };
        if current == prior {
            return true;
        }
        let (Some(x), Some(y)) = (prior.as_object(), current.as_object()) else {
            return false;
        };
        if x.get("type") != y.get("type") || x.get("default") != y.get("default") {
            return false;
        }
        let (Some(xe), Some(ye)) = (
            x.get("enum").and_then(|v| v.as_array()),
            y.get("enum").and_then(|v| v.as_array()),
        ) else {
            return false;
        };
        x.keys()
            .all(|k| matches!(k.as_str(), "type" | "default" | "enum"))
            && y.keys()
                .all(|k| matches!(k.as_str(), "type" | "default" | "enum"))
            && ye.iter().all(|value| xe.contains(value))
    })
}

fn is_resolved_schema(value: &serde_json::Value) -> bool {
    let Some(schema) = value.as_object() else {
        return false;
    };
    if schema
        .keys()
        .any(|key| matches!(key.as_str(), "$ref" | "allOf" | "anyOf" | "oneOf"))
    {
        return false;
    }
    // Names under `properties` are caller-chosen parameter names, not schema
    // operators. Values in defaults/const/enums are instance data; never
    // interpret their object keys as `$ref` or composition keywords.
    for key in [
        "properties",
        "patternProperties",
        "$defs",
        "definitions",
        "dependentSchemas",
    ] {
        if let Some(value) = schema.get(key) {
            let Some(entries) = value.as_object() else {
                return false;
            };
            if !entries.values().all(is_resolved_schema) {
                return false;
            }
        }
    }
    for key in [
        "items",
        "additionalProperties",
        "unevaluatedProperties",
        "contains",
        "not",
        "if",
        "then",
        "else",
        "propertyNames",
    ] {
        if let Some(value) = schema.get(key) {
            if value.is_boolean() {
                continue;
            }
            if key == "items" && value.is_array() {
                if !value
                    .as_array()
                    .is_some_and(|items| items.iter().all(is_resolved_schema))
                {
                    return false;
                }
            } else if !is_resolved_schema(value) {
                return false;
            }
        }
    }
    true
}

/// A stamped slate is an admission for one connector, not a reusable grant.
/// Reserve its identity in the same transaction as the key registration.
pub(in crate::connector_key) fn bind_connector_slate_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    slate_id: EntityId,
    key_id: &EntityId,
) -> Result<()> {
    if read_connector_slate_in_txn(vault, txn, slate_id)?.is_none() {
        return Err(crate::connector_key::record::invalid_body(
            "slate_ref does not resolve",
        ));
    }
    if SLATE_BINDING.contains(&vault.store, txn, &slate_id)? {
        return Err(crate::connector_key::record::invalid_body(
            "slate already bound to a connector",
        ));
    }
    SLATE_BINDING.put(&vault.store, txn, &slate_id, key_id)
}

pub(crate) fn read_connector_slate_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<ConnectorGrantSlate>> {
    GRANT_SLATE.get(&vault.store, txn, &id)
}

impl Vault {
    /// Persists the typed admission artifact. Free text, partial rows, duplicate
    /// tools, and owner columns in the draft all fail before the first write.
    pub fn store_connector_slate(
        &self,
        manifest: &[SlateToolManifest],
        model_output: &str,
    ) -> Result<EntityId> {
        let rows: Vec<SlateDraftRow> = serde_json::from_str(model_output).map_err(|_| invalid())?;
        validate(manifest, &rows)?;
        let manifest_bytes = serde_json::to_vec(manifest).map_err(|_| invalid())?;
        let slate = ConnectorGrantSlate {
            manifest: manifest.to_vec(),
            manifest_hash: *blake3::hash(&manifest_bytes).as_bytes(),
            rows: rows
                .into_iter()
                .map(|draft| SlateRow {
                    draft,
                    owner_override: None,
                })
                .collect(),
            revision: 0,
            owner_actor: None,
            owner_authentication: None,
        };
        let id = EntityId::now();
        self.with_write_txn(|txn| {
            GRANT_SLATE.put(&self.store, txn, &id, &slate)?;
            Ok(id)
        })
    }
    pub fn connector_slate(&self, id: EntityId) -> Result<Option<ConnectorGrantSlate>> {
        let txn = self.store.env.read_txn()?;
        read_connector_slate_in_txn(self, &txn, id)
    }
    /// One authenticated stamp for the entire typed slate. This neither
    /// qualifies a connector nor activates its key: probes own that transition.
    pub fn override_connector_slate(
        &self,
        owner: &AuthenticatedOwner,
        id: EntityId,
        expected_revision: u64,
        overrides: &BTreeMap<String, SlateOwnerOverride>,
    ) -> Result<ConnectorGrantSlate> {
        self.with_write_txn(|txn| {
            crate::memory::verify_deletion_authority_in_txn(
                self,
                txn,
                owner.actor(),
                crate::edge::EdgeActorClass::Human,
            )
            .map_err(|_| Error::InvalidConfig("grant slate owner binding required".to_owned()))?;
            let mut slate = GRANT_SLATE
                .get(&self.store, txn, &id)?
                .ok_or(Error::EntityNotFound)?;
            if slate.revision != expected_revision {
                return Err(Error::ConcurrentWrite("connector slate revision"));
            }
            if overrides
                .keys()
                .any(|name| !slate.rows.iter().any(|row| &row.draft.tool == name))
            {
                return Err(invalid());
            }
            for row in &mut slate.rows {
                if let Some(value) = overrides.get(&row.draft.tool) {
                    row.owner_override = Some(value.clone());
                }
            }
            slate.revision = slate
                .revision
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("slate revision"))?;
            slate.owner_actor = Some(owner.actor().to_hex());
            slate.owner_authentication = Some(owner.decision_id().to_hex());
            GRANT_SLATE.put(&self.store, txn, &id, &slate)?;
            Ok(slate)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn typed_manifest_draft_floor_and_owner_override() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
        let mut manifest = Vec::new();
        for name in ["read", "send", "header", "legacy.ask"] {
            manifest.push(SlateToolManifest {
                name: name.into(),
                data_class: SlateDataClass::Personal,
                header_parameters: if name == "header" {
                    vec!["authorization".into()]
                } else {
                    vec![]
                },
                resolved_input_schema: Some(serde_json::json!({"type":"object"})),
                trigger: None,
                destroys: false,
                spends: false,
                sends_outward: name == "send",
                legacy_ask: name == "legacy.ask",
            });
        }
        let rows = draft_connector_slate(&manifest);
        assert_eq!(rows[0].disposition, SlateDisposition::Auto);
        assert_eq!(rows[2].data_class, SlateDataClass::Header);
        assert!(!rows[3].enabled);
        assert!(
            vault
                .store_connector_slate(&manifest, "approve all tools")
                .is_err()
        );
        let mut bad = rows.clone();
        bad[1].disposition = SlateDisposition::Auto;
        assert!(
            vault
                .store_connector_slate(&manifest, &serde_json::to_string(&bad).unwrap())
                .is_err()
        );
        let mut unresolved = manifest.clone();
        unresolved[0].resolved_input_schema =
            Some(serde_json::json!({"$ref":"#/definitions/hidden"}));
        assert!(
            vault
                .store_connector_slate(
                    &unresolved,
                    &serde_json::to_string(&draft_connector_slate(&unresolved)).unwrap()
                )
                .is_err()
        );
        let mut keyword_names = manifest.clone();
        keyword_names[0].resolved_input_schema = Some(serde_json::json!({
            "type":"object", "properties":{
                "oneOf":{"type":"string"}, "$ref":{"type":"string"},
                "allOf":{"type":"object","default":{"$ref":"ordinary data"}}
            }, "default":{"anyOf":"ordinary data"}
        }));
        assert!(
            vault
                .store_connector_slate(
                    &keyword_names,
                    &serde_json::to_string(&draft_connector_slate(&keyword_names)).unwrap()
                )
                .is_ok()
        );
        let mut missing = manifest.clone();
        missing[0].resolved_input_schema = None;
        assert!(
            vault
                .store_connector_slate(
                    &missing,
                    &serde_json::to_string(&draft_connector_slate(&missing)).unwrap()
                )
                .is_err()
        );
        let id = vault.store_connector_slate(&manifest, &serde_json::to_string(&rows).unwrap())?;
        let owner = EntityId::now();
        vault.put_entity(
            &owner,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )?;
        let auth = vault.authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            crate::store::GateDecisionId::from_bytes(*EntityId::now().as_bytes()),
        )?;
        let slate = vault.override_connector_slate(
            &auth,
            id,
            0,
            &[(
                "send".into(),
                SlateOwnerOverride {
                    disposition: SlateDisposition::Auto,
                    enabled: true,
                },
            )]
            .into(),
        )?;
        assert_eq!(
            slate.rows()[1].draft.disposition,
            SlateDisposition::ConfirmFirst
        );
        assert_eq!(
            slate.rows()[1].effective_disposition(),
            SlateDisposition::Auto
        );
        assert_eq!(vault.connector_slate(id)?, Some(slate));
        Ok(())
    }
}

#[cfg(test)]
mod revision_tests {
    use super::*;
    use serde_json::json;

    fn tool(name: &str) -> SlateToolManifest {
        SlateToolManifest {
            name: name.into(),
            data_class: SlateDataClass::Public,
            header_parameters: vec![],
            resolved_input_schema: Some(json!({"type":"object",
                "properties":{"query":{"type":"string","enum":["a","b"]}}})),
            trigger: None,
            destroys: false,
            spends: false,
            sends_outward: false,
            legacy_ask: false,
        }
    }
    fn slate(manifest: Vec<SlateToolManifest>, rows: Vec<SlateDraftRow>) -> ConnectorGrantSlate {
        validate(&manifest, &rows).expect("valid permuted slate");
        ConnectorGrantSlate {
            manifest,
            rows: rows
                .into_iter()
                .map(|draft| SlateRow {
                    draft,
                    owner_override: None,
                })
                .collect(),
            manifest_hash: [0; 32],
            revision: 0,
            owner_actor: None,
            owner_authentication: None,
        }
    }
    #[test]
    fn permutations_and_schema_defaults_are_checked_by_tool_identity() {
        let tools = vec![tool("A"), tool("B")];
        let mut old_rows = draft_connector_slate(&tools);
        old_rows[0].enabled = false;
        let old = slate(tools.clone(), old_rows);
        let mut next_rows = draft_connector_slate(&tools);
        next_rows[1].enabled = false;
        next_rows.reverse();
        let next = slate(tools.clone(), next_rows);
        assert!(
            slate_expands(&old, &next, &BTreeSet::new()),
            "A became enabled despite reordered rows"
        );
        let old = slate(tools.clone(), draft_connector_slate(&tools));
        let mut changed = tools.clone();
        changed[0].resolved_input_schema = Some(json!({"type":"object",
            "properties":{"query":{"type":"string","enum":["a","b"],"default":"b"}}}));
        assert!(slate_expands(
            &old,
            &slate(changed.clone(), draft_connector_slate(&changed)),
            &BTreeSet::new()
        ));
        changed = tools;
        changed[0].resolved_input_schema = Some(json!({"type":"object",
            "properties":{"query":{"type":"string","enum":["a"]}}}));
        assert!(!slate_expands(
            &old,
            &slate(changed.clone(), draft_connector_slate(&changed)),
            &BTreeSet::new()
        ));
    }
    #[test]
    fn resolved_policy_controls_class_carry_and_header_is_independent() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
        let txn = vault.store.env.read_txn()?;
        let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
        let default = policy.connector_class_carry();
        drop(txn);
        let base = tool("A");
        let prior = SlateToolManifest {
            data_class: SlateDataClass::Personal,
            ..base.clone()
        };
        let next = SlateToolManifest {
            data_class: SlateDataClass::Public,
            ..base.clone()
        };
        let old = slate(vec![prior.clone()], draft_connector_slate(&[prior]));
        let new = slate(vec![next.clone()], draft_connector_slate(&[next]));
        assert!(!slate_expands(&old, &new, &default));
        let header = SlateToolManifest {
            data_class: SlateDataClass::Header,
            ..base
        };
        let header = slate(vec![header.clone()], draft_connector_slate(&[header]));
        assert!(slate_expands(&old, &header, &default));
        assert!(slate_expands(&header, &new, &default));
        // A trusted holder row narrows the shipped carry table to empty.
        let data = crate::gate::default_policy_manifest().unwrap();
        let mut cursor = std::io::Cursor::new(data);
        let rmpv::Value::Map(mut entries) =
            rmpv::decode::read_value(&mut cursor).expect("policy map")
        else {
            panic!("policy map");
        };
        *entries
            .iter_mut()
            .find(|(k, _)| k.as_str() == Some("connector_class_carry"))
            .expect("shipped policy carry row") = (
            rmpv::Value::from("connector_class_carry"),
            rmpv::Value::Array(vec![]),
        );
        *entries
            .iter_mut()
            .find(|(k, _)| k.as_str() == Some("connector_class_role"))
            .expect("role row") = (
            rmpv::Value::from("connector_class_role"),
            rmpv::Value::from("holder"),
        );
        entries.retain(|(key, _)| key.as_str() != Some("connector_class_precedence"));
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, &rmpv::Value::Map(entries)).expect("encode policy");
        crate::test_util::put_policy_manifest_bytes(&vault, EntityId::now(), &encoded)?;
        let txn = vault.store.env.read_txn()?;
        let narrowed =
            crate::gate::resolve_policy_manifest(&vault.store, &txn)?.connector_class_carry();
        assert!(narrowed.is_empty());
        assert!(slate_expands(&old, &new, &narrowed));
        Ok(())
    }
    fn write_class_policy(
        vault: &Vault,
        id: EntityId,
        role: &str,
        precedence: Option<&str>,
        rows: &[(&str, &str)],
    ) -> Result<()> {
        fn set_row(entries: &mut [(rmpv::Value, rmpv::Value)], key: &str, value: rmpv::Value) {
            entries
                .iter_mut()
                .find(|(name, _)| name.as_str() == Some(key))
                .expect("default policy class row")
                .1 = value;
        }
        let data = crate::gate::default_policy_manifest().unwrap();
        let mut cursor = std::io::Cursor::new(data);
        let rmpv::Value::Map(mut entries) =
            rmpv::decode::read_value(&mut cursor).expect("default policy map")
        else {
            panic!("default policy map");
        };
        set_row(
            &mut entries,
            "connector_class_carry",
            rmpv::Value::Array(
                rows.iter()
                    .map(|(from, to)| {
                        rmpv::Value::Array(vec![rmpv::Value::from(*from), rmpv::Value::from(*to)])
                    })
                    .collect(),
            ),
        );
        set_row(
            &mut entries,
            "connector_class_role",
            rmpv::Value::from(role),
        );
        if let Some(precedence) = precedence {
            set_row(
                &mut entries,
                "connector_class_precedence",
                rmpv::Value::from(precedence),
            );
        } else {
            entries.retain(|(key, _)| key.as_str() != Some("connector_class_precedence"));
        }
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, &rmpv::Value::Map(entries)).expect("encode policy");
        crate::test_util::put_policy_manifest_bytes(vault, id, &encoded)
    }

    #[test]
    fn vault_class_ceiling_is_configurable_holder_capped_and_frontier_bound() -> Result<()> {
        type Frontier = ([u8; 32], BTreeSet<(String, String)>, bool);
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
        let default_id = crate::gate::default_policy_manifest_id()?;
        let frontier = |vault: &Vault| -> Result<Frontier> {
            let txn = vault.store.env.read_txn()?;
            let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
            Ok((
                policy.read_frontier_hash()?,
                policy.connector_class_carry(),
                policy.is_fail_closed(),
            ))
        };
        let original = frontier(&vault)?;
        assert!(!original.1.contains(&("header".into(), "secret".into())));
        // The vault owner can author a relation absent from the shipped row.
        write_class_policy(
            &vault,
            default_id,
            "vault",
            Some("nested"),
            &[("header", "secret"), ("public", "personal")],
        )?;
        let revised = frontier(&vault)?;
        assert!(!revised.2);
        assert_ne!(
            original.0, revised.0,
            "class-only owner edit moves policy frontier"
        );
        assert!(revised.1.contains(&("header".into(), "secret".into())));
        // A holder row can narrow the vault ceiling; a pair outside it is
        // parsed but cannot authorize anything the vault never granted.
        write_class_policy(
            &vault,
            EntityId::now(),
            "holder",
            None,
            &[("header", "secret"), ("secret", "header")],
        )?;
        let nested = frontier(&vault)?;
        assert_eq!(
            nested.1,
            BTreeSet::from([("header".into(), "secret".into())])
        );
        assert_ne!(nested.0, revised.0);
        write_class_policy(
            &vault,
            default_id,
            "vault",
            Some("holder_override"),
            &[("header", "secret"), ("public", "personal")],
        )?;
        let overridden = frontier(&vault)?;
        assert!(!overridden.2);
        assert_eq!(overridden.1, nested.1);
        assert_ne!(
            nested.0, overridden.0,
            "precedence-only edit moves policy frontier"
        );
        // A second holder under single-holder override is ambiguous, not a
        // license to select an arbitrary widening row.
        write_class_policy(
            &vault,
            EntityId::now(),
            "holder",
            None,
            &[("public", "personal")],
        )?;
        assert!(frontier(&vault)?.2);
        Ok(())
    }
}
