//! ARCH-0072 typed per-tool grant slates. The drafter's floor is not an
//! owner restriction: only an authenticated owner can set override columns.
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const PREFIX: &[u8] = b"connector.grant_slate.v1/";
const BIND_PREFIX: &[u8] = b"connector.grant_slate.binding.v1/";
fn key(id: EntityId) -> Vec<u8> {
    [PREFIX, id.as_bytes()].concat()
}
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
) -> bool {
    let class_rank = |class| match class {
        SlateDataClass::Public => 0_u8,
        SlateDataClass::Personal => 1,
        SlateDataClass::Secret => 2,
        SlateDataClass::Header => 3,
    };
    next.manifest.iter().zip(&next.rows).any(|(tool, row)| {
        if !row.enabled() {
            return false;
        }
        let Some((old_tool, old_row)) = old
            .manifest
            .iter()
            .zip(&old.rows)
            .find(|(candidate, _)| candidate.name == tool.name)
        else {
            return true;
        };
        !old_row.enabled()
            || class_rank(tool.data_class) > class_rank(old_tool.data_class)
            || tool
                .header_parameters
                .iter()
                .any(|param| !old_tool.header_parameters.contains(param))
            || tool.destroys && !old_tool.destroys
            || tool.spends && !old_tool.spends
            || tool.sends_outward && !old_tool.sends_outward
            || tool.legacy_ask && !old_tool.legacy_ask
            || row.effective_disposition() == SlateDisposition::Auto
                && old_row.effective_disposition() == SlateDisposition::ConfirmFirst
    })
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
    let binding = [BIND_PREFIX, slate_id.as_bytes()].concat();
    if vault.store.vault_meta.get(&*txn, &binding)?.is_some() {
        return Err(crate::connector_key::record::invalid_body(
            "slate already bound to a connector",
        ));
    }
    vault
        .store
        .vault_meta
        .put(txn, &binding, key_id.as_bytes())?;
    Ok(())
}

pub(in crate::connector_key) fn read_connector_slate_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<ConnectorGrantSlate>> {
    vault
        .store
        .vault_meta
        .get(txn, &key(id))?
        .map(|raw| serde_json::from_slice(&raw).map_err(|_| invalid()))
        .transpose()
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
            self.store.vault_meta.put(
                txn,
                &key(id),
                &serde_json::to_vec(&slate).map_err(|_| invalid())?,
            )?;
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
            let raw = self
                .store
                .vault_meta
                .get(txn, &key(id))?
                .ok_or(Error::EntityNotFound)?;
            let mut slate: ConnectorGrantSlate =
                serde_json::from_slice(&raw).map_err(|_| invalid())?;
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
            self.store.vault_meta.put(
                txn,
                &key(id),
                &serde_json::to_vec(&slate).map_err(|_| invalid())?,
            )?;
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
