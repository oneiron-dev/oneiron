//! ARCH-0072 typed per-capability grant slates. Every row starts at `auto`
//! and a draft never widens past it. Only an authenticated owner sets the
//! override columns; the key's holder may only tighten its own rows.
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::side_table::{self, LegacyJson, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const GRANT_SLATE: SideTable<EntityId, ConnectorGrantSlate, LegacyJson> =
    SideTable::new(&side_table::CONNECTOR_GRANT_SLATE);
/// The one connector key a stamped slate admits. Key: slate id.
const SLATE_BINDING: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::CONNECTOR_GRANT_SLATE_BINDING);
/// ARCH-0054's one aggregate, with the slate's two named inputs: the
/// manifest hash and the grant hash.
const SLATE_STAMP_DOMAIN: &[u8] = b"connector-grant-slate-stamp-v1";
const SLATE_GRANT_DOMAIN: &[u8] = b"connector-grant-slate-grant-v1";

fn invalid() -> Error {
    Error::InvalidConfig("invalid typed connector grant slate".to_owned())
}

/// The four DEC-0006 capability settings. Declaration order is strictness,
/// so `Ord` reads "tighter": always allow < auto < always ask < never allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlateDisposition {
    /// Bypasses the per-call ask inside the bound; never the catastrophe floor.
    AlwaysAllow,
    /// The default: the per-call verdict, learning through standing grants.
    Auto,
    /// Asks for every call, even one a standing grant covers.
    AlwaysAsk,
    /// Removes the tool from the connector's callable catalog.
    NeverAllow,
}
impl SlateDisposition {
    pub const ALL: [Self; 4] = [
        Self::AlwaysAllow,
        Self::Auto,
        Self::AlwaysAsk,
        Self::NeverAllow,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AlwaysAllow => "always_allow",
            Self::Auto => "auto",
            Self::AlwaysAsk => "always_ask",
            Self::NeverAllow => "never_allow",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|setting| setting.as_str() == value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlateDataClass {
    Public,
    Personal,
    Secret,
    Header,
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
    /// The connector's declared `readOnlyHint` and `idempotentHint`. A call
    /// to a read-only tool that destroys nothing, or to an idempotent one,
    /// retries after an ambiguous reply instead of abandoning the intent.
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub idempotent: bool,
}
impl SlateToolManifest {
    /// Irreversible or header-bearing: `auto` already asks per call for these.
    pub(super) fn floor(&self) -> bool {
        self.destroys
            || self.spends
            || self.sends_outward
            || !self.header_parameters.is_empty()
            || self.data_class == SlateDataClass::Header
            || self.legacy_ask
    }
    /// A parameter that reaches the wire as a header is its own data class.
    pub fn row_data_class(&self) -> SlateDataClass {
        if self.header_parameters.is_empty() {
            self.data_class
        } else {
            SlateDataClass::Header
        }
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
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlateOwnerOverride {
    pub disposition: SlateDisposition,
}
/// An autonomous tightening by the key's holder. It needs no stamp and is
/// provenance-marked, so it never reads as an owner tap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlateHolderNarrow {
    pub disposition: SlateDisposition,
    pub actor: String,
    pub at: u64,
}
/// The holder's own facet narrowing, kept beside the owner's limit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlateFacetNarrow {
    pub facets: BTreeSet<EntityId>,
    pub actor: String,
    pub at: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlateRow {
    pub draft: SlateDraftRow,
    pub owner_override: Option<SlateOwnerOverride>,
    pub holder_narrow: Option<SlateHolderNarrow>,
}
impl SlateRow {
    /// What the owner accepted: the override, else the stamped draft.
    pub fn stamped_disposition(&self) -> SlateDisposition {
        self.owner_override
            .as_ref()
            .map_or(self.draft.disposition, |o| o.disposition)
    }
    /// What a call meets: the stamped setting, tightened by any holder narrow.
    pub fn effective_disposition(&self) -> SlateDisposition {
        self.holder_narrow
            .as_ref()
            .map_or(self.stamped_disposition(), |narrow| {
                narrow.disposition.max(self.stamped_disposition())
            })
    }
    pub fn enabled(&self) -> bool {
        self.effective_disposition() != SlateDisposition::NeverAllow
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
    /// The owner's opt-in facet limit on the Grant scope; `None` is every facet.
    facet_limit: Option<BTreeSet<EntityId>>,
    holder_facet_narrow: Option<SlateFacetNarrow>,
    /// The slate this one revises (a drift delta); `None` at connector add.
    prior: Option<EntityId>,
    /// Rows new or expanded against `prior`: the only rows the tap re-asks.
    reask: BTreeSet<String>,
    /// The aggregate the last owner stamp bound.
    stamped_aggregate: Option<[u8; 32]>,
}
impl ConnectorGrantSlate {
    pub fn rows(&self) -> &[SlateRow] {
        &self.rows
    }
    pub fn row(&self, tool: &str) -> Option<&SlateRow> {
        self.rows.iter().find(|row| row.draft.tool == tool)
    }
    pub fn manifest(&self) -> &[SlateToolManifest] {
        &self.manifest
    }
    pub fn tool(&self, name: &str) -> Option<&SlateToolManifest> {
        self.manifest.iter().find(|tool| tool.name == name)
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
    pub fn facet_limit(&self) -> Option<&BTreeSet<EntityId>> {
        self.facet_limit.as_ref()
    }
    /// The facets the Grant reaches: the owner's limit met with the holder's.
    pub fn effective_facets(&self) -> Option<BTreeSet<EntityId>> {
        let narrow = self.holder_facet_narrow.as_ref().map(|n| &n.facets);
        match (self.facet_limit.as_ref(), narrow) {
            (None, None) => None,
            (Some(only), None) | (None, Some(only)) => Some(only.clone()),
            (Some(limit), Some(narrow)) => Some(limit.intersection(narrow).copied().collect()),
        }
    }
    pub fn prior(&self) -> Option<EntityId> {
        self.prior
    }
    pub fn reask(&self) -> &BTreeSet<String> {
        &self.reask
    }
    /// The setting a call on `tool` meets. A tool the slate never declared
    /// raises the ask rather than dying as a silent deny (DEC-0006 inv. 3).
    pub fn tool_setting(&self, tool: &str) -> SlateDisposition {
        self.row(tool)
            .map_or(SlateDisposition::AlwaysAsk, SlateRow::effective_disposition)
    }
    /// The owner-accepted grant: each row's stamped setting and class, plus
    /// the facet limit. Holder narrows sit outside it, so they never break it.
    pub fn grant_hash(&self) -> [u8; 32] {
        let rows: Vec<_> = self
            .rows
            .iter()
            .map(|row| {
                (
                    row.draft.tool.as_str(),
                    row.stamped_disposition().as_str(),
                    row.draft.data_class.as_str(),
                )
            })
            .collect();
        let mut hasher = blake3::Hasher::new();
        hasher.update(SLATE_GRANT_DOMAIN);
        hasher.update(&serde_json::to_vec(&(rows, &self.facet_limit)).unwrap_or_default());
        *hasher.finalize().as_bytes()
    }
    fn aggregate(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(SLATE_STAMP_DOMAIN);
        hasher.update(&self.manifest_hash);
        hasher.update(&self.grant_hash());
        *hasher.finalize().as_bytes()
    }
    /// If either input moved since the owner's stamp, the stamp no longer
    /// holds and the key cannot qualify until a human re-stamps it.
    pub fn stamp_holds(&self) -> bool {
        self.stamped_aggregate == Some(self.aggregate())
    }
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
        // A draft grants nothing: it may pre-fill a tighter setting, but only
        // the owner's own override can choose `always allow`.
        if !seen.insert(&row.tool)
            || row.rationale.trim().is_empty()
            || row.rationale.len() > 4096
            || row.disposition == SlateDisposition::AlwaysAllow
            || !tool
                .resolved_input_schema
                .as_ref()
                .is_some_and(|schema| schema.is_object() && is_resolved_schema(schema))
            || row.data_class != tool.row_data_class()
        {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Whether the declaration itself reaches further than before: a richer data
/// class, new headers or effects, a changed trigger, or a schema that is not a
/// provable restriction.
pub(in crate::connector_key) fn declaration_expands(
    old: &SlateToolManifest,
    next: &SlateToolManifest,
    carry: &BTreeSet<(String, String)>,
) -> bool {
    next.data_class != old.data_class
        && !carry.contains(&(
            next.data_class.as_str().into(),
            old.data_class.as_str().into(),
        ))
        || next
            .header_parameters
            .iter()
            .any(|param| !old.header_parameters.contains(param))
        || next.destroys && !old.destroys
        || next.spends && !old.spends
        || next.sends_outward && !old.sends_outward
        || next.legacy_ask && !old.legacy_ask
        || next.trigger != old.trigger
        || !schema_narrows(
            old.resolved_input_schema.as_ref(),
            next.resolved_input_schema.as_ref(),
        )
}

/// A dropped facet limit, or a facet the old limit lacked, widens the Grant.
fn facets_widen(old: Option<&BTreeSet<EntityId>>, next: Option<&BTreeSet<EntityId>>) -> bool {
    match (old, next) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(old), Some(next)) => !next.is_subset(old),
    }
}

/// Compare the fully typed grant declaration and the effective settings.
/// Unchanged or reduced authority carries its earlier consent; new tools,
/// richer declarations, a looser setting or a wider facet set need a tap.
pub(in crate::connector_key) fn slate_expands(
    old: &ConnectorGrantSlate,
    next: &ConnectorGrantSlate,
    carry: &BTreeSet<(String, String)>,
) -> bool {
    facets_widen(
        old.effective_facets().as_ref(),
        next.effective_facets().as_ref(),
    ) || next.manifest.iter().any(|tool| {
        let row = next
            .row(&tool.name)
            .expect("validated slate has one row per tool");
        if !row.enabled() {
            return false;
        }
        let (Some(old_tool), Some(old_row)) = (old.tool(&tool.name), old.row(&tool.name)) else {
            return true;
        };
        declaration_expands(old_tool, tool, carry)
            || row.effective_disposition() < old_row.effective_disposition()
    })
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
    read_slate_in_store_txn(&vault.store, txn, id)
}

pub(in crate::connector_key) fn read_slate_in_store_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<ConnectorGrantSlate>> {
    GRANT_SLATE.get(store, txn, &id)
}

/// Every stored slate, for the drafter's read of the owner's past rulings.
pub(in crate::connector_key) fn scan_slates_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(EntityId, ConnectorGrantSlate)>> {
    GRANT_SLATE.scan(store, txn)
}

/// A fresh, unstamped slate over validated draft rows. `prior` and `reask`
/// are set only for a drift delta, which also carries the prior facet rows.
pub(in crate::connector_key) fn new_slate(
    manifest: &[SlateToolManifest],
    rows: Vec<SlateRow>,
    prior: Option<&ConnectorGrantSlate>,
    prior_id: Option<EntityId>,
    reask: BTreeSet<String>,
) -> Result<ConnectorGrantSlate> {
    let drafts: Vec<SlateDraftRow> = rows.iter().map(|row| row.draft.clone()).collect();
    validate(manifest, &drafts)?;
    let manifest_bytes = serde_json::to_vec(manifest).map_err(|_| invalid())?;
    Ok(ConnectorGrantSlate {
        manifest: manifest.to_vec(),
        manifest_hash: *blake3::hash(&manifest_bytes).as_bytes(),
        rows,
        revision: 0,
        owner_actor: None,
        owner_authentication: None,
        facet_limit: prior.and_then(|slate| slate.facet_limit.clone()),
        holder_facet_narrow: prior.and_then(|slate| slate.holder_facet_narrow.clone()),
        prior: prior_id,
        reask,
        stamped_aggregate: None,
    })
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
        let rows = rows
            .into_iter()
            .map(|draft| SlateRow {
                draft,
                owner_override: None,
                holder_narrow: None,
            })
            .collect();
        self.put_new_slate(new_slate(manifest, rows, None, None, BTreeSet::new())?)
    }
    pub(in crate::connector_key) fn put_new_slate(
        &self,
        slate: ConnectorGrantSlate,
    ) -> Result<EntityId> {
        let id = EntityId::now();
        self.with_write_txn_grouped(|txn| {
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
        self.stamp_slate(owner, id, expected_revision, overrides, None)
    }
    /// The same one tap, also setting the owner's opt-in facet limit on the
    /// Grant scope (`None` reaches every facet). It clears a holder's facet
    /// narrow: the owner is looking at the whole grant.
    pub fn stamp_connector_slate(
        &self,
        owner: &AuthenticatedOwner,
        id: EntityId,
        expected_revision: u64,
        overrides: &BTreeMap<String, SlateOwnerOverride>,
        facet_limit: Option<BTreeSet<EntityId>>,
    ) -> Result<ConnectorGrantSlate> {
        self.stamp_slate(owner, id, expected_revision, overrides, Some(facet_limit))
    }
    /// "Flip to all-manual": every row `always ask` (a `never allow` row
    /// stays removed), then the one stamp.
    pub fn accept_connector_slate_all_manual(
        &self,
        owner: &AuthenticatedOwner,
        id: EntityId,
        expected_revision: u64,
    ) -> Result<ConnectorGrantSlate> {
        let slate = self.connector_slate(id)?.ok_or(Error::EntityNotFound)?;
        let overrides = slate
            .rows
            .iter()
            .filter(|row| row.stamped_disposition() != SlateDisposition::NeverAllow)
            .map(|row| {
                (
                    row.draft.tool.clone(),
                    SlateOwnerOverride {
                        disposition: SlateDisposition::AlwaysAsk,
                    },
                )
            })
            .collect();
        self.override_connector_slate(owner, id, expected_revision, &overrides)
    }
    fn stamp_slate(
        &self,
        owner: &AuthenticatedOwner,
        id: EntityId,
        expected_revision: u64,
        overrides: &BTreeMap<String, SlateOwnerOverride>,
        facet_limit: Option<Option<BTreeSet<EntityId>>>,
    ) -> Result<ConnectorGrantSlate> {
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            crate::memory::verify_deletion_authority_in_txn(
                self,
                txn,
                actor,
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
                    // The owner's ruling on a row reverses a holder's narrow.
                    row.owner_override = Some(value.clone());
                    row.holder_narrow = None;
                }
            }
            if let Some(limit) = facet_limit {
                if limit.as_ref().is_some_and(BTreeSet::is_empty) {
                    return Err(invalid());
                }
                slate.facet_limit = limit;
                slate.holder_facet_narrow = None;
            }
            slate.revision = slate
                .revision
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("slate revision"))?;
            slate.owner_actor = Some(actor.to_hex());
            slate.owner_authentication = Some(owner.decision_id().to_hex());
            slate.stamped_aggregate = Some(slate.aggregate());
            GRANT_SLATE.put(&self.store, txn, &id, &slate)?;
            Ok(slate)
        })
    }
    /// ARCH-0072 self-update: the key's own holder tightens rows or the facet
    /// set of its bound slate, with no stamp. Narrowing is free, widening
    /// never is. The tightening is receipted on the key's log and marked with
    /// the holder, and the owner's stamp on a row reverses it.
    pub fn narrow_connector_slate(
        &self,
        key_id: &EntityId,
        holder: EntityId,
        narrows: &BTreeMap<String, SlateDisposition>,
        facets: Option<BTreeSet<EntityId>>,
        at: u64,
    ) -> Result<ConnectorGrantSlate> {
        use crate::connector_key::record::invalid_body;
        if narrows.is_empty() && facets.is_none() {
            return Err(invalid_body("slate narrow names no row or facet"));
        }
        self.with_write_txn_grouped(|txn| {
            let record = super::txn::read_connector_key_in_txn(&self.store, txn, key_id)?
                .ok_or(Error::EntityNotFound)?;
            if record.actor_entity_ref != Some(holder) {
                return Err(invalid_body("only the key's holder narrows its slate"));
            }
            let slate_id = record
                .slate_ref
                .ok_or_else(|| invalid_body("connector slate missing"))?;
            let mut slate = GRANT_SLATE
                .get(&self.store, txn, &slate_id)?
                .ok_or_else(|| invalid_body("connector slate missing"))?;
            for (tool, disposition) in narrows {
                let row = slate
                    .rows
                    .iter_mut()
                    .find(|row| &row.draft.tool == tool)
                    .ok_or_else(invalid)?;
                if *disposition <= row.effective_disposition() {
                    return Err(invalid_body("a holder narrow must tighten the row"));
                }
                row.holder_narrow = Some(SlateHolderNarrow {
                    disposition: *disposition,
                    actor: holder.to_hex(),
                    at,
                });
            }
            if let Some(facets) = facets {
                if facets.is_empty()
                    || slate
                        .effective_facets()
                        .is_some_and(|current| !facets.is_subset(&current))
                {
                    return Err(invalid_body("a holder facet narrow must tighten the set"));
                }
                slate.holder_facet_narrow = Some(SlateFacetNarrow {
                    facets,
                    actor: holder.to_hex(),
                    at,
                });
            }
            GRANT_SLATE.put(&self.store, txn, &slate_id, &slate)?;
            let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
            super::txn::append_connector_key_op_record(
                &self.store,
                txn,
                key_id,
                "gate.connector_key.slate_narrow",
                &record,
                policy.read_frontier_hash()?,
                at,
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
        let owner = vault.ensure_embedded_owner_actor().unwrap();
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
