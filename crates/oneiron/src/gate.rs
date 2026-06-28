//! DEC-0005 vault-resident policy manifest resolver.
//!
//! The resolver is intentionally data-only. It loads PolicyManifestV1 rows
//! from PACK entities and returns stable inputs for the future Gate write/read
//! surfaces; current write behavior only consumes the source-trust slice.
#![cfg_attr(not(test), allow(dead_code))]

use std::cmp::Ordering;
use std::io::Cursor;

use rmpv::Value;

use crate::claim::{
    ClaimSource, SOURCE_TRUST_AUTO_KEY, SOURCE_TRUST_KEY, SOURCE_TRUST_MANIFEST_KIND,
    SOURCE_TRUST_MANIFEST_MARKER, SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY,
    SOURCE_TRUST_RECEIPTED_KEY, SOURCE_TRUST_WARNED_KEY, SourceTrustCeiling, SourceTrustRow,
    sensitivity_band_from_value,
};
use crate::error::{Error, Result};
use crate::store::Store;
use crate::types::{ENTITY_TYPE_REGISTRY, EntityClassification, EntityId};

const POLICY_MANIFEST_MARKER: &str = "dec_0005_policy_manifest_v1";
const POLICY_MANIFEST_KIND: &str = "policy_manifest_v1";
const POLICY_MANIFEST_SCHEMA_VERSION: &str = "1.1";
const CURRENT_POLICY_ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

const KEY_MANIFEST: &str = "manifest";
const KEY_KIND: &str = "kind";
const KEY_SCHEMA_VERSION: &str = "schema_version";
const KEY_PACK_ID: &str = "pack_id";
const KEY_PACK_VERSION: &str = "pack_version";
const KEY_MIN_ENGINE_VERSION: &str = "min_engine_version";
const KEY_DEFAULTS: &str = "defaults";
const KEY_RULES: &str = "rules";
const KEY_ACTOR_CEILINGS: &str = "actor_ceilings";
const KEY_SCOPED_GRANTS: &str = "scoped_grants";
const KEY_SIGNATURES: &str = "signatures";
const KEY_PREFIX: &str = "prefix";
const KEY_AXES: &str = "axes";
const KEY_CRITICALITY: &str = "criticality";
const KEY_SENSITIVITY: &str = "sensitivity";
const KEY_ACTOR_CLASS: &str = "actor_class";
const KEY_ACTOR_REF: &str = "actor_ref";
const KEY_CEILING: &str = "ceiling";
const KEY_GRANT_ID: &str = "grant_id";
const KEY_WORLD: &str = "world";
const KEY_FACET: &str = "facet";
const KEY_SCOPE: &str = "scope";
const KEY_SIG_KEY_ID: &str = "key_id";
const KEY_SIG_ALG: &str = "alg";
const KEY_SIG_VALUE: &str = "sig";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum PolicyManifestStatus {
    Valid,
    #[default]
    Missing,
    Malformed,
    UnsupportedVersion,
    EngineVersionFloor,
    UnknownAxis,
}

impl PolicyManifestStatus {
    #[must_use]
    pub(crate) const fn is_fail_closed(self) -> bool {
        !matches!(self, Self::Valid)
    }

    const fn merge(self, other: Self) -> Self {
        use PolicyManifestStatus::{
            EngineVersionFloor, Malformed, Missing, UnknownAxis, UnsupportedVersion, Valid,
        };

        match (self, other) {
            (Malformed, _) | (_, Malformed) => Malformed,
            (UnsupportedVersion, _) | (_, UnsupportedVersion) => UnsupportedVersion,
            (EngineVersionFloor, _) | (_, EngineVersionFloor) => EngineVersionFloor,
            (UnknownAxis, _) | (_, UnknownAxis) => UnknownAxis,
            (Missing, status) => status,
            (status, Missing) => status,
            (Valid, Valid) => Valid,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PolicyCriticality {
    Normal,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PolicySensitivity {
    Normal,
    Sensitive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ApprovalCeiling {
    Auto,
    Proposed,
}

impl ApprovalCeiling {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "proposed" => Some(Self::Proposed),
            _ => None,
        }
    }

    const fn most_restrictive(self, other: Self) -> Self {
        match (self, other) {
            (Self::Proposed, _) | (_, Self::Proposed) => Self::Proposed,
            (Self::Auto, Self::Auto) => Self::Auto,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActorCeiling {
    pub(crate) actor_class: String,
    pub(crate) actor_ref: Option<String>,
    pub(crate) ceiling: ApprovalCeiling,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScopedGrant {
    pub(crate) grant_id: String,
    pub(crate) actor_class: Option<String>,
    pub(crate) actor_ref: Option<String>,
    pub(crate) world: Option<String>,
    pub(crate) facet: Option<String>,
    pub(crate) scope: Option<String>,
    pub(crate) ceiling: ApprovalCeiling,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyManifestSignature {
    pub(crate) key_id: String,
    pub(crate) algorithm: String,
    pub(crate) signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyDecisionInputs {
    pub(crate) status: PolicyManifestStatus,
    pub(crate) criticality: PolicyCriticality,
    pub(crate) sensitivity: PolicySensitivity,
    pub(crate) source_trust: SourceTrustCeiling,
    pub(crate) actor_ceiling: ApprovalCeiling,
    pub(crate) scoped_grants: Vec<ScopedGrant>,
    pub(crate) signatures: Vec<PolicyManifestSignature>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PolicyManifestResolver {
    status: PolicyManifestStatus,
    manifests: Vec<ResolvedManifest>,
    actor_ceilings: Vec<ActorCeiling>,
    scoped_grants: Vec<ScopedGrant>,
    signatures: Vec<PolicyManifestSignature>,
    source_trust: SourceTrustCeiling,
}

impl PolicyManifestResolver {
    pub(crate) fn load_from_store(store: &Store, txn: &heed::RwTxn<'_>) -> Result<Self> {
        let mut resolver = Self::default();

        for entry in ENTITY_TYPE_REGISTRY
            .iter()
            .filter(|entry| entry.classification == EntityClassification::Pack)
        {
            for index_entry in store.type_index.prefix_iter(txn, &[entry.type_byte])? {
                let (key, _) = index_entry?;
                if key.len() != 17 {
                    resolver.mark_malformed();
                    continue;
                }
                let id = match EntityId::from_bytes(
                    key[1..17]
                        .try_into()
                        .map_err(|_| Error::CorruptedIndex("policy manifest type index key"))?,
                ) {
                    Ok(id) => id,
                    Err(_) => {
                        resolver.mark_malformed();
                        continue;
                    }
                };
                let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
                    resolver.mark_malformed();
                    continue;
                };
                let Some(header) = crate::batch::EntityMetadataHeader::parse(raw) else {
                    resolver.mark_malformed();
                    continue;
                };
                if header.entity_type != entry.type_byte {
                    resolver.mark_malformed();
                    continue;
                }

                resolver.merge_decode_result(decode_manifest_entity(
                    &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                ));
            }
        }

        Ok(resolver)
    }

    #[must_use]
    pub(crate) fn status(&self) -> PolicyManifestStatus {
        self.status
    }

    #[must_use]
    pub(crate) fn source_trust_ceiling(&self) -> SourceTrustCeiling {
        if matches!(
            self.status,
            PolicyManifestStatus::Malformed
                | PolicyManifestStatus::UnsupportedVersion
                | PolicyManifestStatus::EngineVersionFloor
                | PolicyManifestStatus::UnknownAxis
        ) {
            let mut ceiling = self.source_trust;
            ceiling.mark_malformed();
            ceiling
        } else {
            self.source_trust
        }
    }

    #[must_use]
    pub(crate) fn resolve(
        &self,
        predicate: &str,
        actor_class: &str,
        actor_ref: Option<&str>,
    ) -> PolicyDecisionInputs {
        let status = self.status;
        if status.is_fail_closed() {
            return PolicyDecisionInputs {
                status,
                criticality: PolicyCriticality::Critical,
                sensitivity: PolicySensitivity::Sensitive,
                source_trust: self.source_trust_ceiling(),
                actor_ceiling: ApprovalCeiling::Proposed,
                scoped_grants: Vec::new(),
                signatures: self.signatures.clone(),
            };
        }

        PolicyDecisionInputs {
            status,
            criticality: self.resolve_criticality(predicate),
            sensitivity: self.resolve_sensitivity(predicate),
            source_trust: self.source_trust,
            actor_ceiling: self.resolve_actor_ceiling(actor_class, actor_ref),
            scoped_grants: self.scoped_grants.clone(),
            signatures: self.signatures.clone(),
        }
    }

    #[must_use]
    pub(crate) fn resolve_actor_ceiling(
        &self,
        actor_class: &str,
        actor_ref: Option<&str>,
    ) -> ApprovalCeiling {
        if self.status.is_fail_closed() {
            return ApprovalCeiling::Proposed;
        }

        let class_ceiling = self
            .actor_ceilings
            .iter()
            .filter(|row| row.actor_class == actor_class && row.actor_ref.is_none())
            .map(|row| row.ceiling)
            .reduce(ApprovalCeiling::most_restrictive)
            .unwrap_or(ApprovalCeiling::Proposed);

        let Some(actor_ref) = actor_ref else {
            return class_ceiling;
        };

        self.actor_ceilings
            .iter()
            .filter(|row| {
                row.actor_class == actor_class && row.actor_ref.as_deref() == Some(actor_ref)
            })
            .fold(class_ceiling, |ceiling, row| {
                ceiling.most_restrictive(row.ceiling)
            })
    }

    #[must_use]
    pub(crate) fn resolve_criticality(&self, predicate: &str) -> PolicyCriticality {
        if self.status.is_fail_closed() {
            return PolicyCriticality::Critical;
        }

        self.manifests
            .iter()
            .map(|manifest| manifest.axes_for(predicate).criticality)
            .max()
            .unwrap_or(PolicyCriticality::Critical)
    }

    #[must_use]
    pub(crate) fn resolve_sensitivity(&self, predicate: &str) -> PolicySensitivity {
        if self.status.is_fail_closed() {
            return PolicySensitivity::Sensitive;
        }

        self.manifests
            .iter()
            .map(|manifest| manifest.axes_for(predicate).sensitivity)
            .max()
            .unwrap_or(PolicySensitivity::Sensitive)
    }

    fn merge_decode_result(&mut self, decoded: DecodeOutcome) {
        match decoded {
            DecodeOutcome::Absent => {}
            DecodeOutcome::Malformed => self.mark_malformed(),
            DecodeOutcome::UnsupportedVersion => {
                self.status = self.status.merge(PolicyManifestStatus::UnsupportedVersion);
            }
            DecodeOutcome::EngineVersionFloor => {
                self.status = self.status.merge(PolicyManifestStatus::EngineVersionFloor);
            }
            DecodeOutcome::UnknownAxis(manifest) => {
                self.merge_manifest(manifest);
                self.status = self.status.merge(PolicyManifestStatus::UnknownAxis);
            }
            DecodeOutcome::Manifest(manifest) => {
                self.merge_manifest(manifest);
                self.status = self.status.merge(PolicyManifestStatus::Valid);
            }
        }
    }

    fn merge_manifest(&mut self, manifest: ResolvedManifest) {
        self.source_trust.merge(manifest.source_trust);
        self.actor_ceilings
            .extend(manifest.actor_ceilings.iter().cloned());
        self.scoped_grants
            .extend(manifest.scoped_grants.iter().cloned());
        self.signatures.extend(manifest.signatures.iter().cloned());
        self.manifests.push(manifest);
    }

    fn mark_malformed(&mut self) {
        self.status = self.status.merge(PolicyManifestStatus::Malformed);
        self.source_trust.mark_malformed();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Axes {
    criticality: PolicyCriticality,
    sensitivity: PolicySensitivity,
}

impl Default for Axes {
    fn default() -> Self {
        Self {
            criticality: PolicyCriticality::Critical,
            sensitivity: PolicySensitivity::Sensitive,
        }
    }
}

impl Axes {
    fn merge(self, other: Self) -> Self {
        Self {
            criticality: self.criticality.max(other.criticality),
            sensitivity: self.sensitivity.max(other.sensitivity),
        }
    }
}

#[derive(Debug, Clone)]
struct ResolvedManifest {
    defaults: Axes,
    rules: Vec<ResolvedRule>,
    actor_ceilings: Vec<ActorCeiling>,
    scoped_grants: Vec<ScopedGrant>,
    signatures: Vec<PolicyManifestSignature>,
    source_trust: SourceTrustCeiling,
}

impl ResolvedManifest {
    fn axes_for(&self, predicate: &str) -> Axes {
        let mut selected = self.defaults;
        let mut selected_len = 0;

        for rule in &self.rules {
            if predicate.starts_with(&rule.prefix) {
                match rule.prefix.len().cmp(&selected_len) {
                    Ordering::Greater => {
                        selected = rule.axes;
                        selected_len = rule.prefix.len();
                    }
                    Ordering::Equal => {
                        selected = selected.merge(rule.axes);
                    }
                    Ordering::Less => {}
                }
            }
        }

        selected
    }
}

#[derive(Debug, Clone)]
struct ResolvedRule {
    prefix: String,
    axes: Axes,
}

enum DecodeOutcome {
    Absent,
    Malformed,
    UnsupportedVersion,
    EngineVersionFloor,
    UnknownAxis(ResolvedManifest),
    Manifest(ResolvedManifest),
}

fn decode_manifest_entity(data: &[u8]) -> DecodeOutcome {
    let mut cursor = Cursor::new(data);
    let value = match rmpv::decode::read_value(&mut cursor) {
        Ok(value) => value,
        Err(_) => return DecodeOutcome::Absent,
    };
    if cursor.position() != data.len() as u64 {
        return DecodeOutcome::Absent;
    }
    let Value::Map(entries) = value else {
        return DecodeOutcome::Absent;
    };

    match manifest_mark(&entries) {
        ManifestMark::Absent => DecodeOutcome::Absent,
        ManifestMark::Malformed => DecodeOutcome::Malformed,
        ManifestMark::UnsupportedVersion => DecodeOutcome::UnsupportedVersion,
        ManifestMark::LegacySourceTrust => decode_legacy_source_trust_manifest(&entries),
        ManifestMark::PolicyV1 => decode_policy_manifest(&entries),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManifestMark {
    Absent,
    PolicyV1,
    LegacySourceTrust,
    Malformed,
    UnsupportedVersion,
}

fn manifest_mark(entries: &[(Value, Value)]) -> ManifestMark {
    let mut marked = false;

    match single_map_value(entries, KEY_MANIFEST) {
        MapValue::Missing => {}
        MapValue::Duplicate => return ManifestMark::Malformed,
        MapValue::Present(Value::String(value)) => match value.as_str() {
            Some(POLICY_MANIFEST_MARKER) => marked = true,
            Some(SOURCE_TRUST_MANIFEST_MARKER) => return ManifestMark::LegacySourceTrust,
            Some(value) if value.starts_with("dec_0005_policy_manifest") => {
                return ManifestMark::UnsupportedVersion;
            }
            Some(_) => {}
            None => return ManifestMark::Malformed,
        },
        MapValue::Present(_) => return ManifestMark::Malformed,
    }

    match single_map_value(entries, KEY_KIND) {
        MapValue::Missing => {}
        MapValue::Duplicate => return ManifestMark::Malformed,
        MapValue::Present(Value::String(value)) => match value.as_str() {
            Some(POLICY_MANIFEST_KIND) => marked = true,
            Some(SOURCE_TRUST_MANIFEST_KIND) => return ManifestMark::LegacySourceTrust,
            Some(_) => {}
            None => return ManifestMark::Malformed,
        },
        MapValue::Present(_) => return ManifestMark::Malformed,
    }

    if marked || has_policy_manifest_shape(entries) {
        match single_map_value(entries, KEY_SCHEMA_VERSION) {
            MapValue::Missing => ManifestMark::PolicyV1,
            MapValue::Duplicate => ManifestMark::Malformed,
            MapValue::Present(value) if schema_version_supported(value) => ManifestMark::PolicyV1,
            MapValue::Present(_) => ManifestMark::UnsupportedVersion,
        }
    } else {
        ManifestMark::Absent
    }
}

fn has_policy_manifest_shape(entries: &[(Value, Value)]) -> bool {
    matches!(single_map_value(entries, KEY_PACK_ID), MapValue::Present(_))
        && matches!(
            single_map_value(entries, KEY_DEFAULTS),
            MapValue::Present(_)
        )
        && matches!(single_map_value(entries, KEY_RULES), MapValue::Present(_))
        && matches!(
            single_map_value(entries, KEY_ACTOR_CEILINGS),
            MapValue::Present(_)
        )
}

fn schema_version_supported(value: &Value) -> bool {
    value.as_str().is_some_and(|value| {
        value == "1" || value == POLICY_MANIFEST_SCHEMA_VERSION || value == "v1"
    }) || value.as_u64() == Some(1)
}

fn decode_policy_manifest(entries: &[(Value, Value)]) -> DecodeOutcome {
    let Some(pack_id) = required_string(entries, KEY_PACK_ID) else {
        return DecodeOutcome::Malformed;
    };
    if pack_id.is_empty() {
        return DecodeOutcome::Malformed;
    }

    let Some(pack_version) = required_string(entries, KEY_PACK_VERSION) else {
        return DecodeOutcome::Malformed;
    };
    if pack_version.is_empty() {
        return DecodeOutcome::Malformed;
    }

    let Some(min_engine_version) = required_string(entries, KEY_MIN_ENGINE_VERSION) else {
        return DecodeOutcome::Malformed;
    };
    if min_engine_version.is_empty() {
        return DecodeOutcome::Malformed;
    }

    let Some(defaults) = required_axes(entries, KEY_DEFAULTS) else {
        return DecodeOutcome::Malformed;
    };
    let Some(rules) = required_rules(entries) else {
        return DecodeOutcome::Malformed;
    };
    let Some(actor_ceilings) = required_actor_ceilings(entries) else {
        return DecodeOutcome::Malformed;
    };
    let Some(scoped_grants) = optional_scoped_grants(entries) else {
        return DecodeOutcome::Malformed;
    };
    let Some(signatures) = optional_signatures(entries) else {
        return DecodeOutcome::Malformed;
    };

    let (source_trust, source_trust_unknown_axis) = match optional_source_trust(entries) {
        Some(value) => value,
        None => return DecodeOutcome::Malformed,
    };

    let has_unknown_axis =
        defaults.1 || rules.iter().any(|rule| rule.1) || source_trust_unknown_axis;
    let manifest = ResolvedManifest {
        defaults: defaults.0,
        rules: rules.into_iter().map(|(rule, _)| rule).collect(),
        actor_ceilings,
        scoped_grants,
        signatures,
        source_trust,
    };

    if version_is_above_current(&min_engine_version, CURRENT_POLICY_ENGINE_VERSION) {
        DecodeOutcome::EngineVersionFloor
    } else if has_unknown_axis {
        DecodeOutcome::UnknownAxis(manifest)
    } else {
        DecodeOutcome::Manifest(manifest)
    }
}

fn decode_legacy_source_trust_manifest(entries: &[(Value, Value)]) -> DecodeOutcome {
    let Some((source_trust, _)) = optional_source_trust(entries) else {
        return DecodeOutcome::Malformed;
    };

    DecodeOutcome::Manifest(ResolvedManifest {
        defaults: Axes::default(),
        rules: Vec::new(),
        actor_ceilings: Vec::new(),
        scoped_grants: Vec::new(),
        signatures: Vec::new(),
        source_trust,
    })
}

fn required_string(entries: &[(Value, Value)], key: &str) -> Option<String> {
    match single_map_value(entries, key) {
        MapValue::Present(Value::String(value)) => value.as_str().map(str::to_owned),
        _ => None,
    }
}

fn required_axes(entries: &[(Value, Value)], key: &str) -> Option<(Axes, bool)> {
    match single_map_value(entries, key) {
        MapValue::Present(value) => parse_axes(value),
        _ => None,
    }
}

fn required_rules(entries: &[(Value, Value)]) -> Option<Vec<(ResolvedRule, bool)>> {
    let rules = match single_map_value(entries, KEY_RULES) {
        MapValue::Present(Value::Array(rules)) => rules,
        _ => return None,
    };

    let mut out = Vec::with_capacity(rules.len());
    for rule in rules {
        let Value::Map(entries) = rule else {
            return None;
        };
        let prefix = required_string(entries, KEY_PREFIX)?;
        let (axes, unknown_axis) = required_axes(entries, KEY_AXES)?;
        out.push((ResolvedRule { prefix, axes }, unknown_axis));
    }
    Some(out)
}

fn parse_axes(value: &Value) -> Option<(Axes, bool)> {
    let Value::Map(entries) = value else {
        return None;
    };

    let mut axes = Axes::default();
    let mut unknown_axis = false;
    let mut seen_criticality = false;
    let mut seen_sensitivity = false;

    for (key, value) in entries {
        let key = key.as_str()?;
        match key {
            KEY_CRITICALITY => {
                if seen_criticality {
                    return None;
                }
                seen_criticality = true;
                axes.criticality = parse_criticality(value)?;
            }
            KEY_SENSITIVITY => {
                if seen_sensitivity {
                    return None;
                }
                seen_sensitivity = true;
                axes.sensitivity = parse_sensitivity(value)?;
            }
            SOURCE_TRUST_KEY => {
                parse_source_trust_axis(value)?;
            }
            _ => unknown_axis = true,
        }
    }

    Some((axes, unknown_axis))
}

fn parse_criticality(value: &Value) -> Option<PolicyCriticality> {
    match value.as_str()? {
        "normal" => Some(PolicyCriticality::Normal),
        "critical" => Some(PolicyCriticality::Critical),
        _ => None,
    }
}

fn parse_sensitivity(value: &Value) -> Option<PolicySensitivity> {
    match value.as_str()? {
        "normal" | "public" | "internal" => Some(PolicySensitivity::Normal),
        "sensitive" | "restricted" => Some(PolicySensitivity::Sensitive),
        _ => None,
    }
}

fn required_actor_ceilings(entries: &[(Value, Value)]) -> Option<Vec<ActorCeiling>> {
    let rows = match single_map_value(entries, KEY_ACTOR_CEILINGS) {
        MapValue::Present(Value::Array(rows)) => rows,
        _ => return None,
    };

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        let actor_class = required_string(entries, KEY_ACTOR_CLASS)?;
        if actor_class.is_empty() {
            return None;
        }
        let actor_ref = optional_string(entries, KEY_ACTOR_REF)?;
        let ceiling = ApprovalCeiling::parse(&required_string(entries, KEY_CEILING)?)?;
        out.push(ActorCeiling {
            actor_class,
            actor_ref,
            ceiling,
        });
    }
    Some(out)
}

fn optional_scoped_grants(entries: &[(Value, Value)]) -> Option<Vec<ScopedGrant>> {
    let rows = match single_map_value(entries, KEY_SCOPED_GRANTS) {
        MapValue::Missing => return Some(Vec::new()),
        MapValue::Present(Value::Array(rows)) => rows,
        _ => return None,
    };

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        let grant_id = required_string(entries, KEY_GRANT_ID)?;
        if grant_id.is_empty() {
            return None;
        }
        let actor_class = optional_string(entries, KEY_ACTOR_CLASS)?;
        let actor_ref = optional_string(entries, KEY_ACTOR_REF)?;
        let world = optional_string(entries, KEY_WORLD)?;
        let facet = optional_string(entries, KEY_FACET)?;
        let scope = optional_string(entries, KEY_SCOPE)?;
        let ceiling = match single_map_value(entries, KEY_CEILING) {
            MapValue::Missing => ApprovalCeiling::Proposed,
            MapValue::Present(Value::String(value)) => ApprovalCeiling::parse(value.as_str()?)?,
            _ => return None,
        };
        out.push(ScopedGrant {
            grant_id,
            actor_class,
            actor_ref,
            world,
            facet,
            scope,
            ceiling,
        });
    }
    Some(out)
}

fn optional_signatures(entries: &[(Value, Value)]) -> Option<Vec<PolicyManifestSignature>> {
    let rows = match single_map_value(entries, KEY_SIGNATURES) {
        MapValue::Missing => return Some(Vec::new()),
        MapValue::Present(Value::Array(rows)) => rows,
        _ => return None,
    };

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        let key_id = required_string(entries, KEY_SIG_KEY_ID)?;
        let algorithm = required_string(entries, KEY_SIG_ALG)?;
        let signature = match single_map_value(entries, KEY_SIG_VALUE) {
            MapValue::Present(Value::Binary(bytes)) => bytes.clone(),
            MapValue::Present(Value::String(value)) => value.as_str()?.as_bytes().to_vec(),
            _ => return None,
        };
        if key_id.is_empty() || algorithm.is_empty() || signature.is_empty() {
            return None;
        }
        out.push(PolicyManifestSignature {
            key_id,
            algorithm,
            signature,
        });
    }
    Some(out)
}

fn optional_string(entries: &[(Value, Value)], key: &str) -> Option<Option<String>> {
    match single_map_value(entries, key) {
        MapValue::Missing => Some(None),
        MapValue::Present(Value::String(value)) => value.as_str().map(str::to_owned).map(Some),
        _ => None,
    }
}

fn optional_source_trust(entries: &[(Value, Value)]) -> Option<(SourceTrustCeiling, bool)> {
    match single_map_value(entries, SOURCE_TRUST_KEY) {
        MapValue::Missing => Some((SourceTrustCeiling::default(), false)),
        MapValue::Duplicate => None,
        MapValue::Present(value) => parse_source_trust_axis(value),
    }
}

fn parse_source_trust_axis(value: &Value) -> Option<(SourceTrustCeiling, bool)> {
    let Value::Map(source_rows) = value else {
        return None;
    };

    let mut ceiling = SourceTrustCeiling::default();
    for (source_key, row_value) in source_rows {
        let source = source_key.as_str().and_then(ClaimSource::parse)?;
        let row = parse_source_trust_row(row_value)?;
        ceiling.set_row(source, row);
    }
    Some((ceiling, false))
}

fn parse_source_trust_row(value: &Value) -> Option<SourceTrustRow> {
    match value {
        Value::Boolean(false) => Some(SourceTrustRow {
            max_auto_sensitivity: None,
            receipted: false,
            warned: false,
        }),
        Value::Integer(_) | Value::String(_) => Some(SourceTrustRow {
            max_auto_sensitivity: sensitivity_band_from_value(value),
            receipted: false,
            warned: false,
        }),
        Value::Map(entries) => {
            let mut max_auto_sensitivity = None;
            let mut auto_disabled = false;
            let mut receipted = false;
            let mut warned = false;

            for (key, value) in entries {
                let key = key.as_str()?;
                match key {
                    SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY => {
                        max_auto_sensitivity = Some(sensitivity_band_from_value(value)?);
                    }
                    SOURCE_TRUST_AUTO_KEY => match value {
                        Value::Boolean(false) => auto_disabled = true,
                        Value::Boolean(true) => {}
                        _ => return None,
                    },
                    SOURCE_TRUST_RECEIPTED_KEY => {
                        receipted = value.as_bool()?;
                    }
                    SOURCE_TRUST_WARNED_KEY => {
                        warned = value.as_bool()?;
                    }
                    _ => {}
                }
            }

            Some(SourceTrustRow {
                max_auto_sensitivity: if auto_disabled {
                    None
                } else {
                    Some(max_auto_sensitivity?)
                },
                receipted,
                warned,
            })
        }
        _ => None,
    }
}

enum MapValue<'a> {
    Missing,
    Present(&'a Value),
    Duplicate,
}

fn single_map_value<'a>(entries: &'a [(Value, Value)], needle: &str) -> MapValue<'a> {
    let mut found = None;
    for (key, value) in entries {
        if key.as_str() == Some(needle) {
            if found.is_some() {
                return MapValue::Duplicate;
            }
            found = Some(value);
        }
    }
    found.map_or(MapValue::Missing, MapValue::Present)
}

fn version_is_above_current(required: &str, current: &str) -> bool {
    let Some(required) = parse_version_triplet(required) else {
        return true;
    };
    let Some(current) = parse_version_triplet(current) else {
        return true;
    };
    required > current
}

fn parse_version_triplet(value: &str) -> Option<(u64, u64, u64)> {
    let version = value.strip_prefix('v').unwrap_or(value);
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::{
        ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, check_source_trust,
    };
    use crate::types::{ENTITY_TYPE_TASK_LIST, VaultConfig};
    use crate::{TimeRange, Vault};

    fn test_id(seed: u8) -> EntityId {
        EntityId::from_bytes([seed; 16]).expect("valid id")
    }

    fn test_time(value: u64) -> TimeRange {
        TimeRange {
            start: value,
            end: value,
        }
    }

    fn encode_value(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, value).expect("manifest encode");
        out
    }

    fn temp_vault() -> (tempfile::TempDir, Vault) {
        let tmp = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
        (tmp, vault)
    }

    fn put_manifest(vault: &Vault, seed: u8, manifest: Value) {
        vault
            .put_entity(
                &test_id(seed),
                ENTITY_TYPE_TASK_LIST,
                test_time(1),
                1,
                &encode_value(&manifest),
            )
            .expect("put policy manifest");
    }

    fn load(vault: &Vault) -> PolicyManifestResolver {
        let wtxn = vault.store.env.write_txn().expect("write txn");
        PolicyManifestResolver::load_from_store(&vault.store, &wtxn).expect("load resolver")
    }

    fn valid_manifest() -> Value {
        let source_row = Value::Map(vec![
            (
                Value::from(SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY),
                Value::from(0_u64),
            ),
            (
                Value::from(SOURCE_TRUST_RECEIPTED_KEY),
                Value::Boolean(true),
            ),
            (Value::from(SOURCE_TRUST_WARNED_KEY), Value::Boolean(true)),
        ]);

        Value::Map(vec![
            (
                Value::from(KEY_MANIFEST),
                Value::from(POLICY_MANIFEST_MARKER),
            ),
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(POLICY_MANIFEST_SCHEMA_VERSION),
            ),
            (Value::from(KEY_PACK_ID), Value::from("core-policy")),
            (Value::from(KEY_PACK_VERSION), Value::from("2026.06.12")),
            (
                Value::from(KEY_MIN_ENGINE_VERSION),
                Value::from(CURRENT_POLICY_ENGINE_VERSION),
            ),
            (
                Value::from(KEY_DEFAULTS),
                Value::Map(vec![
                    (Value::from(KEY_CRITICALITY), Value::from("normal")),
                    (Value::from(KEY_SENSITIVITY), Value::from("normal")),
                ]),
            ),
            (
                Value::from(KEY_RULES),
                Value::Array(vec![Value::Map(vec![
                    (Value::from(KEY_PREFIX), Value::from("health.")),
                    (
                        Value::from(KEY_AXES),
                        Value::Map(vec![
                            (Value::from(KEY_CRITICALITY), Value::from("critical")),
                            (Value::from(KEY_SENSITIVITY), Value::from("sensitive")),
                        ]),
                    ),
                ])]),
            ),
            (
                Value::from(KEY_ACTOR_CEILINGS),
                Value::Array(vec![
                    Value::Map(vec![
                        (Value::from(KEY_ACTOR_CLASS), Value::from("companion")),
                        (Value::from(KEY_CEILING), Value::from("auto")),
                    ]),
                    Value::Map(vec![
                        (Value::from(KEY_ACTOR_CLASS), Value::from("mcp")),
                        (Value::from(KEY_CEILING), Value::from("proposed")),
                    ]),
                    Value::Map(vec![
                        (Value::from(KEY_ACTOR_CLASS), Value::from("companion")),
                        (Value::from(KEY_ACTOR_REF), Value::from("agent:narrowed")),
                        (Value::from(KEY_CEILING), Value::from("proposed")),
                    ]),
                ]),
            ),
            (
                Value::from(SOURCE_TRUST_KEY),
                Value::Map(vec![(Value::from("tool_output"), source_row)]),
            ),
            (
                Value::from(KEY_SCOPED_GRANTS),
                Value::Array(vec![Value::Map(vec![
                    (Value::from(KEY_GRANT_ID), Value::from("grant-1")),
                    (Value::from(KEY_ACTOR_CLASS), Value::from("mcp")),
                    (Value::from(KEY_WORLD), Value::from("world-a")),
                    (Value::from(KEY_CEILING), Value::from("proposed")),
                ])]),
            ),
            (
                Value::from(KEY_SIGNATURES),
                Value::Array(vec![Value::Map(vec![
                    (Value::from(KEY_SIG_KEY_ID), Value::from("owner-key")),
                    (Value::from(KEY_SIG_ALG), Value::from("ed25519")),
                    (Value::from(KEY_SIG_VALUE), Value::Binary(vec![0xAB; 64])),
                ])]),
            ),
        ])
    }

    #[test]
    fn policy_manifest_valid_fixture_resolves_gate_inputs() {
        let (_tmp, vault) = temp_vault();
        put_manifest(&vault, 0x31, valid_manifest());

        let resolver = load(&vault);
        assert_eq!(resolver.status(), PolicyManifestStatus::Valid);
        assert_eq!(
            resolver.resolve_criticality("health.condition"),
            PolicyCriticality::Critical
        );
        assert_eq!(
            resolver.resolve_sensitivity("profile.name"),
            PolicySensitivity::Normal
        );
        assert_eq!(
            resolver.resolve_actor_ceiling("companion", None),
            ApprovalCeiling::Auto
        );
        assert_eq!(
            resolver.resolve_actor_ceiling("companion", Some("agent:narrowed")),
            ApprovalCeiling::Proposed
        );

        let decision = resolver.resolve("health.condition", "mcp", None);
        assert_eq!(decision.actor_ceiling, ApprovalCeiling::Proposed);
        assert_eq!(decision.scoped_grants.len(), 1);
        assert_eq!(decision.signatures.len(), 1);

        let source_trust = resolver.source_trust_ceiling();
        check_source_trust(
            Some(ClaimSource::ToolOutput),
            ClaimApprovalStatus::Auto,
            Some(0),
            &source_trust,
        )
        .expect("signed fixture permits low-sensitivity tool output");
    }

    #[test]
    fn policy_manifest_missing_fixture_fails_closed() {
        let (_tmp, vault) = temp_vault();
        let resolver = load(&vault);

        assert_eq!(resolver.status(), PolicyManifestStatus::Missing);
        assert_eq!(
            resolver.resolve_criticality("profile.name"),
            PolicyCriticality::Critical
        );
        assert_eq!(
            resolver.resolve_actor_ceiling("companion", None),
            ApprovalCeiling::Proposed
        );

        let source_trust = resolver.source_trust_ceiling();
        let err = check_source_trust(
            Some(ClaimSource::ToolOutput),
            ClaimApprovalStatus::Auto,
            Some(0),
            &source_trust,
        )
        .expect_err("missing manifest rejects risky auto source");
        assert!(matches!(
            err,
            Error::SourceNotTrustedForAuto {
                claim_source: "tool_output"
            }
        ));
    }

    #[test]
    fn policy_manifest_malformed_fixture_fails_closed() {
        let (_tmp, vault) = temp_vault();
        let mut manifest = valid_manifest();
        let Value::Map(entries) = &mut manifest else {
            unreachable!("fixture map")
        };
        entries.push((Value::from(KEY_ACTOR_CEILINGS), Value::Array(Vec::new())));
        put_manifest(&vault, 0x32, manifest);

        let resolver = load(&vault);
        assert_eq!(resolver.status(), PolicyManifestStatus::Malformed);
        assert_eq!(
            resolver.resolve_sensitivity("profile.name"),
            PolicySensitivity::Sensitive
        );
    }

    #[test]
    fn policy_manifest_version_fixture_fails_closed_without_bricking() {
        let (_tmp, vault) = temp_vault();
        let mut manifest = valid_manifest();
        let Value::Map(entries) = &mut manifest else {
            unreachable!("fixture map")
        };
        for (key, value) in entries {
            if key.as_str() == Some(KEY_MIN_ENGINE_VERSION) {
                *value = Value::from("999.0.0");
            }
        }
        put_manifest(&vault, 0x33, manifest);

        let resolver = load(&vault);
        assert_eq!(resolver.status(), PolicyManifestStatus::EngineVersionFloor);
        assert_eq!(
            resolver.resolve_criticality("profile.name"),
            PolicyCriticality::Critical
        );
        assert_eq!(
            resolver.resolve_actor_ceiling("companion", None),
            ApprovalCeiling::Proposed
        );
    }

    #[test]
    fn policy_manifest_unknown_axis_degrades_to_most_restrictive_known() {
        let (_tmp, vault) = temp_vault();
        let mut manifest = valid_manifest();
        let Value::Map(entries) = &mut manifest else {
            unreachable!("fixture map")
        };
        for (key, value) in entries {
            if key.as_str() == Some(KEY_DEFAULTS) {
                let Value::Map(defaults) = value else {
                    unreachable!("defaults map")
                };
                defaults.push((Value::from("future_axis"), Value::from("permit")));
            }
        }
        put_manifest(&vault, 0x34, manifest);

        let resolver = load(&vault);
        assert_eq!(resolver.status(), PolicyManifestStatus::UnknownAxis);
        assert_eq!(
            resolver.resolve_sensitivity("profile.name"),
            PolicySensitivity::Sensitive
        );
    }

    #[test]
    fn policy_manifest_legacy_source_trust_marker_still_resolves() {
        let (_tmp, vault) = temp_vault();
        let source_row = Value::Map(vec![
            (
                Value::from(SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY),
                Value::from(0_u64),
            ),
            (
                Value::from(SOURCE_TRUST_RECEIPTED_KEY),
                Value::Boolean(true),
            ),
            (Value::from(SOURCE_TRUST_WARNED_KEY), Value::Boolean(true)),
        ]);
        put_manifest(
            &vault,
            0x35,
            Value::Map(vec![
                (
                    Value::from(KEY_MANIFEST),
                    Value::from(SOURCE_TRUST_MANIFEST_MARKER),
                ),
                (
                    Value::from(SOURCE_TRUST_KEY),
                    Value::Map(vec![(Value::from("tool_output"), source_row)]),
                ),
            ]),
        );

        let resolver = load(&vault);
        assert_eq!(resolver.status(), PolicyManifestStatus::Valid);
        check_source_trust(
            Some(ClaimSource::ToolOutput),
            ClaimApprovalStatus::Auto,
            Some(0),
            &resolver.source_trust_ceiling(),
        )
        .expect("legacy source-trust marker remains compatible");
    }

    #[test]
    fn policy_decision_inputs_are_stable_for_claim_body_fixture() {
        let (_tmp, vault) = temp_vault();
        put_manifest(&vault, 0x36, valid_manifest());
        let resolver = load(&vault);

        let body = ClaimBody::new(
            "health.condition",
            ClaimSubject::Entity(test_id(0x44)),
            Value::from("ok"),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        let decision = resolver.resolve(&body.predicate, "companion", None);
        assert_eq!(decision.criticality, PolicyCriticality::Critical);
        assert_eq!(decision.sensitivity, PolicySensitivity::Sensitive);
    }
}
