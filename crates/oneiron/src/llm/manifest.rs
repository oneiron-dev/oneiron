//! Manifest v2 role bindings, per-vault narrow-only route dials, and verdict floors.
use super::{AutoCheckOutcome, LlmRequest, ModelId, ModelLocality, ModelTierRef};
use crate::{
    Vault,
    error::{Error, Result},
    store::Store,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};
const MANIFEST_KEY: &[u8] = b"llm:manifest:v2";
const ROUTES_KEY: &[u8] = b"llm:resident_routes:v1";
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelRole {
    RetrievalEmbedder,
    Reranker,
    ExtractionEncoder,
    ExtractionTeacher,
    GenerativeReasoner,
    Checker,
    DreamerCurrent,
    DreamerTarget,
    Asr,
    Captioner,
    DocParsing,
    AudioVad,
    TtsDeferred,
}
pub const MODEL_ROLES: [ModelRole; 13] = [
    ModelRole::RetrievalEmbedder,
    ModelRole::Reranker,
    ModelRole::ExtractionEncoder,
    ModelRole::ExtractionTeacher,
    ModelRole::GenerativeReasoner,
    ModelRole::Checker,
    ModelRole::DreamerCurrent,
    ModelRole::DreamerTarget,
    ModelRole::Asr,
    ModelRole::Captioner,
    ModelRole::DocParsing,
    ModelRole::AudioVad,
    ModelRole::TtsDeferred,
];
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelSlot {
    Llm,
    Embedder,
    Oneironer,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelBinding {
    pub model: ModelId,
    pub slot: ModelSlot,
    pub tier: ModelTierRef,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceBand {
    Low,
    Medium,
    High,
    Certain,
}
impl ConfidenceBand {
    fn for_confidence(value: u32) -> Option<Self> {
        match value {
            0..=499_999 => Some(Self::Low),
            500_000..=799_999 => Some(Self::Medium),
            800_000..=979_999 => Some(Self::High),
            980_000..=1_000_000 => Some(Self::Certain),
            _ => None,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictMode {
    Shadow,
    Enforce,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerdictBinding {
    pub model: ModelId,
    pub slot: ModelSlot,
    pub floor: ConfidenceBand,
    pub mode: VerdictMode,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictBasis {
    CalibratedModel,
    DeterministicFallback,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibratedVerdict {
    pub model: ModelId,
    pub allow: bool,
    pub confidence_millionths: u32,
    pub band: ConfidenceBand,
    pub basis: VerdictBasis,
}
impl CalibratedVerdict {
    pub fn validate(&self) -> Result<()> {
        if ConfidenceBand::for_confidence(self.confidence_millionths) != Some(self.band) {
            return Err(invalid("verdict confidence and band mismatch"));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelManifest {
    pub version: u8,
    pub roles: BTreeMap<ModelRole, ModelBinding>,
    pub routes: BTreeMap<ModelSlot, ModelLocality>,
    #[serde(default)]
    pub verdict: Option<VerdictBinding>,
}
fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.into())
}
fn route_rank(route: ModelLocality) -> u8 {
    match route {
        ModelLocality::OnDevice => 0,
        ModelLocality::OwnServer => 1,
        ModelLocality::ThirdParty => 2,
    }
}
impl ModelManifest {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let value: Self =
            serde_json::from_slice(bytes).map_err(|e| Error::InvalidConfig(e.to_string()))?;
        value.validate()?;
        Ok(value)
    }
    pub fn load(path: &Path) -> Result<Self> {
        Self::from_json(&std::fs::read(path)?)
    }
    pub fn validate(&self) -> Result<()> {
        if self.version != 2
            || MODEL_ROLES
                .iter()
                .any(|role| !self.roles.contains_key(role))
        {
            return Err(invalid("manifest v2 requires all 13 roles"));
        }
        if [ModelSlot::Llm, ModelSlot::Embedder, ModelSlot::Oneironer]
            .iter()
            .any(|slot| !self.routes.contains_key(slot))
        {
            return Err(invalid("manifest requires route for each slot"));
        }
        if self
            .roles
            .values()
            .any(|row| row.tier.as_str().trim().is_empty())
        {
            return Err(invalid("empty model tier"));
        }
        if self
            .verdict
            .as_ref()
            .is_some_and(|v| v.slot != ModelSlot::Llm)
        {
            return Err(invalid("verdict requires llm slot"));
        }
        Ok(())
    }
    pub fn binding(&self, role: ModelRole) -> Result<&ModelBinding> {
        self.roles
            .get(&role)
            .ok_or_else(|| invalid("missing role binding"))
    }
    pub fn bind_request(
        &self,
        role: ModelRole,
        routes: &BTreeMap<ModelSlot, ModelLocality>,
        request: &mut LlmRequest,
    ) -> Result<()> {
        self.validate()?;
        let binding = self.binding(role)?;
        let widest = *self
            .routes
            .get(&binding.slot)
            .ok_or_else(|| invalid("missing slot route"))?;
        let route = routes.get(&binding.slot).copied().unwrap_or(widest);
        if route_rank(route) > route_rank(widest) {
            return Err(invalid("resident route cannot widen manifest pin"));
        }
        request.model = binding.model.clone();
        request.envelope.locality = route;
        request.envelope.tier.vault_policy = Some(binding.tier.clone());
        Ok(())
    }
}
pub(crate) fn read_manifest(store: &Store, txn: &heed::RoTxn<'_>) -> Result<Option<ModelManifest>> {
    store
        .vault_meta
        .get(txn, MANIFEST_KEY)?
        .map(|bytes| ModelManifest::from_json(&bytes))
        .transpose()
}
impl Vault {
    pub fn set_model_manifest(&self, manifest: &ModelManifest) -> Result<()> {
        manifest.validate()?;
        let mut txn = self.store.env.write_txn()?;
        // A tighter owner pin clears stale resident routes atomically.
        self.store.vault_meta.delete(&mut txn, ROUTES_KEY)?;
        let bytes =
            serde_json::to_vec(manifest).map_err(|e| Error::InvalidConfig(e.to_string()))?;
        self.store.vault_meta.put(&mut txn, MANIFEST_KEY, &bytes)?;
        txn.commit()?;
        Ok(())
    }
    pub fn model_manifest(&self) -> Result<Option<ModelManifest>> {
        read_manifest(&self.store, &self.store.env.read_txn()?)
    }
    pub fn set_model_route(&self, slot: ModelSlot, route: ModelLocality) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        let manifest =
            read_manifest(&self.store, &txn)?.ok_or_else(|| invalid("manifest not configured"))?;
        if route_rank(route) > route_rank(manifest.routes[&slot]) {
            return Err(invalid("resident route cannot widen manifest pin"));
        }
        let mut routes = read_routes(&self.store, &txn)?;
        routes.insert(slot, route);
        let bytes = serde_json::to_vec(&routes).map_err(|e| Error::InvalidConfig(e.to_string()))?;
        self.store.vault_meta.put(&mut txn, ROUTES_KEY, &bytes)?;
        txn.commit()?;
        Ok(())
    }
    /// Call-path binding: absent manifest preserves explicit host configuration.
    pub fn bind_model_role(&self, role: ModelRole, request: &mut LlmRequest) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        if let Some(manifest) = read_manifest(&self.store, &txn)? {
            manifest.bind_request(role, &read_routes(&self.store, &txn)?, request)?;
        }
        Ok(())
    }
}
fn read_routes(store: &Store, txn: &heed::RoTxn<'_>) -> Result<BTreeMap<ModelSlot, ModelLocality>> {
    store
        .vault_meta
        .get(txn, ROUTES_KEY)?
        .map(|bytes| {
            serde_json::from_slice(&bytes).map_err(|e| Error::InvalidConfig(e.to_string()))
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

/// A calibrated check can only hold. Shadow emits a receipt reason without holding.
pub(crate) fn apply_verdict_floor(
    binding: Option<&VerdictBinding>,
    outcome: AutoCheckOutcome,
) -> (AutoCheckOutcome, Option<&'static str>) {
    let Some(binding) = binding else {
        return (
            if matches!(outcome, AutoCheckOutcome::Verdict(_)) {
                AutoCheckOutcome::Unavailable
            } else {
                outcome
            },
            None,
        );
    };
    let pass = matches!(&outcome, AutoCheckOutcome::Verdict(v) if v.validate().is_ok() && v.model == binding.model && v.allow && v.band >= binding.floor && v.basis == VerdictBasis::CalibratedModel);
    if pass {
        return (AutoCheckOutcome::Allow, Some("verdict_pass"));
    }
    match binding.mode {
        VerdictMode::Shadow => (AutoCheckOutcome::Allow, Some("verdict_shadow_hold")),
        VerdictMode::Enforce => (
            AutoCheckOutcome::Hold {
                reasons: vec!["verdict_floor".into()],
            },
            Some("verdict_enforce_hold"),
        ),
    }
}
#[cfg(test)]
mod tests;
