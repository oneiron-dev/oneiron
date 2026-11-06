//! Manifest v2 role bindings, per-vault narrow-only route dials, and verdict floors.
use super::{AutoCheckOutcome, CallPurpose, LlmRequest, ModelId, ModelLocality};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{
    Vault,
    error::{Error, Result},
    store::Store,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

/// The vault's pinned model-role manifest. Key: ().
const MANIFEST: SideTable<(), ModelManifest, LegacyJson> =
    SideTable::new(&side_table::LLM_MANIFEST);
/// Per-vault narrow-only resident route overrides. Key: ().
const RESIDENT_ROUTES: SideTable<(), BTreeMap<ModelSlot, ModelLocality>, LegacyJson> =
    SideTable::new(&side_table::LLM_RESIDENT_ROUTES);
/// The passing extraction-teacher probe approval behind the pinned teacher. Key: ().
const TEACHER_APPROVAL: SideTable<(), TeacherProbeApproval, LegacyJson> =
    SideTable::new(&side_table::LLM_EXTRACTION_TEACHER_PROBE);
pub mod doors;
mod encoder_export;
mod teacher_probe;
pub use encoder_export::{
    CheckpointPin, EncoderDistillationRequest, EncoderExport, SharedBaseFork,
};
pub(crate) use teacher_probe::valid_holder_ref as valid_teacher_probe_holder_ref;
pub use teacher_probe::{TEACHER_PROBE_ID, TeacherProbeApproval, TeacherProbePolicy};
// The band and basis vocabulary is the claim's own (FIX 7761).
pub use crate::claim::{ConfidenceBand, VerdictBasis};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelManifest {
    pub version: u8,
    pub roles: BTreeMap<ModelRole, ModelBinding>,
    pub routes: BTreeMap<ModelSlot, ModelLocality>,
    #[serde(default)]
    pub verdict: Option<VerdictBinding>,
    /// Owner-configured runtime seat policy. An absent row takes bundled data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seat_policy: Option<super::seat::SeatPolicy>,
}
use crate::model_binding::invalid;
fn model_for_route(
    binding: &ModelBinding,
    route: ModelLocality,
    widest: ModelLocality,
) -> Result<&ModelId> {
    if route == widest {
        Ok(&binding.model)
    } else {
        binding
            .route_models
            .get(&route)
            .ok_or_else(|| invalid("resident route has no model binding"))
    }
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
        self.seat_policy.as_ref().map_or_else(
            || super::seat::SeatPolicy::bundled().map(|_| ()),
            super::seat::SeatPolicy::validate,
        )?;
        if self.version != 2
            || MODEL_ROLES
                .iter()
                .any(|role| !role.is_optional() && !self.roles.contains_key(role))
        {
            return Err(invalid("manifest v2 requires every role key"));
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
        for binding in self.roles.values() {
            let widest = self.routes[&binding.slot];
            let mut models = std::collections::BTreeSet::from([&binding.model]);
            if binding.route_models.iter().any(|(route, model)| {
                route_rank(*route) >= route_rank(widest) || !models.insert(model)
            }) {
                return Err(invalid(
                    "route model must be distinct and narrower than the slot pin",
                ));
            }
        }
        if self
            .verdict
            .as_ref()
            .is_some_and(|v| v.slot != ModelSlot::Llm)
        {
            return Err(invalid("verdict requires llm slot"));
        }
        self.validate_families()
    }
    /// The two families stay apart: the extraction encoder binds the
    /// Oneironer slot and no other role does, and no generative role is
    /// served by a model the encoder is bound to, on any route. Tagging is
    /// never collapsed into the generative seat (ARCH-0036, OF-138).
    fn validate_families(&self) -> Result<()> {
        if self.roles.iter().any(|(role, binding)| {
            (*role == ModelRole::ExtractionEncoder) != (binding.slot == ModelSlot::Oneironer)
        }) {
            return Err(invalid(
                "extraction_encoder binds the oneironer slot, and only it does",
            ));
        }
        let models = |binding: &ModelBinding| {
            std::iter::once(binding.model.clone())
                .chain(binding.route_models.values().cloned())
                .collect::<std::collections::BTreeSet<_>>()
        };
        let encoder = models(self.binding(ModelRole::ExtractionEncoder)?);
        if self
            .roles
            .iter()
            .filter(|(role, _)| role.is_generative())
            .any(|(_, binding)| !models(binding).is_disjoint(&encoder))
        {
            return Err(invalid(
                "a generative role cannot be served by the extraction encoder's model",
            ));
        }
        Ok(())
    }
    /// The encoder the vault binds at `route`: the model the Oneironer slot
    /// must serve for this vault's turns to be tagged. A narrower route than
    /// the slot's pin takes its own route model.
    pub fn extraction_encoder(&self, route: ModelLocality) -> Result<&ModelId> {
        let binding = self.binding(ModelRole::ExtractionEncoder)?;
        let widest = *self
            .routes
            .get(&ModelSlot::Oneironer)
            .ok_or_else(|| invalid("missing slot route"))?;
        if route_rank(route) > route_rank(widest) {
            return Err(invalid("resident route cannot widen manifest pin"));
        }
        model_for_route(binding, route, widest)
    }
    pub fn binding(&self, role: ModelRole) -> Result<&ModelBinding> {
        self.roles
            .get(&role)
            .ok_or_else(|| invalid("missing role binding"))
    }
    /// The row's own disposition, else the role's default.
    pub fn disposition(&self, role: ModelRole) -> Result<ModelDisposition> {
        Ok(self
            .binding(role)?
            .disposition
            .unwrap_or(role.default_disposition()))
    }
    pub fn bind_request(
        &self,
        role: ModelRole,
        routes: &BTreeMap<ModelSlot, ModelLocality>,
        request: &mut LlmRequest,
    ) -> Result<()> {
        self.validate()?;
        let binding = self.binding(role)?;
        // An offline role binds background work only: a served call through
        // it is refused until the owner marks its row served.
        if self.disposition(role)? == ModelDisposition::Offline
            && !matches!(
                request.envelope.purpose,
                CallPurpose::Extraction
                    | CallPurpose::Consolidation
                    | CallPurpose::Eval
                    | CallPurpose::AutonomyForHuman
                    | CallPurpose::AutonomyOwnTime
            )
        {
            return Err(invalid(
                "this role is offline: it serves background passes, not a served call; set its manifest row's disposition to served to route a seat to it",
            ));
        }
        let widest = *self
            .routes
            .get(&binding.slot)
            .ok_or_else(|| invalid("missing slot route"))?;
        let route = routes.get(&binding.slot).copied().unwrap_or(widest);
        if route_rank(route) > route_rank(widest) {
            return Err(invalid("resident route cannot widen manifest pin"));
        }
        request.model = model_for_route(binding, route, widest)?.clone();
        request.envelope.locality = route;
        request.envelope.tier.vault_policy = Some(binding.tier.clone());
        Ok(())
    }
}
pub(crate) fn read_manifest(store: &Store, txn: &heed::RoTxn<'_>) -> Result<Option<ModelManifest>> {
    let Some(manifest) = MANIFEST.get(store, txn, &())? else {
        return Ok(None);
    };
    manifest.validate()?;
    Ok(Some(manifest))
}
impl Vault {
    /// Update a manifest without changing its approved extraction-teacher binding.
    /// Initial teacher pins, and any teacher change, require a passing probe receipt.
    pub fn set_model_manifest(&self, manifest: &ModelManifest) -> Result<()> {
        self.write_model_manifest(manifest, None, None)
    }

    /// Publish the bench-approved teacher binding and its receipt in one vault transaction.
    pub fn set_model_manifest_with_teacher_approval(
        &self,
        manifest: &ModelManifest,
        approval: &TeacherProbeApproval,
    ) -> Result<()> {
        self.write_model_manifest(manifest, Some(approval), None)
    }

    fn write_model_manifest(
        &self,
        manifest: &ModelManifest,
        new_approval: Option<&TeacherProbeApproval>,
        new_encoder_export: Option<&EncoderExport>,
    ) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        self.write_model_manifest_in_txn(&mut txn, manifest, new_approval, new_encoder_export)?;
        txn.commit()?;
        Ok(())
    }

    /// Training swaps commit their receipt and custody binding with the manifest.
    pub(crate) fn write_model_manifest_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        manifest: &ModelManifest,
        new_approval: Option<&TeacherProbeApproval>,
        new_encoder_export: Option<&EncoderExport>,
    ) -> Result<()> {
        manifest.validate()?;
        let saved_approval = TEACHER_APPROVAL.get(&self.store, txn, &())?;
        let approval = new_approval
            .or(saved_approval.as_ref())
            .ok_or_else(|| invalid("extraction_teacher pin requires a passing probe approval"))?;
        let policy = self.teacher_probe_policy_in_txn(txn, approval.holder_ref.as_deref())?;
        approval.verify(manifest, &policy)?;
        if let Some(export) = new_encoder_export {
            if &export.request.teacher_approval != approval {
                return Err(invalid(
                    "encoder export requires the pinned teacher approval",
                ));
            }
            export.verify(manifest, &policy)?;
            encoder_export::ENCODER_EXPORT.put(&self.store, txn, &(), export)?;
        } else if let Some(export) = encoder_export::ENCODER_EXPORT.get(&self.store, txn, &())? {
            if &export.request.teacher_approval != approval
                || export.verify(manifest, &policy).is_err()
            {
                encoder_export::ENCODER_EXPORT.delete(&self.store, txn, &())?;
            }
        }
        if let Some(approval) = new_approval {
            TEACHER_APPROVAL.put(&self.store, txn, &(), approval)?;
        }
        // Each resident narrowing the new pins still admit stays, so a bind on
        // one slot leaves the owner's other narrowed slots as they were (FIX
        // 9919). One the new pins widen past, or leave without a model at its
        // route, clears in this transaction; so does a row that does not
        // decode, as every write cleared it before.
        let kept: BTreeMap<_, _> = read_routes(&self.store, txn)
            .unwrap_or_default()
            .into_iter()
            .filter(|(slot, route)| route_admits(manifest, *slot, *route).is_ok())
            .collect();
        if kept.is_empty() {
            RESIDENT_ROUTES.delete(&self.store, txn, &())?;
        } else {
            RESIDENT_ROUTES.put(&self.store, txn, &(), &kept)?;
        }
        MANIFEST.put(&self.store, txn, &(), manifest)
    }
    pub fn model_manifest(&self) -> Result<Option<ModelManifest>> {
        read_manifest(&self.store, &self.store.env.read_txn()?)
    }
    /// The model a call of `role` binds in the caller's snapshot: the
    /// manifest's pin at the slot's effective route, or `fallback` (the
    /// role's seat) when no manifest is set. A candidate to price, not
    /// serving authority: whether a host serves it is the host's to say.
    pub fn price_model_for_role_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        role: ModelRole,
        fallback: &ModelId,
    ) -> Result<ModelId> {
        let Some(manifest) = read_manifest(&self.store, txn)? else {
            return Ok(fallback.clone());
        };
        let binding = manifest.binding(role)?;
        let widest = *manifest
            .routes
            .get(&binding.slot)
            .ok_or_else(|| invalid("missing slot route"))?;
        let route = read_routes(&self.store, txn)?
            .get(&binding.slot)
            .copied()
            .unwrap_or(widest);
        if route_rank(route) > route_rank(widest) {
            return Err(invalid("resident route cannot widen manifest pin"));
        }
        Ok(model_for_route(binding, route, widest)?.clone())
    }
    /// Effective per-vault route, including a resident narrowing if present.
    pub fn model_route(&self, slot: ModelSlot) -> Result<Option<ModelLocality>> {
        let txn = self.store.env.read_txn()?;
        let Some(manifest) = read_manifest(&self.store, &txn)? else {
            return Ok(None);
        };
        Ok(Some(effective_route(
            &manifest,
            &read_routes(&self.store, &txn)?,
            slot,
        )?))
    }
    pub fn set_model_route(&self, slot: ModelSlot, route: ModelLocality) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        self.set_model_route_in_txn(&mut txn, slot, route)?;
        txn.commit()?;
        Ok(())
    }
    fn set_model_route_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        slot: ModelSlot,
        route: ModelLocality,
    ) -> Result<()> {
        let manifest =
            read_manifest(&self.store, txn)?.ok_or_else(|| invalid("manifest not configured"))?;
        route_admits(&manifest, slot, route)?;
        let mut routes = read_routes(&self.store, txn)?;
        routes.insert(slot, route);
        RESIDENT_ROUTES.put(&self.store, txn, &(), &routes)
    }
}
/// Whether `manifest` admits a resident narrowing of `slot` to `route`: no
/// wider than the slot's pin, and every served role on the slot has a model
/// at that route.
fn route_admits(manifest: &ModelManifest, slot: ModelSlot, route: ModelLocality) -> Result<()> {
    let pin = *manifest
        .routes
        .get(&slot)
        .ok_or_else(|| invalid("missing slot route"))?;
    if route_rank(route) > route_rank(pin) {
        return Err(invalid("resident route cannot widen manifest pin"));
    }
    for (role, binding) in &manifest.roles {
        if *role != ModelRole::ExtractionTeacher && binding.slot == slot {
            model_for_route(binding, route, pin)?;
        }
    }
    Ok(())
}
pub(super) fn effective_route(
    manifest: &ModelManifest,
    routes: &BTreeMap<ModelSlot, ModelLocality>,
    slot: ModelSlot,
) -> Result<ModelLocality> {
    let pin = manifest.routes[&slot];
    let route = routes.get(&slot).copied().unwrap_or(pin);
    if route_rank(route) > route_rank(pin) {
        return Err(invalid("resident route cannot widen manifest pin"));
    }
    Ok(route)
}
pub(super) fn read_routes(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<BTreeMap<ModelSlot, ModelLocality>> {
    Ok(RESIDENT_ROUTES.get(store, txn, &())?.unwrap_or_default())
}
pub(crate) use crate::claim_check::apply_verdict_floor;
#[cfg(test)]
mod tests;

pub use crate::model_binding::{
    CalibratedVerdict, MODEL_ROLES, ModelBinding, ModelDisposition, ModelRole, ModelSlot,
    VerdictBinding, VerdictMode,
};
