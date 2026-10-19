//! Owner-proof model manifest, independent route dials and resolved role receipts.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{
    ModelManifest, ModelRole, ModelSlot, TeacherProbeApproval, invalid, model_for_route,
    read_manifest, read_routes,
};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::memory::extraction::EncoderOutput;
use crate::{LlmRequest, LlmResponse, ModelId, ModelLocality, ModelTierRef, Vault};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelManifestReplace {
    pub manifest: ModelManifest,
    /// Required for the initial teacher pin or a change to that binding.
    #[serde(default)]
    pub teacher_approval: Option<TeacherProbeApproval>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelRouteRead {
    pub slot: ModelSlot,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelRouteReplace {
    pub slot: ModelSlot,
    pub route: ModelLocality,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelRouteView {
    pub slot: ModelSlot,
    pub pin: Option<ModelLocality>,
    pub route: Option<ModelLocality>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelRoleRead {
    pub role: ModelRole,
}

/// A role's binding in one snapshot, not permission to execute it. A call
/// returns the same facts for the model and route its provider actually used.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelRoleReceipt {
    pub role: ModelRole,
    pub model: ModelId,
    pub revision: String,
    pub provider: String,
    pub slot: ModelSlot,
    pub tier: ModelTierRef,
    pub route: ModelLocality,
    /// BLAKE3 of the registered catalog entry in this snapshot, not a
    /// provider-supplied revision. None when the host alone attests the model.
    pub catalog_revision: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelRoleInvoke {
    pub role: ModelRole,
    pub input: ModelRoleInput,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ModelRoleInput {
    /// The role selects model and route; the request cannot override either.
    Generate { request: Box<LlmRequest> },
    /// A query through the vault's retrieval embedder, not a media seat.
    Embed { text: String },
    /// A write-free extraction over caller-supplied text, never a claim write.
    Tag { text: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelRoleInvocation {
    pub receipt: ModelRoleReceipt,
    pub output: ModelRoleOutput,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ModelRoleOutput {
    Generated { response: LlmResponse },
    Embedded { vector: Vec<f32> },
    Tagged { output: EncoderOutput },
}

fn route_view(
    manifest: Option<&ModelManifest>,
    routes: &BTreeMap<ModelSlot, ModelLocality>,
    slot: ModelSlot,
) -> Result<ModelRouteView> {
    Ok(ModelRouteView {
        slot,
        pin: manifest.map(|manifest| manifest.routes[&slot]),
        route: manifest
            .map(|manifest| super::effective_route(manifest, routes, slot))
            .transpose()?,
    })
}

impl Vault {
    pub fn model_manifest_as_owner(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<Option<ModelManifest>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        read_manifest(&self.store, &txn)
    }

    /// The proof, teacher approval and manifest guards all run under this
    /// writer. The returned manifest is the one this transaction published.
    pub fn replace_model_manifest_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: ModelManifestReplace,
    ) -> Result<ModelManifest> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        self.write_model_manifest_in_txn(
            &mut txn,
            &input.manifest,
            input.teacher_approval.as_ref(),
            None,
        )?;
        txn.commit()?;
        Ok(input.manifest)
    }

    pub fn model_route_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: ModelRouteRead,
    ) -> Result<ModelRouteView> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let manifest = read_manifest(&self.store, &txn)?;
        route_view(manifest.as_ref(), &read_routes(&self.store, &txn)?, input.slot)
    }

    pub fn replace_model_route_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: ModelRouteReplace,
    ) -> Result<ModelRouteView> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        self.set_model_route_in_txn(&mut txn, input.slot, input.route)?;
        let manifest = read_manifest(&self.store, &txn)?;
        let view = route_view(manifest.as_ref(), &read_routes(&self.store, &txn)?, input.slot)?;
        txn.commit()?;
        Ok(view)
    }

    pub fn model_role_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: ModelRoleRead,
    ) -> Result<ModelRoleReceipt> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let manifest = read_manifest(&self.store, &txn)?
            .ok_or_else(|| invalid("manifest not configured"))?;
        let binding = manifest.binding(input.role)?;
        let route = super::effective_route(
            &manifest,
            &read_routes(&self.store, &txn)?,
            binding.slot,
        )?;
        let model = model_for_route(binding, route, manifest.routes[&binding.slot])?;
        let registered = super::super::registry::read_model_registry_row(
            &self.store,
            &txn,
            model,
        )?;
        let catalog_revision = catalog_revision(registered.as_ref())?;
        Ok(ModelRoleReceipt {
            role: input.role,
            revision: model.revision().to_owned(),
            provider: model.provider().to_owned(),
            model: model.clone(),
            slot: binding.slot,
            tier: binding.tier.clone(),
            route,
            catalog_revision,
        })
    }
}

/// The catalog identity inference admission and displayed role receipts share.
pub(in crate::llm) fn catalog_revision(
    row: Option<&crate::llm::registry::ModelRegistryRow>,
) -> Result<Option<String>> {
    row.map(|row| {
        serde_json::to_vec(&row.catalog)
            .map(|bytes| blake3::hash(&bytes).to_hex().to_string())
            .map_err(|_| invalid("model catalog fingerprint could not be encoded"))
    })
    .transpose()
}
