//! Owner-proof model manifest, independent route dials and resolved role receipts.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{
    ModelManifest, ModelRole, ModelSlot, TeacherProbeApproval, invalid, model_for_route,
    read_manifest, read_routes,
};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::memory::extraction::{EncoderExecution, EncoderOutput};
use crate::{LlmRequest, LlmResponse, ModelId, ModelLocality, ModelTierRef, Vault};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelManifestReplace {
    pub manifest: ModelManifest,
    /// Required for the initial teacher pin or a change to that binding.
    #[serde(default)]
    pub teacher_approval: Option<TeacherProbeApproval>,
}

/// Binds the Oneironer the server has loaded. The binding's identity is the
/// loaded slot's; these guards only compare with it, and a mismatch refuses.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OneironerBind {
    /// The checkpoint the caller expects the loaded Oneironer to serve.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_checkpoint_sha16: Option<String>,
    /// The stack the caller expects the loaded Oneironer to serve.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_stack_sha16: Option<String>,
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
    Generated {
        response: LlmResponse,
    },
    Embedded {
        vector: Vec<f32>,
    },
    Tagged {
        output: EncoderOutput,
        /// What ran this call: the worker's runtime, compute and pick. Never
        /// a binding read, which cannot know a later call's worker.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        execution: Option<EncoderExecution>,
    },
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

    /// Binds `model`, the Oneironer a host has loaded, into the current
    /// manifest under this writer: `extraction_encoder` takes it in the
    /// Oneironer slot at `tier`, the tier the host names the loaded bundle
    /// by, never the row's current one, and the Oneironer route is pinned on
    /// the device. Every other role, route, the verdict and the seat policy
    /// stay. The proof, the saved teacher approval and the manifest guards
    /// run here as a replace runs them, and so does the rest of that write: a
    /// stale encoder export is dropped, and a resident route override stays
    /// only while the new pins still admit it (FIX 9919).
    /// The returned manifest is the one this transaction published. A vault
    /// with no manifest is refused.
    pub fn bind_oneironer_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        model: &ModelId,
        tier: &ModelTierRef,
    ) -> Result<ModelManifest> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let mut manifest =
            read_manifest(&self.store, &txn)?.ok_or_else(|| invalid("manifest not configured"))?;
        let current = manifest.binding(ModelRole::ExtractionEncoder)?;
        let row = super::ModelBinding {
            model: model.clone(),
            slot: ModelSlot::Oneironer,
            tier: tier.clone(),
            // The on-device pin is the narrowest route: no route model is
            // narrower than it.
            route_models: BTreeMap::new(),
            disposition: current.disposition,
            reads_audio: current.reads_audio,
        };
        manifest.roles.insert(ModelRole::ExtractionEncoder, row);
        manifest
            .routes
            .insert(ModelSlot::Oneironer, ModelLocality::OnDevice);
        self.write_model_manifest_in_txn(&mut txn, &manifest, None, None)?;
        txn.commit()?;
        Ok(manifest)
    }

    pub fn model_route_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: ModelRouteRead,
    ) -> Result<ModelRouteView> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let manifest = read_manifest(&self.store, &txn)?;
        route_view(
            manifest.as_ref(),
            &read_routes(&self.store, &txn)?,
            input.slot,
        )
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
        let view = route_view(
            manifest.as_ref(),
            &read_routes(&self.store, &txn)?,
            input.slot,
        )?;
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
        let manifest =
            read_manifest(&self.store, &txn)?.ok_or_else(|| invalid("manifest not configured"))?;
        let binding = manifest.binding(input.role)?;
        let route =
            super::effective_route(&manifest, &read_routes(&self.store, &txn)?, binding.slot)?;
        let model = model_for_route(binding, route, manifest.routes[&binding.slot])?;
        let registered = super::super::registry::read_model_registry_row(&self.store, &txn, model)?;
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
