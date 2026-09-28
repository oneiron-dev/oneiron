//! One snapshot and one admission for policy-managed inference calls.
//! A row requests a route; only a concrete host/catalog binding establishes it.
use std::collections::BTreeMap;

use super::{
    CallPurpose, ExtractionEgressPredicate, LlmRequest, ModelId, ModelLocality,
    ValidatedPurposeDefaults, defaults,
    manifest::{self, ModelManifest, ModelRole, ModelSlot},
    registry::{self, ModelRegistryRow, ModelWireFormat},
};
use crate::{
    Vault,
    error::{Error, Result},
    store::Store,
};

/// Host-provided evidence of the transport behind a selected model. Registered
/// means the live catalog row must exist. Advertised means the injected host
/// attests its own backend's identity and locality; a catalog row, if present,
/// must agree. Neither form can relabel an existing local/remote model.
#[derive(Debug, Clone)]
pub enum HostInferenceBinding {
    Registered,
    Advertised {
        model: ModelId,
        locality: ModelLocality,
    },
}

/// The actual backend and nonlocal extraction authority are host inputs, never
/// fields supplied by an LLM request or by the editable policy table.
pub struct HostInferenceContext<'a> {
    pub binding: HostInferenceBinding,
    pub extraction_egress: Option<&'a dyn ExtractionEgressPredicate>,
}
impl HostInferenceContext<'_> {
    pub fn selected_locality(&self) -> Option<ModelLocality> {
        match &self.binding {
            HostInferenceBinding::Registered => None,
            HostInferenceBinding::Advertised { locality, .. } => Some(*locality),
        }
    }
}

/// Private, verified identity returned beside the final request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundInference {
    model: ModelId,
    locality: ModelLocality,
    wire: Option<ModelWireFormat>,
}
impl BoundInference {
    pub fn model(&self) -> &ModelId {
        &self.model
    }
    pub fn locality(&self) -> ModelLocality {
        self.locality
    }
    pub fn wire(&self) -> Option<ModelWireFormat> {
        self.wire
    }
}

/// Only the validated request can be passed to budget/provider by managed callers.
pub struct AuthorizedInference {
    request: LlmRequest,
    binding: BoundInference,
}
impl AuthorizedInference {
    pub fn request(&self) -> &LlmRequest {
        &self.request
    }
    pub fn binding(&self) -> &BoundInference {
        &self.binding
    }
    pub fn into_request(self) -> LlmRequest {
        self.request
    }
}

/// The effective rows and routing inputs from ONE LMDB read snapshot. Absence
/// is resolved here, not independently in HTTP and in the role binder.
pub struct InferencePolicySnapshot {
    defaults: ValidatedPurposeDefaults,
    manifest: Option<ModelManifest>,
    routes: BTreeMap<ModelSlot, ModelLocality>,
    registry: Option<ModelRegistryRow>,
    role_bound: bool,
}
impl InferencePolicySnapshot {
    fn load(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        role: Option<ModelRole>,
        request: &mut LlmRequest,
    ) -> Result<Self> {
        let defaults = defaults::read_effective_defaults(store, txn)?;
        // Raw calls have their own explicit host-selected model; a role call
        // may instead bind a manifest model. Read its registry row afterwards.
        let manifest = if role.is_some() {
            manifest::read_manifest(store, txn)?
        } else {
            None
        };
        let routes = if manifest.is_some() {
            manifest::read_routes(store, txn)?
        } else {
            BTreeMap::new()
        };
        defaults.table().apply(&mut request.envelope);
        if let (Some(role), Some(manifest)) = (role, &manifest) {
            manifest.bind_request(role, &routes, request)?;
        }
        let registry = registry::read_model_registry_row(store, txn, &request.model)?;
        if role.is_none()
            && let Some(row) = &registry
        {
            request.envelope.locality = row.catalog.locality;
        }
        Ok(Self {
            defaults,
            manifest,
            routes,
            registry,
            role_bound: role.is_some(),
        })
    }
    pub fn defaults(&self) -> &ValidatedPurposeDefaults {
        &self.defaults
    }
    pub fn has_manifest(&self) -> bool {
        self.manifest.is_some()
    }
    pub fn routes(&self) -> &BTreeMap<ModelSlot, ModelLocality> {
        &self.routes
    }

    fn bind(
        &self,
        request: &LlmRequest,
        host: &HostInferenceContext<'_>,
    ) -> Result<BoundInference> {
        if self.role_bound
            && self.manifest.is_none()
            && request.envelope.tier.per_seat.is_none()
            && self
                .defaults
                .table()
                .purpose(&request.envelope.purpose)
                .is_some_and(|row| row.locality != request.envelope.locality)
        {
            return Err(invalid("no model binding for inference default locality"));
        }
        let selected = &request.model;
        let locality = match &host.binding {
            HostInferenceBinding::Registered => {
                self.registry
                    .as_ref()
                    .ok_or_else(|| invalid("no registered model for host transport"))?
                    .catalog
                    .locality
            }
            HostInferenceBinding::Advertised { model, locality } if model == selected => *locality,
            HostInferenceBinding::Advertised { .. } => {
                return Err(invalid("host backend model differs from selected route"));
            }
        };
        if locality != request.envelope.locality {
            return Err(invalid("model locality differs from bound transport"));
        }
        if let Some(row) = &self.registry
            && row.catalog.locality != locality
        {
            return Err(invalid("registry locality differs from host transport"));
        }
        // A local lease must be backed by a registered Local transport, not
        // by caller JSON or an unverified host label.
        if locality == ModelLocality::OnDevice
            && !self.registry.as_ref().is_some_and(|row| {
                row.wire == ModelWireFormat::Local
                    && row.catalog.locality == ModelLocality::OnDevice
            })
        {
            return Err(invalid("local inference has no local model binding"));
        }
        Ok(BoundInference {
            model: selected.clone(),
            locality,
            wire: self.registry.as_ref().map(|row| row.wire),
        })
    }
}
fn invalid(reason: &'static str) -> Error {
    Error::InvalidConfig(reason.into())
}

/// The same final-request predicate for role-bound calls and raw HTTP calls.
fn admit_extraction(
    snapshot: &InferencePolicySnapshot,
    request: &LlmRequest,
    binding: &BoundInference,
    host: &HostInferenceContext<'_>,
) -> Result<()> {
    if request.envelope.purpose != CallPurpose::Extraction
        || binding.locality == ModelLocality::OnDevice
    {
        return Ok(());
    }
    if !defaults::locality_within_extraction_bound(
        binding.locality,
        snapshot.defaults.table().extraction_max_locality,
    ) || !host
        .extraction_egress
        .is_some_and(|predicate| predicate.permits(request))
    {
        return Err(invalid(
            "nonlocal extraction needs host egress authorization",
        ));
    }
    Ok(())
}

impl Vault {
    fn authorize_inference(
        &self,
        role: Option<ModelRole>,
        request: LlmRequest,
        host: &HostInferenceContext<'_>,
    ) -> Result<AuthorizedInference> {
        let mut request = request;
        let txn = self.store.env.read_txn()?;
        let snapshot = InferencePolicySnapshot::load(&self.store, &txn, role, &mut request)?;
        let binding = snapshot.bind(&request, host)?;
        drop(txn); // Host code may read the vault; never call it under an LMDB reader.
        admit_extraction(&snapshot, &request, &binding, host)?;
        Ok(AuthorizedInference { request, binding })
    }
    pub fn authorize_model_role(
        &self,
        role: ModelRole,
        request: LlmRequest,
        host: &HostInferenceContext<'_>,
    ) -> Result<AuthorizedInference> {
        self.authorize_inference(Some(role), request, host)
    }
    pub fn authorize_raw_inference(
        &self,
        request: LlmRequest,
        host: &HostInferenceContext<'_>,
    ) -> Result<AuthorizedInference> {
        self.authorize_inference(None, request, host)
    }
}
