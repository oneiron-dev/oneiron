//! One snapshot and one admission for policy-managed inference calls.
//! A row requests a route; only a concrete host/catalog binding establishes it.
use std::collections::BTreeMap;

use super::{
    CallPurpose, LlmRequest, ModelId, ModelLocality, ValidatedPurposeDefaults, defaults,
    manifest::{self, ModelManifest, ModelRole, ModelSlot},
    registry::{self, ModelRegistryRow, ModelWireFormat},
};
use crate::{
    Vault,
    error::{Error, Result},
    store::Store,
};

/// Private, verified identity returned beside the final request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundInference {
    model: ModelId,
    locality: ModelLocality,
    wire: Option<ModelWireFormat>,
    catalog_revision: Option<String>,
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
    /// The registered catalog entry the authorizer read for this call.
    pub fn catalog_revision(&self) -> Option<&str> {
        self.catalog_revision.as_deref()
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
        host: &HostInferenceBinding,
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
        // `PurposeDefaultTable::apply`, on the row the call is admitted as.
        if let Some(row) = defaults
            .table()
            .purpose(admitted_as(&request.envelope.purpose))
        {
            request.envelope.tier.purpose_default = Some(row.tier.clone());
        }
        if let (Some(role), Some(manifest)) = (role, &manifest) {
            manifest.bind_request(role, &routes, request)?;
        }
        // Installed catalog rows are stored rows: the pack install activates them.
        let registry = registry::read_model_registry_row(store, txn, &request.model)?;
        // A raw call takes its row's locality, except on the host's
        // supervised native transport (I2-LOCAL): that row names the
        // provider's own-server endpoint, and `bind` checks it as that.
        if role.is_none()
            && !matches!(host, HostInferenceBinding::SupervisedNativeLocal { .. })
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
                .purpose(admitted_as(&request.envelope.purpose))
                .is_some_and(|row| row.locality != request.envelope.locality)
        {
            return Err(invalid(InferenceRefusal::NoDefaultBinding));
        }
        let selected = &request.model;
        let native = matches!(
            host.binding,
            HostInferenceBinding::SupervisedNativeLocal { .. }
        );
        let locality = match &host.binding {
            HostInferenceBinding::Registered => {
                self.registry
                    .as_ref()
                    .ok_or_else(|| invalid(InferenceRefusal::NoRegisteredModel))?
                    .catalog
                    .locality
            }
            HostInferenceBinding::Advertised {
                model, locality, ..
            } if model == selected => *locality,
            HostInferenceBinding::SupervisedNativeLocal { model, .. } if model == selected => {
                ModelLocality::OnDevice
            }
            HostInferenceBinding::Advertised { .. }
            | HostInferenceBinding::SupervisedNativeLocal { .. } => {
                return Err(invalid(InferenceRefusal::HostModelDiffers));
            }
        };
        if locality != request.envelope.locality {
            return Err(invalid(InferenceRefusal::LocalityDiffers));
        }
        if let Some(row) = &self.registry {
            // The supervised native view of a model registers as the
            // own-server endpoint it is also served at: that row, and only
            // that one, agrees with it (I2-LOCAL).
            let agrees = if native {
                native_view_of(row)
            } else {
                row.catalog.locality == locality
            };
            if !agrees {
                return Err(invalid(InferenceRefusal::RegistryLocalityDiffers));
            }
        }
        // A local lease must be backed by a registered Local transport, or by
        // the host's supervised native transport, not by caller JSON or an
        // unverified host label.
        if locality == ModelLocality::OnDevice
            && !native
            && !self.registry.as_ref().is_some_and(|row| {
                row.wire == ModelWireFormat::Local
                    && row.catalog.locality == ModelLocality::OnDevice
            })
        {
            return Err(invalid(InferenceRefusal::NoLocalBinding));
        }
        Ok(BoundInference {
            model: selected.clone(),
            locality,
            wire: self.registry.as_ref().map(|row| row.wire),
            catalog_revision: manifest::doors::catalog_revision(self.registry.as_ref())?,
        })
    }
}
fn invalid(refusal: InferenceRefusal) -> Error {
    Error::InvalidConfig(refusal.reason().into())
}

/// Why the authorizer refused a call: each reason is fixed text that names
/// no caller field, key or vault row, so an inference door may send it to
/// its caller and log it (STEP-DOOR-REFUSAL-REASON).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InferenceRefusal {
    /// A role call with no manifest, whose purpose default names another
    /// locality than the call's.
    NoDefaultBinding,
    /// The host binds the call to a catalog row, and none is registered.
    NoRegisteredModel,
    /// The host's transport serves another model than the call selects.
    HostModelDiffers,
    /// The call's locality is not the one its transport runs at.
    LocalityDiffers,
    /// The model's registered locality is not its host transport's.
    RegistryLocalityDiffers,
    /// An on-device call with no local model behind it.
    NoLocalBinding,
    /// A nonlocal extraction the host's egress did not authorize.
    ExtractionEgress,
}
impl InferenceRefusal {
    const ALL: [Self; 7] = [
        Self::NoDefaultBinding,
        Self::NoRegisteredModel,
        Self::HostModelDiffers,
        Self::LocalityDiffers,
        Self::RegistryLocalityDiffers,
        Self::NoLocalBinding,
        Self::ExtractionEgress,
    ];
    pub fn reason(self) -> &'static str {
        match self {
            Self::NoDefaultBinding => "no model binding for inference default locality",
            Self::NoRegisteredModel => "no registered model for host transport",
            Self::HostModelDiffers => "host backend model differs from selected route",
            Self::LocalityDiffers => "model locality differs from bound transport",
            Self::RegistryLocalityDiffers => "registry locality differs from host transport",
            Self::NoLocalBinding => "local inference has no local model binding",
            Self::ExtractionEgress => "nonlocal extraction needs host egress authorization",
        }
    }
    /// The refusal `error` is, or `None` for any other error the authorizer
    /// returns (a store or decode fault), whose text a door does not send.
    pub fn of(error: &Error) -> Option<Self> {
        let Error::InvalidConfig(text) = error else {
            return None;
        };
        Self::ALL
            .into_iter()
            .find(|refusal| refusal.reason() == text.as_str())
    }
}

/// Whether `row` is the registered form of a model the host also serves over
/// its supervised native transport (I2-LOCAL): the same model id, registered
/// as its provider's own-server endpoint over an OpenAI-compatible or
/// own-server wire. A third-party row, or one that says another transport
/// runs it on device (a Local in-process wire), contradicts that transport.
fn native_view_of(row: &ModelRegistryRow) -> bool {
    row.catalog.locality == ModelLocality::OwnServer
        && matches!(
            row.wire,
            ModelWireFormat::OpenaiCompat | ModelWireFormat::OwnServer
        )
}

/// The same final-request predicate for role-bound calls and raw HTTP calls,
/// for extraction and every purpose admitted as one.
fn admit_extraction(
    snapshot: &InferencePolicySnapshot,
    request: &LlmRequest,
    binding: &BoundInference,
    host: &HostInferenceContext<'_>,
) -> Result<()> {
    if *admitted_as(&request.envelope.purpose) != CallPurpose::Extraction
        || binding.locality == ModelLocality::OnDevice
    {
        return Ok(());
    }
    if !super::locality_within_extraction_bound(
        binding.locality,
        snapshot.defaults.table().extraction_max_locality,
    ) || !host
        .extraction_egress
        .is_some_and(|predicate| predicate.permits(request))
    {
        return Err(invalid(InferenceRefusal::ExtractionEgress));
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
        let snapshot =
            InferencePolicySnapshot::load(&self.store, &txn, role, &host.binding, &mut request)?;
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

pub use crate::inference_context::{HostInferenceBinding, HostInferenceContext, admitted_as};
