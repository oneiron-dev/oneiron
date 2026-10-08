//! A role-bound call's model under the vault's live model manifest.
//!
//! Chat turns and workflow steps are calls of a model role, so they are
//! admitted through that role (ARCH-0036). When the vault has a manifest,
//! its binding for the role at the effective route (the pin, narrowed by any
//! resident route) names the model, and this server must serve exactly that
//! model at exactly that route. A model it does not serve there is refused
//! before any call leaves: a vault's route may narrow, never silently widen.
//! Without a manifest the role's seat is the binding: the owner's `[models]`
//! ladder, pinned the way a routed seat is.
use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::llm::manifest::ModelRole;
use oneiron::llm::{HostInferenceBinding, HostInferenceContext};
use oneiron::{LlmBackend, LlmRequest, ModelId, ModelLocality, ModelTierRef, Vault};

use super::ModelRuntime;
use crate::config::models::role_key;

/// Why a role-bound call was refused before it left.
#[derive(Debug)]
pub enum RoleRefusal {
    /// No `[models]` rung serves the role.
    NoSeat,
    /// The vault's route names a model this server does not serve there.
    RouteNotServed {
        model: ModelId,
        route: ModelLocality,
    },
    /// The engine's inference admission refused the call.
    Refused(Box<oneiron::Error>),
}

impl RoleRefusal {
    fn refused(error: oneiron::Error) -> Self {
        Self::Refused(Box::new(error))
    }
}

impl std::fmt::Display for RoleRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSeat => write!(f, "no [models] rung serves this role"),
            Self::RouteNotServed { model, route } => write!(
                f,
                "the vault's model route names {model} at {}; this server does not serve it there",
                serde_json::to_value(route)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_else(|| format!("{route:?}"))
            ),
            Self::Refused(error) => write!(f, "{error}"),
        }
    }
}

/// An admitted request and the backend that serves it.
pub struct RoleCall {
    pub request: LlmRequest,
    pub backend: Arc<dyn LlmBackend>,
}

impl ModelRuntime {
    /// Admits `request` as a call of `role` against the vault's live policy.
    pub fn admit_role(
        &self,
        vault: &Vault,
        role: ModelRole,
        mut request: LlmRequest,
    ) -> Result<RoleCall, RoleRefusal> {
        let seat = self.seat(role).ok_or(RoleRefusal::NoSeat)?;
        let (model, locality, backend) = match vault
            .model_manifest()
            .map_err(RoleRefusal::refused)?
        {
            None => {
                // The seat is this call's binding, as a routed seat's is:
                // a purpose default only places a call nothing binds.
                request.envelope.tier.per_seat = Some(ModelTierRef(role_key(role)));
                (seat.model.clone(), seat.locality, Arc::clone(&seat.backend))
            }
            Some(manifest) => {
                let slot = manifest.binding(role).map_err(RoleRefusal::refused)?.slot;
                let route = vault
                    .model_route(slot)
                    .map_err(RoleRefusal::refused)?
                    .ok_or_else(|| {
                        RoleRefusal::refused(oneiron::Error::InvalidConfig(
                            "model manifest changed during admission".into(),
                        ))
                    })?;
                let mut bound = request.clone();
                manifest
                    .bind_request(role, &BTreeMap::from([(slot, route)]), &mut bound)
                    .map_err(RoleRefusal::refused)?;
                match self
                    .router
                    .as_ref()
                    .and_then(|router| router.served(&bound.model))
                {
                    Some((served, backend)) if served == route => (bound.model, served, backend),
                    _ => {
                        return Err(RoleRefusal::RouteNotServed {
                            model: bound.model,
                            route,
                        });
                    }
                }
            }
        };
        // A manifest-bound model on this role's own ladder answers as that
        // rung, with its prompt; the bare provider behind it has none.
        let backend = seat.rung(&model).unwrap_or(backend);
        request.model = model.clone();
        request.envelope.locality = locality;
        let request = vault
            .authorize_model_role(
                role,
                request,
                &HostInferenceContext {
                    binding: HostInferenceBinding::Advertised { model, locality },
                    extraction_egress: None,
                },
            )
            .map_err(RoleRefusal::refused)?
            .into_request();
        Ok(RoleCall { request, backend })
    }
}
